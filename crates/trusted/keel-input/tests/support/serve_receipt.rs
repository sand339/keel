use super::{Teardown, latest, unmet};
use keel_audit::{
    AuditError, AuditWriter, KernelAudit, Redactor, RunKey, TeardownReceipt, inspect_file,
};
use keel_kernel::{AuditSink as _, RunTeardownEvent};
use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

fn session(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("keel-receipt-{name}-{nonce:x}"));
    fs::create_dir(&root).unwrap();
    root
}

/// Writes a sealed chain for runtime pid 4242 whose teardown names `named`.
fn sealed_chain(directory: &Path, named: Option<String>) -> PathBuf {
    let chain = directory.join("audit-4242-1-0.ndjson");
    let key = RunKey::new([7; 32]);
    key.write_new(&chain.with_extension("key")).unwrap();
    let writer = AuditWriter::spawn(
        &chain,
        "receipt-test",
        key,
        Redactor::new(["run-secret"]).unwrap(),
    )
    .unwrap();
    let mut audit = KernelAudit::new(writer);
    audit
        .record_run_teardown(RunTeardownEvent {
            stop_reason: "shutdown",
            escalated: false,
            checks: Vec::new(),
            supervisor_key: named,
        })
        .unwrap();
    audit.shutdown().unwrap();
    chain
}

fn read(path: &Path) -> TeardownReceipt {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

#[test]
fn receipt_binds_the_sealed_chain_and_the_files_it_kept() {
    let directory = session("bound");
    let supervisor = RunKey::new([9; 32]);
    let chain = sealed_chain(&directory, Some(supervisor.public_hex()));
    let pid_file = directory.join("attach.pid");
    fs::write(&pid_file, "1\n").unwrap();
    fs::write(directory.join("floor.json"), "{}").unwrap();

    let mut teardown = Teardown::begin();
    teardown.remove_file("pid-file", &pid_file);
    let (path, ok) = teardown
        .finish(&directory, 4242, UNIX_EPOCH, &supervisor, "stop")
        .unwrap();

    assert!(ok);
    assert_eq!(path, directory.join("audit-4242-1-0.receipt.json"));
    assert!(!pid_file.exists());
    let receipt = read(&path);
    let seal = inspect_file(&chain, &RunKey::new([7; 32]))
        .unwrap()
        .seal_hash;
    receipt
        .verify(&RunKey::from_hex(&supervisor.public_hex()).unwrap(), seal)
        .unwrap();
    assert_eq!(receipt.run_id, "receipt-test");
    assert_eq!(receipt.stop_reason, "stop");
    assert_eq!(receipt.checks.len(), 2);
    assert!(receipt.checks["0.pid-file"].starts_with("ok: "));
    assert_eq!(receipt.checks["1.audit-chain"], "ok: audit-4242-1-0.ndjson");
    assert_eq!(
        receipt.retained["floor.json"],
        "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
    );
    assert_eq!(latest(&directory), Some(path.clone()));
    assert!(unmet(&path).unwrap().is_empty());
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn a_chain_naming_another_supervisor_fails_the_receipt() {
    let directory = session("other");
    let chain = sealed_chain(&directory, Some(RunKey::new([8; 32]).public_hex()));
    let supervisor = RunKey::new([9; 32]);

    let (path, ok) = Teardown::begin()
        .finish(&directory, 4242, UNIX_EPOCH, &supervisor, "exited")
        .unwrap();

    assert!(!ok);
    let receipt = read(&path);
    let seal = inspect_file(&chain, &RunKey::new([7; 32]))
        .unwrap()
        .seal_hash;
    receipt
        .verify(&RunKey::from_hex(&supervisor.public_hex()).unwrap(), seal)
        .unwrap();
    assert_eq!(
        unmet(&path).unwrap(),
        [
            "0.audit-chain unmet: teardown record does not name this supervisor: audit-4242-1-0.ndjson"
        ]
    );
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn a_missing_chain_or_an_edited_receipt_is_reported() {
    let directory = session("missing");
    let supervisor = RunKey::new([9; 32]);
    let (path, ok) = Teardown::begin()
        .finish(&directory, 4242, UNIX_EPOCH, &supervisor, "forced")
        .unwrap();
    assert!(!ok);
    assert_eq!(path, directory.join("audit-4242.receipt.json"));

    let verifier = RunKey::from_hex(&supervisor.public_hex()).unwrap();
    let mut edited = read(&path);
    edited.checks.insert(
        "0.audit-chain".to_owned(),
        "ok: audit-4242.ndjson".to_owned(),
    );
    edited.ok = true;
    assert_eq!(
        edited.verify(&verifier, None),
        Err(AuditError::Receipt("signature does not verify"))
    );
    assert_eq!(
        read(&path).verify(&verifier, Some([1; 32])),
        Err(AuditError::Receipt("does not name this chain's seal"))
    );
    fs::remove_dir_all(directory).unwrap();
}
