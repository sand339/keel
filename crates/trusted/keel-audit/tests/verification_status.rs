#![doc = "Audit completion-state and legacy-format regression tests."]

use keel_audit::{
    AuditError, AuditPayload, AuditWriter, Redactor, RunKey, inspect_file, read_verified_file,
    read_verified_prefix, verify_file,
};
use std::{collections::BTreeMap, fs};

#[test]
fn authenticated_prefix_is_reported_but_not_accepted_as_complete() {
    let root = std::env::temp_dir().join(format!("keel-audit-prefix-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir(&root).unwrap();
    let path = root.join("audit.ndjson");
    let key = RunKey::new([31; 32]);
    let writer = AuditWriter::spawn(
        &path,
        "status-test",
        key,
        Redactor::new(Vec::<String>::new()).unwrap(),
    )
    .unwrap();
    writer
        .record(AuditPayload {
            timestamp_ms: 1,
            event: "test".to_owned(),
            action_id: None,
            fields: BTreeMap::new(),
        })
        .unwrap();
    writer.shutdown().unwrap();
    let complete = fs::read_to_string(&path).unwrap();
    fs::write(&path, format!("{}\n", complete.lines().next().unwrap())).unwrap();

    assert_eq!(
        inspect_file(&path, &RunKey::new([31; 32])).unwrap(),
        keel_audit::VerificationStatus {
            records: 1,
            sealed: false
        }
    );
    assert_eq!(
        verify_file(&path, &RunKey::new([31; 32])),
        Err(AuditError::Unsealed)
    );
    assert_eq!(
        read_verified_file(&path, &RunKey::new([31; 32])),
        Err(AuditError::Unsealed)
    );
    let (records, status) = read_verified_prefix(&path, &RunKey::new([31; 32])).unwrap();
    assert_eq!(records.len(), 1, "the authenticated prefix is readable");
    assert_eq!(records[0].payload.event, "test");
    assert!(!status.sealed, "and is reported as unsealed");
    assert!(
        read_verified_prefix(&path, &RunKey::new([32; 32])).is_err(),
        "a wrong key authenticates nothing"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn retired_mac_shape_is_named_as_legacy() {
    let root = std::env::temp_dir().join(format!("keel-audit-legacy-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir(&root).unwrap();
    let path = root.join("audit.ndjson");
    let writer = AuditWriter::spawn(
        &path,
        "legacy-test",
        RunKey::new([32; 32]),
        Redactor::new(Vec::<String>::new()).unwrap(),
    )
    .unwrap();
    writer.shutdown().unwrap();
    let text = fs::read_to_string(&path).unwrap();
    let mut value: serde_json::Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
    value["mac"] = serde_json::Value::String("00".repeat(32));
    fs::write(
        &path,
        format!("{}\n", serde_json::to_string(&value).unwrap()),
    )
    .unwrap();
    assert_eq!(
        inspect_file(&path, &RunKey::new([32; 32])),
        Err(AuditError::LegacySignature(0))
    );
    fs::remove_dir_all(root).unwrap();
}
