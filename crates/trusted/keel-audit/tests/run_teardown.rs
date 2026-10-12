#![doc = "The run teardown record: its fields, admission binding, and place in the chain."]

use keel_audit::{AuditWriter, KernelAudit, Redactor, RunKey, read_verified_file};
use keel_kernel::{
    AuditSink as _, RunAdmittedEvent, RunResourceEvent, RunTeardownEvent, TeardownCheck,
};
use std::{fs, path::PathBuf};

fn chain(name: &str) -> (PathBuf, KernelAudit) {
    let root = std::env::temp_dir().join(format!("keel-audit-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir(&root).unwrap();
    let path = root.join("audit.ndjson");
    let writer = AuditWriter::spawn(
        &path,
        "teardown-test",
        RunKey::new([41; 32]),
        Redactor::new(["run-secret"]).unwrap(),
    )
    .unwrap();
    (path, KernelAudit::new(writer))
}

fn teardown(unmet: Option<&str>) -> RunTeardownEvent {
    RunTeardownEvent {
        stop_reason: "exited",
        escalated: true,
        checks: vec![
            TeardownCheck {
                kind: "backend-group",
                detail: "pgid 4242".to_owned(),
                unmet: None,
            },
            TeardownCheck {
                kind: "scratch",
                detail: "/tmp/keel-runtime-1-0".to_owned(),
                unmet: unmet.map(str::to_owned),
            },
        ],
        supervisor_key: None,
    }
}

#[test]
fn teardown_is_bound_to_the_admission_and_precedes_the_seal() {
    let (path, mut audit) = chain("teardown-bound");
    audit
        .record_run_admitted(RunAdmittedEvent {
            manifest: "{\"version\":1}".to_owned(),
            digest: [0xab; 32],
        })
        .unwrap();
    audit.record_run_teardown(teardown(None)).unwrap();
    audit.shutdown().unwrap();

    // The verified reader requires the seal and returns the records before it.
    let records = read_verified_file(&path, &RunKey::new([41; 32])).unwrap();
    let events = records
        .iter()
        .map(|record| record.payload.event.as_str())
        .collect::<Vec<_>>();
    assert_eq!(events, ["kernel.run-admitted", "kernel.run-teardown"]);
    let fields = &records[1].payload.fields;
    assert_eq!(fields["admission_sha256"], "ab".repeat(32));
    assert_eq!(fields["stop_reason"], "exited");
    assert_eq!(fields["escalated"], "true");
    assert_eq!(fields["ok"], "true");
    assert_eq!(fields["check.0.backend-group"], "ok: pgid 4242");
    assert_eq!(fields["check.1.scratch"], "ok: /tmp/keel-runtime-1-0");
    fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
fn an_unmet_postcondition_is_named_and_fails_the_record() {
    let (path, mut audit) = chain("teardown-unmet");
    audit
        .record_run_teardown(teardown(Some("cannot remove: run-secret denied")))
        .unwrap();
    audit.shutdown().unwrap();

    let records = read_verified_file(&path, &RunKey::new([41; 32])).unwrap();
    let fields = &records[0].payload.fields;
    assert_eq!(fields["ok"], "false");
    assert!(!fields.contains_key("admission_sha256"));
    assert_eq!(
        fields["check.1.scratch"],
        "unmet: cannot remove: [REDACTED] denied: /tmp/keel-runtime-1-0"
    );
    fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
fn each_created_resource_is_recorded_for_recovery() {
    let (path, mut audit) = chain("run-resource");
    audit
        .record_run_resource(RunResourceEvent {
            kind: "backend-group",
            detail: "pgid 4242".to_owned(),
        })
        .unwrap();
    audit.shutdown().unwrap();

    let records = read_verified_file(&path, &RunKey::new([41; 32])).unwrap();
    assert_eq!(records[0].payload.event, "kernel.run-resource");
    assert_eq!(records[0].payload.fields["kind"], "backend-group");
    assert_eq!(records[0].payload.fields["detail"], "pgid 4242");
    fs::remove_dir_all(path.parent().unwrap()).unwrap();
}
