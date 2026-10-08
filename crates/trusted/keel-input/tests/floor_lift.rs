#![doc = "Acceptance test for live, gated floor attestation."]

use keel_audit::{RunKey, read_verified_file, verify_file};
use keel_input::{RuntimeIntent, terminal_gate_channel};
use keel_kernel::GateDecision;
use keel_provenance::FloorState;
use std::{
    ffi::OsString,
    fs, thread,
    time::{SystemTime, UNIX_EPOCH},
};

#[test]
fn approved_lift_changes_the_live_kernel_and_persists_on_shutdown() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("keel-live-floor-lift-{nonce:x}"));
    fs::create_dir(&root).unwrap();
    let request = root.join("request.json");
    fs::write(
        &request,
        r#"{"session_id":"session-1","allow":[],"provenance":"floor","harness":"test","harness_args":[]}"#,
    )
    .unwrap();
    let intent = RuntimeIntent::from_runtime_arguments(&[
        OsString::from("run"),
        OsString::from("--request"),
        request.into_os_string(),
    ])
    .unwrap();
    let (gate, controller) = terminal_gate_channel();
    let broker = intent.start_kernel_broker_with_gate(gate).unwrap();
    let control = broker.control();
    let worker = thread::spawn(move || control.lift_floor(2));
    let prompt = controller.receive().unwrap();
    assert_eq!(prompt.payload().action_class, "lift-floor");
    assert_eq!(
        prompt.payload().exact_target,
        b"session: \"session-1\"\nrequested floor: 2"
    );
    assert!(
        String::from_utf8_lossy(&prompt.payload().floor_history[0])
            .contains("workspace://direct-exposure")
    );
    prompt.decide(GateDecision::Approve).unwrap();
    assert_eq!(worker.join().unwrap().unwrap(), 2);
    let audit_path = broker.audit_path().to_owned();
    let key_path = broker.audit_key_path().to_owned();
    let report = broker.shutdown().unwrap();
    assert_eq!(report.session_facts.floor, 2);
    assert_eq!(
        FloorState::load(&root.join("floor.json"), "session-1")
            .unwrap()
            .unwrap()
            .floor(),
        2
    );
    let key = RunKey::from_hex(&fs::read_to_string(key_path).unwrap()).unwrap();
    assert_eq!(verify_file(&audit_path, &key).unwrap(), 4);
    let records = read_verified_file(&audit_path, &key).unwrap();
    assert!(records.iter().any(|record| {
        record.payload.fields.get("action_class") == Some(&"lift-floor".to_owned())
    }));
    fs::remove_dir_all(root).unwrap();
}
