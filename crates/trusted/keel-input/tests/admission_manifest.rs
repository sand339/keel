#![doc = "Each run records a canonical admission manifest before any action."]

use keel_audit::{RunKey, read_verified_file};
use keel_input::RuntimeIntent;
use ring::digest::{SHA256, digest};
use std::{
    ffi::OsString,
    fmt::Write as _,
    fs,
    time::{SystemTime, UNIX_EPOCH},
};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut text, byte| {
        let _ = write!(text, "{byte:02x}");
        text
    })
}

#[test]
fn the_manifest_is_canonical_bound_and_first() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("keel-admission-{nonce:x}"));
    fs::create_dir(&root).unwrap();
    let request = root.join("request.json");
    fs::write(
        &request,
        r#"{"session_id":"admitted-1","allow":["egress:docs.rs"],"provenance":"floor","harness":"none","harness_args":[],"cpus":2}"#,
    )
    .unwrap();
    let broker = RuntimeIntent::from_runtime_arguments(&[
        OsString::from("run"),
        OsString::from("--request"),
        request.into_os_string(),
    ])
    .unwrap()
    .start_kernel_broker()
    .unwrap();
    let kernel = root.join("vmlinuz");
    fs::write(&kernel, b"kernel bytes").unwrap();
    assert!(
        broker
            .record_admission(&[("kernel", &root.join("absent"))], None)
            .is_err(),
        "an unreadable artifact refuses the run"
    );
    broker
        .record_admission(&[("kernel", &kernel)], Some("6.12.111-0-virt"))
        .unwrap();
    let (audit, key) = (
        broker.audit_path().to_owned(),
        broker.audit_key_path().to_owned(),
    );
    broker.shutdown().unwrap();

    let key = RunKey::from_hex(&fs::read_to_string(key).unwrap()).unwrap();
    let records = read_verified_file(&audit, &key).unwrap();
    let events = records
        .iter()
        .map(|record| record.payload.event.as_str())
        .collect::<Vec<_>>();
    let admitted = events
        .iter()
        .position(|event| *event == "kernel.run-admitted")
        .expect("admission record");
    assert_eq!(
        events
            .iter()
            .filter(|event| **event == "kernel.run-admitted")
            .count(),
        1
    );
    assert!(
        events[..admitted]
            .iter()
            .all(|event| *event == "kernel.enforcement-state"),
        "only the startup state precedes admission: {events:?}"
    );
    let fields = &records[admitted].payload.fields;
    let manifest = &fields["manifest"];
    assert_eq!(
        fields["manifest_sha256"],
        hex(digest(&SHA256, manifest.as_bytes()).as_ref())
    );
    let mut value: serde_json::Value = serde_json::from_str(manifest).unwrap();
    value.sort_all_objects();
    assert_eq!(&value.to_string(), manifest, "keys sorted, no whitespace");
    assert_eq!(value["version"], 1);
    assert_eq!(value["run_id"], "admitted-1");
    assert_eq!(value["run"]["cpus"], 2);
    assert_eq!(value["run"]["starting_floor"], 0);
    assert_eq!(value["kernel_release"], "6.12.111-0-virt");
    assert_eq!(
        value["artifacts"]["kernel"],
        hex(digest(&SHA256, b"kernel bytes").as_ref())
    );
    assert_eq!(
        value["authority"]["egress_hosts"],
        serde_json::json!(["docs.rs"])
    );
    assert_eq!(value["model"]["provider"], serde_json::Value::Null);
    assert_eq!(value["admission"]["admitted_by"], "not-required");
    assert_eq!(value["workspace"]["head"].as_str().map(str::len), Some(40));
    fs::remove_dir_all(root).unwrap();
}
