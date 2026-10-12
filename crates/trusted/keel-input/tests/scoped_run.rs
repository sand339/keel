#![doc = "A scoped run is admitted with its scope and refuses everything outside it without a prompt."]

use keel_audit::{RunKey, read_verified_file};
use keel_input::RuntimeIntent;
use keel_kernel::{EGRESS_ALLOWED, EGRESS_DENIED};
use std::{
    ffi::OsString,
    fs,
    io::{Read as _, Write as _},
    os::unix::net::UnixStream,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

fn parse(root: &Path, body: &str) -> Result<RuntimeIntent, String> {
    let path = root.join("request.json");
    fs::write(&path, body).unwrap();
    RuntimeIntent::from_runtime_arguments(&[
        OsString::from("run"),
        OsString::from("--request"),
        path.into_os_string(),
    ])
}

fn connect(socket: &Path, host: &str) -> u8 {
    let mut stream = UnixStream::connect(socket).unwrap();
    stream.write_all(b"KEEL-EGRESS-V2\0").unwrap();
    stream
        .write_all(&u16::try_from(host.len()).unwrap().to_be_bytes())
        .unwrap();
    stream.write_all(host.as_bytes()).unwrap();
    stream.write_all(&443_u16.to_be_bytes()).unwrap();
    stream.write_all(&[2]).unwrap();
    let mut response = Vec::new();
    let mut byte = [0_u8; 1];
    while response.len() < 2 && stream.read(&mut byte).unwrap() == 1 {
        response.push(byte[0]);
        if byte[0] == EGRESS_DENIED || byte[0] == EGRESS_ALLOWED {
            break;
        }
    }
    *response.last().unwrap()
}

#[test]
fn scope_is_admitted_and_enforced_without_prompts() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("keel-scoped-{nonce:x}"));
    fs::create_dir(&root).unwrap();
    let request = |extra: &str| {
        format!(
            r#"{{"session_id":"scoped-1","allow":[],"provenance":"floor","harness":"none","harness_args":[]{extra}}}"#
        )
    };
    assert!(
        parse(&root, &request(r#","profile":"scoped""#)).is_err(),
        "no scope"
    );
    assert!(
        parse(
            &root,
            &request(r#","profile":"recon","scope":["a.example"]"#)
        )
        .is_err()
    );
    assert!(parse(&root, &request(r#","profile":"scoped","scope":["*"]"#)).is_err());

    let mut intent = parse(
        &root,
        &request(
            r#","profile":"scoped","scope":["*.target.example"],"exclude":["admin.target.example"]"#,
        ),
    )
    .unwrap();
    let summary = intent
        .task_admission()
        .expect("a scoped run needs admission");
    assert!(
        summary.contains(
            "scope (all else refused): *.target.example:443,80 !admin.target.example:443,80"
        ),
        "{summary}"
    );
    intent.admit_task();
    let broker = intent.start_kernel_broker().unwrap();
    assert_eq!(
        connect(broker.socket_path(), "app.target.example"),
        EGRESS_ALLOWED
    );
    assert_eq!(connect(broker.socket_path(), "evil.example"), EGRESS_DENIED);
    assert_eq!(
        connect(broker.socket_path(), "admin.target.example"),
        EGRESS_DENIED
    );
    let (audit, key) = (
        broker.audit_path().to_owned(),
        broker.audit_key_path().to_owned(),
    );
    broker.shutdown().unwrap();

    let key = RunKey::from_hex(&fs::read_to_string(key).unwrap()).unwrap();
    let records = read_verified_file(&audit, &key).unwrap();
    let out_of_scope = records
        .iter()
        .filter(|record| {
            record.payload.event == "kernel.action"
                && record.payload.fields.get("rules").map(String::as_str)
                    == Some(r#"["kernel:out-of-scope"]"#)
                && !record.payload.fields.contains_key("prompt_presented")
        })
        .count();
    assert_eq!(
        out_of_scope, 2,
        "both refusals are scope refusals, not prompts"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn scope_none_admits_no_host_beyond_the_run() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("keel-scoped-none-{nonce:x}"));
    fs::create_dir(&root).unwrap();
    let request = |scope: &str| {
        format!(
            r#"{{"session_id":"scoped-2","allow":[],"provenance":"floor","harness":"none","harness_args":[],"profile":"scoped","scope":{scope}}}"#
        )
    };
    assert!(parse(&root, &request(r#"["none","a.example"]"#)).is_err());
    let mut intent = parse(&root, &request(r#"["none"]"#)).unwrap();
    let summary = intent
        .task_admission()
        .expect("a scoped run needs admission");
    assert!(
        summary.contains("scope (all else refused): none"),
        "{summary}"
    );
    intent.admit_task();
    let broker = intent.start_kernel_broker().unwrap();
    assert_eq!(
        connect(broker.socket_path(), "app.target.example"),
        EGRESS_DENIED
    );
    broker.shutdown().unwrap();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn admitted_target_recording_names_refused_hosts_in_the_audit() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("keel-record-targets-{nonce:x}"));
    fs::create_dir(&root).unwrap();
    let mut intent = parse(
        &root,
        r#"{"session_id":"scoped-3","allow":[],"provenance":"floor","harness":"none","harness_args":[],"profile":"scoped","scope":["none"],"record_targets":true}"#,
    )
    .unwrap();
    let summary = intent
        .task_admission()
        .expect("target recording needs admission");
    assert!(summary.contains("record-targets:"), "{summary}");
    intent.admit_task();
    let broker = intent.start_kernel_broker().unwrap();
    assert_eq!(
        connect(broker.socket_path(), "unlisted.example"),
        EGRESS_DENIED
    );
    let (audit, key) = (
        broker.audit_path().to_owned(),
        broker.audit_key_path().to_owned(),
    );
    broker.shutdown().unwrap();
    let key = RunKey::from_hex(&fs::read_to_string(key).unwrap()).unwrap();
    let records = read_verified_file(&audit, &key).unwrap();
    let target = records
        .iter()
        .find(|record| record.payload.event == "kernel.action")
        .and_then(|record| record.payload.fields.get("target"))
        .expect("recorded target");
    assert!(target.contains("unlisted.example:443"), "{target}");
    let manifest = records
        .iter()
        .find(|record| record.payload.event == "kernel.run-admitted")
        .and_then(|record| record.payload.fields.get("manifest"));
    assert!(
        manifest.is_none_or(|manifest| manifest.contains(r#""record_targets":true"#)),
        "the manifest records the choice"
    );
    fs::remove_dir_all(root).unwrap();
}
