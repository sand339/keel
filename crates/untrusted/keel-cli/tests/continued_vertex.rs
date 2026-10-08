#![doc = "Acceptance coverage for resumed CLI vertices."]

use keel_cli::{Command, parse_args, write_runtime_request_in};
use keel_input::RuntimeIntent;
use keel_provenance::{FloorState, PersistedMode, SessionFacts, SourceRef};
use std::{
    ffi::OsString,
    fs,
    time::{SystemTime, UNIX_EPOCH},
};

#[test]
fn continue_does_not_trust_unsigned_persisted_floor_authority() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory = std::env::temp_dir().join(format!("keel-continue-{nonce:x}"));
    fs::create_dir(&directory).unwrap();

    let source = SourceRef::Host {
        host: "api.github.com".to_owned(),
        path: "/repos/example/project/issues/7".to_owned(),
    };
    let mut prior_facts = SessionFacts::default();
    prior_facts.record_floor_observation(0, source.clone(), 42);
    FloorState::capture("session-1", PersistedMode::Floor, &prior_facts)
        .save(&directory.join("floor.json"))
        .unwrap();

    let command = parse_args(
        [
            "run",
            "--continue",
            "session-1",
            "--provenance",
            "floor",
            "test",
        ]
        .map(OsString::from),
    )
    .unwrap();
    let Command::Run(request) = command else {
        panic!("expected run request");
    };
    assert_eq!(request.session_id, "session-1");

    let request_path = write_runtime_request_in(&request, &directory).unwrap();
    let intent = RuntimeIntent::from_runtime_arguments(&[
        OsString::from("run"),
        OsString::from("--request"),
        request_path.into_os_string(),
    ])
    .unwrap();
    let report = intent.start_kernel_broker().unwrap().shutdown().unwrap();

    assert_eq!(report.session_facts.floor, 0);
    assert_eq!(report.session_facts.floor_history.len(), 1);
    assert_eq!(
        report.session_facts.floor_history[0].source,
        SourceRef::File {
            path: "workspace://direct-exposure".to_owned(),
            author: None,
        }
    );
    assert_ne!(report.session_facts.floor_history[0].source, source);
    let persisted = FloorState::load(&directory.join("floor.json"), "session-1")
        .unwrap()
        .unwrap();
    assert_eq!(persisted.floor(), 0);

    fs::remove_dir_all(directory).unwrap();
}
