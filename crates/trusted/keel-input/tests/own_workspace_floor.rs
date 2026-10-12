#![doc = "workspace:own starts the floor at the declared rank, from a clean clone, only after trusted admission."]

use keel_input::RuntimeIntent;
use std::{
    ffi::OsString,
    fs,
    path::Path,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

fn git(directory: &Path, arguments: &[&str]) {
    let status = Command::new("/usr/bin/git")
        .arg("-C")
        .arg(directory)
        .args([
            "-c",
            "user.name=keel",
            "-c",
            "user.email=keel@example.invalid",
        ])
        .args(arguments)
        .status()
        .unwrap();
    assert!(status.success(), "git {arguments:?}");
}

fn intent(request: &Path) -> RuntimeIntent {
    RuntimeIntent::from_runtime_arguments(&[
        OsString::from("run"),
        OsString::from("--request"),
        request.as_os_str().to_owned(),
    ])
    .unwrap()
}

// One test in this binary, because it changes the process's working
// directory, which the broker reads as the workspace.
#[test]
fn an_own_workspace_starts_at_rank_two_only_once_admitted() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir()
        .canonicalize()
        .unwrap()
        .join(format!("keel-own-floor-{nonce:x}"));
    let repository = root.join("repository");
    fs::create_dir_all(&repository).unwrap();
    git(&repository, &["init", "-q"]);
    fs::write(repository.join("README.md"), "own\n").unwrap();
    git(&repository, &["add", "."]);
    git(&repository, &["commit", "-qm", "accepted"]);
    std::env::set_current_dir(&repository).unwrap();
    let request = |session: &str| {
        let directory = root.join("state/sessions").join(session);
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("request.json");
        fs::write(
            &path,
            format!(
                r#"{{"session_id":"{session}","allow":["workspace:own"],"provenance":"floor","harness":"none","harness_args":[]}}"#
            ),
        )
        .unwrap();
        path
    };

    let unadmitted = request("own-unadmitted");
    let summary = intent(&unadmitted)
        .task_admission()
        .expect("task authority");
    assert!(
        summary.contains("workspace:own: rank 2 for HEAD"),
        "{summary}"
    );
    assert!(intent(&unadmitted).start_kernel_broker().is_err());
    assert!(!unadmitted.with_file_name("workspace").exists());

    let admitted = request("own-admitted");
    let mut own = intent(&admitted);
    own.admit_task();
    let broker = own.start_kernel_broker().unwrap();
    let clone = admitted.with_file_name("workspace").canonicalize().unwrap();
    assert_eq!(broker.workspace(), clone);
    broker.shutdown().unwrap();
    let floor: serde_json::Value =
        serde_json::from_slice(&fs::read(admitted.with_file_name("floor.json")).unwrap()).unwrap();
    assert_eq!(floor["floor"], 2);
    let ledger = fs::read_dir(root.join("state/accepted-heads"))
        .unwrap()
        .count();
    assert_eq!(
        ledger, 1,
        "the acceptance is recorded outside every session"
    );

    let plain = root.join("state/sessions/plain/request.json");
    fs::create_dir_all(plain.parent().unwrap()).unwrap();
    fs::write(
        &plain,
        r#"{"session_id":"plain","allow":[],"provenance":"floor","harness":"none","harness_args":[]}"#,
    )
    .unwrap();
    intent(&plain)
        .start_kernel_broker()
        .unwrap()
        .shutdown()
        .unwrap();
    let floor: serde_json::Value =
        serde_json::from_slice(&fs::read(plain.with_file_name("floor.json")).unwrap()).unwrap();
    assert_eq!(
        floor["floor"], 0,
        "without the declaration the workspace stays rank 0"
    );
    fs::remove_dir_all(root).unwrap();
}
