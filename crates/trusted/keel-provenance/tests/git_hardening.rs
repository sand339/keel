//! Regression coverage for repository-controlled host Git execution.

use keel_provenance::{GitClassifier, SessionFacts};
use std::{
    fs,
    os::unix::fs::PermissionsExt as _,
    path::Path,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

#[test]
fn repository_fsmonitor_cannot_execute_during_trusted_classification() {
    let workspace = std::env::temp_dir().join(format!(
        "keel-provenance-host-git-{}-{:x}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&workspace).unwrap();
    git(&workspace, &["init", "-q"]);
    git(&workspace, &["config", "user.name", "Operator"]);
    git(
        &workspace,
        &["config", "user.email", "operator@example.com"],
    );
    fs::write(workspace.join("owned.txt"), "owned\n").unwrap();
    git(&workspace, &["add", "owned.txt"]);
    git(&workspace, &["commit", "-q", "-m", "owned"]);
    let marker = workspace.join("fsmonitor-ran");
    let hook = workspace.join("evil-fsmonitor");
    fs::write(
        &hook,
        format!("#!/bin/sh\ntouch '{}'\nprintf '{{}}'\n", marker.display()),
    )
    .unwrap();
    fs::set_permissions(&hook, fs::Permissions::from_mode(0o700)).unwrap();
    git(
        &workspace,
        &["config", "core.fsmonitor", hook.to_str().unwrap()],
    );

    let classifier =
        GitClassifier::new(&workspace, ["operator@example.com".to_owned()], Vec::new()).unwrap();
    classifier
        .classify_file("owned.txt", &SessionFacts::default())
        .unwrap();
    assert!(!marker.exists(), "repository-controlled fsmonitor executed");
    fs::remove_dir_all(workspace).unwrap();
}

fn git(workspace: &Path, arguments: &[&str]) {
    let status = Command::new("git")
        .arg("-C")
        .arg(workspace)
        .args(arguments)
        .status()
        .unwrap();
    assert!(status.success());
}
