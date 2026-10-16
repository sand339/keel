//! Regression coverage for repository-controlled host Git execution.

use keel_provenance::{GitClassifier, SessionFacts, content_filter_overrides, trusted_git_command};
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

/// Admission's `git status` on the live workspace must not run a filter the
/// guest configured, whether in `.git/config` itself, through an include, or
/// named only by `.git/info/attributes`.
#[test]
fn repository_content_filters_cannot_execute_during_trusted_status() {
    let workspace = scratch("filter");
    git(&workspace, &["init", "-q"]);
    fs::write(workspace.join("tracked.txt"), "tracked\n").unwrap();
    git(&workspace, &["add", "tracked.txt"]);
    git(
        &workspace,
        &[
            "-c",
            "user.name=Operator",
            "-c",
            "user.email=operator@example.com",
            "commit",
            "-q",
            "-m",
            "tracked",
        ],
    );
    let ran = |name: &str| workspace.join(format!("ran-{name}"));
    let included = workspace.join("included.config");
    fs::write(
        &included,
        format!(
            "[filter \"inc.with.dots\"]\n\tprocess = touch '{}'\n",
            ran("process").display()
        ),
    )
    .unwrap();
    git(
        &workspace,
        &["config", "include.path", included.to_str().unwrap()],
    );
    let clean = format!("touch '{}'; cat", ran("clean").display());
    git(&workspace, &["config", "filter.local.clean", &clean]);
    fs::write(
        workspace.join(".gitattributes"),
        "tracked.txt filter=local\n",
    )
    .unwrap();
    fs::write(
        workspace.join(".git/info/attributes"),
        "* filter=inc.with.dots\n",
    )
    .unwrap();
    // Same size, newer mtime: Git must re-hash the file to compare it, and
    // hashing runs the filter.
    std::thread::sleep(std::time::Duration::from_millis(1100));
    fs::write(workspace.join("tracked.txt"), "tracked\n").unwrap();

    let overrides = content_filter_overrides(&workspace).unwrap();
    let status = trusted_git_command()
        .arg("-C")
        .arg(&workspace)
        .args(&overrides)
        .args(["status", "--porcelain", "--ignore-submodules=all"])
        .output()
        .unwrap();
    assert!(status.status.success());
    assert!(String::from_utf8_lossy(&status.stdout).contains(".gitattributes"));
    assert!(
        !ran("process").exists() && !ran("clean").exists(),
        "a repository filter executed"
    );

    // Control: the same status without the overrides runs the filter.
    let _ = trusted_git_command()
        .arg("-C")
        .arg(&workspace)
        .args(["status", "--porcelain"])
        .output()
        .unwrap();
    assert!(ran("process").exists(), "the fixture's filter must be live");
    fs::remove_dir_all(workspace).unwrap();
}

#[test]
fn a_filter_driver_that_cannot_be_overridden_is_refused() {
    let workspace = scratch("filter-name");
    git(&workspace, &["init", "-q"]);
    git(&workspace, &["config", "filter.a=b.clean", "true"]);
    assert!(content_filter_overrides(&workspace).is_err());
    assert_eq!(
        content_filter_overrides(&scratch_repository()).unwrap(),
        Vec::<String>::new()
    );
    fs::remove_dir_all(workspace).unwrap();
}

fn scratch_repository() -> std::path::PathBuf {
    let workspace = scratch("no-filter");
    git(&workspace, &["init", "-q"]);
    workspace
}

fn scratch(name: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "keel-provenance-{name}-{}-{:x}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&path).unwrap();
    path
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
