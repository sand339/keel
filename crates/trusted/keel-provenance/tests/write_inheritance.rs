#![doc = "Phase 2 write-inheritance acceptance scenarios."]

use keel_provenance::{ClassificationTable, GitClassifier, Rank, ResultObservation, SessionFacts};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

#[test]
fn floor_zero_write_and_reread_stays_rank_zero() {
    assert_write_and_reread(0, Rank::UntrustedContent);
}

#[test]
fn floor_three_write_and_reread_stays_rank_three() {
    assert_write_and_reread(3, Rank::TrustedInstruction);
}

fn assert_write_and_reread(floor: u8, expected: Rank) {
    let workspace = scratch();
    fs::create_dir(&workspace).expect("workspace");
    let path = "generated.txt";
    fs::write(workspace.join(path), "inherited content\n").expect("write content");
    let classifier =
        GitClassifier::new(&workspace, Vec::<String>::new(), Vec::<PathBuf>::new()).expect("git");
    let table = ClassificationTable::builtin(Vec::<String>::new());
    let mut facts = SessionFacts::default();
    facts.floor = floor;
    facts.record_write(path, true, 1);

    let result = table
        .classify(
            ResultObservation::WorkspaceFile {
                path: path.to_owned(),
            },
            &classifier,
            &facts,
        )
        .expect("classification");
    assert_eq!(result.rank(), Some(expected));
    result.apply(&mut facts, 2);
    assert_eq!(facts.floor, floor);
    assert_eq!(facts.writer_floor(path), Some(floor));
    fs::remove_dir_all(workspace).expect("cleanup");
}

fn scratch() -> PathBuf {
    // Both tests in this binary share the pid, so the timestamp is all that
    // separates their workspaces, and a clock that does not tick per nanosecond
    // hands them the same one. A counter separates them whatever the clock does.
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "keel-write-inheritance-{}-{nonce}-{sequence}",
        std::process::id()
    ))
}
