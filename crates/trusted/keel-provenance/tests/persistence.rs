#![doc = "Acceptance tests for durable provenance floors."]

use keel_provenance::{FloorState, PersistedMode, SessionFacts, SourceRef};
use std::{
    fs,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

#[test]
fn non_authoritative_snapshot_reconstructs_history_and_write_labels() {
    let root = scratch();
    fs::create_dir(&root).unwrap();
    let path = root.join("floor.json");
    let mut facts = SessionFacts::default();
    facts.record_write("transcript.json", true, 1);
    facts.record_floor_observation(
        0,
        SourceRef::Host {
            host: "evil.example".to_owned(),
            path: "/issue/1".to_owned(),
        },
        2,
    );

    FloorState::capture("session-1", PersistedMode::GateContext, &facts)
        .save(&path)
        .unwrap();
    let loaded = FloorState::load(&path, "session-1")
        .unwrap()
        .expect("saved state");
    let resumed = loaded.resume_facts();

    assert_eq!(resumed.floor, 0);
    assert_eq!(resumed.floor_history, facts.floor_history);
    assert_eq!(resumed.writer_floor("transcript.json"), Some(1));
    assert!(FloorState::load(&path, "other-session").is_err());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn approved_lift_starts_a_new_floor_epoch_without_discarding_history() {
    let root = scratch();
    fs::create_dir(&root).unwrap();
    let path = root.join("floor.json");
    let mut facts = SessionFacts::default();
    facts.record_floor_observation(
        0,
        SourceRef::Host {
            host: "evil.example".to_owned(),
            path: "/issue/1".to_owned(),
        },
        1,
    );
    facts.lift_floor(2);
    FloorState::capture("session-1", PersistedMode::Floor, &facts)
        .save(&path)
        .unwrap();
    let mut resumed = FloorState::load(&path, "session-1")
        .unwrap()
        .unwrap()
        .resume_facts();
    assert_eq!(resumed.floor, 2);
    assert_eq!(resumed.floor_history.len(), 1);

    resumed.record_floor_observation(
        1,
        SourceRef::Shell {
            command: "trusted wrapper output".to_owned(),
        },
        2,
    );
    FloorState::capture("session-1", PersistedMode::Floor, &resumed)
        .save(&path)
        .unwrap();
    let loaded = FloorState::load(&path, "session-1").unwrap().unwrap();
    assert_eq!(loaded.floor(), 1);
    assert_eq!(loaded.resume_facts().floor_history.len(), 2);
    fs::remove_dir_all(root).unwrap();
}

fn scratch() -> std::path::PathBuf {
    // Both tests in this binary run at once and create their directory, so two
    // that read the clock in the same tick collide: one fails to create, or one
    // removes the other's tree on the way out. macOS does not tick the clock per
    // nanosecond, so this happened. A counter makes the name unique whatever the
    // granularity; the timestamp stays only to keep the artifacts sortable.
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("keel-floor-state-{nonce:x}-{sequence}"))
}
