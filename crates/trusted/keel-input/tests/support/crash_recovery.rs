#[cfg(target_os = "linux")]
use super::executable_name;
use super::{Expected, elapsed_seconds, recover_directory};
use keel_audit::{AuditPayload, AuditWriter, Redactor, RunKey};
use std::{
    collections::BTreeMap,
    env, fs,
    os::unix::{
        fs::PermissionsExt as _,
        process::{CommandExt as _, ExitStatusExt as _},
    },
    path::{Path, PathBuf},
    process::{Child, Command},
    time::{SystemTime, UNIX_EPOCH},
};

const DEAD_PID: u32 = 999_999;

fn nonce() -> String {
    format!(
        "{:x}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    )
}

fn session() -> PathBuf {
    let root = env::temp_dir().join(format!("keel-recovery-test-{}", nonce()));
    fs::create_dir(&root).unwrap();
    root
}

fn now_ms() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

/// Writes the chain of a run with process id `pid`, recording `resources`,
/// sealed or cut off before its seal as a crash leaves it.
fn chain(directory: &Path, pid: u32, resources: &[(&str, String)], sealed: bool) -> PathBuf {
    let path = directory.join(format!("audit-{pid}-1-0.ndjson"));
    let key = RunKey::new([3; 32]);
    key.write_new(&path.with_extension("key")).unwrap();
    let writer = AuditWriter::spawn(
        &path,
        "recovery-test",
        key,
        Redactor::new(["s3cret"]).unwrap(),
    )
    .unwrap();
    for (kind, detail) in resources {
        writer
            .record(AuditPayload {
                timestamp_ms: now_ms(),
                event: "kernel.run-resource".to_owned(),
                action_id: None,
                fields: BTreeMap::from([
                    ("kind".to_owned(), (*kind).to_owned()),
                    ("detail".to_owned(), detail.clone()),
                ]),
            })
            .unwrap();
    }
    writer.shutdown().unwrap();
    if !sealed {
        let text = fs::read_to_string(&path).unwrap();
        let lines = text.lines().collect::<Vec<_>>();
        fs::write(&path, format!("{}\n", lines[..lines.len() - 1].join("\n"))).unwrap();
    }
    path
}

/// A directory made as the runtime makes its own: private to this user.
fn private_dir(path: &Path) {
    fs::create_dir(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

fn group_leader() -> Child {
    Command::new("/bin/sleep")
        .arg("30")
        .process_group(0)
        .spawn()
        .unwrap()
}

fn sleeping_backend() -> Expected {
    Expected {
        runtime: "keel-input-runtime",
        backend: &["sleep"],
    }
}

#[test]
fn recovery_releases_what_the_interrupted_chain_names() {
    let directory = session();
    let scratch = env::temp_dir()
        .canonicalize()
        .unwrap()
        .join(format!("keel-runtime-{DEAD_PID}-{}", nonce()));
    private_dir(&scratch);
    fs::write(scratch.join("launch"), "x").unwrap();
    let broker = Path::new("/tmp")
        .canonicalize()
        .unwrap()
        .join(format!("keel-kernel-{DEAD_PID}-{}", nonce()));
    private_dir(&broker);
    let unrelated = env::temp_dir()
        .canonicalize()
        .unwrap()
        .join(format!("keel-unrelated-{}", nonce()));
    private_dir(&unrelated);
    // After a real crash the orphaned leader is reaped by launchd; here the
    // test is its parent, so a thread reaps it as recovery ends the group.
    let backend = group_leader();
    let pgid = backend.id();
    let reaper = std::thread::spawn(move || {
        let mut backend = backend;
        backend.wait().unwrap()
    });
    chain(
        &directory,
        DEAD_PID,
        &[
            ("broker-dir", broker.display().to_string()),
            ("scratch", scratch.display().to_string()),
            ("scratch", unrelated.display().to_string()),
            ("backend-group", format!("pgid {pgid}")),
        ],
        false,
    );

    let recovered = recover_directory(&directory, &sleeping_backend()).unwrap();

    assert_eq!(recovered.len(), 1);
    let (path, checks) = &recovered[0];
    assert_eq!(
        path,
        &directory.join(format!("audit-{DEAD_PID}-1-0.recovery.json"))
    );
    assert!(checks["0.broker-dir"].starts_with("ok: "));
    assert!(checks["1.scratch"].starts_with("ok: "));
    assert!(checks["2.scratch"].starts_with("unmet: not a directory this run names"));
    assert!(
        checks["3.backend-group"].starts_with("ok: pgid "),
        "{checks:?}"
    );
    assert!(!scratch.exists() && !broker.exists());
    assert!(
        unrelated.exists(),
        "a path the run does not name is never removed"
    );
    assert!(reaper.join().unwrap().signal().is_some());
    let record: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    assert_eq!(record["ok"], false);
    assert_eq!(record["records"], 4);
    assert!(
        recover_directory(&directory, &sleeping_backend())
            .unwrap()
            .is_empty(),
        "a recorded recovery is not repeated"
    );
    fs::remove_dir_all(unrelated).unwrap();
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn a_group_with_foreign_members_is_not_signalled() {
    let directory = session();
    let mut stranger = group_leader();
    chain(
        &directory,
        DEAD_PID,
        &[("backend-group", format!("pgid {}", stranger.id()))],
        false,
    );

    let expected = Expected {
        runtime: "keel-input-runtime",
        backend: &["keel-runtime"],
    };
    let recovered = recover_directory(&directory, &expected).unwrap();

    assert_eq!(
        recovered[0].1["0.backend-group"],
        format!(
            "unmet: has members that are not Keel components: pgid {}",
            stranger.id()
        )
    );
    assert!(
        stranger.try_wait().unwrap().is_none(),
        "the stranger survives"
    );
    stranger.kill().unwrap();
    stranger.wait().unwrap();
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn sealed_chains_and_live_writers_are_left_alone() {
    let directory = session();
    chain(&directory, DEAD_PID, &[], true);
    let own = std::process::id();
    let own_name = Path::new(&env::current_exe().unwrap())
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    chain(&directory, own, &[], false);

    // The test binary stands in for a live writer only when its name is the
    // expected runtime name, so name it so for this pass.
    let expected = Expected {
        runtime: Box::leak(own_name.into_boxed_str()),
        backend: &[],
    };
    assert!(recover_directory(&directory, &expected).unwrap().is_empty());
    fs::remove_dir_all(directory).unwrap();
}

/// KSR-043: a record torn by the crash ends the chain's authenticated prefix,
/// and a chain that cannot be read at all does not stop the next one.
#[test]
fn a_torn_tail_is_recovered_and_an_unreadable_chain_is_skipped() {
    let directory = session();
    let unreadable = chain(&directory, DEAD_PID - 1, &[], false);
    fs::write(&unreadable, "not a record\n").unwrap();
    let scratch = env::temp_dir()
        .canonicalize()
        .unwrap()
        .join(format!("keel-runtime-{DEAD_PID}-{}", nonce()));
    private_dir(&scratch);
    let torn = chain(
        &directory,
        DEAD_PID,
        &[("scratch", scratch.display().to_string())],
        true,
    );
    let text = fs::read_to_string(&torn).unwrap();
    let lines = text.lines().collect::<Vec<_>>();
    let seal = lines[lines.len() - 1];
    fs::write(
        &torn,
        format!(
            "{}\n{}",
            lines[..lines.len() - 1].join("\n"),
            &seal[..seal.len() / 2]
        ),
    )
    .unwrap();

    let written = recover_directory(&directory, &sleeping_backend()).unwrap();
    assert_eq!(written.len(), 1, "{written:?}");
    assert!(
        written[0]
            .0
            .ends_with(format!("audit-{DEAD_PID}-1-0.recovery.json"))
    );
    assert!(!scratch.exists(), "the torn chain's scratch is released");
    fs::remove_dir_all(directory).unwrap();
}

/// KSR-041: `keel setup` renames a new runtime over a running one, which is
/// still the runtime.
#[cfg(target_os = "linux")]
#[test]
fn a_runtime_replaced_while_it_runs_is_still_the_runtime() {
    let directory = session();
    let program = directory.join("keel-input-runtime");
    fs::copy("/bin/sleep", &program).unwrap();
    // Another test's fork can briefly hold the copy open for writing.
    let mut child = (0..50)
        .find_map(|_| match Command::new(&program).arg("30").spawn() {
            Err(error) if error.kind() == std::io::ErrorKind::ExecutableFileBusy => {
                std::thread::sleep(std::time::Duration::from_millis(20));
                None
            }
            spawned => Some(spawned.unwrap()),
        })
        .unwrap();
    let replacement = directory.join("replacement");
    fs::copy("/bin/sleep", &replacement).unwrap();
    fs::rename(&replacement, &program).unwrap();
    let pid = i32::try_from(child.id()).unwrap();
    assert!(
        fs::read_link(format!("/proc/{pid}/exe"))
            .unwrap()
            .to_string_lossy()
            .ends_with(" (deleted)")
    );
    assert_eq!(
        executable_name(pid, "").as_deref(),
        Some("keel-input-runtime")
    );
    child.kill().unwrap();
    child.wait().unwrap();
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn ps_elapsed_time_is_parsed_in_every_shape() {
    assert_eq!(elapsed_seconds("07"), Some(7));
    assert_eq!(elapsed_seconds("01:07"), Some(67));
    assert_eq!(elapsed_seconds("02:01:07"), Some(7267));
    assert_eq!(elapsed_seconds("3-02:01:07"), Some(266_467));
    assert_eq!(elapsed_seconds("x:07"), None);
}

/// KSR-053: a directory the chain names is released wherever the run's own
/// temporary root was, but not one that is shared or another user's to make.
#[test]
fn recorded_directories_are_checked_by_ownership_not_by_root() {
    let directory = session();
    let elsewhere = directory.canonicalize().unwrap().join("tmpdir");
    private_dir(&elsewhere);
    let scratch = elsewhere.join(format!("keel-runtime-{DEAD_PID}-0"));
    private_dir(&scratch);
    let shared = elsewhere.join(format!("keel-images-{DEAD_PID}-0"));
    fs::create_dir(&shared).unwrap();
    fs::set_permissions(&shared, fs::Permissions::from_mode(0o755)).unwrap();
    chain(
        &directory,
        DEAD_PID,
        &[
            ("scratch", scratch.display().to_string()),
            ("images", shared.display().to_string()),
        ],
        false,
    );
    let written = recover_directory(&directory, &sleeping_backend()).unwrap();
    let checks = &written[0].1;
    assert!(checks["0.scratch"].starts_with("ok: "), "{checks:?}");
    assert!(!scratch.exists());
    assert!(checks["1.images"].starts_with("unmet: "), "{checks:?}");
    assert!(shared.exists());
    fs::remove_dir_all(directory).unwrap();
}
