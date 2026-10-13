use super::{spawn_stoppable, teardown::RunResources, trusted_scratch};
use nix::{
    errno::Errno,
    sys::signal::{SigSet, Signal, killpg},
    unistd::Pid,
};
use std::{
    fs,
    io::{BufRead as _, BufReader},
    os::unix::{
        fs::PermissionsExt as _,
        process::{CommandExt as _, ExitStatusExt as _},
    },
    path::Path,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

fn group_leader(script: &str) -> std::process::Child {
    Command::new("/bin/sh")
        .args(["-c", script])
        .process_group(0)
        .spawn()
        .unwrap()
}

fn group_is_gone(pid: u32) -> bool {
    killpg(Pid::from_raw(pid.cast_signed()), None) == Err(Errno::ESRCH)
}

fn scratch_with_contents() -> std::path::PathBuf {
    let scratch = trusted_scratch("teardown-test").unwrap();
    fs::create_dir(scratch.join("keel-control")).unwrap();
    fs::write(scratch.join("keel-control/ca.pem"), "certificate").unwrap();
    scratch
}

#[test]
fn release_escalates_when_the_group_ignores_sigterm() {
    let mut resources = RunResources::default();
    let mut leader = Command::new("/bin/sh")
        .args(["-c", "trap '' TERM; echo ready; while :; do sleep 1; done"])
        .stdout(Stdio::piped())
        .process_group(0)
        .spawn()
        .unwrap();
    let mut ready = String::new();
    BufReader::new(leader.stdout.take().unwrap())
        .read_line(&mut ready)
        .unwrap();
    assert_eq!(ready, "ready\n");
    let pid = leader.id();
    resources.backend(leader);
    let started = Instant::now();
    let released = resources.release();
    assert_eq!(released.error(), None);
    assert!(released.escalated);
    assert!(
        started.elapsed() >= Duration::from_secs(2),
        "SIGTERM alone ended the group"
    );
    assert!(group_is_gone(pid));
}

#[test]
fn release_ends_members_that_outlive_the_leader() {
    let mut resources = RunResources::default();
    let leader = group_leader("sleep 30 &");
    let pid = leader.id();
    resources.backend(leader).wait().unwrap();
    assert!(!group_is_gone(pid), "the orphaned member should still run");
    assert_eq!(resources.release().error(), None);
    assert!(group_is_gone(pid));
}

#[test]
fn release_removes_and_verifies_the_scratch_directory() {
    let mut resources = RunResources::default();
    let scratch = resources.scratch(scratch_with_contents()).to_path_buf();
    assert_eq!(resources.release().error(), None);
    assert!(!scratch.exists());
}

#[test]
fn dropping_unreleased_resources_ends_the_group_and_removes_scratch() {
    let mut resources = RunResources::default();
    let scratch = resources.scratch(scratch_with_contents()).to_path_buf();
    let leader = group_leader("sleep 30");
    let pid = leader.id();
    resources.backend(leader);
    drop(resources);
    assert!(group_is_gone(pid));
    assert!(!scratch.exists());
}

#[test]
fn release_names_a_path_it_cannot_remove() {
    let parent = trusted_scratch("teardown-test-parent").unwrap();
    let scratch = parent.join("scratch");
    fs::create_dir(&scratch).unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o500)).unwrap();
    let mut resources = RunResources::default();
    resources.scratch(scratch.clone());
    let released = resources.release();
    let error = released.error().unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
    fs::remove_dir_all(&parent).unwrap();
    assert!(error.starts_with("run teardown incomplete: "), "{error}");
    assert!(error.contains(&*scratch.to_string_lossy()), "{error}");
    assert_eq!(released.checks[0].kind, "scratch");
    assert!(released.checks[0].unmet.is_some());
    assert!(!Path::new(&scratch).exists());
}

fn self_terminating_child(stoppable: bool) -> std::process::ExitStatus {
    // Runs on its own thread so the blocked mask does not leak to other tests.
    thread::spawn(move || {
        let mut termination = SigSet::empty();
        termination.add(Signal::SIGTERM);
        termination.thread_block().unwrap();
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "kill -TERM $$; sleep 1"]);
        let mut child = if stoppable {
            spawn_stoppable(&mut command, termination).unwrap()
        } else {
            command.spawn().unwrap()
        };
        child.wait().unwrap()
    })
    .join()
    .unwrap()
}

#[test]
fn children_inherit_the_blocked_termination_signals() {
    // Rust starts Linux children with an empty signal mask, so there every
    // child is already stoppable; macOS children inherit the blocked mask.
    let expected = cfg!(target_os = "linux").then_some(Signal::SIGTERM as i32);
    assert_eq!(self_terminating_child(false).signal(), expected);
}

#[test]
fn stoppable_children_can_be_terminated() {
    assert_eq!(
        self_terminating_child(true).signal(),
        Some(Signal::SIGTERM as i32)
    );
}
