//! The run's resource registry: the only path that removes what one run
//! created on the host, and the check that each resource is really gone.

use keel_input::TeardownCheck;
use nix::{
    errno::Errno,
    sys::signal::{Signal, killpg},
    unistd::Pid,
};
use std::{
    fs, io,
    path::{Path, PathBuf},
    process::Child,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

const TERMINATE_GRACE: Duration = Duration::from_secs(2);
const KILL_GRACE: Duration = Duration::from_secs(1);

/// Resources one run owns, released on every exit path, including early
/// errors, because release also runs on drop.
#[derive(Default)]
pub(super) struct RunResources {
    backend: Option<Child>,
    helper: Option<Child>,
    scratch: Option<PathBuf>,
}

impl RunResources {
    pub(super) fn scratch(&mut self, path: PathBuf) -> &Path {
        self.scratch.insert(path)
    }

    /// Registers the backend, which leads its own process group.
    pub(super) fn backend(&mut self, child: Child) -> &mut Child {
        self.backend.insert(child)
    }

    /// Registers the extraction helper, which leads its own process group.
    pub(super) fn helper(&mut self, child: Child) -> &mut Child {
        self.helper.insert(child)
    }

    pub(super) fn running_backend(&mut self) -> io::Result<&mut Child> {
        self.backend
            .as_mut()
            .ok_or_else(|| io::Error::other("runtime backend is not running"))
    }

    /// Ends the backend's whole process group, then removes the scratch
    /// directory, and reports each postcondition.
    pub(super) fn release(&mut self) -> Released {
        let mut released = Released::default();
        if let Some(mut child) = self.backend.take() {
            let group = Pid::from_raw(child.id().cast_signed());
            let (escalated, unmet) = end_group(&mut child, group);
            released.escalated = escalated;
            released.checks.push(TeardownCheck {
                kind: "backend-group",
                detail: format!("pgid {group}"),
                unmet,
            });
        }
        if let Some(mut child) = self.helper.take() {
            let group = Pid::from_raw(child.id().cast_signed());
            let (escalated, unmet) = end_group(&mut child, group);
            released.escalated |= escalated;
            released.checks.push(TeardownCheck {
                kind: "extract-group",
                detail: format!("pgid {group}"),
                unmet,
            });
        }
        if let Some(scratch) = self.scratch.take() {
            released.checks.push(TeardownCheck {
                kind: "scratch",
                detail: scratch.display().to_string(),
                unmet: remove_verified(&scratch),
            });
        }
        released
    }
}

impl Drop for RunResources {
    fn drop(&mut self) {
        if let Some(error) = self.release().error() {
            eprintln!("keel: {error}");
        }
    }
}

/// What one release established.
#[derive(Default)]
pub(super) struct Released {
    pub(super) escalated: bool,
    pub(super) checks: Vec<TeardownCheck>,
}

impl Released {
    /// Names every postcondition that does not hold.
    pub(super) fn error(&self) -> Option<String> {
        let unmet = self
            .checks
            .iter()
            .filter_map(|check| {
                let unmet = check.unmet.as_ref()?;
                Some(format!("{} {}: {unmet}", check.kind, check.detail))
            })
            .collect::<Vec<_>>();
        (!unmet.is_empty()).then(|| format!("run teardown incomplete: {}", unmet.join("; ")))
    }
}

/// Asks the backend group to stop and, if it is still running after the same
/// grace release allows, ends it with `SIGKILL`, so a stop never waits on a
/// backend that ignores `SIGTERM`. Returns at once; `escalated` records the
/// kill for the teardown record. Until the leader is reaped, or while a
/// member remains, the group id cannot be reused.
pub(super) fn request_stop(group: Pid, escalated: &Arc<AtomicBool>) {
    let _ = killpg(group, Signal::SIGTERM);
    let escalated = Arc::clone(escalated);
    thread::spawn(move || {
        thread::sleep(TERMINATE_GRACE);
        if killpg(group, None).is_ok() {
            escalated.store(true, Ordering::Release);
            let _ = killpg(group, Signal::SIGKILL);
        }
    });
}

/// Signals the group with `SIGTERM`, escalates to `SIGKILL` after a bounded
/// grace, and reaps the leader. An unreaped leader keeps the group id from
/// being reused while it is signalled; once the leader has been reaped, a
/// live member does the same. Returns whether `SIGKILL` was needed and the
/// unmet postcondition, if any.
fn end_group(child: &mut Child, group: Pid) -> (bool, Option<String>) {
    if group_ended(child, group) {
        return (false, None);
    }
    let _ = killpg(group, Signal::SIGTERM);
    if wait_ended(child, group, TERMINATE_GRACE) {
        return (false, None);
    }
    let _ = killpg(group, Signal::SIGKILL);
    let unmet = (!wait_ended(child, group, KILL_GRACE)).then(|| "still has members".to_owned());
    (true, unmet)
}

fn wait_ended(child: &mut Child, group: Pid, grace: Duration) -> bool {
    let deadline = Instant::now() + grace;
    loop {
        if group_ended(child, group) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn group_ended(child: &mut Child, group: Pid) -> bool {
    let _ = child.try_wait();
    killpg(group, None) == Err(Errno::ESRCH)
}

fn remove_verified(path: &Path) -> Option<String> {
    match fs::remove_dir_all(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Some(format!("cannot remove: {error}")),
    }
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        _ => Some("still present".to_owned()),
    }
}
