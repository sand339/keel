//! The run's resource registry: the only path that removes what one run
//! created on the host, and the check that each resource is really gone.

use super::receipt;
use keel_audit::RunKey;
use keel_input::{RunTeardownEvent, RuntimeBroker, TeardownCheck};
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
    time::{Duration, Instant, SystemTime},
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
    images: Option<PathBuf>,
}

impl RunResources {
    pub(super) fn scratch(&mut self, path: PathBuf) -> &Path {
        self.scratch.insert(path)
    }

    /// Registers the private copies of the boot images admission hashed.
    pub(super) fn images(&mut self, path: PathBuf) -> &Path {
        self.images.insert(path)
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
        if let Some(images) = self.images.take() {
            released.checks.push(TeardownCheck {
                kind: "images",
                detail: images.display().to_string(),
                unmet: remove_verified(&images),
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

/// One run from its broker's start to its sealed chain. On every exit, the
/// normal one and each early error, it releases the run's resources, seals
/// the chain with a teardown record, and, for a run no `serve` supervises,
/// signs its own receipt, so every run that opened a chain ends with one.
pub(super) struct RunSession {
    broker: Option<RuntimeBroker>,
    /// The run's host resources, released before the chain is sealed.
    pub(super) resources: RunResources,
    /// The supervising `serve` process's key, which signs the receipt.
    supervisor_key: Option<String>,
    /// An unsupervised run's own receipt key, held only in memory.
    own_key: Option<RunKey>,
    started: SystemTime,
}

impl RunSession {
    /// Takes the run's broker. `supervisor_key` is `serve`'s public key; with
    /// none, the run generates its own key and records its public half.
    pub(super) fn new(
        broker: RuntimeBroker,
        supervisor_key: Option<String>,
        started: SystemTime,
    ) -> Result<Self, String> {
        let own_key = match supervisor_key {
            Some(_) => None,
            None => Some(RunKey::generate().map_err(|error| error.to_string())?),
        };
        Ok(Self {
            broker: Some(broker),
            resources: RunResources::default(),
            supervisor_key,
            own_key,
            started,
        })
    }

    /// The broker and the resources together, for spawning what the run
    /// registers.
    pub(super) fn parts(&mut self) -> (&RuntimeBroker, &mut RunResources) {
        (
            self.broker
                .as_ref()
                .expect("the broker lives until the session ends"),
            &mut self.resources,
        )
    }

    pub(super) fn broker(&self) -> &RuntimeBroker {
        self.broker
            .as_ref()
            .expect("the broker lives until the session ends")
    }

    /// Seals the chain with what `released` established, then writes the
    /// unsupervised run's receipt. Ending twice does nothing.
    pub(super) fn end(
        &mut self,
        stop_reason: &'static str,
        escalated: bool,
        released: &Released,
    ) -> Result<(), String> {
        let Some(broker) = self.broker.take() else {
            return Ok(());
        };
        let directory = broker.audit_path().parent().map(Path::to_path_buf);
        let broker_directory = broker.socket_path().parent().map(Path::to_path_buf);
        let supervisor_key = self
            .supervisor_key
            .clone()
            .or_else(|| self.own_key.as_ref().map(RunKey::public_hex));
        let sealed = broker.shutdown_with_teardown(Some(RunTeardownEvent {
            stop_reason,
            escalated,
            checks: released.checks.clone(),
            supervisor_key,
        }));
        if let (Some(key), Some(directory)) = (&self.own_key, directory) {
            let mut teardown = receipt::Teardown::begin();
            if let Some(broker_directory) = broker_directory {
                teardown.check_absent("broker-dir", &broker_directory);
            }
            let (path, ok) = teardown
                .finish(
                    &directory,
                    std::process::id(),
                    self.started,
                    key,
                    stop_reason,
                )
                .map_err(|error| format!("write teardown receipt: {error}"))?;
            if !ok {
                eprintln!(
                    "keel: teardown receipt names unmet checks: {}",
                    path.display()
                );
            }
        }
        sealed.map(drop)
    }
}

impl Drop for RunSession {
    /// An early error: release, seal with stop reason `error`, and receipt.
    fn drop(&mut self) {
        if self.broker.is_some() {
            let released = self.resources.release();
            if let Err(error) = self.end("error", released.escalated, &released) {
                eprintln!("keel: {error}");
            }
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
