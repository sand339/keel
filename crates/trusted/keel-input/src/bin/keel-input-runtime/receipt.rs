//! The supervisor's teardown receipt: what `serve` removes and checks after
//! the run's chain is sealed, signed by the key that chain names.

use keel_audit::{RunKey, TeardownReceipt, read_verified_prefix};
use nix::{
    errno::Errno,
    sys::signal::{Signal, killpg},
    unistd::Pid,
};
use ring::digest::{SHA256, digest};
use std::{
    collections::BTreeMap,
    fmt::Write as _,
    fs::{self, File, OpenOptions},
    io::{self, Write as _},
    os::unix::fs::OpenOptionsExt as _,
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const GROUP_GRACE: Duration = Duration::from_secs(5);
const KILL_GRACE: Duration = Duration::from_secs(1);

/// Checks gathered while the supervisor releases what it owns.
pub(super) struct Teardown {
    started_ms: u64,
    escalated: bool,
    checks: BTreeMap<String, String>,
}

impl Teardown {
    pub(super) fn begin() -> Self {
        Self {
            started_ms: now_ms(),
            escalated: false,
            checks: BTreeMap::new(),
        }
    }

    pub(super) fn escalated(&mut self) {
        self.escalated = true;
    }

    pub(super) fn check(&mut self, kind: &str, detail: &str, unmet: Option<String>) {
        let outcome = unmet.map_or_else(|| "ok".to_owned(), |unmet| format!("unmet: {unmet}"));
        self.checks.insert(
            format!("{}.{kind}", self.checks.len()),
            format!("{outcome}: {detail}"),
        );
    }

    /// Ends whatever remains of the runtime's process group, whose leader the
    /// caller has already reaped. A remaining member keeps the group id from
    /// being reused while it is signalled.
    pub(super) fn end_group(&mut self, kind: &str, group: Pid) {
        let ended = || killpg(group, None) == Err(Errno::ESRCH);
        let mut unmet = None;
        if !ended() {
            let _ = killpg(group, Signal::SIGTERM);
            if !wait_until(GROUP_GRACE, ended) {
                self.escalated = true;
                let _ = killpg(group, Signal::SIGKILL);
                if !wait_until(KILL_GRACE, ended) {
                    unmet = Some("still has members".to_owned());
                }
            }
        }
        self.check(kind, &format!("pgid {group}"), unmet);
    }

    pub(super) fn remove_dir(&mut self, kind: &str, path: &Path) {
        let unmet = match fs::remove_dir_all(path) {
            Err(error) if error.kind() != io::ErrorKind::NotFound => {
                Some(format!("cannot remove: {error}"))
            }
            _ => match fs::symlink_metadata(path) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => None,
                _ => Some("still present".to_owned()),
            },
        };
        self.check(kind, &path.display().to_string(), unmet);
    }

    pub(super) fn into_checks(self) -> BTreeMap<String, String> {
        self.checks
    }

    pub(super) fn remove_file(&mut self, kind: &str, path: &Path) {
        let unmet = match fs::remove_file(path) {
            Err(error) if error.kind() != io::ErrorKind::NotFound => {
                Some(format!("cannot remove: {error}"))
            }
            _ => match fs::symlink_metadata(path) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => None,
                _ => Some("still present".to_owned()),
            },
        };
        self.check(kind, &path.display().to_string(), unmet);
    }

    /// Binds the receipt to the run's sealed chain, records the digests of
    /// the files kept on purpose, signs it, and makes it durable. Returns the
    /// receipt's path and whether every check passed.
    pub(super) fn finish(
        mut self,
        directory: &Path,
        runtime_pid: u32,
        spawned: SystemTime,
        supervisor: &RunKey,
        stop_reason: &str,
    ) -> io::Result<(PathBuf, bool)> {
        let chain = run_chain(directory, runtime_pid, spawned);
        let (run_id, chain_tip, unmet) = match &chain {
            Ok(chain) => bind_chain(chain, &supervisor.public_hex()),
            Err(unmet) => (String::new(), String::new(), Some((*unmet).to_owned())),
        };
        let name = chain.as_ref().map_or_else(
            |_| format!("audit-{runtime_pid}"),
            |chain| file_name(chain).trim_end_matches(".ndjson").to_owned(),
        );
        self.check("audit-chain", &format!("{name}.ndjson"), unmet);
        let mut retained = BTreeMap::new();
        for kept in ["attach.exit", "floor.json"] {
            if let Ok(bytes) = fs::read(directory.join(kept)) {
                retained.insert(kept.to_owned(), hex(digest(&SHA256, &bytes).as_ref()));
            }
        }
        let mut receipt = TeardownReceipt {
            version: 1,
            run_id,
            chain: format!("{name}.ndjson"),
            chain_tip,
            stop_reason: stop_reason.to_owned(),
            escalated: self.escalated,
            started_ms: self.started_ms,
            finished_ms: now_ms(),
            checks: self.checks,
            retained,
            ok: false,
            signature: String::new(),
        };
        receipt.sign(supervisor).map_err(io::Error::other)?;
        let path = directory.join(format!("{name}.receipt.json"));
        write_durably(&path, &serde_json::to_vec(&receipt)?)?;
        Ok((path, receipt.ok))
    }
}

/// The chain this run's broker created: named for its process id and
/// written after the supervisor spawned it.
fn run_chain(directory: &Path, pid: u32, spawned: SystemTime) -> Result<PathBuf, &'static str> {
    let prefix = format!("audit-{pid}-");
    let mut found = fs::read_dir(directory)
        .map_err(|_| "session directory is unreadable")?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            let name = file_name(path);
            name.starts_with(&prefix)
                && name.ends_with(".ndjson")
                && fs::metadata(path)
                    .and_then(|metadata| metadata.modified())
                    .is_ok_and(|modified| modified >= spawned)
        });
    match (found.next(), found.next()) {
        (Some(chain), None) => Ok(chain),
        (None, _) => Err("not found"),
        (Some(_), Some(_)) => Err("ambiguous"),
    }
}

/// Requires a sealed chain whose teardown record names this supervisor.
fn bind_chain(chain: &Path, supervisor: &str) -> (String, String, Option<String>) {
    let verified = fs::read_to_string(chain.with_extension("key"))
        .map_err(|error| error.to_string())
        .and_then(|key| RunKey::from_hex(&key).map_err(|error| error.to_string()))
        .and_then(|key| read_verified_prefix(chain, &key).map_err(|error| error.to_string()));
    let (records, status) = match verified {
        Ok(verified) => verified,
        Err(error) => return (String::new(), String::new(), Some(error)),
    };
    let run_id = records
        .first()
        .map(|record| record.run_id.clone())
        .unwrap_or_default();
    let tip = status.seal_hash.map(|hash| hex(&hash)).unwrap_or_default();
    let names_supervisor = records.iter().any(|record| {
        record.payload.event == "kernel.run-teardown"
            && record
                .payload
                .fields
                .get("supervisor_key")
                .map(String::as_str)
                == Some(supervisor)
    });
    let unmet = if !status.sealed {
        Some("not sealed".to_owned())
    } else if !names_supervisor {
        Some("teardown record does not name this supervisor".to_owned())
    } else {
        None
    };
    (run_id, tip, unmet)
}

/// The most recently written receipt in a session directory.
pub(super) fn latest(directory: &Path) -> Option<PathBuf> {
    fs::read_dir(directory)
        .ok()?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| file_name(path).ends_with(".receipt.json"))
        .max_by_key(|path| {
            fs::metadata(path)
                .and_then(|metadata| metadata.modified())
                .ok()
        })
}

/// Reads a receipt for display and names each unmet check.
pub(super) fn unmet(path: &Path) -> io::Result<Vec<String>> {
    let receipt: TeardownReceipt = serde_json::from_slice(&fs::read(path)?)?;
    Ok(receipt
        .checks
        .into_iter()
        .filter(|(_, outcome)| !outcome.starts_with("ok"))
        .map(|(kind, outcome)| format!("{kind} {outcome}"))
        .collect())
}

pub(super) fn write_durably(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let partial = path.with_extension("partial");
    let _ = fs::remove_file(&partial);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&partial)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(&partial, path)?;
    File::open(path.parent().unwrap_or(Path::new(".")))?.sync_all()
}

fn wait_until(grace: Duration, done: impl Fn() -> bool) -> bool {
    let deadline = Instant::now() + grace;
    loop {
        if done() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        thread::sleep(Duration::from_millis(10));
    }
}

pub(super) fn file_name(path: &Path) -> &str {
    path.file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut text, byte| {
        let _ = write!(text, "{byte:02x}");
        text
    })
}

pub(super) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

#[cfg(test)]
#[path = "../../../tests/support/serve_receipt.rs"]
mod tests;
