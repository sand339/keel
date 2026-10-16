//! Crash recovery: releases what an interrupted run's authenticated chain
//! says it created, and records what recovery observed and when. The earlier
//! chain is never rewritten, and nothing here claims cleanup at crash time.

use super::receipt::{Teardown, file_name, now_ms, write_durably};
use keel_audit::{AuditRecord, RunKey, read_verified_prefix};
use nix::unistd::Pid;
use serde::Serialize;
use std::{
    collections::BTreeMap,
    error::Error,
    fs, io,
    os::unix::fs::MetadataExt as _,
    path::{Path, PathBuf},
    process::Command,
};

/// The process names recovery accepts as a run's writer and backend group.
pub(super) struct Expected {
    pub(super) runtime: &'static str,
    pub(super) backend: &'static [&'static str],
}

pub(super) const KEEL: Expected = Expected {
    runtime: "keel-input-runtime",
    backend: if cfg!(target_os = "linux") {
        &[
            "bwrap",
            "keel-runtime",
            "keel-ch",
            "cloud-hypervisor",
            "virtiofsd",
            "git",
            "keel-extract",
        ]
    } else {
        &[
            "sandbox-exec",
            "keel-runtime",
            "keel-vz-spike",
            "deno",
            "git",
            "keel-extract",
        ]
    },
};

/// What one recovery pass observed for one interrupted chain. It is not
/// signed: no key the chain names survives the crash.
#[derive(Serialize)]
struct RecoveryRecord {
    version: u8,
    chain: String,
    records: u64,
    recovered_ms: u64,
    checks: BTreeMap<String, String>,
    ok: bool,
}

pub(super) fn recover(arguments: &[std::ffi::OsString]) -> Result<(), Box<dyn Error>> {
    let [actual, socket_flag, socket] = arguments else {
        return Err("usage: keel-input-runtime recover --socket ATTACH.sock".into());
    };
    if actual != "recover" || socket_flag != "--socket" {
        return Err("usage: keel-input-runtime recover --socket ATTACH.sock".into());
    }
    let directory = Path::new(socket)
        .parent()
        .ok_or("attach socket has no session directory")?;
    let recovered = recover_directory(directory, &KEEL)?;
    if recovered.is_empty() {
        println!("Nothing to recover.");
    }
    let mut unmet = Vec::new();
    for (path, checks) in recovered {
        println!("Recovery record {}", path.display());
        unmet.extend(
            checks
                .into_iter()
                .filter(|(_, outcome)| !outcome.starts_with("ok"))
                .map(|(kind, outcome)| format!("{kind} {outcome}")),
        );
    }
    if unmet.is_empty() {
        Ok(())
    } else {
        Err(format!("recovery incomplete: {}", unmet.join("; ")).into())
    }
}

/// Recovers every chain in `directory` that is unsealed, whose writer is
/// gone, and that has no recovery record yet; then the supervisor's files if
/// the supervisor is gone. Returns each record written and its checks.
pub(super) fn recover_directory(
    directory: &Path,
    expected: &Expected,
) -> io::Result<Vec<(PathBuf, BTreeMap<String, String>)>> {
    let mut written = Vec::new();
    let user = fs::metadata(directory)?.uid();
    let mut chains = fs::read_dir(directory)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            let name = file_name(path);
            name.starts_with("audit-") && name.ends_with(".ndjson")
        })
        .collect::<Vec<_>>();
    chains.sort();
    for chain in chains {
        let record_path = chain.with_extension("recovery.json");
        let Some(pid) = writer_pid(&chain) else {
            continue;
        };
        if record_path.exists() || process_name(pid).as_deref() == Some(expected.runtime) {
            continue;
        }
        let Ok(key) = fs::read_to_string(chain.with_extension("key")) else {
            continue;
        };
        // One chain that cannot be read must not stop the others, or the
        // supervisor files after them, from being recovered (KSR-043).
        let prefix = RunKey::from_hex(&key)
            .and_then(|key| read_verified_prefix(&chain, &key))
            .map_err(|error| error.to_string());
        let (records, status) = match prefix {
            Ok(prefix) => prefix,
            Err(error) => {
                eprintln!("keel: {}: not recovered: {error}", chain.display());
                continue;
            }
        };
        if status.sealed {
            continue;
        }
        let mut teardown = Teardown::begin();
        for record in records
            .iter()
            .filter(|record| record.payload.event == "kernel.run-resource")
        {
            release(&mut teardown, record, pid, user, expected);
        }
        let checks = teardown.into_checks();
        let record = RecoveryRecord {
            version: 1,
            chain: file_name(&chain).to_owned(),
            records: status.records,
            recovered_ms: now_ms(),
            ok: checks.values().all(|outcome| outcome.starts_with("ok")),
            checks: checks.clone(),
        };
        write_durably(&record_path, &serde_json::to_vec(&record)?)?;
        written.push((record_path, checks));
    }
    let supervisor = directory.join("attach.pid");
    let serve_pid = fs::read_to_string(&supervisor)
        .ok()
        .and_then(|pid| pid.trim().parse::<u32>().ok());
    if let Some(pid) = serve_pid
        && process_name(pid).as_deref() != Some(expected.runtime)
    {
        let mut teardown = Teardown::begin();
        teardown.remove_file("attach-socket", &directory.join("attach.sock"));
        teardown.remove_file("pid-file", &supervisor);
        let checks = teardown.into_checks();
        let record_path = directory.join(format!("attach-{pid}.recovery.json"));
        let record = RecoveryRecord {
            version: 1,
            chain: String::new(),
            records: 0,
            recovered_ms: now_ms(),
            ok: checks.values().all(|outcome| outcome.starts_with("ok")),
            checks: checks.clone(),
        };
        write_durably(&record_path, &serde_json::to_vec(&record)?)?;
        written.push((record_path, checks));
    }
    Ok(written)
}

/// Releases one recorded resource after checking it is still what the run
/// created: a path of the run's own naming in the temporary directory, or a
/// process group of Keel components that has not been reused since.
/// `user` owns the session directory, and so every directory the run made.
fn release(
    teardown: &mut Teardown,
    record: &AuditRecord,
    pid: u32,
    user: u32,
    expected: &Expected,
) {
    let fields = &record.payload.fields;
    let detail = fields.get("detail").map_or("", String::as_str);
    match fields.get("kind").map(String::as_str) {
        Some(kind @ ("scratch" | "images" | "broker-dir")) => {
            let prefix = match kind {
                "scratch" => format!("keel-runtime-{pid}-"),
                "images" => format!("keel-images-{pid}-"),
                _ => format!("keel-kernel-{pid}-"),
            };
            // The run recorded the canonical path it created under its own
            // temporary root, which this process's `TMPDIR` need not match
            // (KSR-053). The path must still be one the run would create: its
            // naming, a private directory of this user, or already gone.
            let path = Path::new(detail);
            let parent = path.parent().filter(|parent| parent.is_absolute());
            let ours = match fs::symlink_metadata(path) {
                Ok(metadata) => {
                    metadata.is_dir() && metadata.uid() == user && metadata.mode() & 0o777 == 0o700
                }
                Err(error) => error.kind() == io::ErrorKind::NotFound,
            };
            let owned = parent
                .is_some_and(|parent| parent.canonicalize().ok().as_deref() == Some(parent))
                && file_name(path).starts_with(&prefix)
                && ours;
            if owned {
                teardown.remove_dir(kind, path);
            } else {
                let unmet = Some("not a directory this run names".to_owned());
                teardown.check(kind, detail, unmet);
            }
        }
        Some(kind @ ("backend-group" | "extract-group")) => {
            let Some(group) = detail
                .strip_prefix("pgid ")
                .and_then(|group| group.parse::<i32>().ok())
                .filter(|group| *group > 1)
            else {
                teardown.check(kind, detail, Some("malformed".to_owned()));
                return;
            };
            match foreign_group(group, record.payload.timestamp_ms, expected) {
                Some(unmet) => teardown.check(kind, detail, Some(unmet)),
                None => teardown.end_group(kind, Pid::from_raw(group)),
            }
        }
        _ => teardown.check("unknown", detail, Some("unknown resource kind".to_owned())),
    }
}

/// Why a recorded group must not be signalled, if it must not. A group whose
/// leader is gone cannot have been reused while members remain; a live leader
/// must have started before the run recorded it.
fn foreign_group(group: i32, recorded_ms: u64, expected: &Expected) -> Option<String> {
    let Some(members) = group_members(group) else {
        return Some("process table is unreadable".to_owned());
    };
    let recognized = |name: &str| expected.backend.contains(&name) || name.starts_with("git-");
    if members.iter().any(|(_, _, name)| !recognized(name)) {
        return Some("has members that are not Keel components".to_owned());
    }
    let started_after = members.iter().any(|(pid, elapsed, _)| {
        *pid == group && now_ms().saturating_sub(elapsed * 1000) > recorded_ms + 2000
    });
    started_after.then(|| "leader started after the run recorded it".to_owned())
}

/// Each member of `group` as (pid, seconds since start, executable name).
/// `None` when the process table cannot be read.
fn group_members(group: i32) -> Option<Vec<(i32, u64, String)>> {
    let output = Command::new("/bin/ps")
        .args(["-A", "-o", "pid=,pgid=,etime=,comm="])
        .env_clear()
        .output()
        .ok()
        .filter(|output| output.status.success())?;
    let table = String::from_utf8(output.stdout).ok()?;
    Some(
        table
            .lines()
            .filter_map(|line| {
                let mut fields = line.split_whitespace();
                let member = fields.next()?.parse().ok()?;
                let leader = fields.next()?.parse::<i32>().ok()?;
                let elapsed = elapsed_seconds(fields.next()?)?;
                let command = fields.collect::<Vec<_>>().join(" ");
                let name = executable_name(member, &command)?;
                (leader == group).then_some((member, elapsed, name))
            })
            .collect(),
    )
}

/// Parses `ps` elapsed time, `[[DD-]HH:]MM:SS`.
fn elapsed_seconds(value: &str) -> Option<u64> {
    let (days, clock) = value
        .split_once('-')
        .map_or(Some((0, value)), |(days, clock)| {
            Some((days.parse::<u64>().ok()?, clock))
        })?;
    let seconds = clock.split(':').try_fold(0_u64, |total, part| {
        Some(total * 60 + part.parse::<u64>().ok()?)
    })?;
    Some(days * 86_400 + seconds)
}

fn writer_pid(chain: &Path) -> Option<u32> {
    file_name(chain)
        .strip_prefix("audit-")?
        .split('-')
        .next()?
        .parse()
        .ok()
}

fn process_name(pid: u32) -> Option<String> {
    let output = Command::new("/bin/ps")
        .args(["-p", &pid.to_string(), "-o", "comm="])
        .env_clear()
        .output()
        .ok()?;
    let command = String::from_utf8(output.stdout).ok()?;
    executable_name(i32::try_from(pid).ok()?, command.trim())
}

/// The file name of the program a process runs. macOS `ps` reports its path.
/// Linux `ps` reports a name cut to 15 bytes that the process may change, so
/// there the name comes from the kernel's link to the executable.
// Each platform reads one of the two.
#[allow(unused_variables)]
fn executable_name(pid: i32, reported: &str) -> Option<String> {
    #[cfg(target_os = "linux")]
    let path = fs::read_link(format!("/proc/{pid}/exe")).ok()?;
    #[cfg(not(target_os = "linux"))]
    let path = PathBuf::from(reported);
    let name = path.file_name()?.to_str()?;
    // An executable replaced while it runs, as `keel setup` does, is still the
    // same program; Linux marks the link to it (KSR-041).
    Some(name.strip_suffix(" (deleted)").unwrap_or(name).to_owned())
}

#[cfg(test)]
#[path = "../../../tests/support/crash_recovery.rs"]
mod tests;
