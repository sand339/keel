//! `workspace:own`: an operator-declared workspace rank, bound to the `HEAD`
//! the operator accepted and served to the guest as a clean clone of it, so
//! the guest can read nothing the acceptance did not cover (PLAN D80).

use keel_provenance::{LockfilePins, MAX_LOCKFILE_BYTES, trusted_git_command};
use ring::digest::{SHA256, digest};
use std::{
    fs,
    io::Write as _,
    os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
};

/// The rank an own workspace starts the floor at.
pub(crate) const OWN_RANK: u8 = 2;

/// How the workspace's `HEAD` relates to the one last accepted for it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Acceptance {
    First,
    Unchanged,
    Ahead(u64),
    Diverged(String),
}

/// A workspace whose `HEAD` the operator is asked to accept.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OwnWorkspace {
    root: PathBuf,
    commit: String,
    acceptance: Acceptance,
    ledger: PathBuf,
    pins: Result<LockfilePins, String>,
}

impl OwnWorkspace {
    /// Reads `HEAD` and its relation to the last acceptance recorded under
    /// `state_root`, which the guest cannot write.
    pub(crate) fn inspect(root: &Path, state_root: &Path) -> Result<Self, String> {
        let commit = git(root, &["rev-parse", "--verify", "--quiet", "HEAD^{commit}"])
            .filter(|commit| is_object_id(commit))
            .ok_or("workspace:own needs a workspace with a committed HEAD")?;
        let name =
            crate::manifest::hex(digest(&SHA256, root.as_os_str().as_encoded_bytes()).as_ref());
        let ledger = state_root
            .join("accepted-heads")
            .join(format!("{name}.json"));
        let accepted = fs::read(&ledger)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
            .and_then(|value| value["commit"].as_str().map(str::to_owned))
            .filter(|commit| is_object_id(commit));
        let acceptance = match accepted {
            None => Acceptance::First,
            Some(accepted) if accepted == commit => Acceptance::Unchanged,
            Some(accepted) => {
                let ancestor = trusted_git_command()
                    .arg("-C")
                    .arg(root)
                    .args(["merge-base", "--is-ancestor", &accepted, &commit])
                    .status()
                    .is_ok_and(|status| status.success());
                let count = git(
                    root,
                    &["rev-list", "--count", &format!("{accepted}..{commit}")],
                )
                .and_then(|count| count.parse().ok());
                match count.filter(|_| ancestor) {
                    Some(count) => Acceptance::Ahead(count),
                    None => Acceptance::Diverged(accepted),
                }
            }
        };
        let pins = npm_pins(root, &commit);
        Ok(Self {
            root: root.to_path_buf(),
            commit,
            acceptance,
            ledger,
            pins,
        })
    }

    pub(crate) fn commit(&self) -> &str {
        &self.commit
    }

    /// The registry artifacts the accepted `package-lock.json` pins (W4b).
    pub(crate) fn pins(&self) -> LockfilePins {
        self.pins.clone().unwrap_or_default()
    }

    /// The admission line for lockfile inheritance, if there is a lockfile.
    pub(crate) fn pins_summary(&self) -> Option<String> {
        match &self.pins {
            Ok(pins) if pins.is_empty() => None,
            Ok(pins) => Some(format!(
                "workspace:own: {} npm package(s) pinned by package-lock.json keep rank \
                 {OWN_RANK} when fetched; their install scripts run at that rank",
                pins.len()
            )),
            Err(error) => Some(format!(
                "workspace:own: package-lock.json pins nothing ({error}); registry fetches lower the floor"
            )),
        }
    }

    /// The admission line. Commit messages are not shown: a tainted session
    /// may have written them, so the operator reviews the range with Git.
    pub(crate) fn summary(&self) -> String {
        let head = &self.commit[..12];
        let relation = match &self.acceptance {
            Acceptance::First => "first acceptance of this workspace".to_owned(),
            Acceptance::Unchanged => "unchanged since last accepted".to_owned(),
            Acceptance::Ahead(count) => {
                format!(
                    "{count} commit(s) since the last accepted HEAD; review them before approving"
                )
            }
            Acceptance::Diverged(accepted) => format!(
                "history diverged from the last accepted {}; review it before approving",
                &accepted[..12]
            ),
        };
        format!("workspace:own: rank {OWN_RANK} for HEAD {head}, {relation}")
    }

    /// Records the acceptance and clones the accepted commit's branch, without
    /// tags, into `destination`: `HEAD` and its own history, and no other
    /// branch, stash, reflog, unreachable object, configuration, or ignored or
    /// untracked file. Fetching over `file://` sends only reachable objects.
    /// The clone is not shallow, because the backend's Git relay mirrors it
    /// with `--local`. Only after this may the floor start at the declared
    /// rank.
    pub(crate) fn accept_into(&self, destination: &Path) -> Result<(), String> {
        if destination.exists() {
            return Err("workspace:own needs a new session; its clone already exists".to_owned());
        }
        let source = format!("file://{}", self.root.display());
        let cloned = trusted_git_command()
            .args(["clone", "--quiet", "--no-tags", "--single-branch"])
            .arg(&source)
            .arg(destination)
            .status()
            .map_err(|error| error.to_string())?;
        let head = git(
            destination,
            &["rev-parse", "--verify", "--quiet", "HEAD^{commit}"],
        );
        if !cloned.success() || head.as_deref() != Some(self.commit.as_str()) {
            let _ = fs::remove_dir_all(destination);
            return Err("workspace HEAD moved during admission; start the run again".to_owned());
        }
        // The clone's origin is the host path it came from; point it at the
        // real remote, or drop it, so pushes reach only the admitted origin.
        let origin = git(&self.root, &["config", "--get", "remote.origin.url"]);
        let remote = match &origin {
            Some(url) => vec!["remote", "set-url", "origin", url.as_str()],
            None => vec!["remote", "remove", "origin"],
        };
        if git(destination, &remote).is_none() {
            let _ = fs::remove_dir_all(destination);
            return Err("cannot configure the workspace clone's origin".to_owned());
        }
        self.write_ledger()
    }

    fn write_ledger(&self) -> Result<(), String> {
        let directory = self
            .ledger
            .parent()
            .ok_or("acceptance ledger has no directory")?;
        fs::create_dir_all(directory).map_err(|error| error.to_string())?;
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
            .map_err(|error| error.to_string())?;
        let partial = self.ledger.with_extension("partial");
        let _ = fs::remove_file(&partial);
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&partial)
            .map_err(|error| error.to_string())?;
        let body = serde_json::json!({ "commit": self.commit, "root": self.root });
        file.write_all(body.to_string().as_bytes())
            .and_then(|()| file.sync_all())
            .map_err(|error| error.to_string())?;
        fs::rename(&partial, &self.ledger).map_err(|error| error.to_string())
    }
}

/// Reads `package-lock.json` from the accepted commit's tree, not the
/// working tree, so the pins are exactly what the operator accepted.
fn npm_pins(root: &Path, commit: &str) -> Result<LockfilePins, String> {
    let output = trusted_git_command()
        .arg("-C")
        .arg(root)
        .args(["cat-file", "blob", &format!("{commit}:package-lock.json")])
        .output()
        .map_err(|error| error.to_string())?;
    if !output.status.success() {
        return Ok(LockfilePins::default());
    }
    if output.stdout.len() > MAX_LOCKFILE_BYTES {
        return Err("package-lock.json exceeds 16 MiB".to_owned());
    }
    LockfilePins::from_npm_lockfile(&output.stdout)
}

fn git(directory: &Path, arguments: &[&str]) -> Option<String> {
    trusted_git_command()
        .arg("-C")
        .arg(directory)
        .args(arguments)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn is_object_id(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
#[path = "../tests/support/own_workspace.rs"]
mod tests;
