//! Linux confinement for the untrusted children, through bubblewrap.
//!
//! On macOS each child runs under a `sandbox-exec` profile. On Linux the same
//! policy is a bubblewrap command line: the child sees only the paths its
//! macOS profile allows, so a path it may not read or execute does not exist
//! for it. Bubblewrap is an operating-system binary outside the trusted code,
//! in the position `sandbox-exec` holds on macOS; this module only builds its
//! argument vector.

use std::{
    ffi::OsString,
    path::{Path, PathBuf},
};

/// The packaged bubblewrap every supported distribution installs here.
pub(super) const BWRAP: &str = "/usr/bin/bwrap";

/// Shared libraries and the loader cache a dynamically linked program needs.
/// Missing entries are skipped, since distributions lay these out differently.
const SYSTEM_LIBRARIES: &[&str] = &[
    "/usr/lib",
    "/usr/lib64",
    "/lib",
    "/lib64",
    "/etc/ld.so.cache",
    "/etc/localtime",
];

/// What one confined child may reach.
#[derive(Default)]
pub(super) struct Confinement {
    /// Paths visible read-only, including every program the child may run.
    pub(super) read_only: Vec<PathBuf>,
    /// Paths visible read-write.
    pub(super) read_write: Vec<PathBuf>,
    /// Device nodes passed through, such as `/dev/kvm`.
    pub(super) devices: Vec<PathBuf>,
    /// The child's working directory.
    pub(super) directory: Option<PathBuf>,
}

impl Confinement {
    /// The bubblewrap arguments that run `program` with `arguments` confined.
    ///
    /// Every namespace is unshared, so the child has no network but loopback
    /// and pathname Unix sockets it can see, and sees only its own processes.
    /// The environment passes through from the launcher, which clears it.
    /// Capabilities are dropped, `no_new_privs` is set by bubblewrap itself,
    /// and the child is killed if the launcher dies. It runs in a new session
    /// with no controlling terminal, so it cannot reach the operator's tty to
    /// inject keystrokes through `TIOCSTI` or paint over the trusted screen.
    pub(super) fn arguments(&self, program: &Path, arguments: &[OsString]) -> Vec<OsString> {
        let mut argv: Vec<OsString> = [
            "--die-with-parent",
            "--new-session",
            "--unshare-all",
            "--cap-drop",
            "ALL",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--tmpfs",
            "/tmp",
        ]
        .into_iter()
        .map(OsString::from)
        .collect();
        for library in SYSTEM_LIBRARIES {
            bind(&mut argv, "--ro-bind-try", Path::new(library));
        }
        for path in &self.read_only {
            bind(&mut argv, "--ro-bind", path);
        }
        for path in &self.read_write {
            bind(&mut argv, "--bind", path);
        }
        for path in &self.devices {
            bind(&mut argv, "--dev-bind", path);
        }
        if let Some(directory) = &self.directory {
            argv.push("--chdir".into());
            argv.push(directory.into());
        }
        argv.push("--".into());
        argv.push(program.into());
        argv.extend(arguments.iter().cloned());
        argv
    }
}

fn bind(argv: &mut Vec<OsString>, option: &str, path: &Path) {
    argv.push(option.into());
    argv.push(path.into());
    argv.push(path.into());
}

/// Parses the process group and the terminal's foreground process group out
/// of `/proc/<pid>/stat`. The command name may itself contain spaces and
/// parentheses, so fields are counted after its last closing parenthesis.
pub(super) fn stat_process_groups(stat: &str) -> Option<(i32, i32)> {
    let fields = stat.get(stat.rfind(')')? + 1..)?;
    let mut fields = fields.split_ascii_whitespace();
    // After the name: state, ppid, pgrp, session, tty_nr, tpgid.
    let group = fields.nth(2)?.parse().ok()?;
    let foreground = fields.nth(2)?.parse().ok()?;
    Some((group, foreground))
}
