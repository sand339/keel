//! PID 1 supervision and per-connection process attribution.
//!
//! The confined workload keeps UID 0, so it could signal any other root
//! process. PID 1 is different: the kernel delivers no signal to it from
//! inside its namespace unless it installs a handler, and this supervisor
//! installs none. It therefore keeps root, which it needs to read every
//! process's file table, and answers one question for the guest relays: which
//! process, and which ancestry, owns this loopback connection?
//!
//! The answer is the guest's own claim. The host treats it as an asserted
//! origin that can only narrow authority.

use serde::Serialize;
use std::{
    fs,
    io::{self, BufRead as _, BufReader, Read as _, Write as _},
    os::unix::{
        fs::{PermissionsExt as _, chown},
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    process::Command,
    thread,
    time::Duration,
};

use super::confine::SERVICE_UID;

/// Socket on which the supervisor answers relay queries. Its directory is
/// owned by the service UID, so the capability-free workload cannot reach it.
pub const ATTRIBUTION_SOCKET: &str = "/run/keel-attribution/socket";
const MAX_ANCESTORS: usize = 16;
const MAX_ARGUMENTS: usize = 8;
const MAX_ARGUMENT_BYTES: usize = 160;
/// Paths the workload may write: code that runs from them is workspace code.
const WRITABLE_ROOTS: &[&str] = &["/workspace/", "/tmp/", "/var/tmp/", "/root/"];
const SCRIPT_SUFFIXES: &[&str] = &[
    ".js", ".mjs", ".cjs", ".ts", ".py", ".sh", ".rb", ".pl", ".php",
];

/// One process in an attributed connection's ancestry, nearest first.
#[derive(Debug, Serialize)]
pub struct Process {
    pub pid: u32,
    pub exe: String,
    pub argv: Vec<String>,
    pub workspace_code: bool,
}

/// The guest's account of who opened a connection.
#[derive(Debug, Default, Serialize)]
pub struct Origin {
    /// Whether the owning process was found.
    pub known: bool,
    /// Whether the owner or any ancestor ran workspace-controlled code.
    pub workspace_code: bool,
    pub chain: Vec<Process>,
}

/// Runs `command` as the workload's terminal, serves attribution queries, reaps
/// orphans, and powers the guest off when the command exits.
pub fn supervise(command: &[String]) -> ! {
    if let Err(error) = serve_attribution() {
        eprintln!("[keel-init] attribution service unavailable: {error}");
    }
    let status = Command::new(&command[0])
        .args(&command[1..])
        .spawn()
        .map_or(127, |child| reap_until(child.id()));
    println!("[keel-init] workload exited with status {status}");
    // SAFETY: sync and reboot take no pointers; PID 1 powering off after the
    // workload ends is the guest's intended lifecycle.
    unsafe {
        libc::sync();
        libc::reboot(libc::RB_POWER_OFF);
    }
    loop {
        thread::sleep(Duration::from_hours(1));
    }
}

/// Reaps every child PID 1 inherits until `main` exits, returning its status.
fn reap_until(main: u32) -> i32 {
    loop {
        let mut status = 0;
        // SAFETY: waitpid(-1) with valid status storage.
        let pid = unsafe { libc::waitpid(-1, &raw mut status, 0) };
        if pid < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return 1;
        }
        if u32::try_from(pid).ok() == Some(main) {
            return if libc::WIFEXITED(status) {
                libc::WEXITSTATUS(status)
            } else {
                128 + libc::WTERMSIG(status)
            };
        }
    }
}

fn serve_attribution() -> io::Result<()> {
    let directory = Path::new(ATTRIBUTION_SOCKET)
        .parent()
        .ok_or_else(|| io::Error::other("attribution socket has no directory"))?;
    fs::create_dir_all(directory)?;
    chown(directory, Some(SERVICE_UID), Some(SERVICE_UID))?;
    fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
    let _ = fs::remove_file(ATTRIBUTION_SOCKET);
    let listener = UnixListener::bind(ATTRIBUTION_SOCKET)?;
    chown(ATTRIBUTION_SOCKET, Some(SERVICE_UID), Some(SERVICE_UID))?;
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            thread::spawn(move || {
                let _ = answer(stream);
            });
        }
    });
    Ok(())
}

/// Answers `tcp LOCAL_PORT PEER_PORT` with one JSON origin line.
fn answer(stream: UnixStream) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(1)))?;
    let mut line = String::new();
    BufReader::new((&stream).take(64)).read_line(&mut line)?;
    let mut fields = line.split_whitespace();
    let origin = match (fields.next(), fields.next(), fields.next()) {
        (Some("tcp"), Some(local), Some(peer)) => match (local.parse(), peer.parse()) {
            (Ok(local), Ok(peer)) => attribute(local, peer),
            _ => Origin::default(),
        },
        _ => Origin::default(),
    };
    let mut stream = stream;
    serde_json::to_writer(&mut stream, &origin).map_err(io::Error::other)?;
    stream.write_all(b"\n")
}

/// Finds the process owning the client end of a loopback connection to the
/// relay's `local_port` from `peer_port`, and describes its ancestry.
pub fn attribute(local_port: u16, peer_port: u16) -> Origin {
    let Some(inode) = socket_inode(local_port, peer_port) else {
        return Origin::default();
    };
    let Some(pid) = socket_owner(&inode) else {
        return Origin::default();
    };
    let mut chain = Vec::new();
    let mut current = pid;
    while current > 1 && chain.len() < MAX_ANCESTORS {
        let process = describe(current);
        let parent = parent_of(current);
        chain.push(process);
        match parent {
            Some(parent) if parent != current => current = parent,
            _ => break,
        }
    }
    Origin {
        known: true,
        workspace_code: chain.iter().any(|process| process.workspace_code),
        chain,
    }
}

/// The inode of the client socket `127.0.0.1:peer_port -> 127.0.0.1:local_port`.
fn socket_inode(local_port: u16, peer_port: u16) -> Option<String> {
    let table = fs::read_to_string("/proc/net/tcp").ok()?;
    let client = format!("0100007F:{peer_port:04X}");
    let server = format!("0100007F:{local_port:04X}");
    table.lines().skip(1).find_map(|line| {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        (fields.get(1) == Some(&client.as_str()) && fields.get(2) == Some(&server.as_str()))
            .then(|| fields.get(9).map(|inode| (*inode).to_owned()))
            .flatten()
    })
}

fn socket_owner(inode: &str) -> Option<u32> {
    let target = format!("socket:[{inode}]");
    fs::read_dir("/proc").ok()?.flatten().find_map(|entry| {
        let pid = entry.file_name().to_str()?.parse::<u32>().ok()?;
        fs::read_dir(entry.path().join("fd"))
            .ok()?
            .flatten()
            .any(|fd| {
                fs::read_link(fd.path()).is_ok_and(|link| link.as_os_str() == target.as_str())
            })
            .then_some(pid)
    })
}

fn parent_of(pid: u32) -> Option<u32> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // The command name may contain spaces and parentheses; fields resume
    // after the last closing parenthesis.
    stat.rsplit_once(')')?
        .1
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

fn describe(pid: u32) -> Process {
    let exe = fs::read_link(format!("/proc/{pid}/exe"))
        .map(|path| path.display().to_string())
        .unwrap_or_default();
    let cwd = fs::read_link(format!("/proc/{pid}/cwd")).unwrap_or_default();
    let argv = fs::read(format!("/proc/{pid}/cmdline"))
        .unwrap_or_default()
        .split(|byte| *byte == 0)
        .filter(|argument| !argument.is_empty())
        .take(MAX_ARGUMENTS)
        .map(|argument| {
            let argument = String::from_utf8_lossy(argument);
            argument.chars().take(MAX_ARGUMENT_BYTES).collect()
        })
        .collect::<Vec<String>>();
    let workspace_code = runs_workspace_code(&exe, &argv, &cwd);
    Process {
        pid,
        exe,
        argv,
        workspace_code,
    }
}

/// Whether a process runs code the workload could have written: an
/// executable or script argument under a writable root, which includes any
/// `node_modules` there. Read-only system paths, such as the guest's bundled
/// browser server, are not workspace code: Landlock keeps the workload from
/// writing them.
fn runs_workspace_code(exe: &str, argv: &[String], cwd: &Path) -> bool {
    let writable = |path: &str| {
        let absolute = if path.starts_with('/') {
            PathBuf::from(path)
        } else {
            cwd.join(path)
        };
        let absolute = absolute.display().to_string();
        WRITABLE_ROOTS.iter().any(|root| absolute.starts_with(root))
    };
    writable(exe)
        || (writable(&cwd.display().to_string())
            && cwd.display().to_string().contains("/node_modules/"))
        || argv.iter().skip(1).any(|argument| {
            !argument.starts_with('-')
                && SCRIPT_SUFFIXES
                    .iter()
                    .any(|suffix| argument.ends_with(suffix))
                && writable(argument)
        })
}

/// Asks the supervisor about one relay connection. Any failure yields an
/// unknown origin, which the host treats as least trusted.
pub fn query(local_port: u16, peer_port: u16) -> Vec<u8> {
    let unknown = br#"{"known":false,"workspace_code":false,"chain":[]}"#.to_vec();
    let Ok(mut stream) = UnixStream::connect(ATTRIBUTION_SOCKET) else {
        return unknown;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
    if writeln!(stream, "tcp {local_port} {peer_port}").is_err() {
        return unknown;
    }
    let mut line = String::new();
    match BufReader::new(stream.take(4096)).read_line(&mut line) {
        Ok(_) if !line.trim().is_empty() => line.trim().as_bytes().to_vec(),
        _ => unknown,
    }
}
