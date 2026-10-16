// Most of these tests exercise macOS sandbox-exec; elsewhere their imports
// are unused.
#![cfg_attr(not(target_os = "macos"), allow(unused_imports))]

use super::{
    CANONICAL_TERMINAL_RESET, CLEAR_PRIMARY_SCREEN, clear_cancelled_approval_screen,
    forward_renderer_reply, host_v8_confirmation_matches, input_source_is_trusted,
    renderer_sandbox_profile, runtime_sandbox_profile, trusted_scratch,
};
use std::{
    ffi::OsStr,
    fs,
    io::{Read as _, Write as _},
    net::{Ipv4Addr, TcpListener},
    os::unix::net::UnixListener,
    path::Path,
    process::{Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{SystemTime, UNIX_EPOCH},
};

#[cfg(target_os = "macos")]
static SANDBOX_TEST_LOCK: Mutex<()> = Mutex::new(());

struct ExitedGuest;

impl std::io::Write for ExitedGuest {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct FlushTrackedTerminal {
    bytes: Vec<u8>,
    flushed: Arc<AtomicBool>,
}

impl std::io::Write for FlushTrackedTerminal {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.flushed.store(true, Ordering::Release);
        Ok(())
    }
}

#[test]
fn a_late_terminal_reply_does_not_replace_a_completed_v8_result() {
    forward_renderer_reply(&mut ExitedGuest, b"\x1b[24;80R").unwrap();
}

#[test]
fn cancelled_approval_clears_the_trusted_screen_before_repaint() {
    let flushed = Arc::new(AtomicBool::new(false));
    let repainted = Arc::new(AtomicBool::new(false));
    let mut terminal = FlushTrackedTerminal {
        bytes: Vec::new(),
        flushed: Arc::clone(&flushed),
    };
    let repaint_complete = Arc::clone(&repainted);

    clear_cancelled_approval_screen(&mut terminal, true, || {
        assert!(
            flushed.load(Ordering::Acquire),
            "renderer repaint ran before the trusted clear was flushed"
        );
        repaint_complete.store(true, Ordering::Release);
        Ok(())
    })
    .unwrap();

    let expected = [
        b"\x1b]2;keel mux\x07".as_slice(),
        CANONICAL_TERMINAL_RESET,
        CLEAR_PRIMARY_SCREEN,
    ]
    .concat();
    assert_eq!(terminal.bytes, expected);
    assert!(repainted.load(Ordering::Acquire));
}

#[test]
fn trusted_terminal_reset_restores_primary_full_page_before_painting() {
    let offset = |needle: &[u8]| {
        CANONICAL_TERMINAL_RESET
            .windows(needle.len())
            .position(|window| window == needle)
            .unwrap_or_else(|| panic!("missing terminal reset sequence: {needle:?}"))
    };

    let synchronized_output_off = offset(b"\x1b[?2026l");
    let primary_buffer = offset(b"\x1b[?1049l");
    let left_right_margins_off = offset(b"\x1b[?69l");
    let origin_mode_off = offset(b"\x1b[?6l");
    let vertical_margins_reset = offset(b"\x1b[r");

    assert!(synchronized_output_off < primary_buffer);
    assert!(primary_buffer < left_right_margins_off);
    assert!(left_right_margins_off < origin_mode_off);
    assert!(origin_mode_off < vertical_margins_reset);
    assert!(CANONICAL_TERMINAL_RESET.ends_with(b"\x1b[0m"));
}

#[test]
fn persistent_attach_is_not_a_trusted_approval_source() {
    let trusted =
        |source: Option<&str>, owned| input_source_is_trusted(source.map(OsStr::new), owned);
    assert!(!trusted(Some("persistent-attach"), true));
    assert!(trusted(Some("trusted-terminal"), true));
    assert!(trusted(Some("trusted-supervisor"), false));
}

#[test]
fn host_v8_requires_the_exact_trusted_confirmation() {
    assert!(host_v8_confirmation_matches("HOST V8\n"));
    assert!(!host_v8_confirmation_matches("yes\n"));
}

#[cfg(target_os = "macos")]
#[test]
fn renderer_sandbox_can_execute_only_its_renderer() {
    let _sandbox_guard = SANDBOX_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let profile = renderer_sandbox_profile(Path::new("/usr/bin/true"));
    let allowed = Command::new("/usr/bin/sandbox-exec")
        .args(["-p", &profile])
        .arg("/usr/bin/true")
        .status()
        .expect("sandbox-exec");
    assert!(allowed.success());

    let denied = Command::new("/usr/bin/sandbox-exec")
        .args(["-p", &profile])
        .arg("/usr/bin/false")
        .status()
        .expect("sandbox-exec");
    assert!(!denied.success());
}

#[cfg(target_os = "macos")]
#[test]
fn runtime_sandbox_allows_expected_metadata_and_denies_outside_reads() {
    let _sandbox_guard = SANDBOX_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let scratch = trusted_scratch("sandbox-test").expect("scratch");
    let component_parent = trusted_scratch("sandbox-components-test").expect("component parent");
    let components = component_parent.join("nested/components");
    fs::create_dir_all(&components).expect("component fixture directory");
    let component_file = components.join("keel-v8-sdk.ts");
    fs::write(&component_file, b"export const keel = {};\n").expect("component fixture");
    let secret = std::env::temp_dir().join(format!("keel-sandbox-secret-{}", std::process::id()));
    fs::write(&secret, b"must not be readable").expect("secret fixture");
    let workspace = std::env::current_dir()
        .expect("workspace")
        .canonicalize()
        .expect("canonical workspace");
    let profile = runtime_sandbox_profile(
        [
            Path::new("/usr/bin/true"),
            Path::new("/bin/realpath"),
            Path::new("/bin/cat"),
            Path::new("/nonexistent/keel-git-helpers"),
        ],
        Path::new("/nonexistent/keel-git-data"),
        &workspace,
        [&components, Path::new("/nonexistent/keel-images")],
        Path::new("/dev/null"),
        [&scratch, Path::new("/dev/null")],
        Path::new("/tmp/keel-test-broker.sock"),
        Some(18_081),
    );
    let valid = Command::new("/usr/bin/sandbox-exec")
        .args(["-p", &profile])
        .arg("/usr/bin/true")
        .output()
        .expect("sandbox-exec");
    assert!(
        valid.status.success(),
        "runtime sandbox profile must compile: {}\n{profile}",
        String::from_utf8_lossy(&valid.stderr)
    );

    let workspace_read = Command::new("/usr/bin/sandbox-exec")
        .args(["-p", &profile])
        .arg("/bin/realpath")
        .arg(workspace.join("Cargo.toml"))
        .output()
        .expect("sandbox-exec");
    assert!(
        workspace_read.status.success(),
        "runtime sandbox must permit metadata traversal to workspace files: {}\n{profile}",
        String::from_utf8_lossy(&workspace_read.stderr)
    );

    let component_read = Command::new("/usr/bin/sandbox-exec")
        .args(["-p", &profile])
        .arg("/bin/realpath")
        .arg(&component_file)
        .output()
        .expect("sandbox-exec");
    assert!(
        component_read.status.success(),
        "runtime sandbox must permit metadata traversal to installed components: {}\n{profile}",
        String::from_utf8_lossy(&component_read.stderr)
    );

    let denied = Command::new("/usr/bin/sandbox-exec")
        .args(["-p", &profile])
        .arg("/bin/cat")
        .arg(&secret)
        .status()
        .expect("sandbox-exec");
    assert!(!denied.success(), "sandbox escaped its read allowlist");
    fs::remove_file(secret).expect("remove fixture");
    fs::remove_dir_all(component_parent).expect("remove component fixture");
    fs::remove_dir_all(scratch).expect("remove scratch");
}

#[cfg(target_os = "macos")]
#[test]
fn runtime_sandbox_writes_only_its_guest_events_file_in_the_session() {
    let _sandbox_guard = SANDBOX_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let scratch = trusted_scratch("sandbox-guest-events-test").expect("scratch");
    let session = trusted_scratch("sandbox-session-test").expect("session");
    let guest_events = session.join("guest-1-0.ndjson");
    let audit = session.join("audit-1-0.ndjson");
    let workspace = std::env::current_dir()
        .expect("workspace")
        .canonicalize()
        .expect("canonical workspace");
    let profile = runtime_sandbox_profile(
        [
            Path::new("/usr/bin/true"),
            Path::new("/usr/bin/touch"),
            Path::new("/bin/cat"),
            Path::new("/nonexistent/keel-git-helpers"),
        ],
        Path::new("/nonexistent/keel-git-data"),
        &workspace,
        [
            Path::new("/nonexistent/keel-components"),
            Path::new("/nonexistent/keel-images"),
        ],
        Path::new("/dev/null"),
        [&scratch, &guest_events],
        Path::new("/tmp/keel-test-broker.sock"),
        None,
    );
    let touch = |path: &Path| {
        Command::new("/usr/bin/sandbox-exec")
            .args(["-p", &profile])
            .arg("/usr/bin/touch")
            .arg(path)
            .status()
            .expect("sandbox-exec")
            .success()
    };
    assert!(touch(&guest_events), "the guest-events file is writable");
    assert!(!touch(&audit), "no other session file is writable");
    assert!(!audit.exists());
    fs::remove_dir_all(session).expect("remove session");
    fs::remove_dir_all(scratch).expect("remove scratch");
}

#[cfg(target_os = "macos")]
#[test]
fn runtime_sandbox_cannot_bind_ip_listeners() {
    let _sandbox_guard = SANDBOX_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let scratch = trusted_scratch("sandbox-network-test").expect("scratch");
    let reserve = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("reserve proxy port");
    let proxy_port = reserve.local_addr().expect("proxy address").port();
    drop(reserve);
    let profile = runtime_sandbox_profile(
        [
            Path::new("/usr/bin/nc"),
            Path::new("/usr/bin/true"),
            Path::new("/usr/bin/printf"),
            Path::new("/nonexistent/keel-git-helpers"),
        ],
        Path::new("/nonexistent/keel-git-data"),
        &std::env::current_dir().expect("workspace"),
        [Path::new("/usr/bin"), Path::new("/nonexistent/keel-images")],
        Path::new("/dev/null"),
        [&scratch, Path::new("/dev/null")],
        Path::new("/tmp/keel-test-broker.sock"),
        Some(proxy_port),
    );

    let denied = Command::new("/usr/bin/sandbox-exec")
        .args(["-p", &profile, "/usr/bin/nc", "-l", "127.0.0.1"])
        .arg(proxy_port.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .output()
        .expect("attempt listener bind");
    assert!(
        !denied.status.success()
            && String::from_utf8_lossy(&denied.stderr).contains("Operation not permitted"),
        "runtime sandbox must reject every new IP listener: {}\n{profile}",
        String::from_utf8_lossy(&denied.stderr)
    );

    fs::remove_dir_all(scratch).expect("remove scratch");
}

// The profile emits its TCP rules after the Unix-socket rules. Seatbelt
// intermittently applies a later `(deny network-outbound (remote
// unix-socket))` to a TCP connect, which refused the assigned port on roughly
// one port in eight; this test then failed at that rate.
#[cfg(target_os = "macos")]
#[test]
fn runtime_sandbox_connects_only_to_the_assigned_v8_proxy_port() {
    let _sandbox_guard = SANDBOX_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let scratch = trusted_scratch("sandbox-connect-test").expect("scratch");
    let allowed_listener =
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind allowed listener");
    let allowed_port = allowed_listener
        .local_addr()
        .expect("allowed address")
        .port();
    let denied_listener =
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind denied listener");
    let denied_port = denied_listener.local_addr().expect("denied address").port();
    let profile = runtime_sandbox_profile(
        [
            Path::new("/usr/bin/nc"),
            Path::new("/usr/bin/true"),
            Path::new("/usr/bin/printf"),
            Path::new("/nonexistent/keel-git-helpers"),
        ],
        Path::new("/nonexistent/keel-git-data"),
        &std::env::current_dir().expect("workspace"),
        [Path::new("/usr/bin"), Path::new("/nonexistent/keel-images")],
        Path::new("/dev/null"),
        [&scratch, Path::new("/dev/null")],
        Path::new("/tmp/keel-test-broker.sock"),
        Some(allowed_port),
    );

    let allowed = Command::new("/usr/bin/sandbox-exec")
        .args(["-p", &profile, "/usr/bin/nc", "-nz", "127.0.0.1"])
        .arg(allowed_port.to_string())
        .output()
        .expect("connect to assigned listener");
    assert!(
        allowed.status.success(),
        "runtime sandbox must permit its assigned loopback connection: {}\n{profile}",
        String::from_utf8_lossy(&allowed.stderr)
    );

    let denied = Command::new("/usr/bin/sandbox-exec")
        .args(["-p", &profile, "/usr/bin/nc", "-nz", "127.0.0.1"])
        .arg(denied_port.to_string())
        .output()
        .expect("connect to unassigned listener");
    assert!(
        !denied.status.success(),
        "runtime sandbox must reject unassigned loopback connections\n{profile}"
    );
    drop((allowed_listener, denied_listener));
    fs::remove_dir_all(scratch).expect("remove scratch");
}

#[cfg(target_os = "macos")]
#[test]
fn runtime_sandbox_connects_only_to_the_assigned_broker_socket() {
    let _sandbox_guard = SANDBOX_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_nanos();
    let scratch =
        Path::new("/private/tmp").join(format!("keel-sb-unix-{}-{unique:x}", std::process::id()));
    fs::create_dir(&scratch).expect("short sandbox scratch");
    let broker = scratch.join("broker.sock");
    let other = scratch.join("other.sock");
    let broker_listener = UnixListener::bind(&broker).expect("bind broker socket");
    let other_listener = UnixListener::bind(&other).expect("bind other socket");
    let profile = runtime_sandbox_profile(
        [
            Path::new("/usr/bin/nc"),
            Path::new("/usr/bin/true"),
            Path::new("/usr/bin/printf"),
            Path::new("/nonexistent/keel-git-helpers"),
        ],
        Path::new("/nonexistent/keel-git-data"),
        &std::env::current_dir().expect("workspace"),
        [Path::new("/usr/bin"), Path::new("/nonexistent/keel-images")],
        Path::new("/dev/null"),
        [&scratch, Path::new("/dev/null")],
        &broker,
        Some(18_081),
    );
    let receiver = thread::spawn(move || {
        let (mut stream, _) = broker_listener.accept().expect("accept broker connection");
        let mut byte = [0_u8; 1];
        stream.read_exact(&mut byte).expect("read broker probe");
        byte
    });
    let mut allowed = Command::new("/usr/bin/sandbox-exec")
        .args(["-p", &profile, "/usr/bin/nc", "-w", "1", "-U"])
        .arg(&broker)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("connect to assigned broker socket");
    allowed
        .stdin
        .take()
        .expect("broker probe stdin")
        .write_all(b"x")
        .expect("write broker probe");
    let allowed = allowed.wait_with_output().expect("collect broker probe");
    assert!(
        allowed.status.success() && receiver.join().expect("broker receiver") == *b"x",
        "runtime sandbox must permit its assigned broker socket: {}\n{profile}",
        String::from_utf8_lossy(&allowed.stderr)
    );

    let denied = Command::new("/usr/bin/sandbox-exec")
        .args(["-p", &profile, "/usr/bin/nc", "-w", "1", "-U"])
        .arg(&other)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .output()
        .expect("connect to unassigned broker socket");
    assert!(
        !denied.status.success(),
        "runtime sandbox must reject unassigned broker sockets\n{profile}"
    );
    drop(other_listener);
    fs::remove_dir_all(scratch).expect("remove scratch");
}

/// A confined child holding the operator's terminal could inject keystrokes
/// with `TIOCSTI` or paint over the trusted screen, so no profile may open a
/// terminal device even though `/dev` is otherwise readable.
#[cfg(target_os = "macos")]
#[test]
fn confined_children_cannot_open_a_terminal() {
    let _sandbox_guard = SANDBOX_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let pty = nix::pty::openpty(None, None).expect("open a pseudo-terminal");
    let terminal = nix::unistd::ttyname(&pty.slave).expect("terminal path");
    let opens = |profile: Option<&str>, path: &Path| {
        let mut command = Command::new("/usr/bin/sandbox-exec");
        match profile {
            Some(profile) => command.args(["-p", profile, "/bin/bash"]),
            None => command.args(["-p", "(version 1)\n(allow default)", "/bin/bash"]),
        };
        command
            .arg("-c")
            .arg(format!(": < '{}'", path.display()))
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("sandbox-exec")
            .success()
    };
    assert!(
        opens(None, &terminal),
        "control: the terminal opens unconfined"
    );
    let workspace = std::env::current_dir().expect("workspace");
    let runtime = runtime_sandbox_profile(
        [
            Path::new("/bin/bash"),
            Path::new("/usr/bin/true"),
            Path::new("/usr/bin/true"),
            Path::new("/nonexistent/keel-git-helpers"),
        ],
        Path::new("/nonexistent/keel-git-data"),
        &workspace,
        [
            Path::new("/nonexistent/keel-components"),
            Path::new("/nonexistent/keel-images"),
        ],
        Path::new("/dev/null"),
        [
            Path::new("/nonexistent/keel-scratch"),
            Path::new("/dev/null"),
        ],
        Path::new("/tmp/keel-test-broker.sock"),
        None,
    );
    let renderer = renderer_sandbox_profile(Path::new("/bin/bash"));
    for (name, profile) in [("runtime", &runtime), ("renderer", &renderer)] {
        assert!(
            opens(Some(profile), Path::new("/dev/null")),
            "{name}: /dev/null stays usable"
        );
        assert!(
            !opens(Some(profile), &terminal),
            "{name} opened {}",
            terminal.display()
        );
        assert!(
            !opens(Some(profile), Path::new("/dev/tty")),
            "{name} opened /dev/tty"
        );
    }
}

/// KSR-035: the clipboard, `LaunchServices`, and name resolution are host
/// services a confined child could use to read secrets or reach the network
/// around its sandbox. Each probe works unconfined and fails confined.
#[cfg(target_os = "macos")]
#[test]
fn confined_children_cannot_reach_host_services() {
    let _sandbox_guard = SANDBOX_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let probes: [(&str, &[&str], &str); 3] = [
        ("/usr/bin/pbpaste", &[], ""),
        (
            "/usr/bin/lsappinfo",
            &["info", "-only", "name", "Finder"],
            "Finder",
        ),
        (
            "/usr/bin/dscacheutil",
            &["-q", "host", "-a", "name", "localhost"],
            "address",
        ),
    ];
    let reaches = |profile: &str, program: &str, arguments: &[&str], expected: &str| {
        let output = Command::new("/usr/bin/sandbox-exec")
            .args(["-p", profile, program])
            .args(arguments)
            .stdin(Stdio::null())
            .output()
            .expect("sandbox-exec");
        output.status.success() && String::from_utf8_lossy(&output.stdout).contains(expected)
    };
    let workspace = std::env::current_dir().expect("workspace");
    for (program, arguments, expected) in probes {
        assert!(
            reaches("(version 1)\n(allow default)", program, arguments, expected),
            "control: {program} works unconfined"
        );
        let runtime = runtime_sandbox_profile(
            [
                Path::new(program),
                Path::new("/usr/bin/true"),
                Path::new("/usr/bin/true"),
                Path::new("/nonexistent/keel-git-helpers"),
            ],
            Path::new("/nonexistent/keel-git-data"),
            &workspace,
            [
                Path::new("/nonexistent/keel-components"),
                Path::new("/nonexistent/keel-images"),
            ],
            Path::new("/dev/null"),
            [
                Path::new("/nonexistent/keel-scratch"),
                Path::new("/dev/null"),
            ],
            Path::new("/tmp/keel-test-broker.sock"),
            None,
        );
        let renderer = renderer_sandbox_profile(Path::new(program));
        for (name, profile) in [("runtime", &runtime), ("renderer", &renderer)] {
            assert!(
                !reaches(profile, program, arguments, expected),
                "{name} sandbox reached a host service through {program}"
            );
        }
    }
}

/// KSR-054: the backend's confiner starts only once the runtime says so, and
/// a runtime that dies first leaves nothing running.
#[test]
fn the_start_gate_runs_the_command_only_after_start() {
    use std::os::fd::AsRawFd as _;
    let gated = |start: Option<&[u8]>| {
        let (gate, mut writer) = std::io::pipe().unwrap();
        // Above 9, as the runtime's own descriptors are, which dash cannot
        // redirect.
        let mut held = Vec::new();
        let inherited = loop {
            let fd = nix::unistd::dup(&gate).unwrap();
            if fd.as_raw_fd() > 9 {
                break fd;
            }
            held.push(fd);
        };
        drop(held);
        let child = Command::new(super::START_GATE_SHELL)
            .args(["-c", super::START_GATE, "keel-start", "/bin/sh", "-c"])
            .arg(format!(
                "echo ran; [ -e /dev/fd/{} ] && echo leaked; true",
                inherited.as_raw_fd()
            ))
            .env("KEEL_START_FD", inherited.as_raw_fd().to_string())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        drop((inherited, gate));
        if let Some(start) = start {
            // The gate may already have refused and closed its end.
            let _ = writer.write_all(start);
        }
        drop(writer);
        let output = child.wait_with_output().unwrap();
        (
            output.status.code(),
            String::from_utf8(output.stdout).unwrap(),
        )
    };
    assert_eq!(gated(Some(b"start\n")), (Some(0), "ran\n".to_owned()));
    assert_eq!(gated(None), (Some(125), String::new()));
    assert_eq!(gated(Some(b"other\n")), (Some(125), String::new()));
}
