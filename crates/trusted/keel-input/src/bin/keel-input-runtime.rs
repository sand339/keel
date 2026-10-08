#![forbid(unsafe_code)]
#![doc = "Trusted terminal owner for an interactive Keel runtime."]

#[path = "keel-input-runtime/session.rs"]
mod session;

use keel_input::{
    GateController, InputEvent, InputGate, PendingApproval, RuntimeBroker, RuntimeIntent,
    SECURE_ATTENTION, TerminalControl, TerminalControlReader, encode_resize, push_keystroke,
    render_gate, safe_text, terminal_gate_channel,
};
use keel_kernel::GateDecision;
use nix::sys::signal::{SigSet, Signal, killpg};
use nix::unistd::{Pid, dup, getpgrp, tcgetpgrp};
use std::{
    env,
    error::Error,
    fs,
    io::{self, BufRead as _, IsTerminal as _, Read as _, Write as _},
    net::{Ipv4Addr, TcpListener},
    os::{
        fd::AsRawFd as _,
        unix::{fs::PermissionsExt as _, process::CommandExt as _},
    },
    path::{Path, PathBuf},
    process::{Child, ChildStdin, Command, Stdio},
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

const APPROVAL_TITLE_NOTICE: &[u8] = b"\x1b]2;Keel approval: Ctrl-] or Ctrl-A /approve\x07";
const NORMAL_TITLE_NOTICE: &[u8] = b"\x1b]2;keel mux\x07";
const MAX_DISPLAY_SNAPSHOT: usize = 4 * 1024 * 1024;
const RENDER_GUEST: u8 = b'g';
const RENDER_RESIZE: u8 = b'r';
const RENDER_REPAINT: u8 = b'p';
const RENDER_FINISH: u8 = b'f';
const RENDER_APPROVAL_PENDING: u8 = b'a';
const RENDER_APPROVAL_CLEAR: u8 = b'n';
const DISPLAY_SNAPSHOT: u8 = b's';
const DISPLAY_GUEST_INPUT: u8 = b'i';
const MAX_DISPLAY_GUEST_INPUT: usize = 16 * 1024;
const STTY: &str = "/bin/stty";
type RendererControl = Arc<Mutex<ChildStdin>>;

// Guest output is interpreted by the headless renderer, but its snapshots are
// ultimately replayed into the operator's real terminal.  A truncated snapshot
// or an interrupted process can therefore leave that terminal in the alternate
// buffer or with margins that constrain a later ED/CUP.  Every trusted takeover
// and teardown starts from one primary-buffer, full-page geometry before it
// paints anything security-sensitive.
const CANONICAL_TERMINAL_RESET: &[u8] = b"\x18\
\x1b[?2026l\
\x1b[?1049l\
\x1b[?1l\
\x1b[?66l\
\x1b[?69l\
\x1b[?6l\
\x1b[r\
\x1b[?2004l\
\x1b[4l\
\x1b[?45l\
\x1b[?9l\
\x1b[?1000l\
\x1b[?1002l\
\x1b[?1003l\
\x1b[?1004l\
\x1b[?1005l\
\x1b[?1006l\
\x1b[?1015l\
\x1b[?1016l\
\x1b[?7h\
\x1b[?25h\
\x1b[0m";
const CLEAR_PRIMARY_SCREEN: &[u8] = b"\x1b[2J\x1b[H";

struct InteractiveState {
    input: InputGate,
    pending: Option<PendingApproval>,
    /// Only bytes read directly from the terminal owner may enter the trusted
    /// approval UI. Persistent attach traffic is an untrusted byte stream.
    trusted_approval_input: bool,
    shutting_down: bool,
    /// Prevents an approval notification from being injected repeatedly while
    /// a full-screen workload is repainting.
    approval_notice_shown: bool,
    renderer: Option<RendererControl>,
}

fn paint_trusted_screen(
    state: &mut InteractiveState,
    terminal: &mut impl io::Write,
) -> io::Result<()> {
    let pending = state
        .pending
        .as_ref()
        .ok_or_else(|| io::Error::other("trusted mode has no pending kernel action"))?;
    let screen = render_gate(pending.payload(), pending.method(), pending.challenge());
    terminal.write_all(APPROVAL_TITLE_NOTICE)?;
    terminal.write_all(CANONICAL_TERMINAL_RESET)?;
    terminal.write_all(CLEAR_PRIMARY_SCREEN)?;
    terminal.write_all(screen.as_bytes())?;
    terminal.flush()
}

fn renderer_message(renderer: &RendererControl, message: &[u8]) -> io::Result<()> {
    let mut renderer = renderer
        .lock()
        .map_err(|_| io::Error::other("renderer input is unavailable"))?;
    renderer.write_all(message)?;
    renderer.flush()
}

fn forward_renderer_reply(guest: &mut impl io::Write, reply: &[u8]) -> io::Result<()> {
    match guest.write_all(reply).and_then(|()| guest.flush()) {
        // A short-lived workload can exit after asking a terminal query but
        // before xterm has generated its reply. The runtime status remains the
        // authoritative result; a late advisory reply must not replace it.
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => Ok(()),
        result => result,
    }
}

fn set_approval_notice(renderer: Option<&RendererControl>, pending: bool) -> io::Result<()> {
    if let Some(renderer) = renderer {
        let message = if pending {
            RENDER_APPROVAL_PENDING
        } else {
            RENDER_APPROVAL_CLEAR
        };
        renderer_message(renderer, &[message])?;
    }
    Ok(())
}

fn resume_guest_screen(terminal: &mut impl io::Write, _forward: &mut Vec<u8>) -> io::Result<()> {
    terminal.write_all(NORMAL_TITLE_NOTICE)?;
    terminal.write_all(CANONICAL_TERMINAL_RESET)?;
    terminal.write_all(CLEAR_PRIMARY_SCREEN)?;
    terminal.flush()
}
fn clear_cancelled_approval_screen(
    terminal: &mut impl io::Write,
    trusted_screen: bool,
    repaint: impl FnOnce() -> io::Result<()>,
) -> io::Result<()> {
    terminal.write_all(NORMAL_TITLE_NOTICE)?;
    if trusted_screen {
        terminal.write_all(CANONICAL_TERMINAL_RESET)?;
        terminal.write_all(CLEAR_PRIMARY_SCREEN)?;
    }
    terminal.flush()?;
    // Keep the stdout lock through the renderer request. Its output thread
    // cannot replay the restored guest frame until the trusted clear above is
    // complete, so the clear can never erase a frame that arrived first.
    repaint()
}
fn lock_state(
    state: &Arc<Mutex<InteractiveState>>,
) -> io::Result<MutexGuard<'_, InteractiveState>> {
    state
        .lock()
        .map_err(|_| io::Error::other("trusted terminal state is unavailable"))
}
fn spawn_gate_receiver(
    controller: GateController,
    state: Arc<Mutex<InteractiveState>>,
) -> JoinHandle<io::Result<()>> {
    thread::spawn(move || {
        loop {
            let prompt = match controller.receive_timeout(Duration::from_millis(50)) {
                Ok(Some(prompt)) => prompt,
                Ok(None) => {
                    let mut state = lock_state(&state)?;
                    if state
                        .pending
                        .as_ref()
                        .is_none_or(PendingApproval::is_active)
                    {
                        continue;
                    }
                    let trusted_screen = state.input.in_trusted_mode();
                    state.pending = None;
                    state.input = InputGate::new();
                    state.approval_notice_shown = false;
                    let renderer = state.renderer.clone();
                    drop(state);
                    let mut terminal = io::stdout().lock();
                    clear_cancelled_approval_screen(&mut terminal, trusted_screen, || {
                        set_approval_notice(renderer.as_ref(), false)?;
                        if let Some(renderer) = renderer.as_ref() {
                            renderer_message(renderer, &[RENDER_REPAINT])?;
                        }
                        Ok(())
                    })?;
                    continue;
                }
                Err(_) => break,
            };
            let method = prompt.method();
            let challenge = prompt.challenge().map(str::to_owned);
            let mut state = lock_state(&state)?;
            if state.shutting_down || state.pending.is_some() || !state.trusted_approval_input {
                drop(state);
                let _ = prompt.decide(GateDecision::Deny);
                continue;
            }
            let grantable = prompt.payload().session_grant.is_some();
            state
                .input
                .set_pending_with_grant(method, challenge.as_deref(), grantable);
            state.pending = Some(prompt);
            state.approval_notice_shown = false;
            let renderer = state.renderer.clone();
            state.approval_notice_shown = true;
            drop(state);
            set_approval_notice(renderer.as_ref(), true)?;
            let mut terminal = io::stdout().lock();
            terminal.write_all(APPROVAL_TITLE_NOTICE)?;
            terminal.flush()?;
        }
        Ok(())
    })
}
fn begin_shutdown(state: &Arc<Mutex<InteractiveState>>) -> io::Result<()> {
    let pending = {
        let mut state = lock_state(state)?;
        state.shutting_down = true;
        state.input = InputGate::new();
        state.approval_notice_shown = false;
        state.pending.take()
    };
    if let Some(pending) = pending {
        let _ = pending.decide(GateDecision::Deny);
    }
    Ok(())
}
fn route_input(
    state: &Arc<Mutex<InteractiveState>>,
    byte: u8,
    forward: &mut Vec<u8>,
) -> io::Result<bool> {
    let mut state = lock_state(state)?;
    if byte == SECURE_ATTENTION && state.pending.is_some() && !state.trusted_approval_input {
        let pending = state
            .pending
            .take()
            .expect("pending approval checked above");
        state.input = InputGate::new();
        state.approval_notice_shown = false;
        let renderer = state.renderer.clone();
        let mut terminal = io::stdout().lock();
        terminal.write_all(
            b"\r\nKEEL DENIED - approvals require a directly attached trusted terminal\r\n",
        )?;
        terminal.flush()?;
        terminal.write_all(NORMAL_TITLE_NOTICE)?;
        drop(state);
        set_approval_notice(renderer.as_ref(), false)?;
        let _ = pending.decide(GateDecision::Deny);
        return Ok(true);
    }
    match state.input.accept(byte) {
        InputEvent::Forward(byte) => {
            drop(state);
            // The guest hop carries Keel's control messages too, so a literal
            // control byte the operator typed leaves here doubled.
            push_keystroke(forward, byte);
            Ok(false)
        }
        InputEvent::Consumed => Ok(false),
        InputEvent::EnterTrusted => {
            let mut terminal = io::stdout().lock();
            paint_trusted_screen(&mut state, &mut terminal)?;
            Ok(true)
        }
        InputEvent::ChallengeMismatch => {
            let mut terminal = io::stdout().lock();
            terminal
                .write_all(b"\r\nCHALLENGE MISMATCH - try again or press Escape to deny\r\n")?;
            terminal.flush()?;
            Ok(true)
        }
        InputEvent::Approved => {
            let pending = state.pending.take().ok_or_else(|| {
                io::Error::other("approval decision has no pending kernel action")
            })?;
            state.approval_notice_shown = false;
            let renderer = state.renderer.clone();
            let mut terminal = io::stdout().lock();
            resume_guest_screen(&mut terminal, forward)?;
            drop(state);
            set_approval_notice(renderer.as_ref(), false)?;
            let _ = pending.decide(GateDecision::Approve);
            Ok(true)
        }
        InputEvent::ApprovedGrant => {
            let pending = state
                .pending
                .take()
                .ok_or_else(|| io::Error::other("grant decision has no pending kernel action"))?;
            state.approval_notice_shown = false;
            let renderer = state.renderer.clone();
            let mut terminal = io::stdout().lock();
            resume_guest_screen(&mut terminal, forward)?;
            drop(state);
            set_approval_notice(renderer.as_ref(), false)?;
            let _ = pending.decide(GateDecision::ApproveGrant);
            Ok(true)
        }
        InputEvent::Denied => {
            let pending = state.pending.take().ok_or_else(|| {
                io::Error::other("approval decision has no pending kernel action")
            })?;
            state.approval_notice_shown = false;
            let renderer = state.renderer.clone();
            let mut terminal = io::stdout().lock();
            resume_guest_screen(&mut terminal, forward)?;
            drop(state);
            set_approval_notice(renderer.as_ref(), false)?;
            let _ = pending.decide(GateDecision::Deny);
            Ok(true)
        }
    }
}
struct TerminalMode(String);

impl TerminalMode {
    fn enter() -> Result<Self, Box<dyn Error>> {
        let saved = Command::new(STTY)
            .arg("-g")
            .env_clear()
            .stdin(Stdio::inherit())
            .output()?;
        if !saved.status.success() {
            return Err(format!(
                "cannot read terminal mode: {}",
                String::from_utf8_lossy(&saved.stderr)
            )
            .into());
        }
        let saved = String::from_utf8(saved.stdout)?.trim().to_owned();
        if !Command::new(STTY)
            .args(["raw", "-echo", "opost", "onlcr"])
            .env_clear()
            .status()?
            .success()
        {
            return Err("cannot enter raw terminal mode".into());
        }
        Ok(Self(saved))
    }
}
impl Drop for TerminalMode {
    fn drop(&mut self) {
        let mut terminal = io::stdout().lock();
        let _ = terminal.write_all(CANONICAL_TERMINAL_RESET);
        let _ = terminal.flush();
        drop(terminal);
        let _ = Command::new(STTY).arg(&self.0).env_clear().status();
    }
}
#[allow(clippy::too_many_lines)]
fn spawn_runtime(
    arguments: &[std::ffi::OsString],
    broker: &RuntimeBroker,
    isolation: &str,
) -> Result<(Child, PathBuf), Box<dyn Error>> {
    let runtime = bundled_component("keel-runtime", "KEEL_RUNTIME_BACKEND")?;
    let component_root = runtime
        .parent()
        .ok_or("runtime backend has no parent directory")?;
    let installation_root = component_root.parent().unwrap_or(component_root);
    let vz_backend = component_root.join("keel-vz-spike").canonicalize()?;
    let deno = component_root.join("deno").canonicalize()?;
    let sdk = component_root.join("keel-v8-sdk.ts").canonicalize()?;
    let git = trusted_git_toolchain()?;
    let kernel = component_root
        .join("../images/vmlinuz-virt")
        .canonicalize()?;
    let initramfs = component_root
        .join("../images/keel-phase1-initramfs.cpio.zst")
        .canonicalize()?;
    let rootfs = component_root
        .join("../images/keel-phase1-rootfs.squashfs")
        .canonicalize()?;
    let workspace = env::current_dir()?.canonicalize()?;
    let request = arguments
        .get(2)
        .map(PathBuf::from)
        .ok_or("runtime request path is missing")?
        .canonicalize()?;
    // macOS exposes temporary directories through symlinks such as `/tmp` and
    // `/var`. The sandbox compares the resolved vnode spelling, so the policy
    // and child environment must use that same canonical socket path.
    let broker_socket = broker.socket_path().canonicalize()?;
    let scratch = trusted_scratch("runtime")?;
    let allowed_child = if isolation == "v8-sandboxed" {
        &deno
    } else {
        &vz_backend
    };
    let v8_proxy_listener = (isolation == "v8-sandboxed")
        .then(|| TcpListener::bind((Ipv4Addr::LOCALHOST, 0)))
        .transpose()?;
    let v8_proxy_port = v8_proxy_listener
        .as_ref()
        .map(TcpListener::local_addr)
        .transpose()?
        .map(|address| address.port());
    let profile = runtime_sandbox_profile(
        [&runtime, allowed_child, &git.executable, &git.exec_root],
        &git.data_root,
        &workspace,
        installation_root,
        &request,
        &scratch,
        &broker_socket,
        v8_proxy_port,
    );
    let mut command = Command::new("/usr/bin/sandbox-exec");
    command
        .args(["-p", &profile])
        .arg(&runtime)
        .args(arguments)
        .env_clear()
        .env("PATH", git.search_path)
        .env("HOME", &scratch)
        .env("TMPDIR", &scratch)
        .env("KEEL_KERNEL_SOCKET", broker_socket)
        .env("KEEL_RUNTIME_SCRATCH", &scratch)
        .env("KEEL_VZ_BACKEND", &vz_backend)
        .env(
            "KEEL_GIT_UPLOAD_PACK",
            git.exec_root.join("git-upload-pack"),
        )
        .env("KEEL_GIT", git.executable)
        .env("KEEL_DENO", &deno)
        .env("KEEL_V8_SDK", &sdk)
        .env("KEEL_KERNEL", &kernel)
        .env("KEEL_INITRAMFS", &initramfs)
        .env("KEEL_ROOTFS", &rootfs)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    if let Some(port) = v8_proxy_port {
        command.env("KEEL_V8_PROXY_PORT", port.to_string());
    }
    // The run's admission manifest is durable before any workload process
    // exists; failing to record it refuses the run.
    let trusted_runtime = env::current_exe()?;
    let renderer = component_root.join("keel-xterm-renderer");
    let mut artifacts = vec![
        ("trusted_runtime", trusted_runtime.as_path()),
        ("runtime", runtime.as_path()),
        ("kernel", kernel.as_path()),
        ("initramfs", initramfs.as_path()),
        ("rootfs", rootfs.as_path()),
    ];
    if isolation == "v8-sandboxed" {
        artifacts.extend([("v8_runtime", deno.as_path()), ("v8_sdk", sdk.as_path())]);
    } else {
        artifacts.push(("vz_backend", vz_backend.as_path()));
    }
    if renderer.exists() {
        artifacts.push(("renderer", renderer.as_path()));
    }
    let release = fs::read_to_string(component_root.join("../images/kernel-release")).ok();
    broker.record_admission(&artifacts, release.as_deref().map(str::trim))?;
    if let Some((rows, columns)) = terminal_dimensions() {
        command
            .env("KEEL_TERMINAL_ROWS", rows.to_string())
            .env("KEEL_TERMINAL_COLUMNS", columns.to_string());
    }
    if let Some(certificate) = broker.ca_certificate_pem() {
        command.env("KEEL_RUN_CA_PEM", certificate);
    }
    if let Some(sentinel) = broker.git_sentinel() {
        command.env("KEEL_GIT_SENTINEL", sentinel);
    }
    if let Some(repository) = broker.github_private_repository() {
        command.env("KEEL_GITHUB_PRIVATE_REPOSITORY", repository);
    }
    // The untrusted runtime writes the guest's environment, so it is told which
    // provider was selected and which sentinel to hand over — both non-secret.
    // The credential itself was removed above and never leaves this process.
    let provider = keel_secrets::runtime_model_provider()?;
    command.env("KEEL_MODEL_SENTINEL", provider.sentinel);
    if provider.host == keel_secrets::OPENROUTER_HOST {
        command.env("KEEL_MODEL_PROVIDER", "openrouter");
    }
    if let Some(region) = provider.region {
        command.env("KEEL_MODEL_PROVIDER", "bedrock");
        command.env("KEEL_MODEL_REGION", region);
        // Claude Code must use the same authentication protocol as the trusted
        // side of the proxy.  In particular, presenting the public sentinel as
        // a Bedrock bearer token makes newer Claude Code releases select the
        // Bedrock control-plane endpoint.  SSO and environment credentials are
        // held by Keel's SigV4 signer instead, so give the guest dummy signing
        // material and replace its signature at the inspected boundary.
        command.env(
            "KEEL_MODEL_AUTH_MODE",
            if env::var_os("AWS_BEARER_TOKEN_BEDROCK").is_some() {
                "bearer"
            } else {
                "sigv4"
            },
        );
    }
    command.env("TERM", safe_term());
    // `TcpListener` is close-on-exec. `dup(2)` deliberately creates the one
    // inheritable copy that crosses sandbox-exec into keel-runtime; retain it
    // only for the synchronous spawn window and close both parent copies as
    // soon as spawn returns.
    let inherited_v8_proxy = v8_proxy_listener.as_ref().map(dup).transpose()?;
    if let Some(listener) = inherited_v8_proxy.as_ref() {
        command.env("KEEL_V8_PROXY_FD", listener.as_raw_fd().to_string());
    }
    match command.spawn() {
        Ok(child) => Ok((child, scratch)),
        Err(error) => {
            let _ = fs::remove_dir_all(&scratch);
            Err(error.into())
        }
    }
}

fn bundled_component(name: &str, development_override: &str) -> Result<PathBuf, Box<dyn Error>> {
    if cfg!(debug_assertions)
        && env::var_os("KEEL_UNSAFE_DEVELOPMENT_OVERRIDES").as_deref()
            == Some(std::ffi::OsStr::new("1"))
        && let Some(path) = env::var_os(development_override)
    {
        return Ok(PathBuf::from(path).canonicalize()?);
    }
    let path = env::current_exe()?.with_file_name(name).canonicalize()?;
    if !path.is_file() {
        return Err(format!("bundled component is missing: {}", path.display()).into());
    }
    Ok(path)
}

struct GitToolchain {
    executable: PathBuf,
    exec_root: PathBuf,
    data_root: PathBuf,
    search_path: std::ffi::OsString,
}

fn trusted_git_toolchain() -> Result<GitToolchain, Box<dyn Error>> {
    let platform_git = Path::new("/usr/bin/git").canonicalize()?;
    let output = Command::new(platform_git)
        .arg("--exec-path")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "cannot locate Git helpers: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )
        .into());
    }
    let exec_root =
        PathBuf::from(String::from_utf8(output.stdout)?.trim().to_owned()).canonicalize()?;
    // `/usr/bin/git` is an xcrun shim which consults `/var/select` every time
    // it starts. Resolve the selected developer-tools Git while still in the
    // trusted launcher so the runtime sandbox needs neither xcrun nor that
    // host-global configuration path.
    let executable = exec_root.join("../../bin/git").canonicalize()?;
    let data_root = exec_root.join("../../share/git-core").canonicalize()?;
    let search_path = env::join_paths([
        executable
            .parent()
            .ok_or("developer-tools Git has no parent")?,
        Path::new("/usr/bin"),
        Path::new("/bin"),
    ])?;
    Ok(GitToolchain {
        executable,
        exec_root,
        data_root,
        search_path,
    })
}

fn trusted_scratch(label: &str) -> Result<PathBuf, Box<dyn Error>> {
    for attempt in 0..32_u8 {
        let path = env::temp_dir().join(format!("keel-{label}-{}-{attempt}", std::process::id()));
        match fs::create_dir(&path) {
            Ok(()) => {
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
                // `/var` is a symlink to `/private/var` on macOS. Sandbox
                // profiles match the resolved vnode path, so both the policy
                // and the child environment must carry the canonical spelling.
                return Ok(path.canonicalize()?);
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
    }
    Err("cannot create a unique trusted runtime directory".into())
}

fn sb_string(path: &Path) -> String {
    path.to_string_lossy()
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
}

fn sb_ancestor_literals(path: &Path) -> String {
    path.ancestors()
        .skip(1)
        .filter(|ancestor| *ancestor != Path::new("/"))
        .map(|ancestor| format!("(literal \"{}\")", sb_string(ancestor)))
        .collect::<Vec<_>>()
        .join(" ")
}

#[allow(clippy::too_many_arguments)]
fn runtime_sandbox_profile(
    executables: [&Path; 4],
    git_data_root: &Path,
    workspace: &Path,
    components: &Path,
    request: &Path,
    scratch: &Path,
    broker: &Path,
    v8_proxy_port: Option<u16>,
) -> String {
    let [runtime, allowed_child, git, git_exec_root] = executables;
    let (tcp_outbound, tcp_inbound) = v8_proxy_port.map_or_else(
        || (
            "(deny network-outbound (remote ip))".to_owned(),
            "(deny network-inbound (local ip))".to_owned(),
        ),
        |port| {
            let endpoint = format!("localhost:{port}");
            (
                format!(
                    "(deny network-outbound (remote ip))\n(allow network-outbound (remote ip \"{endpoint}\"))"
                ),
                format!(
                    "(deny network-inbound (local ip))\n(allow network-inbound (local ip \"{endpoint}\"))\n(allow network-inbound (remote ip \"{endpoint}\"))"
                ),
            )
        },
    );
    format!(
        r#"(version 1)
(allow default)
(deny file-read* (require-not (require-any
  (literal "/") (literal "/var") (literal "/etc") (literal "/tmp")
  (subpath "{}") {}
  (subpath "{}") {}
  (literal "{}") (subpath "{}") {}
  (subpath "{}") (subpath "{}")
  (subpath "/System") (subpath "/usr/lib") (subpath "/usr/share")
  (subpath "/usr/bin") (subpath "/bin") (subpath "/sbin")
  (subpath "/dev") (subpath "/private/var/db")
  (subpath "/Library/Apple") (literal "/private/etc/localtime")
  (literal "/etc/gitconfig") (literal "/private/etc/gitconfig")
  (literal "/private/var/select") (literal "/private/var/select/sh"))))
(deny file-write* (require-not (require-any
  (subpath "{}") (subpath "{}") (literal "/dev/null"))))
(deny process-exec (require-not (require-any
  (literal "{}") (literal "{}") (literal "{}") (subpath "{}")
  (literal "/bin/sh") (literal "/bin/bash"))))
(deny network-outbound (remote unix-socket))
(allow network-outbound
  (remote unix-socket (path-literal "{}")))
{}
(deny network-bind (local ip))
{}
(deny mach-lookup
  (global-name "com.apple.SecurityServer")
  (global-name "com.apple.securityd")
  (global-name "com.apple.securityd.general")
  (global-name "com.apple.securityd.xpc"))"#,
        sb_string(workspace),
        sb_ancestor_literals(workspace),
        sb_string(components),
        sb_ancestor_literals(components),
        sb_string(request),
        sb_string(scratch),
        sb_ancestor_literals(scratch),
        sb_string(git_exec_root),
        sb_string(git_data_root),
        sb_string(workspace),
        sb_string(scratch),
        sb_string(runtime),
        sb_string(allowed_child),
        sb_string(git),
        sb_string(git_exec_root),
        sb_string(broker),
        tcp_outbound,
        tcp_inbound,
    )
}

fn renderer_sandbox_profile(renderer: &Path) -> String {
    let components = renderer
        .parent()
        .unwrap_or_else(|| Path::new("/nonexistent"));
    format!(
        r#"(version 1)
(allow default)
(deny network*)
(deny file-read* (require-not (require-any
  (literal "/") (literal "/var") (literal "/etc") (literal "/tmp")
  (subpath "{}") (subpath "/System") (subpath "/usr/lib")
  (subpath "/usr/share") (subpath "/usr/bin") (subpath "/bin")
  (subpath "/dev") (subpath "/private/var/db")
  (subpath "/Library/Apple") (literal "/private/etc/localtime"))))
(deny file-write*)
(deny process-fork)
(deny process-exec (require-not (literal "{}")))
(deny mach-lookup
  (global-name "com.apple.SecurityServer")
  (global-name "com.apple.securityd")
  (global-name "com.apple.securityd.general")
  (global-name "com.apple.securityd.xpc"))"#,
        sb_string(components),
        sb_string(renderer),
    )
}

fn safe_term() -> String {
    env::var("TERM")
        .ok()
        .filter(|term| {
            !term.is_empty()
                && term.len() <= 64
                && term
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        })
        .unwrap_or_else(|| "xterm-256color".to_owned())
}

fn input_source_is_trusted(source: Option<&std::ffi::OsStr>, terminal_owned: bool) -> bool {
    source == Some(std::ffi::OsStr::new("trusted-supervisor"))
        || (source == Some(std::ffi::OsStr::new("trusted-terminal")) && terminal_owned)
}

fn terminal_is_owned_by_this_process_group() -> bool {
    tcgetpgrp(io::stdin()).is_ok_and(|foreground| foreground == getpgrp())
}

fn host_v8_confirmation_matches(input: &str) -> bool {
    input.trim_end_matches(['\r', '\n']) == "HOST V8"
}

fn confirm_host_v8_admission(trusted_input: bool) -> Result<(), Box<dyn Error>> {
    if !trusted_input {
        return Err(
            "host V8 requires direct trusted-terminal admission; persistent attach is refused"
                .into(),
        );
    }
    let mut terminal = io::stdout().lock();
    terminal.write_all(
        b"\x1b[2J\x1b[HKEEL TRUSTED ADMISSION\r\n\r\nV8 will run in the lower-assurance host sandbox.\r\nType HOST V8 to continue: ",
    )?;
    terminal.flush()?;
    drop(terminal);
    let mut response = String::new();
    let mut input = io::stdin().lock();
    input.read_line(&mut response)?;
    if response.len() > 64 || !host_v8_confirmation_matches(&response) {
        return Err("host V8 admission denied".into());
    }
    Ok(())
}

fn confirm_task_admission(
    intent: &mut RuntimeIntent,
    trusted_input: bool,
) -> Result<(), Box<dyn Error>> {
    let Some(authority) = intent.task_admission() else {
        return Ok(());
    };
    if !trusted_input {
        return Err("task authority requires direct trusted-terminal admission".into());
    }
    print!(
        "\x1b[2J\x1b[HKEEL TASK ADMISSION\r\n\r\nRequested authority:\r\n  {authority}\r\n\r\nType APPROVE to admit this task: "
    );
    io::stdout().flush()?;
    let mut response = String::new();
    io::stdin().lock().read_line(&mut response)?;
    if response.len() > 64 || response.trim_end_matches(['\r', '\n']) != "APPROVE" {
        return Err("task admission denied".into());
    }
    intent.admit_task();
    Ok(())
}

fn terminal_dimensions() -> Option<(u16, u16)> {
    let output = Command::new(STTY)
        .arg("size")
        .env_clear()
        .stdin(Stdio::inherit())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let size = String::from_utf8(output.stdout).ok()?;
    let mut dimensions = size.split_whitespace();
    let rows = dimensions.next()?.parse::<u16>().ok()?;
    let columns = dimensions.next()?.parse::<u16>().ok()?;
    if rows == 0 || columns == 0 || dimensions.next().is_some() {
        return None;
    }
    Some((rows, columns))
}

/// Stops SIGWINCH from being delivered to a handler so it can be waited for.
///
/// This must run before any other thread or child exists, because both inherit
/// the mask and the waiting thread has to be the signal's only consumer. No
/// process in the runtime chain below this one handles SIGWINCH; each is either
/// a byte filter or the VM host, and this process alone owns the operator's tty.
fn block_resize_signal() -> Result<SigSet, Box<dyn Error>> {
    let mut winch = SigSet::empty();
    winch.add(Signal::SIGWINCH);
    winch.thread_block()?;
    Ok(winch)
}

/// Tells the guest this terminal's new size each time the operator resizes it.
///
/// The guest's pty is sized once from the environment when the VM boots, so
/// without this it keeps painting to the geometry the session started with.
fn renderer_resize(renderer: &RendererControl, rows: u16, columns: u16) -> io::Result<()> {
    let mut message = [0_u8; 5];
    message[0] = RENDER_RESIZE;
    message[1..3].copy_from_slice(&rows.to_be_bytes());
    message[3..5].copy_from_slice(&columns.to_be_bytes());
    renderer_message(renderer, &message)
}

fn spawn_resize_forwarder(
    winch: SigSet,
    guest_input: Arc<Mutex<ChildStdin>>,
    renderer: RendererControl,
) {
    thread::spawn(move || {
        if let Some((rows, columns)) = terminal_dimensions()
            && let Ok(mut guest) = guest_input.lock()
        {
            let _ = guest
                .write_all(&encode_resize(rows, columns))
                .and_then(|()| guest.flush());
            let _ = renderer_resize(&renderer, rows, columns);
        }
        while winch.wait().is_ok() {
            let Some((rows, columns)) = terminal_dimensions() else {
                continue;
            };
            let Ok(mut guest) = guest_input.lock() else {
                return;
            };
            if guest
                .write_all(&encode_resize(rows, columns))
                .and_then(|()| guest.flush())
                .is_err()
            {
                return;
            }
            if renderer_resize(&renderer, rows, columns).is_err() {
                return;
            }
        }
    });
}

#[allow(clippy::too_many_lines)]
fn main() -> Result<(), Box<dyn Error>> {
    let arguments = env::args_os().skip(1).collect::<Vec<_>>();
    match arguments.first().and_then(|argument| argument.to_str()) {
        Some("serve") => return session::serve(&arguments),
        Some("attach") => return session::attach(&arguments),
        Some("stop") => return session::stop(&arguments),
        Some("lift") => return session::lift(&arguments),
        Some("launcher") => return session::launcher(&arguments),
        _ => {}
    }
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() || !io::stderr().is_terminal() {
        return Err("keel-input-runtime requires exclusive terminal stdio".into());
    }
    let winch = block_resize_signal()?;
    let mut intent = RuntimeIntent::from_runtime_arguments(&arguments)?;
    let isolation = intent.isolation().to_owned();
    let input_source = env::var_os("KEEL_INPUT_SOURCE");
    let trusted_approval_input = input_source_is_trusted(
        input_source.as_deref(),
        terminal_is_owned_by_this_process_group(),
    );
    if isolation == "v8-sandboxed" {
        confirm_host_v8_admission(trusted_approval_input)?;
    }
    confirm_task_admission(&mut intent, trusted_approval_input)?;
    let (gate, controller) = terminal_gate_channel();
    let broker = intent.start_kernel_broker_with_gate(gate)?;
    let floor_control = broker.control();
    let (floor_lifts, floor_lift_requests) = mpsc::sync_channel(1);
    let floor_lift_stop = Arc::new(AtomicBool::new(false));
    let worker_stop = Arc::clone(&floor_lift_stop);
    let floor_lift_worker = thread::spawn(move || {
        while !worker_stop.load(Ordering::Acquire) {
            match floor_lift_requests.recv_timeout(Duration::from_millis(50)) {
                Ok(rank) => {
                    if let Err(error) = floor_control.lift_floor(rank) {
                        eprintln!("keel: floor lift failed: {error}");
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
    });
    let audit_path = broker.audit_path().to_path_buf();
    let audit_key_path = broker.audit_key_path().to_path_buf();
    let terminal_mode = TerminalMode::enter()?;
    let interactive = Arc::new(Mutex::new(InteractiveState {
        input: InputGate::new(),
        pending: None,
        trusted_approval_input,
        shutting_down: false,
        approval_notice_shown: false,
        renderer: None,
    }));
    let gate_thread = spawn_gate_receiver(controller, Arc::clone(&interactive));
    let renderer = bundled_component("keel-xterm-renderer", "KEEL_XTERM_RENDERER")?;
    let renderer_profile = renderer_sandbox_profile(&renderer);
    let renderer_directory = renderer
        .parent()
        .ok_or("renderer has no containing directory")?;
    let (mut child, runtime_scratch) = spawn_runtime(&arguments, &broker, &isolation)?;
    let runtime_group = Pid::from_raw(child.id().cast_signed());
    let shutdown_requested = Arc::new(AtomicBool::new(false));
    let mut child_output = child.stdout.take().ok_or("runtime stdout unavailable")?;
    let (rows, columns) = terminal_dimensions().unwrap_or((24, 80));
    let mut renderer_command = Command::new("/usr/bin/sandbox-exec");
    renderer_command
        .args(["-p", &renderer_profile])
        .arg(&renderer)
        .args(["--canonical", &rows.to_string(), &columns.to_string()])
        // A Deno standalone executable resolves its current directory during
        // startup. Keep that lookup inside the renderer's existing read-only
        // allowlist instead of granting it access to the untrusted workspace.
        .current_dir(renderer_directory)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("TERM", safe_term())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut renderer = renderer_command.spawn()?;
    let renderer_control = Arc::new(Mutex::new(
        renderer.stdin.take().ok_or("renderer stdin unavailable")?,
    ));
    lock_state(&interactive)?.renderer = Some(Arc::clone(&renderer_control));
    let renderer_feed = Arc::clone(&renderer_control);
    let feed_thread = thread::spawn(move || -> io::Result<()> {
        let mut guest = [0_u8; 16 * 1024];
        loop {
            let count = child_output.read(&mut guest)?;
            if count == 0 {
                return renderer_message(&renderer_feed, &[RENDER_FINISH]);
            }
            let mut message = Vec::with_capacity(count + 5);
            message.push(RENDER_GUEST);
            message.extend_from_slice(
                &u32::try_from(count)
                    .map_err(|_| io::Error::other("guest display frame is too large"))?
                    .to_be_bytes(),
            );
            message.extend_from_slice(&guest[..count]);
            renderer_message(&renderer_feed, &message)?;
        }
    });
    let mut display = renderer
        .stdout
        .take()
        .ok_or("renderer stdout unavailable")?;
    let guest_input = Arc::new(Mutex::new(
        child.stdin.take().ok_or("runtime stdin unavailable")?,
    ));
    let renderer_guest_input = Arc::clone(&guest_input);
    let runtime_errors = child.stderr.take().ok_or("runtime stderr unavailable")?;
    let output_state = Arc::clone(&interactive);
    let output_thread = thread::spawn(move || -> io::Result<()> {
        let mut first_frame = true;
        loop {
            let mut tag = [0_u8; 1];
            match display.read_exact(&mut tag) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
                Err(error) => return Err(error),
            }
            let mut encoded_length = [0_u8; 4];
            display.read_exact(&mut encoded_length)?;
            let length = usize::try_from(u32::from_be_bytes(encoded_length))
                .map_err(|_| io::Error::other("display snapshot length does not fit usize"))?;
            let limit = match tag[0] {
                DISPLAY_SNAPSHOT => MAX_DISPLAY_SNAPSHOT,
                DISPLAY_GUEST_INPUT => MAX_DISPLAY_GUEST_INPUT,
                _ => return Err(io::Error::other("unknown renderer output frame")),
            };
            if length > limit {
                return Err(io::Error::other("renderer output exceeds trusted limit"));
            }
            let mut frame = vec![0_u8; length];
            display.read_exact(&mut frame)?;
            if tag[0] == DISPLAY_GUEST_INPUT {
                let mut guest = renderer_guest_input
                    .lock()
                    .map_err(|_| io::Error::other("guest input is unavailable"))?;
                forward_renderer_reply(&mut *guest, &frame)?;
                continue;
            }
            let mut state = lock_state(&output_state)?;
            if state.input.in_trusted_mode() {
                continue;
            }
            let mut terminal = io::stdout().lock();
            if first_frame {
                // The guest's kernel log and Keel's own startup output have
                // already scrolled this screen, and the guest paints its
                // first frame from wherever the cursor is left. Homing the
                // cursor once makes the guest's origin the screen's origin;
                // without it the whole guest screen sits however many rows
                // down the preamble happened to reach, for the whole run.
                terminal.write_all(b"\x1b[2J\x1b[H")?;
                first_frame = false;
            }
            terminal.write_all(&frame)?;
            if state.input.has_pending() && !state.approval_notice_shown {
                terminal.write_all(APPROVAL_TITLE_NOTICE)?;
                state.approval_notice_shown = true;
            }
            terminal.flush()?;
        }
    });
    let error_thread = thread::spawn(move || -> io::Result<Vec<u8>> {
        let mut errors = Vec::new();
        io::BufReader::new(runtime_errors).read_to_end(&mut errors)?;
        Ok(errors)
    });
    spawn_resize_forwarder(
        winch,
        Arc::clone(&guest_input),
        Arc::clone(&renderer_control),
    );
    let input_state = Arc::clone(&interactive);
    let input_renderer = Arc::clone(&renderer_control);
    let input_shutdown = Arc::clone(&shutdown_requested);
    let _input_thread = thread::spawn(move || -> io::Result<()> {
        let mut input = io::stdin().lock();
        let mut bytes = [0_u8; 256];
        // Escape sequences must reach the guest terminal in the same read the
        // operator's terminal produced them in. Route every byte of one read
        // through the gate, then forward the surviving bytes in one write.
        let mut forward = Vec::with_capacity(bytes.len());
        let mut keystrokes = Vec::with_capacity(bytes.len());
        let mut reader = TerminalControlReader::new();
        loop {
            let count = input.read(&mut bytes)?;
            if count == 0 {
                return Ok(());
            }
            // A persistent session's attach client reports its terminal size
            // down this same stream. A directly attached terminal sends no
            // control messages and reaches the guest through SIGWINCH instead.
            keystrokes.clear();
            let controls = reader.split(&bytes[..count], &mut keystrokes);
            forward.clear();
            for byte in &keystrokes {
                if route_input(&input_state, *byte, &mut forward)? {
                    break;
                }
            }
            for control in controls {
                match control {
                    TerminalControl::Redraw => {
                        renderer_message(&input_renderer, &[RENDER_REPAINT])?;
                    }
                    TerminalControl::Resize { rows, columns } => {
                        forward.extend_from_slice(&encode_resize(rows, columns));
                        renderer_resize(&input_renderer, rows, columns)?;
                    }
                    TerminalControl::FloorLift(rank) => {
                        let _ = floor_lifts.try_send(rank);
                    }
                    TerminalControl::Shutdown => {
                        input_shutdown.store(true, Ordering::Release);
                        let _ = killpg(runtime_group, Signal::SIGTERM);
                    }
                }
            }
            if !forward.is_empty() {
                let mut guest = guest_input
                    .lock()
                    .map_err(|_| io::Error::other("guest input is unavailable"))?;
                guest.write_all(&forward)?;
                guest.flush()?;
            }
        }
    });
    let status = child.wait()?;
    feed_thread
        .join()
        .map_err(|_| "renderer feed thread panicked")?
        .map_err(|error| format!("send guest output to terminal renderer: {error}"))?;
    let scratch_cleanup = fs::remove_dir_all(&runtime_scratch);
    begin_shutdown(&interactive)?;
    let renderer_status = renderer.wait()?;
    output_thread
        .join()
        .map_err(|_| "display thread panicked")?
        .map_err(|error| format!("write rendered terminal output: {error}"))?;
    let runtime_errors = error_thread.join().map_err(|_| "error thread panicked")??;
    let orderly_shutdown = shutdown_requested.load(Ordering::Acquire);
    if !status.success() && !orderly_shutdown && !runtime_errors.is_empty() {
        writeln!(io::stderr(), "\r\n{}", safe_text(&runtime_errors))?;
    }
    floor_lift_stop.store(true, Ordering::Release);
    floor_lift_worker
        .join()
        .map_err(|_| "floor lift worker panicked")?;
    let _broker_report = broker.shutdown()?;
    gate_thread
        .join()
        .map_err(|_| "gate receiver thread panicked")??;
    drop(terminal_mode);
    report_audit_paths(&audit_path, &audit_key_path);
    if !status.success() && !orderly_shutdown {
        return Err(format!("runtime exited with {status}").into());
    }
    scratch_cleanup?;
    if !renderer_status.success() {
        return Err(format!("renderer exited with {renderer_status}").into());
    }
    Ok(())
}
fn report_audit_paths(audit: &Path, key: &Path) {
    eprintln!(
        "Keel audit: {}\nKeel audit key: {}",
        safe_text(audit.to_string_lossy().as_bytes()),
        safe_text(key.to_string_lossy().as_bytes())
    );
}

#[cfg(test)]
#[path = "../../tests/support/runtime_security.rs"]
mod security_tests;
