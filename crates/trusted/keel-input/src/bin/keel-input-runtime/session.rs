use super::CANONICAL_TERMINAL_RESET;
use keel_input::{
    MuxCommandEvent, MuxCommandInput, TERMINAL_CONTROL, TERMINAL_CONTROL_REDRAW, TerminalControl,
    TerminalControlReader, detached_output_has_pending_approval, encode_floor_lift, encode_resize,
    encode_shutdown, push_keystroke, safe_text,
};
#[cfg(target_os = "macos")]
use nix::sys::socket::{getsockopt, sockopt};
use nix::{
    fcntl::{FcntlArg, OFlag, fcntl},
    libc,
    poll::{PollFd, PollFlags, poll},
    pty::{Winsize, openpty},
    sys::signal::{SigSet, Signal, killpg},
    sys::termios::{InputFlags, LocalFlags, OutputFlags, SetArg, cfmakeraw, tcgetattr, tcsetattr},
    unistd::Pid,
};
use std::{
    env,
    error::Error,
    fs::{self, File},
    io::{self, IsTerminal as _, Read as _, Write as _},
    os::{
        fd::{AsFd as _, OwnedFd},
        unix::{
            fs::PermissionsExt as _,
            net::{UnixListener, UnixStream},
            process::{CommandExt as _, ExitStatusExt as _},
        },
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU8, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

const REDRAW: &[u8] = &[TERMINAL_CONTROL, TERMINAL_CONTROL_REDRAW];
const STTY: &str = "/bin/stty";
const MAX_DETACHED_OUTPUT: usize = 256 * 1024;
const COMPLETED_ATTACH_GRACE: Duration = Duration::from_secs(5);
const GRACEFUL_STOP_TIMEOUT: Duration = Duration::from_secs(5);
const STOP_COMPLETION_TIMEOUT: Duration = Duration::from_secs(8);

struct Cleanup {
    socket: PathBuf,
    pid: PathBuf,
    request: PathBuf,
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.socket);
        let _ = fs::remove_file(&self.pid);
        let _ = fs::remove_file(&self.request);
    }
}

struct ChildGroup {
    child: Child,
    armed: bool,
}

impl ChildGroup {
    fn terminate(&mut self) {
        let pid = Pid::from_raw(self.child.id().cast_signed());
        let _ = killpg(pid, Signal::SIGTERM);
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            if self.child.try_wait().ok().flatten().is_some() {
                self.armed = false;
                return;
            }
            thread::sleep(Duration::from_millis(20));
        }
        let _ = killpg(pid, Signal::SIGKILL);
        let _ = self.child.wait();
        self.armed = false;
    }
}

impl Drop for ChildGroup {
    fn drop(&mut self) {
        if self.armed {
            self.terminate();
        }
    }
}

struct AttachTerminalMode(String);

impl AttachTerminalMode {
    fn enter() -> Result<Self, Box<dyn Error>> {
        let saved = Command::new(STTY)
            .arg("-g")
            .env_clear()
            .stdin(Stdio::inherit())
            .output()?;
        if !saved.status.success() {
            return Err("cannot read terminal mode".into());
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

impl Drop for AttachTerminalMode {
    fn drop(&mut self) {
        let mut terminal = io::stdout().lock();
        let _ = terminal.write_all(CANONICAL_TERMINAL_RESET);
        let _ = terminal.flush();
        drop(terminal);
        let _ = Command::new(STTY).arg(&self.0).env_clear().status();
    }
}

/// Reads the size of this process's controlling terminal.
fn terminal_size() -> Option<(u16, u16)> {
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
    let mut fields = size.split_whitespace();
    let rows = fields.next()?.parse::<u16>().ok()?;
    let columns = fields.next()?.parse::<u16>().ok()?;
    (rows > 0 && columns > 0 && fields.next().is_none()).then_some((rows, columns))
}

/// Tells the session this terminal's size now and whenever the operator resizes.
///
/// The guest's pty is sized once at boot from the terminal that started the
/// session. An operator who attaches from a different window, or who resizes
/// this one, would otherwise leave the guest painting to the old geometry.
fn spawn_resize_reporter(mut stream: UnixStream) -> io::Result<()> {
    let mut winch = SigSet::empty();
    winch.add(Signal::SIGWINCH);
    // Blocking the signal in this thread before any other is spawned is what
    // makes `wait` the only consumer of it.
    winch.thread_block().map_err(io::Error::other)?;
    if let Some((rows, columns)) = terminal_size()
        && let Err(error) = stream
            .write_all(&encode_resize(rows, columns))
            .and_then(|()| stream.flush())
    {
        // A short-lived V8 job can finish after the attach handshake but
        // before this advisory resize. Its buffered result is still
        // readable, so do not replace that result with EPIPE.
        return if matches!(
            error.kind(),
            io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset
        ) {
            Ok(())
        } else {
            Err(error)
        };
    }
    thread::spawn(move || {
        while winch.wait().is_ok() {
            let Some((rows, columns)) = terminal_size() else {
                continue;
            };
            if stream
                .write_all(&encode_resize(rows, columns))
                .and_then(|()| stream.flush())
                .is_err()
            {
                return;
            }
        }
    });
    Ok(())
}

fn dimensions() -> Winsize {
    let parse = |name: &str, default| {
        env::var(name)
            .ok()
            .and_then(|value| value.parse::<u16>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(default)
    };
    Winsize {
        ws_row: parse("KEEL_TERMINAL_ROWS", 24),
        ws_col: parse("KEEL_TERMINAL_COLUMNS", 80),
        ws_xpixel: 0,
        ws_ypixel: 0,
    }
}

fn prepare_slave_terminal(slave: &OwnedFd) -> io::Result<()> {
    let mut attributes = tcgetattr(slave).map_err(io::Error::other)?;
    cfmakeraw(&mut attributes);
    // The runtime's admission prompts still use line input before it takes raw
    // tty ownership. Make Return a newline and let the pty echo that short
    // trusted exchange; `TerminalMode::enter` disables both afterwards.
    attributes.input_flags.insert(InputFlags::ICRNL);
    attributes.local_flags.insert(LocalFlags::ECHO);
    attributes
        .output_flags
        .insert(OutputFlags::OPOST | OutputFlags::ONLCR);
    tcsetattr(slave, SetArg::TCSANOW, &attributes).map_err(io::Error::other)
}

fn resize_slave_terminal(terminal: &File, rows: u16, columns: u16) -> io::Result<()> {
    let status = Command::new(STTY)
        .args(["rows", &rows.to_string(), "cols", &columns.to_string()])
        .env_clear()
        .stdin(Stdio::from(terminal.try_clone()?))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    status
        .success()
        .then_some(())
        .ok_or_else(|| io::Error::other("cannot resize persistent session pty"))
}

fn parse_serve(arguments: &[std::ffi::OsString]) -> Result<(PathBuf, PathBuf), Box<dyn Error>> {
    let [serve, request_flag, request, socket_flag, socket] = arguments else {
        return Err(
            "usage: keel-input-runtime serve --request REQUEST.json --socket ATTACH.sock".into(),
        );
    };
    if serve != "serve" || request_flag != "--request" || socket_flag != "--socket" {
        return Err(
            "usage: keel-input-runtime serve --request REQUEST.json --socket ATTACH.sock".into(),
        );
    }
    Ok((PathBuf::from(request), PathBuf::from(socket)))
}

fn parse_socket(
    arguments: &[std::ffi::OsString],
    operation: &str,
) -> Result<PathBuf, Box<dyn Error>> {
    let [actual, socket_flag, socket] = arguments else {
        return Err(format!("usage: keel-input-runtime {operation} --socket ATTACH.sock").into());
    };
    if actual != operation || socket_flag != "--socket" {
        return Err(format!("usage: keel-input-runtime {operation} --socket ATTACH.sock").into());
    }
    Ok(PathBuf::from(socket))
}

fn prepare_socket(path: &Path) -> io::Result<UnixListener> {
    if path.exists() {
        if UnixStream::connect(path).is_ok() {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "a persistent Keel session is already running",
            ));
        }
        fs::remove_file(path)?;
    }
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("attach socket has no parent directory"))?;
    fs::create_dir_all(parent)?;
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
    let listener = UnixListener::bind(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    listener.set_nonblocking(true)?;
    Ok(listener)
}

fn exit_status_path(socket: &Path) -> PathBuf {
    socket.with_extension("exit")
}

fn persist_exit_status(path: &Path, status: std::process::ExitStatus) -> io::Result<()> {
    let code = status
        .code()
        .or_else(|| status.signal().map(|signal| 128 + signal))
        .unwrap_or(1);
    fs::write(path, format!("{code}\n"))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

fn completed_exit_status(path: &Path) -> io::Result<Option<i32>> {
    match fs::read_to_string(path) {
        Ok(value) => {
            value.trim().parse::<i32>().map(Some).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid session exit status")
            })
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn spawn_foreground(request: &Path, slave: OwnedFd) -> Result<ChildGroup, Box<dyn Error>> {
    let input = File::from(slave.try_clone()?);
    let output = File::from(slave.try_clone()?);
    let errors = File::from(slave);
    let mut command = Command::new(env::current_exe()?);
    command
        .arg("run")
        .arg("--request")
        .arg(request)
        .env("KEEL_INPUT_SOURCE", "trusted-supervisor")
        .stdin(Stdio::from(input))
        .stdout(Stdio::from(output))
        .stderr(Stdio::from(errors))
        .process_group(0);
    Ok(ChildGroup {
        child: command.spawn()?,
        armed: true,
    })
}

#[cfg_attr(not(target_os = "macos"), allow(unused_variables))]
fn peer_terminal_is_foreground(stream: &UnixStream) -> bool {
    #[cfg(target_os = "macos")]
    {
        let Some(pid) = getsockopt(stream, sockopt::LocalPeerPid).ok() else {
            return false;
        };
        let Some(output) = Command::new("/bin/ps")
            .args(["-o", "pgid=,tpgid=", "-p", &pid.to_string()])
            .env_clear()
            .output()
            .ok()
            .and_then(|output| String::from_utf8(output.stdout).ok())
        else {
            return false;
        };
        let mut groups = output.split_whitespace();
        matches!((groups.next(), groups.next(), groups.next()),
            (Some(group), Some(foreground), None) if group != "0" && group == foreground)
    }
    #[cfg(not(target_os = "macos"))]
    false
}

fn read_command(stream: &mut UnixStream) -> io::Result<String> {
    stream.set_read_timeout(Some(Duration::from_secs(1)))?;
    let mut command = Vec::new();
    let mut byte = [0_u8; 1];
    while command.len() < 64 {
        stream.read_exact(&mut byte)?;
        if byte[0] == b'\n' {
            return String::from_utf8(command)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid command"));
        }
        command.push(byte[0]);
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "session command is too long",
    ))
}

fn accept_clients(
    listener: &UnixListener,
    terminal: &mut File,
    attached: &mut Option<UnixStream>,
    attached_once: &mut bool,
    detached_output: &mut Vec<u8>,
) -> io::Result<bool> {
    loop {
        let (stream, _) = match listener.accept() {
            Ok(connection) => connection,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(false),
            Err(error) => return Err(error),
        };
        // One misbehaving or vanishing client must never end the session, so
        // every client failure is reported and dropped instead of returned.
        match serve_client(stream, terminal, attached, attached_once, detached_output) {
            Ok(true) => return Ok(true),
            Ok(false) => {}
            Err(error) => eprintln!("keel: attach client failed: {error}"),
        }
    }
}

fn serve_client(
    mut stream: UnixStream,
    terminal: &mut File,
    attached: &mut Option<UnixStream>,
    attached_once: &mut bool,
    detached_output: &mut Vec<u8>,
) -> io::Result<bool> {
    // Sockets accepted from a non-blocking listener inherit O_NONBLOCK on
    // macOS. The client protocol is blocking with explicit timeouts, so the
    // flag is cleared before the handshake reads or the replay writes.
    stream.set_nonblocking(false)?;
    match read_command(&mut stream)?.as_str() {
        "ATTACH" if attached.is_none() => {
            if !peer_terminal_is_foreground(&stream) {
                stream.write_all(b"UNTRUSTED\n")?;
                return Ok(false);
            }
            stream.write_all(if *attached_once {
                b"OK RESUME\n"
            } else {
                b"OK FIRST\n"
            })?;
            stream.write_all(detached_output)?;
            stream.flush()?;
            detached_output.clear();
            stream.set_read_timeout(Some(Duration::from_millis(5)))?;
            stream.set_write_timeout(Some(Duration::from_secs(5)))?;
            *attached = Some(stream);
            *attached_once = true;
        }
        "ATTACH" => stream.write_all(b"BUSY\n")?,
        "STATUS" => stream.write_all(if attached.is_some() {
            b"ACTIVE\n"
        } else if detached_output_has_pending_approval(detached_output) {
            b"PENDING\n"
        } else {
            b"IDLE\n"
        })?,
        "STOP" => {
            terminal.write_all(&encode_shutdown())?;
            terminal.flush()?;
            stream.write_all(b"STOPPING\n")?;
            return Ok(true);
        }
        command if command.starts_with("LIFT ") => {
            let rank = command[5..].parse::<u8>().ok().filter(|rank| *rank <= 3);
            if !peer_terminal_is_foreground(&stream) {
                stream.write_all(b"UNTRUSTED\n")?;
            } else if attached.is_none() {
                stream.write_all(b"DETACHED\n")?;
            } else if let Some(rank) = rank {
                terminal.write_all(&encode_floor_lift(rank))?;
                stream.write_all(b"PENDING\n")?;
            } else {
                stream.write_all(b"ERROR\n")?;
            }
        }
        _ => stream.write_all(b"ERROR\n")?,
    }
    Ok(false)
}

fn remember_detached_output(output: &mut Vec<u8>, bytes: &[u8]) {
    if bytes.len() >= MAX_DETACHED_OUTPUT {
        output.clear();
        output.extend_from_slice(&bytes[bytes.len() - MAX_DETACHED_OUTPUT..]);
        return;
    }
    let overflow = output
        .len()
        .saturating_add(bytes.len())
        .saturating_sub(MAX_DETACHED_OUTPUT);
    if overflow > 0 {
        output.drain(..overflow);
    }
    output.extend_from_slice(bytes);
}

fn drain_terminal(
    terminal: &mut File,
    attached: &mut Option<UnixStream>,
    detached_output: &mut Vec<u8>,
) -> io::Result<()> {
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        match terminal.read(&mut buffer) {
            Ok(0) => return Ok(()),
            Ok(count) => {
                if let Some(stream) = attached.as_mut() {
                    if stream.write_all(&buffer[..count]).is_err() {
                        *attached = None;
                        remember_detached_output(detached_output, &buffer[..count]);
                    }
                } else {
                    remember_detached_output(detached_output, &buffer[..count]);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(error) if error.raw_os_error() == Some(libc::EIO) => return Ok(()),
            Err(error) => return Err(error),
        }
    }
}

fn forward_input(
    terminal: &mut File,
    attached: &mut Option<UnixStream>,
    input: &mut TerminalControlReader,
    child_group: Pid,
) -> io::Result<()> {
    let Some(stream) = attached.as_mut() else {
        return Ok(());
    };
    let mut buffer = [0_u8; 4096];
    let count = match stream.read(&mut buffer) {
        Ok(0) => {
            *attached = None;
            return Ok(());
        }
        Ok(count) => count,
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ) =>
        {
            return Ok(());
        }
        Err(_) => {
            *attached = None;
            return Ok(());
        }
    };
    let mut keystrokes = Vec::with_capacity(count);
    let controls = input.split(&buffer[..count], &mut keystrokes);
    if !keystrokes.is_empty() {
        terminal.write_all(&keystrokes)?;
    }
    for control in controls {
        match control {
            // Preserve the redraw control for the trusted terminal owner on
            // the far side of this pty. It converts the request into the guest
            // tmux refresh binding, which can reconstruct a newly attached
            // terminal from retained screen state.
            TerminalControl::Redraw => terminal.write_all(REDRAW)?,
            TerminalControl::Resize { rows, columns } => {
                resize_slave_terminal(terminal, rows, columns)?;
                let _ = killpg(child_group, Signal::SIGWINCH);
            }
            TerminalControl::FloorLift(rank) => terminal.write_all(&encode_floor_lift(rank))?,
            TerminalControl::Shutdown => terminal.write_all(&encode_shutdown())?,
        }
    }
    Ok(())
}

pub(super) fn serve(arguments: &[std::ffi::OsString]) -> Result<(), Box<dyn Error>> {
    let (request, socket) = parse_serve(arguments)?;
    let exit_path = exit_status_path(&socket);
    match fs::remove_file(&exit_path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let listener = prepare_socket(&socket)?;
    let pid_path = socket.with_extension("pid");
    fs::write(&pid_path, format!("{}\n", std::process::id()))?;
    fs::set_permissions(&pid_path, fs::Permissions::from_mode(0o600))?;
    let _cleanup = Cleanup {
        socket,
        pid: pid_path,
        request: request.clone(),
    };

    let pty = openpty(Some(&dimensions()), None)?;
    prepare_slave_terminal(&pty.slave)?;
    fcntl(&pty.master, FcntlArg::F_SETFL(OFlag::O_NONBLOCK))?;
    let mut terminal = File::from(pty.master);
    let mut child = spawn_foreground(&request, pty.slave)?;
    let mut attached = None;
    let mut attached_once = false;
    let mut detached_output = Vec::new();
    let mut attach_input = TerminalControlReader::new();
    let mut stop_deadline = None;

    loop {
        if stop_deadline.is_none()
            && accept_clients(
                &listener,
                &mut terminal,
                &mut attached,
                &mut attached_once,
                &mut detached_output,
            )?
        {
            stop_deadline = Some(Instant::now() + GRACEFUL_STOP_TIMEOUT);
        }
        drain_terminal(&mut terminal, &mut attached, &mut detached_output)?;
        forward_input(
            &mut terminal,
            &mut attached,
            &mut attach_input,
            Pid::from_raw(child.child.id().cast_signed()),
        )?;
        if let Some(status) = child.child.try_wait()? {
            child.armed = false;
            drain_terminal(&mut terminal, &mut attached, &mut detached_output)?;
            persist_exit_status(&exit_path, status)?;
            if attached.is_none() && !attached_once && stop_deadline.is_none() {
                let deadline = Instant::now() + COMPLETED_ATTACH_GRACE;
                while Instant::now() < deadline && attached.is_none() {
                    let _ = accept_clients(
                        &listener,
                        &mut terminal,
                        &mut attached,
                        &mut attached_once,
                        &mut detached_output,
                    )?;
                    thread::sleep(Duration::from_millis(5));
                }
            }
            return if status.success() {
                Ok(())
            } else {
                Err(format!("persistent runtime exited with {status}").into())
            };
        }
        if stop_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            child.terminate();
            return Err("graceful session stop timed out; process group was terminated".into());
        }
        thread::sleep(Duration::from_millis(5));
    }
}

/// Requests a floor lift from the live session; approval remains on its trusted terminal.
pub(super) fn lift(arguments: &[std::ffi::OsString]) -> Result<(), Box<dyn Error>> {
    let [lift, rank, socket_flag, socket] = arguments else {
        return Err("usage: keel-input-runtime lift RANK --socket ATTACH.sock".into());
    };
    if lift != "lift" || socket_flag != "--socket" {
        return Err("usage: keel-input-runtime lift RANK --socket ATTACH.sock".into());
    }
    let rank = rank
        .to_str()
        .and_then(|rank| rank.parse::<u8>().ok())
        .filter(|rank| (1..=3).contains(rank))
        .ok_or("floor lift rank must be one through three")?;
    if !io::stdin().is_terminal() {
        return Err("requesting a floor lift requires a foreground terminal".into());
    }
    let mut stream = UnixStream::connect(Path::new(socket))?;
    let response = handshake(&mut stream, format!("LIFT {rank}\n").as_bytes())?;
    match response.as_str() {
        "PENDING" => {
            println!("Floor lift requested; approve it in the attached Keel session.");
            Ok(())
        }
        "DETACHED" => Err(
            "session is detached; attach it and use Ctrl-A /floor-lift before requesting a lift"
                .into(),
        ),
        "UNTRUSTED" => Err("floor lift request did not come from a foreground terminal".into()),
        _ => Err(format!("session refused floor lift: {response}").into()),
    }
}

fn handshake(stream: &mut UnixStream, command: &[u8]) -> io::Result<String> {
    stream.write_all(command)?;
    read_command(stream)
}

fn paint_command_mode(command: &[u8], output: &Arc<Mutex<()>>) -> io::Result<()> {
    let (rows, columns) = terminal_size().unwrap_or((24, 80));
    let width = usize::from(columns.saturating_sub(4));
    let visible = &command[command.len().saturating_sub(width)..];
    let _guard = output
        .lock()
        .map_err(|_| io::Error::other("mux display lock is unavailable"))?;
    let mut terminal = io::stdout().lock();
    write!(
        terminal,
        "\x1b7\x1b[?6l\x1b[{};1H\x1b[0m\x1b[2K  \x1b[7m CMD \x1b[0m  \
         /approve /floor-lift /new /tab /close /resume /detach /redraw  \x1b[2mCtrl-A or Esc returns to PTY\x1b[0m\
         \x1b[{};1H\x1b[2K> {} \x1b[7m \x1b[0m\x1b[?6h\x1b8",
        rows.saturating_sub(1),
        rows,
        String::from_utf8_lossy(visible)
    )?;
    terminal.flush()
}

fn launcher_sandbox_profile(
    renderer: &Path,
    start: &Path,
    workspace_root: &Path,
    result: &Path,
) -> String {
    let renderer_root = renderer
        .parent()
        .unwrap_or_else(|| Path::new("/nonexistent"));
    format!(
        r#"(version 1)
(allow default)
(deny network*)
(deny file-read* (require-not (require-any
  (literal "/") (literal "/var") (literal "/etc") (literal "/tmp")
  (subpath "{}") (subpath "{}") (subpath "{}")
  (subpath "/System") (subpath "/usr/lib")
  (subpath "/usr/share") (subpath "/usr/bin") (subpath "/bin")
  (subpath "/dev") (subpath "/private/var/db")
  (subpath "/Library/Apple") (literal "/private/etc/localtime"))))
(deny file-write* (require-not (literal "{}")))
(deny process-exec (require-not (literal "{}")))
(deny mach-lookup
  (global-name "com.apple.SecurityServer")
  (global-name "com.apple.securityd")
  (global-name "com.apple.securityd.general")
  (global-name "com.apple.securityd.xpc"))"#,
        super::sb_string(start),
        super::sb_string(workspace_root),
        super::sb_string(renderer_root),
        super::sb_string(result),
        super::sb_string(renderer),
    )
}

/// Owns the real terminal while the display-only launcher chooses a workspace.
#[allow(clippy::too_many_lines)]
pub(super) fn launcher(arguments: &[std::ffi::OsString]) -> Result<(), Box<dyn Error>> {
    let [launcher, start, workspace_root, result] = arguments else {
        return Err("usage: keel-input-runtime launcher START WORKSPACE_ROOT RESULT".into());
    };
    if launcher != "launcher" {
        return Err("invalid launcher operation".into());
    }
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err("Keel's start screen requires a real terminal".into());
    }
    let (rows, columns) = terminal_size().unwrap_or((24, 80));
    let renderer = super::bundled_component("keel-render-spike", "KEEL_RENDERER")?;
    // Resolve the operator's starting directory before entering the renderer
    // sandbox. Resolving it inside the sandbox would require granting reads to
    // every ancestor merely to walk the absolute path.
    let workspace_root = Path::new(workspace_root).canonicalize()?;
    let requested_start = Path::new(start).canonicalize()?;
    // A directory browser needs read access below its root. Never turn an
    // arbitrary launch directory (most dangerously $HOME) into that root:
    // browse the current repository when it is recognizably one, otherwise
    // fall back to Keel's managed workspace directory.
    let canonical_start = if fs::symlink_metadata(requested_start.join(".git")).is_ok() {
        requested_start
    } else {
        workspace_root.clone()
    };
    let profile = launcher_sandbox_profile(
        &renderer,
        &canonical_start,
        &workspace_root,
        Path::new(result),
    );
    let mut child = Command::new("/usr/bin/sandbox-exec")
        .args(["-p", &profile])
        .arg(renderer)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("TERM", super::safe_term())
        .args([
            "--launcher".into(),
            rows.to_string().into(),
            columns.to_string().into(),
            canonical_start.into_os_string(),
            workspace_root.into_os_string(),
            result.clone(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut renderer_input = child.stdin.take().ok_or("launcher stdin unavailable")?;
    let mut renderer_output = child.stdout.take().ok_or("launcher stdout unavailable")?;
    let mut renderer_errors = child.stderr.take().ok_or("launcher stderr unavailable")?;
    let error_thread = thread::spawn(move || -> io::Result<Vec<u8>> {
        let mut errors = Vec::new();
        renderer_errors.read_to_end(&mut errors)?;
        Ok(errors)
    });
    let terminal_mode = AttachTerminalMode::enter()?;
    thread::spawn(move || {
        let mut input = io::stdin().lock();
        let mut bytes = [0_u8; 256];
        while let Ok(mut count) = input.read(&mut bytes) {
            // A raw terminal may deliver Escape separately from the remainder
            // of a CSI/SS3 sequence. Briefly coalesce only that ambiguous byte
            // so the renderer can distinguish a lone Escape from an arrow key.
            while count > 0 && count < bytes.len() && bytes[count - 1] == b'\x1b' {
                let readable = {
                    let mut descriptors = [PollFd::new(input.as_fd(), PollFlags::POLLIN)];
                    poll(&mut descriptors, 25_u16).is_ok_and(|ready| ready > 0)
                };
                if !readable {
                    break;
                }
                match input.read(&mut bytes[count..]) {
                    Ok(0) | Err(_) => break,
                    Ok(additional) => count += additional,
                }
            }
            if count == 0
                || renderer_input
                    .write_all(&bytes[..count])
                    .and_then(|()| renderer_input.flush())
                    .is_err()
            {
                return;
            }
        }
    });
    let mut frame = [0_u8; 16 * 1024];
    loop {
        let count = renderer_output.read(&mut frame)?;
        if count == 0 {
            break;
        }
        io::stdout().write_all(&frame[..count])?;
        io::stdout().flush()?;
    }
    let status = child.wait()?;
    let renderer_errors = error_thread
        .join()
        .map_err(|_| "launcher error thread panicked")??;
    drop(terminal_mode);
    io::stdout().write_all(b"\x1b[2J\x1b[H")?;
    io::stdout().flush()?;
    if status.success() {
        Ok(())
    } else if renderer_errors.is_empty() {
        Err(format!("Keel start screen exited with {status}").into())
    } else {
        Err(format!(
            "Keel start screen exited with {status}: {}",
            safe_text(&renderer_errors).trim()
        )
        .into())
    }
}

#[allow(clippy::too_many_lines)]
pub(super) fn attach(arguments: &[std::ffi::OsString]) -> Result<(), Box<dyn Error>> {
    let socket = parse_socket(arguments, "attach")?;
    let exit_path = exit_status_path(&socket);
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err("attaching to a Keel session requires a real terminal".into());
    }
    let mut stream = UnixStream::connect(&socket).map_err(|error| {
        format!(
            "cannot reach the Keel session at {}: {error}",
            socket.display()
        )
    })?;
    let response = handshake(&mut stream, b"ATTACH\n")?;
    let initial = match response.as_str() {
        "OK FIRST" => true,
        "OK RESUME" | "OK" => false,
        _ => return Err(format!("cannot attach to Keel session: {response}").into()),
    };
    stream.set_read_timeout(None)?;
    let terminal_mode = AttachTerminalMode::enter()?;
    spawn_resize_reporter(stream.try_clone()?)?;
    if !initial {
        // A resumed client has no copy of the current terminal state, so ask
        // the guest display to paint one complete frame. The first client already
        // receives a resize event and the guest image refreshes tmux when its
        // pane becomes ready. The redraw refreshes both tmux and the application.
        // A delayed fallback here used to inject Ctrl-L
        // into an active response and corrupt Claude Code's incremental render.
        stream.write_all(REDRAW)?;
        stream.flush()?;
    }
    let mut input_socket = stream.try_clone()?;
    let detached = Arc::new(AtomicU8::new(0));
    let input_detached = Arc::clone(&detached);
    let command = Arc::new(Mutex::new(MuxCommandInput::default()));
    let input_command = Arc::clone(&command);
    let output = Arc::new(Mutex::new(()));
    let input_output = Arc::clone(&output);
    thread::spawn(move || -> io::Result<()> {
        let mut input = io::stdin().lock();
        let mut buffer = [0_u8; 1024];
        // Escape sequences must cross the attach socket in one piece, so the
        // guest terminal sees them exactly as this terminal produced them.
        let mut forward = Vec::with_capacity(buffer.len());
        loop {
            let count = input.read(&mut buffer)?;
            if count == 0 {
                return Ok(());
            }
            forward.clear();
            let mut detach = false;
            for byte in &buffer[..count] {
                let event = input_command
                    .lock()
                    .map_err(|_| io::Error::other("mux command input is unavailable"))?
                    .accept(*byte);
                match event {
                    MuxCommandEvent::Forward(byte) => push_keystroke(&mut forward, byte),
                    MuxCommandEvent::Render => {
                        let command = input_command
                            .lock()
                            .map_err(|_| io::Error::other("mux command input is unavailable"))?
                            .command()
                            .unwrap_or_default()
                            .to_vec();
                        paint_command_mode(&command, &input_output)?;
                    }
                    MuxCommandEvent::Redraw => forward.extend_from_slice(REDRAW),
                    MuxCommandEvent::LiftFloor(rank) => {
                        forward.extend_from_slice(&encode_floor_lift(rank));
                    }
                    MuxCommandEvent::Submit(command) => {
                        for byte in command {
                            push_keystroke(&mut forward, byte);
                        }
                        push_keystroke(&mut forward, b'\r');
                    }
                    MuxCommandEvent::Detach(action) => {
                        detach = true;
                        input_detached.store(action, Ordering::Relaxed);
                        break;
                    }
                }
            }
            if !forward.is_empty() {
                input_socket.write_all(&forward)?;
                input_socket.flush()?;
            }
            if detach {
                input_socket.shutdown(std::net::Shutdown::Both)?;
                return Ok(());
            }
        }
    });
    // Session frames are cursor-addressed escape sequences with few newlines,
    // so `io::copy` into the line-buffered standard output would leave the
    // operator looking at a blank terminal. Flush whatever each read delivers.
    let mut frame = [0_u8; 16 * 1024];
    loop {
        let count = stream.read(&mut frame)?;
        if count == 0 {
            break;
        }
        let screen_guard = output
            .lock()
            .map_err(|_| io::Error::other("mux display lock is unavailable"))?;
        let mut terminal = io::stdout().lock();
        terminal.write_all(&frame[..count])?;
        terminal.flush()?;
        drop(terminal);
        drop(screen_guard);
        let command = command
            .lock()
            .map_err(|_| io::Error::other("mux command input is unavailable"))?
            .command()
            .map(<[u8]>::to_vec);
        if let Some(command) = command {
            paint_command_mode(&command, &output)?;
        }
    }
    drop(terminal_mode);
    let action = detached.load(Ordering::Relaxed);
    if action >= 20 {
        std::process::exit(i32::from(action));
    }
    if let Some(code) = completed_exit_status(&exit_path)?
        && code != 0
    {
        return Err(format!("persistent runtime exited with status {code}").into());
    }
    Ok(())
}

pub(super) fn stop(arguments: &[std::ffi::OsString]) -> Result<(), Box<dyn Error>> {
    let socket = parse_socket(arguments, "stop")?;
    let exit_path = exit_status_path(&socket);
    let mut stream = UnixStream::connect(&socket)?;
    let response = handshake(&mut stream, b"STOP\n")?;
    if response != "STOPPING" {
        return Err(format!("cannot stop Keel session: {response}").into());
    }
    let deadline = Instant::now() + STOP_COMPLETION_TIMEOUT;
    while socket.exists() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    if socket.exists() {
        return Err("Keel session did not finish stopping".into());
    }
    match completed_exit_status(&exit_path)? {
        Some(0) => Ok(()),
        Some(code) => Err(format!("Keel session stopped with status {code}").into()),
        None => Err("Keel session required forced termination before its audit could seal".into()),
    }
}

#[cfg(test)]
#[path = "../../../tests/support/session_runtime.rs"]
mod tests;
