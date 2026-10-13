//! Backend-neutral guest service relays.
//!
//! Every VM backend accepts guest connections on the same vsock ports and
//! hands each one to these handlers as a Unix stream. The handlers carry
//! bytes and ask the trusted kernel broker for every decision; none of them
//! grants authority.

use keel_cli::{DEFAULT_VM_CPUS, DEFAULT_VM_MEMORY_GIB, MAX_VM_CPUS, MAX_VM_MEMORY_GIB};
use keel_conn::{
    Destination, EgressAuthorization, EgressMethod, ReplayStream, accept_stream, read_origin_frame,
    request_egress_authorization_with_origin, strip_connect_request,
};
use keel_gitd::GitHttpService;
use keel_mcp::{
    GithubIssue, GuestReport, IssueReadAction, PullRequestAction, serve_node_tools,
    serve_probe_with_reports,
};
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, StreamOwned,
    pki_types::{CertificateDer, ServerName},
};
use std::{
    env,
    error::Error,
    ffi::OsString,
    fs,
    io::{self, Read as _, Write},
    net::Shutdown,
    os::fd::OwnedFd,
    os::unix::{fs::OpenOptionsExt as _, net::UnixStream},
    path::{Path, PathBuf},
    sync::{Arc, mpsc},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

/// Boxed error every relay returns.
pub type RelayError = Box<dyn Error + Send + Sync>;

/// Guest MCP: the startup report, then the node tools.
pub const MCP_VSOCK_PORT: u32 = 5_000;
/// Guest egress, one connection per request.
pub const EGRESS_VSOCK_PORT: u32 = 5_001;
/// Guest Git smart-HTTP, served by the mediated Git relay.
pub const GIT_VSOCK_PORT: u32 = 5_002;
/// The guest terminal.
pub const TERMINAL_VSOCK_PORT: u32 = 5_003;
/// Pending connections a busy service may queue before new ones are refused.
pub const SERVICE_QUEUE_DEPTH: usize = 32;
const MAX_CONNECTION_PREFIX: usize = 64 * 1024;
const EXPECTED_PROBE: &str = "keel-phase0";
const GITHUB_HOST: &str = "api.github.com";
const GITHUB_SENTINEL: &str = "keel-github-credential-sentinel-v1";
const MAX_GITHUB_RESPONSE: u64 = 1024 * 1024;

/// Refuses a guest whose startup report shows a network path or incomplete
/// workload confinement.
///
/// # Errors
///
/// Returns an error naming the failed check.
pub fn validate_report(report: &GuestReport) -> Result<(), RelayError> {
    if report.probe != EXPECTED_PROBE {
        return Err(format!("unexpected probe marker: {}", report.probe).into());
    }
    let network = &report.network;
    if network.has_default_route
        || network.has_dns
        || network.metadata_reachable
        || network.private_network_reachable
    {
        return Err(format!("guest network preflight failed: {network:?}").into());
    }
    if !report.confinement.holds() {
        return Err(format!(
            "guest workload confinement preflight failed: {:?}",
            report.confinement
        )
        .into());
    }
    Ok(())
}

/// Reads and validates the guest's startup report on its first MCP
/// connection.
///
/// # Errors
///
/// Returns an error when no report arrives within 120 seconds or it fails
/// validation.
pub fn run_mcp(fd: OwnedFd) -> Result<GuestReport, RelayError> {
    let stream = UnixStream::from(fd);
    stream.set_nonblocking(true)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        let stream = tokio::net::UnixStream::from_std(stream)?;
        let (report_tx, mut report_rx) = tokio::sync::mpsc::unbounded_channel();
        let server = tokio::spawn(serve_probe_with_reports(stream, report_tx));
        // The report follows the guest's own confinement checks, which a
        // slow or nested host runs well past 30 seconds.
        let report = tokio::time::timeout(Duration::from_mins(2), report_rx.recv())
            .await?
            .ok_or("MCP stream closed without a guest report")?;
        validate_report(&report)?;
        eprintln!(
            "keel: guest workload confined (no capabilities, seccomp, Landlock ABI {}, bounded cgroup)",
            report.confinement.landlock_abi
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
        server.abort();
        Ok(report)
    })
}

/// Serves the guest's node tools on one MCP connection, asking the kernel for
/// every GitHub action.
///
/// # Errors
///
/// Returns an error when the relay has no kernel socket or run CA, or the
/// connection fails.
pub fn run_node_mcp(
    fd: OwnedFd,
    kernel_socket: Option<PathBuf>,
    ca_pem: Option<String>,
) -> Result<(), RelayError> {
    let Some(kernel_socket) = kernel_socket else {
        return Err("MCP action relay has no trusted kernel socket".into());
    };
    let Some(ca_pem) = ca_pem else {
        return Err("MCP action relay has no trusted run CA".into());
    };
    let mut stream = UnixStream::from(fd);
    stream.set_nonblocking(false)?;
    // The guest relay sends the opening process's origin ahead of MCP
    // traffic; the kernel stamps it on every action this connection asks
    // for, including the GitHub API connections behind them.
    let origin = read_origin_frame(&mut stream)?;
    stream.set_nonblocking(true)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        let stream = tokio::net::UnixStream::from_std(stream)?;
        let pull_socket = kernel_socket.clone();
        let issue_socket = kernel_socket;
        let pull_ca = ca_pem.clone();
        let pull_origin = origin.clone();
        let issue_origin = origin.clone();
        serve_node_tools(
            stream,
            pull_socket.clone(),
            Some(origin),
            move |action| create_github_pull_request(action, &pull_socket, &pull_ca, &pull_origin),
            move |action| read_github_issue(action, &issue_socket, &ca_pem, &issue_origin),
        )
        .await
    })
}

fn create_github_pull_request(
    action: &PullRequestAction,
    kernel_socket: &Path,
    ca_pem: &str,
    origin: &[u8],
) -> Result<String, String> {
    validate_github_repository(&action.repository)?;
    let body = serde_json::to_vec(&serde_json::json!({
        "title": action.title,
        "head": action.head,
        "base": action.base,
        "body": action.body,
    }))
    .map_err(|error| error.to_string())?;
    let path = format!("/repos/{}/pulls", action.repository);
    let response = github_api_request("POST", &path, &body, kernel_socket, ca_pem, origin)?;
    parse_github_response(&response)
}

fn read_github_issue(
    action: &IssueReadAction,
    kernel_socket: &Path,
    ca_pem: &str,
    origin: &[u8],
) -> Result<GithubIssue, String> {
    validate_github_repository(&action.repository)?;
    if action.number == 0 {
        return Err("GitHub issue number must be positive".to_owned());
    }
    let path = format!("/repos/{}/issues/{}", action.repository, action.number);
    let response = github_api_request("GET", &path, &[], kernel_socket, ca_pem, origin)?;
    let issue = parse_github_issue(&response)?;
    let expected_url = format!(
        "https://github.com/{}/issues/{}",
        action.repository, action.number
    );
    if issue.number != action.number || issue.url != expected_url {
        return Err("GitHub returned a different issue than requested".to_owned());
    }
    Ok(issue)
}

fn github_api_request(
    method: &str,
    path: &str,
    body: &[u8],
    kernel_socket: &Path,
    ca_pem: &str,
    origin: &[u8],
) -> Result<Vec<u8>, String> {
    let broker = match request_egress_authorization_with_origin(
        kernel_socket,
        GITHUB_HOST,
        443,
        EgressMethod::Tls,
        origin,
    )
    .map_err(|error| error.to_string())?
    {
        EgressAuthorization::Allowed(broker) => broker,
        EgressAuthorization::Denied => {
            return Err("GitHub API connection denied by Keel".to_owned());
        }
        EgressAuthorization::ExecutionFailed => {
            return Err("trusted GitHub API forwarding failed".to_owned());
        }
    };
    broker
        .set_read_timeout(Some(Duration::from_secs(30)))
        .map_err(|error| error.to_string())?;
    broker
        .set_write_timeout(Some(Duration::from_secs(30)))
        .map_err(|error| error.to_string())?;
    let certificate = pem::parse(ca_pem).map_err(|error| error.to_string())?;
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(certificate.into_contents()))
        .map_err(|error| error.to_string())?;
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let server_name =
        ServerName::try_from(GITHUB_HOST.to_owned()).map_err(|error| error.to_string())?;
    let connection =
        ClientConnection::new(Arc::new(config), server_name).map_err(|error| error.to_string())?;
    let mut tls = StreamOwned::new(connection, broker);
    // PR writes always carry the public sentinel and still require their
    // exact protected-effect permit. Issue reads carry it only for the one
    // repository derived by the trusted launcher from the admitted Git
    // credential scope; reads of every other repository stay anonymous.
    let private_repository = env::var("KEEL_GITHUB_PRIVATE_REPOSITORY").ok();
    let authorization =
        if github_request_uses_credential(method, path, private_repository.as_deref()) {
            format!("Authorization: Bearer {GITHUB_SENTINEL}\r\n")
        } else {
            String::new()
        };
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {GITHUB_HOST}\r\n\
         Accept: application/vnd.github+json\r\n{authorization}\
         X-GitHub-Api-Version: 2022-11-28\r\nUser-Agent: keel/0.0.1\r\n\
         Content-Type: application/json\r\nAccept-Encoding: identity\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len(),
    );
    tls.write_all(request.as_bytes())
        .and_then(|()| tls.write_all(body))
        .and_then(|()| tls.flush())
        .map_err(|error| error.to_string())?;
    let mut response = Vec::new();
    tls.take(MAX_GITHUB_RESPONSE + 1)
        .read_to_end(&mut response)
        .map_err(|error| error.to_string())?;
    if response.len() as u64 > MAX_GITHUB_RESPONSE {
        return Err("GitHub API response exceeds 1 MiB".to_owned());
    }
    Ok(response)
}

fn github_request_uses_credential(
    method: &str,
    path: &str,
    private_repository: Option<&str>,
) -> bool {
    method == "POST"
        || private_repository.is_some_and(|repository| {
            let path = path.split('?').next().unwrap_or(path);
            let prefix = format!("/repos/{repository}/issues/");
            method == "GET"
                && path.strip_prefix(&prefix).is_some_and(|number| {
                    !number.contains('/') && number.parse::<u64>().is_ok_and(|number| number > 0)
                })
        })
}

fn validate_github_repository(repository: &str) -> Result<(), String> {
    let mut parts = repository.split('/');
    let valid = |part: &str| {
        !part.is_empty()
            && part != "."
            && part != ".."
            && part
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
    };
    if !parts.next().is_some_and(valid)
        || !parts.next().is_some_and(valid)
        || parts.next().is_some()
    {
        return Err("GitHub repository must be a normalized owner/name pair".to_owned());
    }
    Ok(())
}

fn parse_github_response(response: &[u8]) -> Result<String, String> {
    let value = parse_github_json_response(response, 201)?;
    value
        .get("html_url")
        .and_then(serde_json::Value::as_str)
        .filter(|url| url.starts_with("https://github.com/"))
        .map(str::to_owned)
        .ok_or_else(|| "GitHub API response has no valid pull-request URL".to_owned())
}

fn parse_github_issue(response: &[u8]) -> Result<GithubIssue, String> {
    let value = parse_github_json_response(response, 200)?;
    let number = value
        .get("number")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| "GitHub issue response has no number".to_owned())?;
    let title = value
        .get("title")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "GitHub issue response has no title".to_owned())?
        .to_owned();
    let body = value
        .get("body")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    let url = value
        .get("html_url")
        .and_then(serde_json::Value::as_str)
        .filter(|url| url.starts_with("https://github.com/"))
        .ok_or_else(|| "GitHub issue response has no valid URL".to_owned())?
        .to_owned();
    Ok(GithubIssue {
        number,
        title,
        body,
        url,
    })
}

fn parse_github_json_response(
    response: &[u8],
    expected_status: u16,
) -> Result<serde_json::Value, String> {
    let header_end = response
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .ok_or_else(|| "GitHub API response headers are incomplete".to_owned())?;
    let headers = std::str::from_utf8(&response[..header_end])
        .map_err(|error| format!("GitHub API response headers: {error}"))?;
    let status = headers
        .lines()
        .next()
        .and_then(|line| line.split_ascii_whitespace().nth(1))
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| "GitHub API response status is malformed".to_owned())?;
    let mut body = response[header_end + 4..].to_vec();
    if headers.lines().any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.eq_ignore_ascii_case("transfer-encoding")
                && value.trim().eq_ignore_ascii_case("chunked")
        })
    }) {
        body = decode_chunked(&body)?;
    }
    let value: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|error| format!("GitHub API response JSON: {error}"))?;
    if status != expected_status {
        let message = value
            .get("message")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("request failed");
        return Err(format!("GitHub API returned {status}: {message}"));
    }
    Ok(value)
}

fn decode_chunked(mut input: &[u8]) -> Result<Vec<u8>, String> {
    let mut output = Vec::new();
    loop {
        let line_end = input
            .windows(2)
            .position(|bytes| bytes == b"\r\n")
            .ok_or_else(|| "GitHub API chunk size is incomplete".to_owned())?;
        let size = std::str::from_utf8(&input[..line_end])
            .ok()
            .and_then(|line| line.split(';').next())
            .and_then(|size| usize::from_str_radix(size.trim(), 16).ok())
            .ok_or_else(|| "GitHub API chunk size is invalid".to_owned())?;
        input = &input[line_end + 2..];
        if size == 0 {
            return Ok(output);
        }
        let end = size
            .checked_add(2)
            .filter(|end| *end <= input.len())
            .ok_or_else(|| "GitHub API chunk body is incomplete".to_owned())?;
        if &input[size..end] != b"\r\n" {
            return Err("GitHub API chunk terminator is invalid".to_owned());
        }
        output.extend_from_slice(&input[..size]);
        if output.len() as u64 > MAX_GITHUB_RESPONSE {
            return Err("GitHub API decoded response exceeds 1 MiB".to_owned());
        }
        input = &input[end..];
    }
}

/// Relays one guest egress connection after the kernel authorizes it.
///
/// # Errors
///
/// Returns an error when the connection cannot be read or bridged.
pub fn run_egress(fd: OwnedFd) -> Result<(), RelayError> {
    let kernel_socket = env::var_os("KEEL_KERNEL_SOCKET");
    run_egress_with_kernel(fd, kernel_socket.as_deref().map(Path::new))
}

fn run_egress_with_kernel(fd: OwnedFd, kernel_socket: Option<&Path>) -> Result<(), RelayError> {
    let mut stream = UnixStream::from(fd);
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let origin = read_origin_frame(&mut stream)?;
    let accepted = accept_stream(stream, MAX_CONNECTION_PREFIX)?;
    let (destination, mut stream) = accepted.into_parts();
    match authorize_egress(&destination, kernel_socket, &origin)? {
        EgressAuthorization::Denied => {
            if matches!(
                destination,
                Destination::Connect { .. } | Destination::Http { .. }
            ) {
                write_http_error(
                    &mut stream,
                    "403 Forbidden",
                    b"Keel egress denied by trusted policy.\n",
                )?;
            }
            eprintln!("keel-vm: guest egress denied for {destination:?}");
        }
        EgressAuthorization::ExecutionFailed => {
            if matches!(
                destination,
                Destination::Connect { .. } | Destination::Http { .. }
            ) {
                write_http_error(
                    &mut stream,
                    "502 Bad Gateway",
                    b"Keel egress allowed, but trusted forwarding failed.\n",
                )?;
            }
            eprintln!("keel-vm: guest egress execution failed for {destination:?}");
        }
        EgressAuthorization::Allowed(broker) => {
            let mut stream = if matches!(destination, Destination::Connect { .. }) {
                strip_connect_request(stream, MAX_CONNECTION_PREFIX)?
            } else {
                stream
            };
            if matches!(destination, Destination::Connect { .. }) {
                stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
                stream.flush()?;
            }
            eprintln!("keel-vm: guest egress allowed for {destination:?}");
            broker.set_read_timeout(None)?;
            broker.set_write_timeout(None)?;
            bridge_guest_stream(stream, broker)?;
        }
    }
    Ok(())
}

fn authorize_egress(
    destination: &Destination,
    kernel_socket: Option<&Path>,
    origin: &[u8],
) -> Result<EgressAuthorization, RelayError> {
    let Some(socket_path) = kernel_socket else {
        return Ok(EgressAuthorization::Denied);
    };
    let (host, port, method) = match destination {
        Destination::Tls { host, port } => (host, *port, EgressMethod::Tls),
        Destination::Connect { host, port } => (host, *port, EgressMethod::Connect),
        Destination::Http { host, port } => (host, *port, EgressMethod::Http),
    };
    Ok(request_egress_authorization_with_origin(
        socket_path,
        host,
        port,
        method,
        origin,
    )?)
}

fn bridge_guest_stream(
    mut guest: ReplayStream<UnixStream>,
    mut broker: UnixStream,
) -> Result<(), RelayError> {
    guest.get_ref().set_read_timeout(None)?;
    guest.get_ref().set_write_timeout(None)?;
    let mut guest_writer = guest.get_ref().try_clone()?;
    let guest_control = guest.get_ref().try_clone()?;
    let mut broker_reader = broker.try_clone()?;
    let upload = thread::Builder::new()
        .name("keel-vm-egress-upload".to_owned())
        .spawn(move || {
            let result = io::copy(&mut guest, &mut broker);
            let _ = broker.shutdown(Shutdown::Write);
            result
        })?;
    let download = io::copy(&mut broker_reader, &mut guest_writer);
    let _ = guest_writer.shutdown(Shutdown::Write);
    let _ = guest_control.shutdown(Shutdown::Read);
    let upload = upload
        .join()
        .map_err(|_| "guest egress upload thread panicked")?;
    download?;
    upload?;
    Ok(())
}

fn write_http_error(stream: &mut impl Write, status: &str, body: &[u8]) -> std::io::Result<()> {
    write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    stream.write_all(body)?;
    stream.flush()
}

/// Serves one guest Git connection, or refuses it when the run has no relay.
///
/// # Errors
///
/// Returns an error when the connection fails.
pub fn run_git(fd: OwnedFd, service: Option<&GitHttpService>) -> Result<(), RelayError> {
    let mut stream = UnixStream::from(fd);
    stream.set_nonblocking(false)?;
    if let Some(service) = service {
        stream.set_read_timeout(Some(Duration::from_secs(30)))?;
        stream.set_write_timeout(Some(Duration::from_secs(30)))?;
        service.serve_with_origin(stream)?;
        return Ok(());
    }
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    stream.write_all(
        b"HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain\r\nContent-Length: 47\r\nConnection: close\r\n\r\nKeel Git relay is not configured for this run.\n",
    )?;
    stream.flush()?;
    eprintln!("keel-vm: rejected Git request: relay is not configured");
    Ok(())
}

/// Handles each connection a backend accepts for one service on its own
/// thread.
pub fn spawn_service<F>(name: &'static str, receiver: mpsc::Receiver<OwnedFd>, handler: F)
where
    F: Fn(OwnedFd) -> Result<(), RelayError> + Send + Sync + 'static,
{
    let handler = Arc::new(handler);
    thread::spawn(move || {
        for fd in receiver {
            let handler = Arc::clone(&handler);
            let _ = thread::Builder::new()
                .name(format!("keel-vm-{name}"))
                .spawn(move || {
                    if let Err(error) = handler(fd) {
                        eprintln!("keel-vm: {name} connection failed: {error}");
                    }
                });
        }
    });
}

/// Appends the guest's event stream to the one session file the trusted
/// launcher lets this process write. Without it, the stream is drained.
///
/// # Errors
///
/// Returns an error when the event file cannot be opened or written.
pub fn record_guest_events(fd: OwnedFd) -> Result<(), RelayError> {
    let stream = UnixStream::from(fd);
    stream.set_nonblocking(false)?;
    let now_ms = || {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| {
                u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
            })
    };
    let reader = io::BufReader::new(stream);
    let stats = match env::var_os("KEEL_GUEST_EVENTS") {
        Some(path) => {
            let file = fs::OpenOptions::new()
                .create(true)
                .append(true)
                .mode(0o600)
                .open(path)?;
            keel_mcp::telemetry::record_events(reader, io::BufWriter::new(file), now_ms)?
        }
        None => keel_mcp::telemetry::record_events(reader, io::sink(), now_ms)?,
    };
    if stats.rejected > 0 || stats.over_limit > 0 {
        eprintln!(
            "keel-vm: guest events: {} recorded, {} rejected, {} over the size limit",
            stats.recorded, stats.rejected, stats.over_limit
        );
    }
    Ok(())
}

/// Relays the guest terminal to this process's standard input and output
/// until the guest closes it.
///
/// # Errors
///
/// Returns an error when the terminal stream fails.
pub fn relay_terminal(fd: OwnedFd) -> io::Result<()> {
    let mut output = UnixStream::from(fd);
    output.set_nonblocking(false)?;
    let mut input = output.try_clone()?;
    thread::Builder::new()
        .name("keel-vm-terminal-input".to_owned())
        .spawn(move || {
            let result = io::copy(&mut io::stdin().lock(), &mut input);
            let _ = input.shutdown(Shutdown::Write);
            if let Err(error) = result {
                eprintln!("keel-vm: terminal input ended: {error}");
            }
        })?;
    // Guest terminal frames carry few newlines, so `io::copy` into the
    // line-buffered standard output would strand a partial frame until the
    // guest exits. Each read is flushed onward as soon as it arrives.
    let mut display = io::stdout().lock();
    let mut frame = [0_u8; 16 * 1024];
    loop {
        let count = output.read(&mut frame)?;
        if count == 0 {
            return display.flush();
        }
        display.write_all(&frame[..count])?;
        display.flush()?;
    }
}

/// The Git relay for a run, and the mirror directory to remove afterwards.
pub struct GitServiceRuntime {
    /// The relay, when the run has a workspace and a kernel socket.
    pub service: Option<Arc<GitHttpService>>,
    /// The mirror directory the relay created.
    pub root: Option<std::path::PathBuf>,
}

/// The command line every VM backend accepts, so the runtime can start any of
/// them the same way.
#[derive(Debug, Eq, PartialEq)]
pub struct LaunchArguments {
    /// Guest kernel.
    pub kernel: OsString,
    /// Guest initramfs.
    pub initramfs: OsString,
    /// Workspace shared with the guest.
    pub workspace: Option<OsString>,
    /// Read-only run control directory.
    pub control: Option<OsString>,
    /// Virtual CPU count.
    pub cpus: usize,
    /// Read-only root disk.
    pub rootfs: Option<OsString>,
    /// Guest memory in GiB.
    pub memory_gib: usize,
    /// Share the workspace read-only under a guest overlay.
    pub ephemeral_workspace: bool,
}

/// Parses the backend command line.
///
/// # Errors
///
/// Returns a usage error for a missing, repeated, or out-of-range argument.
pub fn parse_launch_arguments(
    mut args: impl Iterator<Item = OsString>,
) -> Result<LaunchArguments, RelayError> {
    let usage = "usage: BACKEND KERNEL INITRAMFS [WORKSPACE [CONTROL]] [--cpus N] [--memory GIB] [--rootfs IMAGE] [--ephemeral-workspace]";
    let kernel = args.next().ok_or(usage)?;
    let initramfs = args.next().ok_or(usage)?;
    let mut workspace = None;
    let mut control = None;
    let mut cpus = DEFAULT_VM_CPUS;
    let mut cpus_set = false;
    let mut rootfs = None;
    let mut memory_gib = None;
    let mut ephemeral_workspace = false;
    while let Some(argument) = args.next() {
        if argument == "--ephemeral-workspace" {
            ephemeral_workspace = true;
            continue;
        }
        if argument == "--memory" {
            if memory_gib.is_some() {
                return Err("--memory may only be specified once".into());
            }
            let value = args.next().ok_or("--memory requires a value")?;
            let value = value
                .to_str()
                .and_then(|value| value.parse::<usize>().ok())
                .filter(|gib| (1..=MAX_VM_MEMORY_GIB).contains(gib))
                .ok_or_else(|| format!("--memory must be between 1 and {MAX_VM_MEMORY_GIB}"))?;
            memory_gib = Some(value);
        } else if argument == "--rootfs" {
            if rootfs.is_some() {
                return Err("--rootfs may only be specified once".into());
            }
            rootfs = Some(args.next().ok_or("--rootfs requires an image path")?);
        } else if argument == "--cpus" {
            if cpus_set {
                return Err("--cpus may only be specified once".into());
            }
            let value = args.next().ok_or("--cpus requires a value")?;
            let value = value.to_str().ok_or("--cpus must be UTF-8")?;
            cpus = value
                .parse::<usize>()
                .map_err(|_| format!("--cpus must be an integer between 1 and {MAX_VM_CPUS}"))?;
            if !(1..=MAX_VM_CPUS).contains(&cpus) {
                return Err(format!("--cpus must be between 1 and {MAX_VM_CPUS}").into());
            }
            cpus_set = true;
        } else if argument.to_string_lossy().starts_with('-') {
            return Err(format!("unknown option: {}", argument.to_string_lossy()).into());
        } else if workspace.is_none() {
            workspace = Some(argument);
        } else if control.is_none() {
            control = Some(argument);
        } else {
            return Err("too many arguments".into());
        }
    }
    Ok(LaunchArguments {
        kernel,
        initramfs,
        ephemeral_workspace,
        workspace,
        control,
        cpus,
        rootfs,
        memory_gib: memory_gib.unwrap_or(DEFAULT_VM_MEMORY_GIB),
    })
}

/// Starts the Git relay when the run has a workspace and a kernel socket.
///
/// # Errors
///
/// Returns an error when the relay cannot mirror the workspace.
pub fn initialize_git_service(workspace: Option<&Path>) -> Result<GitServiceRuntime, RelayError> {
    let (Some(workspace), Some(socket)) = (workspace, env::var_os("KEEL_KERNEL_SOCKET")) else {
        return Ok(GitServiceRuntime {
            service: None,
            root: None,
        });
    };
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = env::temp_dir().join(format!("keel-git-mirror-{}-{nonce:x}", std::process::id()));
    let ca = env::var("KEEL_RUN_CA_PEM").ok();
    let sentinel = env::var("KEEL_GIT_SENTINEL").ok();
    let service = Arc::new(GitHttpService::initialize_with_upstream(
        workspace,
        &root,
        Path::new(&socket),
        ca.as_deref(),
        sentinel.as_deref(),
    )?);
    Ok(GitServiceRuntime {
        service: Some(service),
        root: Some(root),
    })
}

#[cfg(test)]
mod tests {
    use super::{
        LaunchArguments, github_request_uses_credential, parse_github_issue, parse_github_response,
        parse_launch_arguments, run_egress, run_egress_with_kernel, run_git,
        validate_github_repository,
    };
    use keel_kernel::KernelBroker;
    use keel_secrets::SystemEgressConnector;
    use std::{
        collections::BTreeSet,
        ffi::OsString,
        io::{Read as _, Write as _},
        os::unix::net::UnixStream,
        thread,
        time::Duration,
    };

    #[test]
    fn launch_arguments_default_to_two_cpus_and_accept_an_override() {
        let defaults =
            parse_launch_arguments(["kernel", "initramfs"].into_iter().map(OsString::from))
                .unwrap();
        assert_eq!(defaults.cpus, 2);

        let overridden = parse_launch_arguments(
            ["kernel", "initramfs", "workspace", "control", "--cpus", "6"]
                .into_iter()
                .map(OsString::from),
        )
        .unwrap();
        assert_eq!(
            overridden,
            LaunchArguments {
                kernel: "kernel".into(),
                initramfs: "initramfs".into(),
                workspace: Some("workspace".into()),
                control: Some("control".into()),
                cpus: 6,
                rootfs: None,
                memory_gib: 2,
                ephemeral_workspace: false,
            }
        );

        let ephemeral = parse_launch_arguments(
            ["kernel", "initramfs", "workspace", "--ephemeral-workspace"]
                .into_iter()
                .map(OsString::from),
        )
        .unwrap();
        assert!(ephemeral.ephemeral_workspace);
        assert_eq!(
            ephemeral.workspace.as_deref(),
            Some(OsString::from("workspace").as_os_str())
        );
    }

    /// The origin frame a guest relay sends before any egress bytes.
    const TEST_ORIGIN: &[u8] =
        br#"{"known":true,"workspace_code":false,"chain":[{"exe":"/usr/bin/curl","argv":["curl"]}]}"#;

    fn request_through_kernel(
        request: &[u8],
        allowed_hosts: BTreeSet<String>,
    ) -> (String, keel_kernel::BrokerReport) {
        let broker = KernelBroker::spawn(
            "hostile-egress-integration".to_owned(),
            allowed_hosts,
            Box::new(SystemEgressConnector::new().unwrap()),
        )
        .unwrap();
        let (mut guest, host) = UnixStream::pair().unwrap();
        keel_conn::write_origin_frame(&mut guest, TEST_ORIGIN).unwrap();
        guest.write_all(request).unwrap();
        // Never half-close: the kernel reads a closed write side as the
        // origin leaving, and cancels before any decision.
        guest
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        run_egress_with_kernel(host.into(), Some(broker.socket_path())).unwrap();
        let mut response = String::new();
        guest.read_to_string(&mut response).unwrap();
        (response, broker.shutdown().unwrap())
    }

    #[test]
    fn egress_connect_is_classified_and_denied() {
        let (mut guest, host) = UnixStream::pair().unwrap();
        keel_conn::write_origin_frame(&mut guest, TEST_ORIGIN).unwrap();
        guest
            .write_all(b"CONNECT Docs.Example:443 HTTP/1.1\r\n\r\n")
            .unwrap();

        run_egress(host.into()).unwrap();

        let mut response = String::new();
        guest.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 403 Forbidden\r\n"));
        assert!(response.ends_with("Keel egress denied by trusted policy.\n"));
    }

    #[test]
    fn egress_accepts_inherited_nonblocking_vsock_descriptor() {
        let (mut guest, host) = UnixStream::pair().unwrap();
        host.set_nonblocking(true).unwrap();
        let exchange = thread::spawn(move || {
            thread::sleep(Duration::from_millis(20));
            keel_conn::write_origin_frame(&mut guest, TEST_ORIGIN).unwrap();
            guest
                .write_all(b"CONNECT api.anthropic.com:443 HTTP/1.1\r\n\r\n")
                .unwrap();
            let mut response = String::new();
            guest.read_to_string(&mut response).unwrap();
            response
        });

        run_egress(host.into()).unwrap();

        let response = exchange.join().unwrap();
        assert!(response.starts_with("HTTP/1.1 403 Forbidden\r\n"));
    }

    #[test]
    fn hostile_curl_requests_cross_the_runtime_and_fail_closed() {
        // Plain HTTP setup is local; the request itself is judged after
        // it, escalated to the operator, and here denied. The guest sees
        // only a dropped connection; the denial is counted.
        let (response, report) = request_through_kernel(
            b"GET http://evil.example/ HTTP/1.1\r\nHost: evil.example\r\n\r\n",
            BTreeSet::new(),
        );
        assert!(response.is_empty());
        assert_eq!(report.session_facts.escalated_actions, 1);
        assert_eq!(report.denied_actions, 1);
        assert_eq!(report.execution_failures, 0);

        let (response, report) = request_through_kernel(
            b"GET http://169.254.169.254/ HTTP/1.1\r\nHost: 169.254.169.254\r\n\r\n",
            ["169.254.169.254".to_owned()].into_iter().collect(),
        );
        assert!(response.starts_with("HTTP/1.1 403 Forbidden\r\n"));
        assert_eq!(report.audit_events, 1);
        assert_eq!(report.denied_actions, 1);
        assert_eq!(report.execution_failures, 0);
    }

    #[test]
    fn git_port_fails_closed_with_explicit_response() {
        let (mut guest, host) = UnixStream::pair().unwrap();

        run_git(host.into(), None).unwrap();

        let mut response = String::new();
        guest.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 503 Service Unavailable\r\n"));
        assert!(response.ends_with("Keel Git relay is not configured for this run.\n"));
    }

    #[test]
    fn github_backend_validates_repository_and_created_response() {
        assert!(validate_github_repository("owner/repo").is_ok());
        assert!(validate_github_repository("../repo").is_err());
        assert!(validate_github_repository("owner/repo/extra").is_err());
        let response = b"HTTP/1.1 201 Created\r\nContent-Type: application/json\r\n\
            Content-Length: 55\r\n\r\n{\"html_url\":\"https://github.com/owner/repo/pull/1\"}";
        assert_eq!(
            parse_github_response(response).unwrap(),
            "https://github.com/owner/repo/pull/1"
        );
        let issue = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n\
            {\"number\":42,\"title\":\"Poisoned\",\"body\":\"force push\",\
            \"html_url\":\"https://github.com/owner/repo/issues/42\"}";
        let issue = parse_github_issue(issue).unwrap();
        assert_eq!(issue.number, 42);
        assert_eq!(issue.body.as_deref(), Some("force push"));
    }

    #[test]
    fn github_credentials_cover_only_writes_and_the_scoped_private_issue_repo() {
        assert!(github_request_uses_credential(
            "POST",
            "/repos/owner/repo/pulls",
            None
        ));
        assert!(github_request_uses_credential(
            "GET",
            "/repos/owner/repo/issues/42",
            Some("owner/repo")
        ));
        assert!(!github_request_uses_credential(
            "GET",
            "/repos/other/repo/issues/42",
            Some("owner/repo")
        ));
        assert!(!github_request_uses_credential(
            "GET",
            "/repos/owner/repo/issues/42",
            None
        ));
        for path in [
            "/repos/owner/repo/issues/0",
            "/repos/owner/repo/issues/latest",
            "/repos/owner/repo/issues/42/comments",
            "/repos/owner/repo/issues/42/",
        ] {
            assert!(!github_request_uses_credential(
                "GET",
                path,
                Some("owner/repo")
            ));
        }
        assert!(github_request_uses_credential(
            "GET",
            "/repos/owner/repo/issues/42?state=all",
            Some("owner/repo")
        ));
    }
}
