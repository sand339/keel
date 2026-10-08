//! Host-side support for the explicitly lower-assurance V8 runtime.

use keel_conn::{
    Destination, EgressAuthorization, EgressMethod, ReplayStream, accept_stream,
    request_egress_authorization_interruptible, strip_connect_request,
};
use std::{
    fmt::Write as _,
    io::{self, Write},
    net::{Ipv4Addr, Shutdown, SocketAddrV4, TcpListener, TcpStream},
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

const MAX_CONNECTION_PREFIX: usize = 64 * 1024;

/// A loopback-only HTTP proxy whose upstream connections are supplied by the
/// trusted kernel broker.
pub struct HostEgressProxy {
    address: SocketAddrV4,
    token: String,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<Result<(), String>>>,
}

impl HostEgressProxy {
    /// Starts a loopback proxy. A missing broker path makes every request fail
    /// closed with HTTP 403.
    ///
    /// # Errors
    ///
    /// Returns an error when the loopback listener or worker cannot be created.
    pub fn start(kernel_socket: Option<PathBuf>) -> Result<Self, String> {
        Self::start_on_port(kernel_socket, 0)
    }

    /// Starts the proxy on one preselected loopback port.
    ///
    /// # Errors
    ///
    /// Returns an error when the port cannot be bound or the worker cannot be
    /// created.
    pub fn start_on_port(kernel_socket: Option<PathBuf>, port: u16) -> Result<Self, String> {
        let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
            .map_err(|error| format!("bind loopback port {port}: {error}"))?;
        Self::start_with_listener(kernel_socket, listener)
    }

    /// Starts the proxy from an already-bound loopback listener.
    ///
    /// # Errors
    ///
    /// Returns an error when the listener is not IPv4 loopback, cannot be
    /// configured, or the worker cannot be created.
    pub fn start_with_listener(
        kernel_socket: Option<PathBuf>,
        listener: TcpListener,
    ) -> Result<Self, String> {
        listener
            .set_nonblocking(true)
            .map_err(|error| format!("configure loopback listener: {error}"))?;
        let std::net::SocketAddr::V4(address) = listener
            .local_addr()
            .map_err(|error| format!("inspect loopback listener: {error}"))?
        else {
            return Err("host V8 proxy did not bind IPv4 loopback".to_owned());
        };
        if *address.ip() != Ipv4Addr::LOCALHOST {
            return Err("host V8 proxy listener is not bound to IPv4 loopback".to_owned());
        }
        // Loopback is reachable by every local process and user, so the
        // brokered egress and credential relay require a per-run secret that
        // only the launched Deno process is given.
        let token = random_token().map_err(|error| format!("generate proxy token: {error}"))?;
        let expected = format!("Basic {}", base64(format!("keel:{token}").as_bytes()));
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let thread = thread::Builder::new()
            .name("keel-v8-egress".to_owned())
            .spawn(move || proxy_loop(&listener, kernel_socket.as_deref(), &expected, &thread_stop))
            .map_err(|error| format!("start loopback proxy worker: {error}"))?;
        Ok(Self {
            address,
            token,
            stop,
            thread: Some(thread),
        })
    }

    /// Returns the loopback proxy URL, including its per-run credential.
    #[must_use]
    pub fn url(&self) -> String {
        format!("http://keel:{}@{}", self.token, self.address)
    }

    /// Returns the loopback `host:port` without credentials.
    #[must_use]
    pub fn address(&self) -> String {
        self.address.to_string()
    }

    /// Stops the listener and waits for every active bridge to finish.
    ///
    /// # Errors
    ///
    /// Returns an error when a proxy worker or listener failed.
    pub fn shutdown(mut self) -> Result<(), String> {
        self.stop.store(true, Ordering::Release);
        let _ = TcpStream::connect(self.address);
        self.thread
            .take()
            .ok_or_else(|| "host V8 proxy thread is unavailable".to_owned())?
            .join()
            .map_err(|_| "host V8 proxy thread panicked".to_owned())?
    }
}

impl Drop for HostEgressProxy {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = TcpStream::connect(self.address);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn proxy_loop(
    listener: &TcpListener,
    kernel_socket: Option<&Path>,
    expected: &str,
    stop: &Arc<AtomicBool>,
) -> Result<(), String> {
    let kernel_socket = kernel_socket.map(Path::to_path_buf);
    let mut workers = Vec::new();
    while !stop.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((stream, _)) => {
                if stop.load(Ordering::Acquire) {
                    break;
                }
                let socket = kernel_socket.clone();
                let expected = expected.to_owned();
                let worker_stop = Arc::clone(stop);
                workers.push(
                    thread::Builder::new()
                        .name("keel-v8-egress-connection".to_owned())
                        .spawn(move || {
                            handle_connection(stream, socket.as_deref(), &expected, &worker_stop)
                        })
                        .map_err(|error| error.to_string())?,
                );
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error.to_string()),
        }
    }
    for worker in workers {
        worker
            .join()
            .map_err(|_| "host V8 proxy connection panicked".to_owned())??;
    }
    Ok(())
}

fn handle_connection(
    stream: TcpStream,
    kernel_socket: Option<&Path>,
    expected: &str,
    stop: &AtomicBool,
) -> Result<(), String> {
    // Sockets accepted from the non-blocking listener inherit O_NONBLOCK on
    // macOS, and a read timeout does not clear it; the bridge's blocking copies
    // would otherwise fail with `WouldBlock` as soon as either side paused.
    stream
        .set_nonblocking(false)
        .map_err(|error| error.to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|error| error.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|error| error.to_string())?;
    let accepted =
        accept_stream(stream, MAX_CONNECTION_PREFIX).map_err(|error| error.to_string())?;
    let (destination, mut stream) = accepted.into_parts();
    let authenticated = !matches!(destination, Destination::Tls { .. })
        && stream
            .buffered_headers(MAX_CONNECTION_PREFIX)
            .is_ok_and(|headers| proxy_authorization_matches(headers, expected));
    if !authenticated {
        write_http_error(
            &mut stream,
            "407 Proxy Authentication Required",
            b"Keel's host V8 proxy accepts only its launched runtime.\n",
        )
        .map_err(|error| error.to_string())?;
        return Ok(());
    }
    let authorization = match authorize(&destination, kernel_socket, stop) {
        Err(error)
            if error.kind() == io::ErrorKind::Interrupted && stop.load(Ordering::Acquire) =>
        {
            return Ok(());
        }
        result => result.map_err(|error| error.to_string())?,
    };
    let broker = match authorization {
        EgressAuthorization::Allowed(broker) => broker,
        EgressAuthorization::Denied => {
            write_http_error(
                &mut stream,
                "403 Forbidden",
                b"Keel egress denied by trusted policy.\n",
            )
            .map_err(|error| error.to_string())?;
            return Ok(());
        }
        EgressAuthorization::ExecutionFailed => {
            write_http_error(
                &mut stream,
                "502 Bad Gateway",
                b"Keel egress allowed, but trusted forwarding failed.\n",
            )
            .map_err(|error| error.to_string())?;
            return Ok(());
        }
    };
    if matches!(destination, Destination::Connect { .. }) {
        stream = strip_connect_request(stream, MAX_CONNECTION_PREFIX)
            .map_err(|error| error.to_string())?;
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .map_err(|error| error.to_string())?;
        stream.flush().map_err(|error| error.to_string())?;
    }
    broker
        .set_read_timeout(None)
        .map_err(|error| error.to_string())?;
    broker
        .set_write_timeout(None)
        .map_err(|error| error.to_string())?;
    bridge(stream, broker).map_err(|error| error.to_string())
}

fn authorize(
    destination: &Destination,
    kernel_socket: Option<&Path>,
    stop: &AtomicBool,
) -> io::Result<EgressAuthorization> {
    let Some(socket_path) = kernel_socket else {
        return Ok(EgressAuthorization::Denied);
    };
    let (host, port, method) = match destination {
        Destination::Tls { host, port } => (host, *port, EgressMethod::Tls),
        Destination::Connect { host, port } => (host, *port, EgressMethod::Connect),
        Destination::Http { host, port } => (host, *port, EgressMethod::Http),
    };
    request_egress_authorization_interruptible(socket_path, host, port, method, stop)
}

fn bridge(mut client: ReplayStream<TcpStream>, mut broker: UnixStream) -> io::Result<()> {
    client.get_ref().set_read_timeout(None)?;
    client.get_ref().set_write_timeout(None)?;
    let mut client_writer = client.get_ref().try_clone()?;
    let client_control = client.get_ref().try_clone()?;
    let mut broker_reader = broker.try_clone()?;
    let upload = thread::Builder::new()
        .name("keel-v8-egress-upload".to_owned())
        .spawn(move || {
            let result = io::copy(&mut client, &mut broker);
            let _ = broker.shutdown(Shutdown::Write);
            result
        })?;
    let download = io::copy(&mut broker_reader, &mut client_writer);
    let _ = client_writer.shutdown(std::net::Shutdown::Write);
    let _ = client_control.shutdown(std::net::Shutdown::Read);
    upload
        .join()
        .map_err(|_| io::Error::other("host V8 upload thread panicked"))??;
    download?;
    Ok(())
}

fn proxy_authorization_matches(headers: &[u8], expected: &str) -> bool {
    let Ok(headers) = std::str::from_utf8(headers) else {
        return false;
    };
    let mut values = headers.lines().skip(1).filter_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.trim()
            .eq_ignore_ascii_case("proxy-authorization")
            .then(|| value.trim())
    });
    // Constant-time comparison is unnecessary for a loopback-only secret that
    // is replaced every run, but exactly one header must carry it.
    matches!((values.next(), values.next()), (Some(value), None) if value == expected)
}

fn random_token() -> io::Result<String> {
    let mut bytes = [0_u8; 16];
    io::Read::read_exact(&mut std::fs::File::open("/dev/urandom")?, &mut bytes)?;
    Ok(bytes.iter().fold(String::new(), |mut output, byte| {
        let _ = write!(output, "{byte:02x}");
        output
    }))
}

fn base64(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let value = chunk
            .iter()
            .enumerate()
            .fold(0_u32, |value, (index, byte)| {
                value | u32::from(*byte) << (16 - 8 * index)
            });
        for index in 0..4 {
            output.push(if index <= chunk.len() {
                char::from(ALPHABET[(value >> (18 - 6 * index) & 63) as usize])
            } else {
                '='
            });
        }
    }
    output
}

fn write_http_error(stream: &mut impl Write, status: &str, body: &[u8]) -> io::Result<()> {
    write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    stream.write_all(body)?;
    stream.flush()
}

#[cfg(test)]
mod tests {
    use super::{HostEgressProxy, base64};
    use std::{
        fs,
        io::{Read, Write},
        net::TcpStream,
        os::unix::net::UnixListener,
        thread,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn credential(proxy: &HostEgressProxy) -> String {
        format!(
            "Proxy-Authorization: Basic {}\r\n",
            base64(format!("keel:{}", proxy.token).as_bytes())
        )
    }

    #[test]
    fn base64_matches_rfc_4648_vectors() {
        for (input, encoded) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
        ] {
            assert_eq!(base64(input.as_bytes()), encoded);
        }
    }

    #[test]
    fn unauthenticated_local_clients_are_refused() {
        let proxy = HostEgressProxy::start(None).unwrap();
        for request in [
            "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n".to_owned(),
            "CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic a2VlbDp3cm9uZw==\r\n\r\n"
                .to_owned(),
            format!("CONNECT example.com:443 HTTP/1.1\r\n{0}{0}\r\n", credential(&proxy)),
        ] {
            let mut client = TcpStream::connect(proxy.address).unwrap();
            client.write_all(request.as_bytes()).unwrap();
            let mut response = String::new();
            client.read_to_string(&mut response).unwrap();
            assert!(response.starts_with("HTTP/1.1 407 "), "{response}");
        }
        assert!(proxy.url().contains(&format!("keel:{}@", proxy.token)));
        proxy.shutdown().unwrap();
    }

    #[test]
    fn missing_kernel_broker_fails_closed() {
        let proxy = HostEgressProxy::start(None).unwrap();
        let mut client = TcpStream::connect(proxy.address).unwrap();
        client
            .write_all(
                format!(
                    "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n{}\r\n",
                    credential(&proxy)
                )
                .as_bytes(),
            )
            .unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 403 Forbidden\r\n"));
        proxy.shutdown().unwrap();
    }

    #[test]
    fn allowed_http_stream_is_bridged_through_the_kernel_socket() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("keel-v8-proxy-{nonce:x}"));
        fs::create_dir(&root).unwrap();
        let path = root.join("kernel.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let broker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut magic = [0_u8; 15];
            stream.read_exact(&mut magic).unwrap();
            assert_eq!(&magic, b"KEEL-EGRESS-V2\0");
            let mut length = [0_u8; 2];
            stream.read_exact(&mut length).unwrap();
            let mut host = vec![0_u8; usize::from(u16::from_be_bytes(length))];
            stream.read_exact(&mut host).unwrap();
            assert_eq!(host, b"example.com");
            let mut suffix = [0_u8; 3];
            stream.read_exact(&mut suffix).unwrap();
            assert_eq!(suffix, [0, 80, 3]);
            stream.write_all(b"PA").unwrap();
            let mut request = [0_u8; 64];
            let count = stream.read(&mut request).unwrap();
            assert!(request[..count].starts_with(b"GET http://example.com/"));
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .unwrap();
        });
        let proxy = HostEgressProxy::start(Some(path)).unwrap();
        let mut client = TcpStream::connect(proxy.address).unwrap();
        client
            .write_all(
                format!(
                    "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n{}\r\n",
                    credential(&proxy)
                )
                .as_bytes(),
            )
            .unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        assert!(response.ends_with("\r\n\r\nok"));
        broker.join().unwrap();
        proxy.shutdown().unwrap();
        fs::remove_dir_all(root).unwrap();
    }
}
