#![doc = "Untrusted connection acceptor for Keel."]

use std::{
    error::Error,
    fmt,
    io::{self, Read, Write},
    os::unix::net::UnixStream,
    path::Path,
    str,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

/// Versioned marker for the two-stage trusted egress protocol.
///
/// A V2 broker acknowledges a complete request with [`EGRESS_PENDING`] before
/// it waits for an operator. That acknowledgement separates a short machine
/// timeout from the bounded human-decision timeout.
pub const EGRESS_BROKER_MAGIC_V2: &[u8] = b"KEEL-EGRESS-V2\0";

pub use keel_kernel::{MAX_ORIGIN_BYTES, ORIGIN_MAGIC};

/// Reads the origin frame a guest relay sends ahead of its traffic.
///
/// # Errors
///
/// Returns an error when the frame is absent, malformed, or over its bound.
pub fn read_origin_frame(reader: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut magic = vec![0_u8; ORIGIN_MAGIC.len()];
    reader.read_exact(&mut magic)?;
    if magic != ORIGIN_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "guest relay sent no origin frame; rerun keel setup",
        ));
    }
    let mut length = [0_u8; 2];
    reader.read_exact(&mut length)?;
    let length = usize::from(u16::from_be_bytes(length));
    if length > MAX_ORIGIN_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "origin frame exceeds its bound",
        ));
    }
    let mut origin = vec![0_u8; length];
    reader.read_exact(&mut origin)?;
    Ok(origin)
}

/// Writes an origin frame. Oversized origins are sent empty, which the
/// kernel reads as an unknown origin.
///
/// # Errors
///
/// Returns an error when the write fails.
pub fn write_origin_frame(writer: &mut impl Write, origin: &[u8]) -> io::Result<()> {
    let origin = if origin.len() > MAX_ORIGIN_BYTES {
        &[][..]
    } else {
        origin
    };
    writer.write_all(ORIGIN_MAGIC)?;
    writer.write_all(
        &u16::try_from(origin.len())
            .unwrap_or_default()
            .to_be_bytes(),
    )?;
    writer.write_all(origin)
}

/// Broker response indicating that a complete request is awaiting a decision.
pub const EGRESS_PENDING: u8 = b'P';

/// Broker response allowing the requested connection.
pub const EGRESS_ALLOWED: u8 = b'A';

/// Broker response denying the requested connection.
pub const EGRESS_DENIED: u8 = b'D';

/// Broker response indicating that trusted forwarding failed.
pub const EGRESS_EXECUTION_FAILED: u8 = b'E';

/// Maximum time allowed for the broker to acknowledge a parsed request.
pub const EGRESS_ACK_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum time allowed for a trusted human decision after acknowledgement.
pub const EGRESS_DECISION_TIMEOUT: Duration = Duration::from_mins(5);

const INTERRUPT_POLL_INTERVAL: Duration = Duration::from_millis(5);

/// Method asserted by an untrusted egress relay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum EgressMethod {
    /// A TLS connection classified from its `ClientHello`.
    Tls = 1,
    /// An HTTP proxy `CONNECT` request.
    Connect = 2,
    /// A plaintext HTTP request.
    Http = 3,
}

/// Terminal decision returned by the trusted egress broker.
#[derive(Debug)]
pub enum EgressAuthorization {
    /// Forwarding is allowed on the returned broker stream.
    Allowed(UnixStream),
    /// Trusted policy denied the connection.
    Denied,
    /// Policy allowed the action but trusted forwarding failed.
    ExecutionFailed,
}

/// Requests an egress connection using the two-stage broker protocol.
///
/// The broker must acknowledge the complete request with `P` within five
/// seconds, then send exactly one terminal `A`, `D`, or `E` byte within five
/// minutes. No network authority is conferred by `P` alone.
///
/// # Errors
///
/// Returns an error for transport failures, malformed broker responses, or a
/// timeout in either phase. All such failures are fail-closed.
pub fn request_egress_authorization(
    socket_path: &Path,
    host: &str,
    port: u16,
    method: EgressMethod,
) -> io::Result<EgressAuthorization> {
    request_egress_authorization_inner(
        socket_path,
        host,
        port,
        method,
        EGRESS_ACK_TIMEOUT,
        EGRESS_DECISION_TIMEOUT,
        None,
        None,
    )
}

/// [`request_egress_authorization`] carrying the guest's origin frame.
///
/// # Errors
///
/// Has the same fail-closed behavior as [`request_egress_authorization`].
pub fn request_egress_authorization_with_origin(
    socket_path: &Path,
    host: &str,
    port: u16,
    method: EgressMethod,
    origin: &[u8],
) -> io::Result<EgressAuthorization> {
    request_egress_authorization_inner(
        socket_path,
        host,
        port,
        method,
        EGRESS_ACK_TIMEOUT,
        EGRESS_DECISION_TIMEOUT,
        None,
        Some(origin),
    )
}

/// Requests egress while allowing a host-side shutdown flag to interrupt both
/// protocol waits.
///
/// # Errors
///
/// Returns [`io::ErrorKind::Interrupted`] when `cancelled` becomes true, and
/// otherwise has the same fail-closed behavior as
/// [`request_egress_authorization`].
pub fn request_egress_authorization_interruptible(
    socket_path: &Path,
    host: &str,
    port: u16,
    method: EgressMethod,
    cancelled: &AtomicBool,
) -> io::Result<EgressAuthorization> {
    request_egress_authorization_inner(
        socket_path,
        host,
        port,
        method,
        EGRESS_ACK_TIMEOUT,
        EGRESS_DECISION_TIMEOUT,
        Some(cancelled),
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn request_egress_authorization_inner(
    socket_path: &Path,
    host: &str,
    port: u16,
    method: EgressMethod,
    acknowledgement_timeout: Duration,
    decision_timeout: Duration,
    cancelled: Option<&AtomicBool>,
    origin: Option<&[u8]>,
) -> io::Result<EgressAuthorization> {
    let mut broker = UnixStream::connect(socket_path)?;
    if let Some(origin) = origin {
        write_origin_frame(&mut broker, origin)?;
    }
    let host_length = u16::try_from(host.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "egress host is too long"))?;
    broker.write_all(EGRESS_BROKER_MAGIC_V2)?;
    broker.write_all(&host_length.to_be_bytes())?;
    broker.write_all(host.as_bytes())?;
    broker.write_all(&port.to_be_bytes())?;
    broker.write_all(&[method as u8])?;
    broker.flush()?;
    // macOS rejects clearing SO_RCVTIMEO on Unix-domain sockets after a
    // timeout has been installed. Use a temporary nonblocking read loop so an
    // allowed stream can return to genuinely blocking tunnel I/O.
    broker.set_nonblocking(true)?;

    let acknowledgement = read_phase_byte(
        &mut broker,
        acknowledgement_timeout,
        cancelled,
        "trusted egress acknowledgement timed out",
    )?;
    if acknowledgement != EGRESS_PENDING {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "trusted egress broker did not acknowledge the request",
        ));
    }

    let decision = read_phase_byte(
        &mut broker,
        decision_timeout,
        cancelled,
        "trusted egress decision timed out",
    )?;
    broker.set_nonblocking(false)?;
    match decision {
        EGRESS_ALLOWED => Ok(EgressAuthorization::Allowed(broker)),
        EGRESS_DENIED => Ok(EgressAuthorization::Denied),
        EGRESS_EXECUTION_FAILED => Ok(EgressAuthorization::ExecutionFailed),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "trusted egress broker returned an invalid terminal decision",
        )),
    }
}

fn read_phase_byte(
    stream: &mut UnixStream,
    timeout: Duration,
    cancelled: Option<&AtomicBool>,
    timeout_message: &'static str,
) -> io::Result<u8> {
    let deadline = Instant::now() + timeout;
    loop {
        if cancelled.is_some_and(|flag| flag.load(Ordering::Acquire)) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "trusted egress wait cancelled",
            ));
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(io::ErrorKind::TimedOut, timeout_message));
        }
        let mut response = [0_u8; 1];
        match stream.read_exact(&mut response) {
            Ok(()) => return Ok(response[0]),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(remaining.min(INTERRUPT_POLL_INTERVAL));
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
}

/// Identifies this crate as outside the trusted computing base.
pub const TRUST_CLASS: &str = "untrusted";

/// Destination asserted by an intercepted guest connection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Destination {
    /// A hostname from a TLS `ClientHello` server-name extension.
    Tls {
        /// Normalized ASCII hostname.
        host: String,
        /// Standard TLS port.
        port: u16,
    },
    /// An HTTP proxy CONNECT authority.
    Connect {
        /// Normalized ASCII hostname.
        host: String,
        /// Requested TCP port.
        port: u16,
    },
    /// A plaintext HTTP request target.
    Http {
        /// Normalized ASCII hostname.
        host: String,
        /// Requested TCP port.
        port: u16,
    },
}

/// Failure while classifying the beginning of a guest connection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParseError {
    /// More bytes are required before classification can finish.
    Incomplete,
    /// The bytes do not form a supported TLS `ClientHello` or HTTP request.
    Malformed(&'static str),
    /// A valid `ClientHello` did not contain a DNS server name.
    MissingServerName,
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Incomplete => formatter.write_str("connection prefix is incomplete"),
            Self::Malformed(reason) => write!(formatter, "malformed connection prefix: {reason}"),
            Self::MissingServerName => {
                formatter.write_str("TLS ClientHello has no DNS server name")
            }
        }
    }
}

impl Error for ParseError {}

/// Failure while reading and classifying a live guest stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AcceptError {
    /// Stream I/O failed.
    Io(String),
    /// Destination prefix was malformed.
    Parse(ParseError),
    /// Peer closed before sending a complete prefix.
    UnexpectedEof,
    /// Classification required more than the configured prefix bound.
    PrefixTooLarge(usize),
}

impl fmt::Display for AcceptError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "connection read failed: {error}"),
            Self::Parse(error) => error.fmt(formatter),
            Self::UnexpectedEof => {
                formatter.write_str("connection closed before destination classification")
            }
            Self::PrefixTooLarge(limit) => {
                write!(formatter, "connection prefix exceeds {limit} bytes")
            }
        }
    }
}

impl Error for AcceptError {}

/// A classified guest stream ready for handoff to trusted TLS handling.
pub struct AcceptedStream<S> {
    destination: Destination,
    stream: ReplayStream<S>,
}

impl<S> AcceptedStream<S> {
    /// Returns the untrusted destination assertion parsed from the stream.
    #[must_use]
    pub const fn destination(&self) -> &Destination {
        &self.destination
    }

    /// Splits the destination assertion from the byte-preserving stream.
    #[must_use]
    pub fn into_parts(self) -> (Destination, ReplayStream<S>) {
        (self.destination, self.stream)
    }
}

/// Stream wrapper that replays classification bytes before reading the socket.
pub struct ReplayStream<S> {
    prefix: Vec<u8>,
    offset: usize,
    inner: S,
}

impl<S> ReplayStream<S> {
    /// Returns the underlying transport.
    #[must_use]
    pub const fn get_ref(&self) -> &S {
        &self.inner
    }

    /// Recovers the underlying transport after all replay requirements end.
    #[must_use]
    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: Read> ReplayStream<S> {
    /// Buffers the complete HTTP header block, still to be replayed, and
    /// returns it without the terminating blank line.
    ///
    /// # Errors
    ///
    /// Returns an error if replay has started, the peer closes early, I/O
    /// fails, or the header block exceeds `max_header`.
    pub fn buffered_headers(&mut self, max_header: usize) -> Result<&[u8], AcceptError> {
        if self.offset != 0 {
            return Err(AcceptError::Io("replay already started".to_owned()));
        }
        loop {
            if let Some(end) = self
                .prefix
                .windows(4)
                .position(|bytes| bytes == b"\r\n\r\n")
            {
                return Ok(&self.prefix[..end]);
            }
            if self.prefix.len() >= max_header {
                return Err(AcceptError::PrefixTooLarge(max_header));
            }
            let mut chunk = [0_u8; 4096];
            let limit = (max_header - self.prefix.len()).min(chunk.len());
            let count = self
                .inner
                .read(&mut chunk[..limit])
                .map_err(|error| AcceptError::Io(error.to_string()))?;
            if count == 0 {
                return Err(AcceptError::UnexpectedEof);
            }
            self.prefix.extend_from_slice(&chunk[..count]);
        }
    }
}

impl<S: Read> Read for ReplayStream<S> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if self.offset < self.prefix.len() {
            let available = &self.prefix[self.offset..];
            let count = available.len().min(output.len());
            output[..count].copy_from_slice(&available[..count]);
            self.offset += count;
            return Ok(count);
        }
        self.inner.read(output)
    }
}

impl<S: Write> Write for ReplayStream<S> {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        self.inner.write(input)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Removes one complete HTTP CONNECT request from a classified replay stream
/// while preserving every byte already sent after its header terminator.
///
/// # Errors
///
/// Returns an error if the request closes early, I/O fails, or its headers
/// exceed `max_header`.
pub fn strip_connect_request<S: Read>(
    mut stream: ReplayStream<S>,
    max_header: usize,
) -> Result<ReplayStream<S>, AcceptError> {
    if max_header == 0 {
        return Err(AcceptError::PrefixTooLarge(0));
    }
    let mut consumed = Vec::with_capacity(max_header.min(16 * 1024));
    let mut chunk = [0_u8; 4096];
    loop {
        let count = stream
            .read(&mut chunk)
            .map_err(|error| AcceptError::Io(error.to_string()))?;
        if count == 0 {
            return Err(AcceptError::UnexpectedEof);
        }
        consumed.extend_from_slice(&chunk[..count]);
        if let Some(position) = consumed.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
            let body_start = position + 4;
            if body_start > max_header {
                return Err(AcceptError::PrefixTooLarge(max_header));
            }
            return Ok(ReplayStream {
                prefix: consumed.split_off(body_start),
                offset: 0,
                inner: stream.into_inner(),
            });
        }
        if consumed.len() >= max_header {
            return Err(AcceptError::PrefixTooLarge(max_header));
        }
    }
}

/// Reads a bounded destination prefix from a stream and preserves all consumed
/// bytes for the trusted handoff.
///
/// This accepts any stream transport, including the file descriptor delivered
/// by a macOS `VZVirtioSocketListener`.
///
/// # Errors
///
/// Returns an error on malformed input, I/O failure, early close, or when a
/// complete destination cannot be parsed within `max_prefix` bytes.
pub fn accept_stream<S: Read>(
    mut stream: S,
    max_prefix: usize,
) -> Result<AcceptedStream<S>, AcceptError> {
    if max_prefix == 0 {
        return Err(AcceptError::PrefixTooLarge(0));
    }
    let mut prefix = Vec::with_capacity(max_prefix.min(16 * 1024));
    loop {
        match parse_destination(&prefix) {
            Ok(destination) => {
                return Ok(AcceptedStream {
                    destination,
                    stream: ReplayStream {
                        prefix,
                        offset: 0,
                        inner: stream,
                    },
                });
            }
            Err(ParseError::Incomplete) => {}
            Err(error) => return Err(AcceptError::Parse(error)),
        }
        if prefix.len() == max_prefix {
            return Err(AcceptError::PrefixTooLarge(max_prefix));
        }
        let remaining = max_prefix - prefix.len();
        let mut buffer = [0_u8; 4096];
        let read_limit = remaining.min(buffer.len());
        let count = stream
            .read(&mut buffer[..read_limit])
            .map_err(|error| AcceptError::Io(error.to_string()))?;
        if count == 0 {
            return Err(AcceptError::UnexpectedEof);
        }
        prefix.extend_from_slice(&buffer[..count]);
    }
}

/// Parses either a TLS `ClientHello` or an HTTP request.
///
/// # Errors
///
/// Returns [`ParseError`] if the prefix is incomplete, malformed, or does not
/// name a destination.
pub fn parse_destination(prefix: &[u8]) -> Result<Destination, ParseError> {
    if prefix.first() == Some(&22) {
        parse_tls_sni(prefix).map(|host| Destination::Tls { host, port: 443 })
    } else {
        parse_http(prefix)
    }
}

fn parse_http(prefix: &[u8]) -> Result<Destination, ParseError> {
    let line_end = prefix
        .windows(2)
        .position(|window| window == b"\r\n")
        .ok_or(ParseError::Incomplete)?;
    let line = str::from_utf8(&prefix[..line_end])
        .map_err(|_| ParseError::Malformed("HTTP request line is not ASCII"))?;
    let mut fields = line.split_ascii_whitespace();
    let method = fields
        .next()
        .ok_or(ParseError::Malformed("HTTP method is missing"))?;
    let target = fields
        .next()
        .ok_or(ParseError::Malformed("HTTP request target is missing"))?;
    if fields.next() != Some("HTTP/1.1") || fields.next().is_some() {
        return Err(ParseError::Malformed("unsupported HTTP request line"));
    }
    if method == "CONNECT" {
        let (host, port) = parse_authority(target, None)?;
        return Ok(Destination::Connect { host, port });
    }
    if !method.bytes().all(|byte| byte.is_ascii_uppercase()) {
        return Err(ParseError::Malformed("HTTP method is invalid"));
    }

    let (host, port) = if let Some(absolute) = target.strip_prefix("http://") {
        let authority_end = absolute.find(['/', '?', '#']).unwrap_or(absolute.len());
        parse_authority(&absolute[..authority_end], Some(80))?
    } else if target.starts_with('/') {
        let headers_end = prefix
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .ok_or(ParseError::Incomplete)?;
        let headers = str::from_utf8(&prefix[line_end + 2..headers_end])
            .map_err(|_| ParseError::Malformed("HTTP headers are not ASCII"))?;
        let mut hosts = headers.lines().filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("host").then(|| value.trim())
        });
        let authority = hosts
            .next()
            .ok_or(ParseError::Malformed("HTTP Host header is missing"))?;
        if hosts.next().is_some() {
            return Err(ParseError::Malformed("multiple HTTP Host headers"));
        }
        parse_authority(authority, Some(80))?
    } else {
        return Err(ParseError::Malformed("unsupported HTTP request target"));
    };
    Ok(Destination::Http { host, port })
}

fn parse_authority(
    authority: &str,
    default_port: Option<u16>,
) -> Result<(String, u16), ParseError> {
    if authority.is_empty() || authority.contains('@') {
        return Err(ParseError::Malformed("HTTP authority is invalid"));
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => {
            let port = port
                .parse::<u16>()
                .ok()
                .filter(|port| *port != 0)
                .ok_or_else(|| {
                    ParseError::Malformed(if default_port.is_none() {
                        "CONNECT port is invalid"
                    } else {
                        "HTTP port is invalid"
                    })
                })?;
            (host, port)
        }
        None => (
            authority,
            default_port.ok_or(ParseError::Malformed("CONNECT port is missing"))?,
        ),
    };
    Ok((normalize_dns_name(host)?, port))
}

fn parse_tls_sni(input: &[u8]) -> Result<String, ParseError> {
    let record_length = usize::from(read_u16(input, 3)?);
    let record = slice(input, 5, record_length)?;
    if record.first() != Some(&1) {
        return Err(ParseError::Malformed("TLS handshake is not a ClientHello"));
    }
    let hello_length = read_u24(record, 1)?;
    let hello = slice(record, 4, hello_length)?;

    let mut cursor = 2 + 32;
    let session_length = usize::from(*hello.get(cursor).ok_or(ParseError::Incomplete)?);
    cursor = checked_advance(cursor, 1 + session_length)?;
    let cipher_length = usize::from(read_u16(hello, cursor)?);
    cursor = checked_advance(cursor, 2 + cipher_length)?;
    let compression_length = usize::from(*hello.get(cursor).ok_or(ParseError::Incomplete)?);
    cursor = checked_advance(cursor, 1 + compression_length)?;
    let all_extensions_length = usize::from(read_u16(hello, cursor)?);
    cursor = checked_advance(cursor, 2)?;
    let extensions = slice(hello, cursor, all_extensions_length)?;

    let mut extension_cursor = 0;
    while extension_cursor < extensions.len() {
        let extension_type = read_u16(extensions, extension_cursor)?;
        let payload_length = usize::from(read_u16(extensions, extension_cursor + 2)?);
        extension_cursor = checked_advance(extension_cursor, 4)?;
        let extension = slice(extensions, extension_cursor, payload_length)?;
        extension_cursor = checked_advance(extension_cursor, payload_length)?;
        if extension_type == 0 {
            return parse_server_name_extension(extension);
        }
    }
    Err(ParseError::MissingServerName)
}

fn parse_server_name_extension(extension: &[u8]) -> Result<String, ParseError> {
    let list_length = usize::from(read_u16(extension, 0)?);
    let names = slice(extension, 2, list_length)?;
    let mut cursor = 0;
    while cursor < names.len() {
        let name_type = *names.get(cursor).ok_or(ParseError::Incomplete)?;
        let dns_length = usize::from(read_u16(names, cursor + 1)?);
        cursor = checked_advance(cursor, 3)?;
        let name = slice(names, cursor, dns_length)?;
        cursor = checked_advance(cursor, dns_length)?;
        if name_type == 0 {
            let name = str::from_utf8(name)
                .map_err(|_| ParseError::Malformed("SNI is not an ASCII DNS name"))?;
            return normalize_dns_name(name);
        }
    }
    Err(ParseError::MissingServerName)
}

fn normalize_dns_name(host: &str) -> Result<String, ParseError> {
    let host = host.strip_suffix('.').unwrap_or(host);
    let valid = !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        });
    if !valid {
        return Err(ParseError::Malformed("destination is not a DNS name"));
    }
    Ok(host.to_ascii_lowercase())
}

fn checked_advance(cursor: usize, amount: usize) -> Result<usize, ParseError> {
    cursor
        .checked_add(amount)
        .ok_or(ParseError::Malformed("length overflow"))
}

fn slice(input: &[u8], offset: usize, length: usize) -> Result<&[u8], ParseError> {
    let end = checked_advance(offset, length)?;
    input.get(offset..end).ok_or(ParseError::Incomplete)
}

fn read_u16(input: &[u8], offset: usize) -> Result<u16, ParseError> {
    let bytes: [u8; 2] = slice(input, offset, 2)?
        .try_into()
        .map_err(|_| ParseError::Incomplete)?;
    Ok(u16::from_be_bytes(bytes))
}

fn read_u24(input: &[u8], offset: usize) -> Result<usize, ParseError> {
    let bytes = slice(input, offset, 3)?;
    Ok((usize::from(bytes[0]) << 16) | (usize::from(bytes[1]) << 8) | usize::from(bytes[2]))
}

#[cfg(test)]
mod tests {
    #[test]
    fn origin_frames_round_trip_and_are_mandatory_when_read() {
        let mut frame = Vec::new();
        super::write_origin_frame(&mut frame, br#"{"known":true}"#).expect("write");
        assert_eq!(
            super::read_origin_frame(&mut frame.as_slice()).expect("read"),
            br#"{"known":true}"#
        );
        assert!(super::read_origin_frame(&mut b"CONNECT example.com:443".as_slice()).is_err());
        let mut oversized = Vec::new();
        super::write_origin_frame(&mut oversized, &vec![b'x'; super::MAX_ORIGIN_BYTES + 1])
            .expect("write");
        assert!(
            super::read_origin_frame(&mut oversized.as_slice())
                .expect("read")
                .is_empty()
        );
    }

    use super::{
        AcceptError, Destination, EGRESS_BROKER_MAGIC_V2, EgressAuthorization, EgressMethod,
        ParseError, accept_stream, parse_destination, request_egress_authorization_inner,
        strip_connect_request,
    };
    use keel_secrets::{TestMitmCa, terminate_stream_once};
    use rustls::{
        ClientConfig, ClientConnection, RootCertStore, StreamOwned, pki_types::ServerName,
    };
    use std::{
        fs,
        io::{Cursor, Read, Write},
        net::{Ipv4Addr, TcpListener, TcpStream},
        os::unix::net::UnixListener,
        path::PathBuf,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        thread,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    struct Chunked {
        inner: Cursor<Vec<u8>>,
        max_read: usize,
    }

    impl Read for Chunked {
        fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
            let count = output.len().min(self.max_read);
            self.inner.read(&mut output[..count])
        }
    }

    fn broker_socket(name: &str) -> (PathBuf, PathBuf, UnixListener) {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        #[cfg(target_os = "macos")]
        let temporary_root = PathBuf::from("/tmp");
        #[cfg(not(target_os = "macos"))]
        let temporary_root = std::env::temp_dir();
        let root =
            temporary_root.join(format!("keel-conn-{name}-{}-{nonce:x}", std::process::id()));
        fs::create_dir(&root).expect("broker root");
        let socket = root.join("broker.sock");
        let listener = UnixListener::bind(&socket).expect("broker listener");
        (root, socket, listener)
    }

    fn read_egress_request(listener: &UnixListener) -> std::os::unix::net::UnixStream {
        let (mut stream, _) = listener.accept().expect("broker accept");
        let mut magic = [0_u8; 15];
        stream.read_exact(&mut magic).expect("protocol marker");
        assert_eq!(&magic, EGRESS_BROKER_MAGIC_V2);
        let mut host_length = [0_u8; 2];
        stream.read_exact(&mut host_length).expect("host length");
        let mut host = vec![0_u8; usize::from(u16::from_be_bytes(host_length))];
        stream.read_exact(&mut host).expect("host");
        assert_eq!(host, b"example.com");
        let mut suffix = [0_u8; 3];
        stream.read_exact(&mut suffix).expect("port and method");
        assert_eq!(suffix, [1, 187, EgressMethod::Connect as u8]);
        stream
    }

    #[test]
    fn egress_waits_for_delayed_terminal_decision_after_pending_ack() {
        let (root, socket, listener) = broker_socket("delayed-allow");
        let broker = thread::spawn(move || {
            let mut stream = read_egress_request(&listener);
            stream.write_all(b"P").expect("pending");
            stream.flush().expect("pending flush");
            thread::sleep(Duration::from_millis(75));
            stream.write_all(b"A").expect("allow");
        });

        let authorization = request_egress_authorization_inner(
            &socket,
            "example.com",
            443,
            EgressMethod::Connect,
            Duration::from_millis(50),
            Duration::from_millis(250),
            None,
            None,
        )
        .expect("two-stage authorization");
        assert!(matches!(authorization, EgressAuthorization::Allowed(_)));
        broker.join().expect("broker thread");
        fs::remove_dir_all(root).expect("remove broker root");
    }

    #[test]
    fn egress_rejects_a_terminal_decision_without_pending_ack() {
        let (root, socket, listener) = broker_socket("missing-pending");
        let broker = thread::spawn(move || {
            let mut stream = read_egress_request(&listener);
            stream.write_all(b"A").expect("legacy allow");
        });

        let error = request_egress_authorization_inner(
            &socket,
            "example.com",
            443,
            EgressMethod::Connect,
            Duration::from_millis(100),
            Duration::from_millis(100),
            None,
            None,
        )
        .expect_err("a V1-style response must fail closed");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        broker.join().expect("broker thread");
        fs::remove_dir_all(root).expect("remove broker root");
    }

    #[test]
    fn egress_pending_without_a_terminal_decision_times_out() {
        let (root, socket, listener) = broker_socket("missing-decision");
        let broker = thread::spawn(move || {
            let mut stream = read_egress_request(&listener);
            stream.write_all(b"P").expect("pending");
            stream.flush().expect("pending flush");
            thread::sleep(Duration::from_millis(150));
        });

        let error = request_egress_authorization_inner(
            &socket,
            "example.com",
            443,
            EgressMethod::Connect,
            Duration::from_millis(100),
            Duration::from_millis(25),
            None,
            None,
        )
        .expect_err("a pending acknowledgement is not authority");
        assert!(matches!(
            error.kind(),
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
        ));
        broker.join().expect("broker thread");
        fs::remove_dir_all(root).expect("remove broker root");
    }

    #[test]
    fn egress_wait_can_be_cancelled_during_trusted_takeover() {
        let (root, socket, listener) = broker_socket("cancelled");
        let broker = thread::spawn(move || {
            let mut stream = read_egress_request(&listener);
            stream.write_all(b"P").expect("pending");
            stream.flush().expect("pending flush");
            thread::sleep(Duration::from_millis(500));
        });
        let cancelled = Arc::new(AtomicBool::new(false));
        let cancellation = Arc::clone(&cancelled);
        let cancel = thread::spawn(move || {
            thread::sleep(Duration::from_millis(25));
            cancellation.store(true, Ordering::Release);
        });

        let error = request_egress_authorization_inner(
            &socket,
            "example.com",
            443,
            EgressMethod::Connect,
            Duration::from_millis(100),
            Duration::from_secs(1),
            Some(&cancelled),
            None,
        )
        .expect_err("shutdown cancellation must interrupt the decision wait");
        assert_eq!(error.kind(), std::io::ErrorKind::Interrupted);
        cancel.join().expect("cancellation thread");
        broker.join().expect("broker thread");
        fs::remove_dir_all(root).expect("remove broker root");
    }

    fn wire_u16(length: usize) -> [u8; 2] {
        u16::try_from(length)
            .expect("test fixture length fits on the wire")
            .to_be_bytes()
    }

    fn client_hello(host: &str) -> Vec<u8> {
        let mut server_name = Vec::new();
        server_name.extend_from_slice(&wire_u16(host.len() + 3));
        server_name.push(0);
        server_name.extend_from_slice(&wire_u16(host.len()));
        server_name.extend_from_slice(host.as_bytes());

        let mut extensions = Vec::new();
        extensions.extend_from_slice(&0_u16.to_be_bytes());
        extensions.extend_from_slice(&wire_u16(server_name.len()));
        extensions.extend_from_slice(&server_name);

        let mut hello = Vec::new();
        hello.extend_from_slice(&[3, 3]);
        hello.extend_from_slice(&[0; 32]);
        hello.push(0);
        hello.extend_from_slice(&2_u16.to_be_bytes());
        hello.extend_from_slice(&0x1301_u16.to_be_bytes());
        hello.push(1);
        hello.push(0);
        hello.extend_from_slice(&wire_u16(extensions.len()));
        hello.extend_from_slice(&extensions);

        let hello_length = u32::try_from(hello.len())
            .expect("test ClientHello length fits on the wire")
            .to_be_bytes();
        let mut handshake = vec![1, hello_length[1], hello_length[2], hello_length[3]];
        handshake.extend_from_slice(&hello);

        let mut record = vec![22, 3, 1];
        record.extend_from_slice(&wire_u16(handshake.len()));
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn extracts_and_normalizes_client_hello_sni() {
        assert_eq!(
            parse_destination(&client_hello("Docs.Example.")).unwrap(),
            Destination::Tls {
                host: "docs.example".to_owned(),
                port: 443,
            }
        );
    }

    #[test]
    fn parses_connect_authority() {
        assert_eq!(
            parse_destination(b"CONNECT Registry.Example:8443 HTTP/1.1\r\nHost: ignored\r\n")
                .unwrap(),
            Destination::Connect {
                host: "registry.example".to_owned(),
                port: 8443,
            }
        );
    }

    #[test]
    fn parses_plain_http_absolute_and_origin_targets() {
        assert_eq!(
            parse_destination(
                b"GET http://Docs.Example:8080/index HTTP/1.1\r\nHost: ignored.example\r\n\r\n"
            )
            .unwrap(),
            Destination::Http {
                host: "docs.example".to_owned(),
                port: 8080,
            }
        );
        assert_eq!(
            parse_destination(b"POST /v1/messages HTTP/1.1\r\nHost: API.Example\r\n\r\n").unwrap(),
            Destination::Http {
                host: "api.example".to_owned(),
                port: 80,
            }
        );
    }

    #[test]
    fn rejects_ambiguous_plain_http_authorities() {
        assert!(matches!(
            parse_destination(b"GET / HTTP/1.1\r\nHost: one.example\r\nHost: two.example\r\n\r\n"),
            Err(ParseError::Malformed("multiple HTTP Host headers"))
        ));
        assert!(matches!(
            parse_destination(b"GET http://user@docs.example/ HTTP/1.1\r\n\r\n"),
            Err(ParseError::Malformed("HTTP authority is invalid"))
        ));
    }

    #[test]
    fn rejects_missing_sni_and_invalid_names() {
        let mut hello = client_hello("valid.example");
        let position = hello
            .windows("valid.example".len())
            .position(|bytes| bytes == b"valid.example")
            .unwrap();
        hello[position] = b'_';
        assert!(matches!(
            parse_destination(&hello),
            Err(ParseError::Malformed("destination is not a DNS name"))
        ));
        assert_eq!(
            parse_destination(b"CONNECT metadata:abc HTTP/1.1\r\n"),
            Err(ParseError::Malformed("CONNECT port is invalid"))
        );
    }

    #[test]
    fn reports_incomplete_records_without_panicking() {
        let hello = client_hello("docs.example");
        for length in 0..hello.len() {
            assert!(parse_destination(&hello[..length]).is_err());
        }
    }

    #[test]
    fn acceptor_handles_partial_reads_and_replays_every_byte() {
        let bytes =
            b"CONNECT Registry.Example:8443 HTTP/1.1\r\nHost: ignored\r\n\r\ninner-bytes".to_vec();
        let accepted = accept_stream(
            Chunked {
                inner: Cursor::new(bytes.clone()),
                max_read: 3,
            },
            4096,
        )
        .expect("complete CONNECT prefix");
        assert_eq!(
            accepted.destination(),
            &Destination::Connect {
                host: "registry.example".to_owned(),
                port: 8443,
            }
        );

        let (_, mut replay) = accepted.into_parts();
        let mut observed = Vec::new();
        replay.read_to_end(&mut observed).expect("replay stream");
        assert_eq!(observed, bytes);
    }

    #[test]
    fn connect_stripping_preserves_pipelined_tunnel_bytes() {
        let bytes =
            b"CONNECT Registry.Example:8443 HTTP/1.1\r\nHost: ignored\r\n\r\ninner-bytes".to_vec();
        let accepted = accept_stream(
            Chunked {
                inner: Cursor::new(bytes),
                max_read: 3,
            },
            4096,
        )
        .expect("complete CONNECT prefix");
        let (_, replay) = accepted.into_parts();
        let mut tunnel = strip_connect_request(replay, 4096).expect("complete CONNECT request");
        let mut observed = Vec::new();
        tunnel.read_to_end(&mut observed).expect("tunnel stream");
        assert_eq!(observed, b"inner-bytes");

        let accepted = accept_stream(
            Cursor::new(b"CONNECT relay.example:443 HTTP/1.1\r\n\r\n".to_vec()),
            4096,
        )
        .expect("complete CONNECT prefix");
        let (_, replay) = accepted.into_parts();
        assert!(matches!(
            strip_connect_request(replay, 8),
            Err(AcceptError::PrefixTooLarge(8))
        ));
    }

    #[test]
    fn acceptor_bounds_incomplete_and_malformed_prefixes() {
        let oversized = accept_stream(Cursor::new(b"CONNECT ".to_vec()), 8);
        assert!(matches!(oversized, Err(AcceptError::PrefixTooLarge(8))));

        let malformed = accept_stream(Cursor::new(b"TRACE somewhere HTTP/1.1\r\n".to_vec()), 4096);
        assert!(matches!(
            malformed,
            Err(AcceptError::Parse(ParseError::Malformed(
                "unsupported HTTP request target"
            )))
        ));
    }

    #[test]
    fn classified_stream_hands_every_tls_byte_to_trusted_termination() {
        let ca = TestMitmCa::generate().expect("test CA");
        let server_config = ca.server_config("relay.example").expect("server config");
        let mut roots = RootCertStore::empty();
        roots.add(ca.certificate_der()).expect("test root");
        let client_config = Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("listener");
        let address = listener.local_addr().expect("listener address");
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            let accepted = accept_stream(stream, 64 * 1024).expect("classify TLS");
            assert_eq!(
                accepted.destination(),
                &Destination::Tls {
                    host: "relay.example".to_owned(),
                    port: 443,
                }
            );
            let (_, replay) = accepted.into_parts();
            terminate_stream_once(replay, server_config, |_| {
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_vec()
            })
            .expect("trusted TLS termination");
        });

        let connection = ClientConnection::new(
            client_config,
            ServerName::try_from("relay.example".to_owned()).expect("server name"),
        )
        .expect("client");
        let mut client =
            StreamOwned::new(connection, TcpStream::connect(address).expect("connect"));
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: relay.example\r\n\r\n")
            .expect("request");
        let mut response = String::new();
        client.read_to_string(&mut response).expect("response");
        server.join().expect("server thread");
        assert!(response.ends_with("ok"));
    }
}
