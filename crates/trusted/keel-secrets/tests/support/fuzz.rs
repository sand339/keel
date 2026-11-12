//! Randomized property tests of the trusted request, response, and
//! credential parsers.
//!
//! These are not coverage-guided: each starts from valid inputs and mutates
//! them with a fixed seed, so a run is deterministic and a failure names the
//! iteration that produced it. They run with the unit tests on every push;
//! `KEEL_FUZZ_ITERATIONS` raises the count for a longer run.

use super::git_vault;
use crate::{
    ConnectionTarget, CredentialSources, EgressDestination, SystemEgressConnector,
    chunked_message_length, complete_event_stream_events, decode_base64, decode_chunked,
    decode_event_stream, interrupted_usage_bound, is_forbidden_ip, origin_form_request,
    parse_credential_process_output, parse_model_usage, parse_utc_timestamp, read_http_request,
    rebuild_http_request, request_line,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// xorshift64*: small, seeded, and good enough to pick mutations.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, bound: usize) -> usize {
        usize::try_from(self.next() % u64::try_from(bound.max(1)).unwrap()).unwrap()
    }

    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }
}

fn iterations() -> usize {
    std::env::var("KEEL_FUZZ_ITERATIONS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(20_000)
}

/// Bytes that mean something to an HTTP or JSON parser.
const TOKENS: &[&[u8]] = &[
    b"\r\n",
    b"\r\n\r\n",
    b"\n",
    b"\r",
    b" ",
    b"\t",
    b"\0",
    b"/",
    b"//",
    b"#",
    b"?",
    b"@",
    b":",
    b"*",
    b"http://",
    b"https://",
    b"HTTP/1.1",
    b"Host: ",
    b"Content-Length: ",
    b"Content-Length: 18446744073709551616\r\n",
    b"Content-Length: -1\r\n",
    b"Transfer-Encoding: chunked\r\n",
    b"0\r\n\r\n",
    b"ffffffffffffffff\r\n",
    b"Authorization: Bearer ",
    b"keel-git-credential-sentinel-v1",
    b"keel-anthropic-credential-sentinel-v1",
    b"packages.example",
    b"169.254.169.254",
    b"%0d%0a",
    b"\xff\xfe",
    b"{",
    b"}",
    b"\"",
    b"\\u0000",
];

/// One or more random edits of one of the valid inputs.
fn mutate(rng: &mut Rng, seeds: &[&[u8]]) -> Vec<u8> {
    let mut bytes = rng.pick(seeds).to_vec();
    for _ in 0..=rng.below(4) {
        let at = rng.below(bytes.len() + 1);
        match rng.below(6) {
            0 if !bytes.is_empty() => {
                let index = rng.below(bytes.len());
                bytes[index] ^= 1 << rng.below(8);
            }
            1 if !bytes.is_empty() => {
                let end = (at + rng.below(8)).min(bytes.len());
                bytes.drain(at.min(end)..end);
            }
            2 => {
                let token = *rng.pick(TOKENS);
                bytes.splice(at..at, token.iter().copied());
            }
            3 if !bytes.is_empty() => {
                let start = rng.below(bytes.len());
                let end = (start + rng.below(16)).min(bytes.len());
                let copy = bytes[start..end].to_vec();
                bytes.splice(at..at, copy);
            }
            4 => bytes.truncate(at),
            _ => {
                let byte = u8::try_from(rng.below(256)).unwrap();
                bytes.insert(at, byte);
            }
        }
    }
    bytes
}

const REQUESTS: &[&[u8]] = &[
    b"GET /crate?x=1 HTTP/1.1\r\nHost: packages.example\r\nAccept: */*\r\n\r\n",
    b"GET http://packages.example/crate HTTP/1.1\r\nHost: packages.example\r\n\r\n",
    b"GET http://packages.example:80/ HTTP/1.1\r\nHost: other.example\r\n\r\n",
    b"POST /upload HTTP/1.1\r\nHost: packages.example\r\nContent-Length: 4\r\n\r\nbody",
    b"POST /v1 HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nbody\r\n0\r\n\r\n",
    b"GET /owner/repo/info/refs?service=git-receive-pack HTTP/1.1\r\nAuthorization: Bearer keel-git-credential-sentinel-v1\r\n\r\n",
];

fn destination() -> EgressDestination {
    EgressDestination {
        server_name: "packages.example".to_owned(),
        port: 80,
    }
}

/// Whatever a request line is turned into, the kernel is shown a path: never
/// an absolute or network-path target, never a fragment, and an `http://`
/// target only for the host this connection was authorized for (KSR-047).
#[test]
fn a_request_target_is_always_reduced_to_a_path_on_the_authorized_host() {
    let mut rng = Rng(0x4b45_454c_0001);
    let destination = destination();
    for iteration in 0..iterations() {
        let request = mutate(&mut rng, REQUESTS);
        let named = std::str::from_utf8(&request)
            .ok()
            .and_then(|text| text.lines().next())
            .and_then(|line| line.split(' ').nth(1))
            .and_then(|target| target.strip_prefix("http://"))
            .map(|rest| {
                let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
                rest[..end].to_ascii_lowercase()
            });
        let Ok(rewritten) = origin_form_request(request.clone(), &destination) else {
            continue;
        };
        if let Some(authority) = named
            && rewritten != request
        {
            assert!(
                authority == "packages.example" || authority == "packages.example:80",
                "iteration {iteration}: an absolute target for {authority:?} was taken"
            );
        }
        if let Ok((_, path)) = request_line(&rewritten) {
            assert!(
                path.starts_with('/') && !path.starts_with("//") && !path.contains('#'),
                "iteration {iteration}: target {path:?} is not origin form"
            );
        }
    }
}

/// A reader that hands out the bytes in pieces of random size, as a socket
/// does.
struct Pieces<'a> {
    bytes: &'a [u8],
    rng: Rng,
}

impl std::io::Read for Pieces<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let count = (1 + self.rng.below(64))
            .min(self.bytes.len())
            .min(buffer.len());
        buffer[..count].copy_from_slice(&self.bytes[..count]);
        self.bytes = &self.bytes[count..];
        Ok(count)
    }
}

/// Reading a request never panics or runs past its bound, however the bytes
/// arrive, and what it returns is a prefix of what was sent.
#[test]
fn reading_a_request_is_bounded_and_returns_what_was_sent() {
    let mut rng = Rng(0x4b45_454c_0002);
    for iteration in 0..iterations() {
        let request = mutate(&mut rng, REQUESTS);
        let mut pieces = Pieces {
            bytes: &request,
            rng: Rng(rng.next() | 1),
        };
        if let Ok(read) = read_http_request(&mut pieces) {
            assert!(
                read.len() <= crate::MAX_HTTP_REQUEST,
                "iteration {iteration}: read {} bytes",
                read.len()
            );
            assert!(
                request.starts_with(&read),
                "iteration {iteration}: the request read is not what was sent"
            );
        }
    }
}

/// A request rebuilt for the upstream names the connected host exactly once,
/// whatever `Host` headers the guest sent.
#[test]
fn a_rebuilt_request_names_only_the_connected_host() {
    let mut rng = Rng(0x4b45_454c_0003);
    let target = ConnectionTarget {
        server_name: "packages.example".to_owned(),
        resolved_ip: Ipv4Addr::new(93, 184, 216, 34).into(),
        port: 443,
    };
    for iteration in 0..iterations() {
        let request = mutate(&mut rng, REQUESTS);
        // The proxy rebuilds only a request whose line it has already parsed.
        if request_line(&request).is_err() {
            continue;
        }
        let Ok(rebuilt) = rebuild_http_request(&request, b"", &target, rng.below(2) == 0) else {
            continue;
        };
        let end = rebuilt
            .windows(4)
            .position(|bytes| bytes == b"\r\n\r\n")
            .unwrap_or(rebuilt.len());
        let head = String::from_utf8_lossy(&rebuilt[..end]).to_ascii_lowercase();
        // Read the head as the most lenient upstream would: any CR or LF ends
        // a line, and space around a name is ignored.
        let lines = head.split(['\r', '\n']).collect::<Vec<_>>();
        let named = |wanted: &str| {
            lines
                .iter()
                .filter_map(|line| line.split_once(':'))
                .filter(|(name, _)| name.trim() == wanted)
                .map(|(_, value)| value.trim().to_owned())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            named("host"),
            ["packages.example"],
            "iteration {iteration}: {head:?}"
        );
        assert_eq!(
            named("content-length"),
            ["0"],
            "iteration {iteration}: {head:?}"
        );
        assert!(
            named("transfer-encoding").is_empty(),
            "iteration {iteration}: {head:?}"
        );
        assert_eq!(
            rebuilt.len(),
            end + 4,
            "iteration {iteration}: bytes follow the head: {head:?}"
        );
    }
}

/// A sentinel never leaves in a request that was not its exact, authorized
/// use, and the real credential never appears for another host.
#[test]
fn sentinels_and_credentials_do_not_escape_their_scope() {
    let mut rng = Rng(0x4b45_454c_0004);
    let vault = git_vault();
    let elsewhere = ConnectionTarget {
        server_name: "other.example".to_owned(),
        resolved_ip: Ipv4Addr::new(93, 184, 216, 34).into(),
        port: 443,
    };
    let sentinel = SystemEgressConnector::GIT_SENTINEL.as_bytes();
    let contains = |bytes: &[u8], needle: &[u8]| bytes.windows(needle.len()).any(|w| w == needle);
    for iteration in 0..iterations() {
        let request = mutate(&mut rng, REQUESTS);
        if let Ok(passed) = vault.refuse_sentinels(request.clone()) {
            assert!(
                !contains(&passed, sentinel),
                "iteration {iteration}: a sentinel passed the plain path"
            );
        }
        if let Ok(injected) = vault.inject(&elsewhere, &request) {
            assert!(
                !contains(&injected, b"real-credential"),
                "iteration {iteration}: the credential was injected for another host"
            );
        }
    }
}

const RESPONSES: &[&[u8]] = &[
    b"4\r\nbody\r\n0\r\n\r\n",
    b"1a\r\nabcdefghijklmnopqrstuvwxyz\r\n0\r\nTrailer: x\r\n\r\n",
    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 62\r\n\r\n{\"usage\":{\"input_tokens\":3,\"output_tokens\":5},\"type\":\"message\"}",
    b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\nevent: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":3}}}\n\nevent: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":5}}\n\n",
    b"{\"Version\":1,\"AccessKeyId\":\"AKIDEXAMPLE\",\"SecretAccessKey\":\"secret\",\"SessionToken\":\"token\",\"Expiration\":\"2030-01-02T03:04:05Z\"}",
    b"2030-01-02T03:04:05.123+01:00",
    b"eyJ0eXBlIjoibWVzc2FnZSJ9",
    b"{\"version\":1,\"providers\":{\"api-key\":{\"source\":{\"kind\":\"process\",\"command\":\"pass show keel/anthropic\"},\"hint\":\"unlock\"}},\"github\":{\"source\":{\"kind\":\"env\",\"variable\":\"GH_TOKEN\"}}}",
];

/// None of the response and credential decoders panics, hangs, or reserves
/// memory for a length the input only claims.
#[test]
fn decoders_survive_malformed_input() {
    let mut rng = Rng(0x4b45_454c_0005);
    for _ in 0..iterations() {
        let bytes = mutate(&mut rng, RESPONSES);
        let _ = decode_chunked(&bytes);
        let _ = chunked_message_length(&bytes);
        let _ = decode_event_stream(&bytes);
        let _ = complete_event_stream_events(&bytes);
        let _ = parse_model_usage(&bytes);
        let _ = interrupted_usage_bound(&bytes);
        let _ = parse_credential_process_output(&bytes);
        if let Ok(text) = std::str::from_utf8(&bytes) {
            let _ = decode_base64(text);
            let _ = parse_utc_timestamp(text);
        }
        if let Ok(sources) = CredentialSources::parse(&bytes) {
            for line in sources.describe(Some("api-key"), true) {
                assert!(
                    line.len() < 600 && !line.chars().any(char::is_control),
                    "a source that parsed is not short printable text: {line:?}"
                );
            }
        }
    }
}

/// An IPv6 address that carries a forbidden IPv4 address is forbidden too,
/// in every embedding a resolver might return.
#[test]
fn a_forbidden_ipv4_address_is_forbidden_in_every_ipv6_form() {
    let mut rng = Rng(0x4b45_454c_0006);
    let special = [
        [127, 0, 0, 1],
        [10, 0, 0, 1],
        [172, 16, 0, 1],
        [192, 168, 1, 1],
        [169, 254, 169, 254],
        [100, 64, 0, 1],
        [0, 0, 0, 0],
        [255, 255, 255, 255],
        [224, 0, 0, 1],
    ];
    for iteration in 0..iterations() {
        let octets = if rng.below(2) == 0 {
            *rng.pick(&special)
        } else {
            let bits = u32::try_from(rng.next() & 0xffff_ffff).unwrap();
            bits.to_be_bytes()
        };
        let v4 = Ipv4Addr::from(octets);
        if !is_forbidden_ip(IpAddr::V4(v4)) {
            continue;
        }
        let [a, b, c, d] = octets;
        let high = u16::from_be_bytes([a, b]);
        let low = u16::from_be_bytes([c, d]);
        for (form, address) in [
            ("mapped", v4.to_ipv6_mapped()),
            ("compatible", Ipv6Addr::new(0, 0, 0, 0, 0, 0, high, low)),
            ("NAT64", Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, high, low)),
            ("6to4", Ipv6Addr::new(0x2002, high, low, 0, 0, 0, 0, 1)),
        ] {
            assert!(
                is_forbidden_ip(IpAddr::V6(address)),
                "iteration {iteration}: {v4} is forbidden, but its {form} form {address} is not"
            );
        }
    }
}
