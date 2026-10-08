use super::{
    AwsCredentialSource, AwsCredentials, ConnectionTarget, CredentialBinding, CredentialScope,
    CredentialVault, EgressDestination, MitmCa, ModelBudgetRequest, ModelEndpoint, ModelUsage,
    OAuthCredential, OAuthRefresher, RefreshedToken, RuntimeCredentialValues, SecretBytes,
    SigV4Signer, SystemEgressConnector, TestMitmCa, TlsError, canonical_request_uri,
    encode_lower_hex, forward_http_once, is_forbidden_ip, model_budget_request,
    parse_credential_process_output, parse_model_usage, parse_utc_timestamp,
    prepare_upstream_request_with_authorizer, proxy_plain_http_once, proxy_tls_http,
    read_http_request_optional, relay_http_response, runtime_model_provider_from,
    sanitize_model_request, sigv4_signature, sigv4_timestamps, terminate_http_once,
};
use keel_audit::{AuditPayload, AuditWriter, RunKey};
use keel_kernel::EgressRequestAuthorizer;
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, ServerConnection, StreamOwned,
    pki_types::ServerName,
};
use serde_json::Value;
use std::{
    collections::{BTreeMap, VecDeque},
    fs,
    io::{Read as _, Write as _},
    net::{IpAddr, Ipv4Addr, TcpListener, TcpStream},
    os::unix::net::UnixStream,
    path::Path,
    sync::Arc,
    thread,
    time::{SystemTime, UNIX_EPOCH},
};

struct IdleThenTimeout {
    first: Option<Vec<u8>>,
}

impl std::io::Read for IdleThenTimeout {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        match self.first.take() {
            Some(bytes) => {
                buffer[..bytes.len()].copy_from_slice(&bytes);
                Ok(bytes.len())
            }
            None => Err(std::io::Error::from(std::io::ErrorKind::TimedOut)),
        }
    }
}

#[test]
fn an_idle_reusable_connection_ends_instead_of_failing() {
    // The guest holds a keep-alive connection open after its last request.
    // That silence is the end of the conversation, not a proxy failure.
    let mut idle = IdleThenTimeout { first: None };
    assert_eq!(read_http_request_optional(&mut idle).unwrap(), None);

    // A request that stops halfway is still an error worth reporting.
    let mut truncated = IdleThenTimeout {
        first: Some(b"POST /v1/messages HTTP/1.1\r\nContent-Length: 9\r\n\r\n".to_vec()),
    };
    let error = read_http_request_optional(&mut truncated).unwrap_err();
    assert_eq!(error.0, "TLS request: timed out");
}

struct ModelAuthorizer;

impl EgressRequestAuthorizer for ModelAuthorizer {
    fn authorize(
        &mut self,
        method: &str,
        path: &str,
        _body_digest: [u8; 32],
        model_budget: Option<ModelBudgetRequest>,
    ) -> Result<(), String> {
        if method == "POST" && path.split('?').next() == Some("/v1/messages") {
            let budget = model_budget.ok_or_else(|| "missing model budget".to_owned())?;
            assert!(budget.input_tokens_upper_bound > 0);
            assert_eq!(budget.max_output_tokens, 32);
            Ok(())
        } else {
            Err(format!("model endpoint denied {method} {path}"))
        }
    }

    fn record_model_usage(&mut self, usage: ModelUsage) -> Result<(), String> {
        assert_eq!(usage.input_tokens, 3);
        assert_eq!(usage.output_tokens, 1);
        Ok(())
    }

    fn record_response(&mut self) -> Result<(), String> {
        Ok(())
    }
}

struct ExpectedAuthorizer {
    method: &'static str,
    path: &'static str,
}

impl EgressRequestAuthorizer for ExpectedAuthorizer {
    fn authorize(
        &mut self,
        method: &str,
        path: &str,
        _body_digest: [u8; 32],
        model_budget: Option<ModelBudgetRequest>,
    ) -> Result<(), String> {
        assert_eq!(method, self.method);
        assert_eq!(path, self.path);
        assert!(model_budget.is_none());
        Ok(())
    }

    fn record_response(&mut self) -> Result<(), String> {
        Ok(())
    }
}

#[test]
fn ephemeral_ca_terminates_a_host_bound_tls_connection() {
    let ca = TestMitmCa::generate().unwrap();
    let front_config = ca.server_config("registry.keel.test").unwrap();
    let upstream_config = ca.server_config("upstream.keel.test").unwrap();
    let upstream_root = ca.certificate_der();
    let mut roots = RootCertStore::empty();
    roots.add(ca.certificate_der()).unwrap();
    let client_config = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let upstream_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let upstream_address = upstream_listener.local_addr().unwrap();
    let upstream = thread::spawn(move || {
        let (stream, _) = upstream_listener.accept().unwrap();
        terminate_http_once(stream, upstream_config, |_| {
            b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\nkeel-pass".to_vec()
        })
        .unwrap();
    });
    let front_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let front_address = front_listener.local_addr().unwrap();
    let front = thread::spawn(move || {
        let (stream, _) = front_listener.accept().unwrap();
        terminate_http_once(stream, front_config, |request| {
            forward_http_once(
                request,
                TcpStream::connect(upstream_address).unwrap(),
                "upstream.keel.test",
                upstream_root,
            )
            .unwrap()
        })
        .unwrap();
    });

    let connection = ClientConnection::new(
        client_config,
        ServerName::try_from("registry.keel.test".to_owned()).unwrap(),
    )
    .unwrap();
    let mut client = StreamOwned::new(connection, TcpStream::connect(front_address).unwrap());
    client
        .write_all(b"GET /probe HTTP/1.1\r\nHost: registry.keel.test\r\n\r\n")
        .unwrap();
    let mut response = String::new();
    client.read_to_string(&mut response).unwrap();
    front.join().unwrap();
    upstream.join().unwrap();
    assert!(response.ends_with("keel-pass"));
}

#[test]
fn plain_http_is_authorized_and_rebound_to_the_connected_host() {
    let upstream_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let upstream_address = upstream_listener.local_addr().unwrap();
    let upstream = thread::spawn(move || {
        let (mut stream, _) = upstream_listener.accept().unwrap();
        let request = super::read_http_request(&mut stream).unwrap();
        let request = std::str::from_utf8(&request).unwrap();
        assert!(request.contains(&format!(
            "\r\nHost: packages.example:{}\r\n",
            upstream_address.port()
        )));
        assert!(!request.contains("attacker-controlled.example"));
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\nkeel-pass",
            )
            .unwrap();
    });
    let (mut client, guest) = UnixStream::pair().unwrap();
    let target = ConnectionTarget {
        server_name: "packages.example".to_owned(),
        resolved_ip: Ipv4Addr::new(93, 184, 216, 34).into(),
        port: upstream_address.port(),
    };
    let destination = EgressDestination {
        server_name: target.server_name.clone(),
        port: target.port,
    };
    let proxy = thread::spawn(move || {
        let mut authorizer = ExpectedAuthorizer {
            method: "GET",
            path: "/crate",
        };
        proxy_plain_http_once(
            guest,
            &destination,
            &CredentialVault::new(),
            &mut authorizer,
            || Ok((TcpStream::connect(upstream_address).unwrap(), target)),
        )
        .unwrap();
    });
    client
            .write_all(
                b"GET /crate HTTP/1.1\r\nHost: attacker-controlled.example\r\nConnection: keep-alive\r\n\r\n",
            )
            .unwrap();
    let mut response = String::new();
    client.read_to_string(&mut response).unwrap();
    proxy.join().unwrap();
    upstream.join().unwrap();
    assert!(response.ends_with("keel-pass"));
}

fn assert_sanitized_model_request(request: &[u8]) {
    assert!(
        !request
            .windows(b"keel-sentinel".len())
            .any(|bytes| bytes == b"keel-sentinel")
    );
    assert!(
        request
            .windows(b"real-credential".len())
            .any(|bytes| bytes == b"real-credential")
    );
    let header_end = request
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .unwrap();
    let headers = std::str::from_utf8(&request[..header_end]).unwrap();
    assert!(
        headers
            .lines()
            .any(|line| line == "Host: api.anthropic.com")
    );
    assert!(!headers.contains("attacker-controlled.example"));
    let content_length = headers
        .lines()
        .find_map(|line| line.strip_prefix("Content-Length: "))
        .unwrap()
        .parse::<usize>()
        .unwrap();
    let body = &request[header_end + 4..];
    assert_eq!(content_length, body.len());
    let body: Value = serde_json::from_slice(body).unwrap();
    assert_eq!(body["model"], "claude-sonnet-4-5-20250929");
    assert!(body.get("mcp_servers").is_none());
    assert!(body.get("container").is_none());
    assert_eq!(body["tools"].as_array().unwrap().len(), 1);
    assert_eq!(body["tools"][0]["type"], "custom");
}

#[test]
fn trusted_tls_proxy_swaps_sentinel_only_after_target_binding() {
    let ca = MitmCa::generate().unwrap();
    let front_config = ca.server_config("api.anthropic.com").unwrap();
    let upstream_config = ca.server_config("api.anthropic.com").unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(ca.certificate_der()).unwrap();
    let client_config = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots.clone())
            .with_no_client_auth(),
    );
    let upstream_client = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let upstream_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let upstream_address = upstream_listener.local_addr().unwrap();
    let upstream = thread::spawn(move || {
        let (stream, _) = upstream_listener.accept().unwrap();
        terminate_http_once(stream, upstream_config, |request| {
                assert_sanitized_model_request(request);
                let body = br#"{"content":[{"type":"text","text":"keel-pass"}],"usage":{"input_tokens":3,"output_tokens":1}}"#;
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    std::str::from_utf8(body).unwrap()
                )
                .into_bytes()
            })
            .unwrap();
    });

    let mut vault = CredentialVault::new();
    vault.insert(
        CredentialBinding::new(
            CredentialScope {
                server_name: "api.anthropic.com".to_owned(),
                methods: ["POST".to_owned()].into_iter().collect(),
                path_prefix: "/v1/messages".to_owned(),
            },
            SecretBytes::new(b"keel-sentinel".to_vec()),
            SecretBytes::new(b"real-credential".to_vec()),
        )
        .unwrap(),
    );
    let front_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let front_address = front_listener.local_addr().unwrap();
    let front = thread::spawn(move || {
        let (guest, _) = front_listener.accept().unwrap();
        let mut authorizer = ModelAuthorizer;
        let destination = EgressDestination {
            server_name: "api.anthropic.com".to_owned(),
            port: 443,
        };
        proxy_tls_http(
            guest,
            front_config,
            upstream_client,
            &destination,
            &vault,
            &mut authorizer,
            false,
            || {
                Ok((
                    TcpStream::connect(upstream_address).unwrap(),
                    ConnectionTarget {
                        server_name: "api.anthropic.com".to_owned(),
                        resolved_ip: Ipv4Addr::new(93, 184, 216, 34).into(),
                        port: 443,
                    },
                ))
            },
        )
        .unwrap();
    });

    let connection = ClientConnection::new(
        client_config,
        ServerName::try_from("api.anthropic.com".to_owned()).unwrap(),
    )
    .unwrap();
    let mut client = StreamOwned::new(connection, TcpStream::connect(front_address).unwrap());
    let body = br#"{"model":"claude-sonnet-4-5-20250929","tools":[{"type":"web_search_20250305"},{"type":"custom"}],"mcp_servers":[{"url":"https://evil.example"}],"container":{"id":"guest"},"max_tokens":32}"#;
    let request = format!(
        "POST /v1/messages HTTP/1.1\r\nHost: attacker-controlled.example\r\nAuthorization: Bearer keel-sentinel\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n{}",
        body.len(),
        std::str::from_utf8(body).unwrap()
    );
    client.write_all(request.as_bytes()).unwrap();
    let mut response = String::new();
    client.read_to_string(&mut response).unwrap();
    front.join().unwrap();
    upstream.join().unwrap();
    assert!(response.contains("keel-pass"));
}

#[test]
#[allow(clippy::too_many_lines)]
fn opted_in_tls_proxy_reauthorizes_sequential_requests() {
    struct ReuseAuthorizer {
        pending: Option<String>,
        paths: Vec<String>,
    }

    impl EgressRequestAuthorizer for ReuseAuthorizer {
        fn authorize(
            &mut self,
            method: &str,
            path: &str,
            _body_digest: [u8; 32],
            model_budget: Option<ModelBudgetRequest>,
        ) -> Result<(), String> {
            assert_eq!(method, "GET");
            assert!(model_budget.is_none());
            assert!(self.pending.replace(path.to_owned()).is_none());
            Ok(())
        }

        fn record_response(&mut self) -> Result<(), String> {
            self.paths
                .push(self.pending.take().ok_or("request was not authorized")?);
            Ok(())
        }
    }

    let ca = MitmCa::generate().unwrap();
    let front_config = ca.server_config("example.com").unwrap();
    let upstream_config = ca.server_config("example.com").unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(ca.certificate_der()).unwrap();
    let client_config = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots.clone())
            .with_no_client_auth(),
    );
    let upstream_client = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let upstream_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let upstream_address = upstream_listener.local_addr().unwrap();
    let upstream = thread::spawn(move || {
        let (stream, _) = upstream_listener.accept().unwrap();
        let connection = ServerConnection::new(upstream_config).unwrap();
        let mut tls = StreamOwned::new(connection, stream);
        for (index, expected_path) in ["/one", "/two"].into_iter().enumerate() {
            let request = super::read_http_request(&mut tls).unwrap();
            let request = std::str::from_utf8(&request).unwrap();
            assert!(request.starts_with(&format!("GET {expected_path} HTTP/1.1\r\n")));
            let final_response = index == 1;
            assert!(request.contains(if final_response {
                "Connection: close\r\n"
            } else {
                "Connection: keep-alive\r\n"
            }));
            let body = format!("response-{index}");
            write!(
                tls,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: {}\r\n\r\n{}",
                body.len(),
                if final_response {
                    "close"
                } else {
                    "keep-alive"
                },
                body
            )
            .unwrap();
            tls.flush().unwrap();
        }
        tls.conn.send_close_notify();
        tls.flush().unwrap();
    });

    let front_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let front_address = front_listener.local_addr().unwrap();
    let front = thread::spawn(move || {
        let (guest, _) = front_listener.accept().unwrap();
        let mut authorizer = ReuseAuthorizer {
            pending: None,
            paths: Vec::new(),
        };
        let destination = EgressDestination {
            server_name: "example.com".to_owned(),
            port: 443,
        };
        proxy_tls_http(
            guest,
            front_config,
            upstream_client,
            &destination,
            &CredentialVault::new(),
            &mut authorizer,
            true,
            || {
                Ok((
                    TcpStream::connect(upstream_address).unwrap(),
                    ConnectionTarget {
                        server_name: "example.com".to_owned(),
                        resolved_ip: Ipv4Addr::new(93, 184, 216, 34).into(),
                        port: 443,
                    },
                ))
            },
        )
        .unwrap();
        authorizer.paths
    });

    let connection = ClientConnection::new(
        client_config,
        ServerName::try_from("example.com".to_owned()).unwrap(),
    )
    .unwrap();
    let mut client = StreamOwned::new(connection, TcpStream::connect(front_address).unwrap());
    for (index, path) in ["/one", "/two"].into_iter().enumerate() {
        write!(
                client,
                "GET {path} HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\nConnection: {}\r\n\r\n",
                if index == 1 { "close" } else { "keep-alive" }
            )
            .unwrap();
        client.flush().unwrap();
        let response =
            relay_http_response(&mut client, &mut std::io::sink(), "test response").unwrap();
        assert!(
            response
                .bytes
                .ends_with(format!("response-{index}").as_bytes())
        );
    }

    assert_eq!(front.join().unwrap(), ["/one", "/two"]);
    upstream.join().unwrap();

    let mut pipelined = b"GET /one HTTP/1.1\r\nContent-Length: 0\r\n\r\n\
                              GET /two HTTP/1.1\r\nContent-Length: 0\r\n\r\n"
        .as_slice();
    assert!(
        super::read_http_request(&mut pipelined)
            .unwrap_err()
            .to_string()
            .contains("pipelining")
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn a_model_request_the_api_refuses_keeps_its_reservation() {
    struct ReservationOutcomeTracker {
        reserved: usize,
        marked: usize,
        released: usize,
        committed: usize,
        settled: usize,
    }

    impl EgressRequestAuthorizer for ReservationOutcomeTracker {
        fn authorize(
            &mut self,
            _method: &str,
            _path: &str,
            _body_digest: [u8; 32],
            model_budget: Option<ModelBudgetRequest>,
        ) -> Result<(), String> {
            self.reserved += usize::from(model_budget.is_some());
            Ok(())
        }

        fn record_response(&mut self) -> Result<(), String> {
            Ok(())
        }

        fn mark_model_request_send_attempted(&mut self) -> Result<(), String> {
            self.marked += 1;
            Ok(())
        }

        fn record_model_usage(&mut self, _usage: ModelUsage) -> Result<(), String> {
            self.settled += 1;
            Ok(())
        }

        fn release_model_reservation(&mut self) -> Result<(), String> {
            self.released += 1;
            Ok(())
        }

        fn commit_model_reservation_conservatively(&mut self) -> Result<(), String> {
            self.committed += 1;
            Ok(())
        }
    }

    let ca = MitmCa::generate().unwrap();
    let front_config = ca.server_config("api.anthropic.com").unwrap();
    let upstream_config = ca.server_config("api.anthropic.com").unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(ca.certificate_der()).unwrap();
    let client_config = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots.clone())
            .with_no_client_auth(),
    );
    let upstream_client = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let upstream_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let upstream_address = upstream_listener.local_addr().unwrap();
    let upstream = thread::spawn(move || {
        let (stream, _) = upstream_listener.accept().unwrap();
        terminate_http_once(stream, upstream_config, |_request| {
            // An API error carries no usage block, which is exactly why it
            // must not be mistaken for an unaccountable response.
            let body = br#"{"type":"error","error":{"type":"invalid_request_error"}}"#;
            format!(
                "HTTP/1.1 400 Bad Request\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                std::str::from_utf8(body).unwrap()
            )
            .into_bytes()
        })
        .unwrap();
    });
    let front_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let front_address = front_listener.local_addr().unwrap();
    let front = thread::spawn(move || {
        let (guest, _) = front_listener.accept().unwrap();
        let mut authorizer = ReservationOutcomeTracker {
            reserved: 0,
            marked: 0,
            released: 0,
            committed: 0,
            settled: 0,
        };
        let destination = EgressDestination {
            server_name: "api.anthropic.com".to_owned(),
            port: 443,
        };
        proxy_tls_http(
            guest,
            front_config,
            upstream_client,
            &destination,
            &CredentialVault::new(),
            &mut authorizer,
            false,
            || {
                Ok((
                    TcpStream::connect(upstream_address).unwrap(),
                    ConnectionTarget {
                        server_name: "api.anthropic.com".to_owned(),
                        resolved_ip: Ipv4Addr::new(93, 184, 216, 34).into(),
                        port: 443,
                    },
                ))
            },
        )
        .unwrap();
        assert_eq!(authorizer.reserved, 1);
        assert_eq!(authorizer.marked, 1);
        assert_eq!(authorizer.released, 0);
        assert_eq!(authorizer.committed, 1);
        assert_eq!(authorizer.settled, 0);
    });

    let connection = ClientConnection::new(
        client_config,
        ServerName::try_from("api.anthropic.com".to_owned()).unwrap(),
    )
    .unwrap();
    let mut client = StreamOwned::new(connection, TcpStream::connect(front_address).unwrap());
    let body = br#"{"model":"claude-opus-5","max_tokens":32}"#;
    let request = format!(
        "POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        std::str::from_utf8(body).unwrap()
    );
    client.write_all(request.as_bytes()).unwrap();
    let mut response = String::new();
    client.read_to_string(&mut response).unwrap();
    front.join().unwrap();
    upstream.join().unwrap();
    // The harness sees the API's own error, so it can explain the failure.
    assert!(
        response.starts_with("HTTP/1.1 400 Bad Request\r\n"),
        "{response}"
    );
    assert!(response.contains("invalid_request_error"), "{response}");
}

#[test]
fn structural_network_ranges_are_denied_before_policy() {
    for address in [
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)),
        "fd00::1".parse().unwrap(),
        "::1".parse().unwrap(),
        IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(0, 1, 2, 3)),
        IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(240, 0, 0, 1)),
        "::ffff:169.254.169.254".parse().unwrap(),
        "::ffff:127.0.0.1".parse().unwrap(),
        "::10.0.0.1".parse().unwrap(),
        "64:ff9b::a9fe:a9fe".parse().unwrap(),
        "2002:7f00:1::".parse().unwrap(),
    ] {
        assert!(is_forbidden_ip(address), "{address}");
    }
    for address in [
        "93.184.216.34",
        "100.128.0.1",
        "::ffff:93.184.216.34",
        "64:ff9b::5db8:d822",
        "2002:5db8:d822::1",
        "2606:4700::1111",
    ] {
        assert!(!is_forbidden_ip(address.parse().unwrap()), "{address}");
    }
}

fn git_vault() -> CredentialVault {
    let mut vault = CredentialVault::new();
    vault.insert(
        CredentialBinding::new(
            CredentialScope {
                server_name: "github.com".to_owned(),
                methods: ["GET".to_owned()].into_iter().collect(),
                path_prefix: "/owner/repo".to_owned(),
            },
            SecretBytes::new(SystemEgressConnector::GIT_SENTINEL.as_bytes().to_vec()),
            SecretBytes::new(b"real-credential".to_vec()),
        )
        .expect("binding"),
    );
    vault
}

#[test]
fn credentials_are_injected_only_on_the_tls_port() {
    let request = format!(
        "GET /owner/repo/info/refs?service=git-receive-pack HTTP/1.1\r\nAuthorization: Bearer {}\r\n\r\n",
        SystemEgressConnector::GIT_SENTINEL
    );
    let target = ConnectionTarget {
        server_name: "github.com".to_owned(),
        resolved_ip: IpAddr::V4(Ipv4Addr::new(140, 82, 112, 3)),
        port: 443,
    };
    assert!(git_vault().inject(&target, request.as_bytes()).is_ok());
    let plaintext_port = ConnectionTarget { port: 80, ..target };
    assert!(
        git_vault()
            .inject(&plaintext_port, request.as_bytes())
            .is_err()
    );
    assert!(git_vault().refuse_sentinels(request.into_bytes()).is_err());
}

#[test]
fn plain_http_never_writes_a_credential_upstream() {
    let upstream_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let upstream_address = upstream_listener.local_addr().unwrap();
    let upstream = thread::spawn(move || {
        let (mut stream, _) = upstream_listener.accept().unwrap();
        let mut received = Vec::new();
        stream.read_to_end(&mut received).unwrap();
        received
    });
    let (mut client, guest) = UnixStream::pair().unwrap();
    let target = ConnectionTarget {
        server_name: "github.com".to_owned(),
        resolved_ip: Ipv4Addr::new(140, 82, 112, 3).into(),
        port: 80,
    };
    let destination = EgressDestination {
        server_name: target.server_name.clone(),
        port: target.port,
    };
    let path = "/owner/repo/info/refs?service=git-receive-pack";
    client
        .write_all(
            format!(
                "GET {path} HTTP/1.1\r\nAuthorization: Bearer {}\r\n\r\n",
                SystemEgressConnector::GIT_SENTINEL
            )
            .as_bytes(),
        )
        .unwrap();
    let mut authorizer = ExpectedAuthorizer {
        method: "GET",
        path,
    };
    let error = proxy_plain_http_once(guest, &destination, &git_vault(), &mut authorizer, || {
        Ok((TcpStream::connect(upstream_address).unwrap(), target))
    })
    .unwrap_err();
    assert!(error.to_string().contains("sentinel"), "{error}");
    assert!(upstream.join().unwrap().is_empty());
}

#[test]
fn sentinel_swap_binds_to_connection_method_and_path() {
    let mut vault = CredentialVault::new();
    vault.insert(
        CredentialBinding::new(
            CredentialScope {
                server_name: "api.example.com".to_owned(),
                methods: ["POST".to_owned()].into_iter().collect(),
                path_prefix: "/v1/messages".to_owned(),
            },
            SecretBytes::new(b"keel-sentinel".to_vec()),
            SecretBytes::new(b"real-credential".to_vec()),
        )
        .expect("nonempty sentinel"),
    );
    let target = ConnectionTarget {
        server_name: "api.example.com".to_owned(),
        resolved_ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
        port: 443,
    };
    let request = b"POST /v1/messages HTTP/1.1\r\nHost: evil.example\r\nAuthorization: Bearer keel-sentinel\r\n\r\n";

    let injected = vault.inject(&target, request).expect("scoped request");

    assert!(
        String::from_utf8(injected)
            .expect("HTTP text")
            .contains("Bearer real-credential")
    );
    let wrong_target = ConnectionTarget {
        server_name: "evil.example".to_owned(),
        ..target
    };
    assert!(vault.inject(&wrong_target, request).is_err());
}

#[test]
fn sentinel_swap_rejects_body_and_ambiguous_header_occurrences() {
    let mut vault = CredentialVault::new();
    vault.insert(
        CredentialBinding::new(
            CredentialScope {
                server_name: "api.example.com".to_owned(),
                methods: ["POST".to_owned()].into_iter().collect(),
                path_prefix: "/v1/messages".to_owned(),
            },
            SecretBytes::new(b"keel-sentinel".to_vec()),
            SecretBytes::new(b"real-credential".to_vec()),
        )
        .expect("binding"),
    );
    let target = ConnectionTarget {
        server_name: "api.example.com".to_owned(),
        resolved_ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
        port: 443,
    };
    let body = br#"{"message":"keel-sentinel"}"#;
    let request = format!(
        "POST /v1/messages HTTP/1.1\r\nx-api-key: keel-sentinel\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        std::str::from_utf8(body).unwrap()
    );
    let error = vault.inject(&target, request.as_bytes()).unwrap_err();
    assert!(error.to_string().contains("request body"));

    let duplicate = b"POST /v1/messages HTTP/1.1\r\nx-api-key: keel-sentinel\r\nAuthorization: Bearer keel-sentinel\r\n\r\n";
    assert!(vault.inject(&target, duplicate).is_err());
    let unrelated = b"POST /v1/messages HTTP/1.1\r\nX-Debug: keel-sentinel\r\n\r\n";
    assert!(vault.inject(&target, unrelated).is_err());
}

#[test]
fn model_request_strips_server_side_execution_and_denies_other_paths() {
    let body = br#"{
            "model": "test",
            "mcp_servers": [{"url": "https://evil.example"}],
            "container": {"id": "guest"},
            "tools": [
                {"type": "web_search_20250305", "name": "search"},
                {"type": "custom", "name": "safe"}
            ]
        }"#;
    let target = ConnectionTarget {
        server_name: "api.anthropic.com".to_owned(),
        resolved_ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
        port: 443,
    };

    let sanitized =
        sanitize_model_request(&target, "/v1/messages?beta=true", body).expect("messages request");
    let value: Value = serde_json::from_slice(&sanitized.body).expect("sanitized JSON");

    assert!(value.get("mcp_servers").is_none());
    assert!(value.get("container").is_none());
    assert_eq!(value["tools"].as_array().expect("tools").len(), 1);
    assert!(sanitized.stripped.contains(&"mcp_servers".to_owned()));
    assert!(
        sanitized
            .stripped
            .contains(&"tools:web_search_20250305".to_owned())
    );
    assert!(sanitize_model_request(&target, "/v1/files", b"{}").is_err());
    let mut authorizer = ModelAuthorizer;
    assert!(
        prepare_upstream_request_with_authorizer(
            &target,
            &CredentialVault::new(),
            b"GET /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\n\r\n",
            &mut authorizer,
            false,
        )
        .is_err()
    );
    let wrong_target = ConnectionTarget {
        server_name: "evil.example".to_owned(),
        resolved_ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
        port: 443,
    };
    assert!(sanitize_model_request(&wrong_target, "/v1/messages", b"{}").is_err());
}

#[test]
fn a_regional_provider_is_selected_host_side_and_swaps_only_in_its_region() {
    assert_eq!(
        runtime_model_provider_from(false, Some("us-east-1".to_owned()))
            .expect("first-party provider")
            .host,
        "api.anthropic.com"
    );
    // A bearer token without a region names no endpoint, and a malformed one
    // names a host this proxy would not recognise as a model endpoint at all.
    assert!(runtime_model_provider_from(true, None).is_err());
    assert!(runtime_model_provider_from(true, Some("US East".to_owned())).is_err());
    let provider =
        runtime_model_provider_from(true, Some("us-east-1".to_owned())).expect("regional provider");
    assert_eq!(provider.host, "bedrock-runtime.us-east-1.amazonaws.com");
    assert_eq!(provider.sentinel, SystemEgressConnector::BEDROCK_SENTINEL);

    let (connector, _, _, _) =
        SystemEgressConnector::from_runtime_values_all(RuntimeCredentialValues {
            bedrock: Some((provider.host.clone(), "bedrock-real-secret".to_owned())),
            ..RuntimeCredentialValues::default()
        })
        .expect("regional credential");
    let public_ip = Ipv4Addr::new(93, 184, 216, 34).into();
    let request = format!(
        "POST /model/us.anthropic.claude-sonnet-4-5-20250929-v1:0/invoke HTTP/1.1\r\n\
             Authorization: Bearer {}\r\n\r\n",
        SystemEgressConnector::BEDROCK_SENTINEL
    );
    let swapped = connector
        .vault
        .inject(
            &ConnectionTarget {
                server_name: provider.host.clone(),
                resolved_ip: public_ip,
                port: 443,
            },
            request.as_bytes(),
        )
        .expect("bound swap");
    assert!(
        swapped
            .windows(19)
            .any(|value| value == b"bedrock-real-secret")
    );
    // The binding is scoped to the region it was configured for, so the same
    // sentinel in another region buys nothing.
    assert!(
        connector
            .vault
            .inject(
                &ConnectionTarget {
                    server_name: "bedrock-runtime.eu-west-1.amazonaws.com".to_owned(),
                    resolved_ip: public_ip,
                    port: 443,
                },
                request.as_bytes(),
            )
            .is_err()
    );
}

#[test]
fn bedrock_control_plane_gets_a_local_refusal_before_authorization() {
    let target = ConnectionTarget {
        server_name: "bedrock.us-east-1.amazonaws.com".to_owned(),
        resolved_ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
        port: 443,
    };
    let request =
        b"GET /inference-profiles HTTP/1.1\r\nHost: bedrock.us-east-1.amazonaws.com\r\n\r\n";
    let mut authorizer = ExpectedAuthorizer {
        method: "must-not-authorize",
        path: "must-not-authorize",
    };
    let result = prepare_upstream_request_with_authorizer(
        &target,
        &CredentialVault::new(),
        request,
        &mut authorizer,
        false,
    );
    let Err(error) = result else {
        panic!("the control-plane request must stay local");
    };
    assert!(error.to_string().contains("is not admitted"));
}

#[test]
fn a_regional_model_endpoint_prices_from_its_path_and_fails_closed() {
    let target = ConnectionTarget {
        server_name: "bedrock-runtime.us-east-1.amazonaws.com".to_owned(),
        resolved_ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
        port: 443,
    };
    let stream = "/model/us.anthropic.claude-sonnet-4-5-20250929-v1:0/invoke-with-response-stream";
    let body = br#"{
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": 32,
            "mcp_servers": [{"url": "https://evil.example"}]
        }"#;

    // The strip list is the same list: a second provider does not get a second
    // set of rules about what the guest may ask the model to execute.
    let sanitized = sanitize_model_request(&target, stream, body).expect("invoke request");
    assert_eq!(sanitized.stripped, vec!["mcp_servers".to_owned()]);
    let endpoint = ModelEndpoint::BedrockInvoke {
        region: "us-east-1".to_owned(),
    };
    let budget =
        model_budget_request(&endpoint, stream, &sanitized.body).expect("path-derived tariff");
    assert_eq!(budget.input_microusd_per_token, 5);
    assert_eq!(budget.output_microusd_per_token, 15);
    let global = "/model/global.anthropic.claude-sonnet-5-5/invoke-with-response-stream";
    let global_budget = model_budget_request(&endpoint, global, &sanitized.body)
        .expect("global inference profile tariff");
    assert_eq!(global_budget.input_microusd_per_token, 5);
    assert_eq!(global_budget.output_microusd_per_token, 15);

    // Every way of arriving without a pinned key refuses: an action outside
    // the table, an identifier with no vendor prefix, a region this table was
    // never quoted for, and a host with no region at all.
    assert!(
        sanitize_model_request(&target, "/model/us.anthropic.claude-x-v1:0/converse", body)
            .is_err()
    );
    assert!(
        model_budget_request(
            &endpoint,
            "/model/mistral.large-v1:0/invoke",
            &sanitized.body
        )
        .is_err()
    );
    let unpriced = ModelEndpoint::BedrockInvoke {
        region: "us-gov-west-1".to_owned(),
    };
    assert!(model_budget_request(&unpriced, stream, &sanitized.body).is_err());
    let regionless = ConnectionTarget {
        server_name: "bedrock-runtime.amazonaws.com".to_owned(),
        ..target.clone()
    };
    assert!(sanitize_model_request(&regionless, stream, body).is_err());

    // A body announcing a different wire contract is refused by the
    // sanitizer, not left to become an upstream 400.
    let mismatched = br#"{"anthropic_version": "bedrock-2099-01-01", "max_tokens": 32}"#;
    let error =
        sanitize_model_request(&target, stream, mismatched).expect_err("unknown wire contract");
    assert!(
        error.to_string().contains("bedrock-2023-05-31"),
        "the error names the contract this code reads: {error}"
    );
}

#[test]
fn model_budget_tariff_and_stream_usage_are_parsed_fail_closed() {
    let messages = ModelEndpoint::AnthropicMessages;
    let budget = model_budget_request(
        &messages,
        "/v1/messages",
        br#"{"model":"claude-sonnet-4-5-20250929","max_tokens":32}"#,
    )
    .expect("pinned tariff");
    assert_eq!(budget.max_output_tokens, 32);
    assert_eq!(budget.input_microusd_per_token, 5);
    assert_eq!(budget.output_microusd_per_token, 15);
    assert!(
        model_budget_request(
            &messages,
            "/v1/messages",
            br#"{"model":"unpriced-model","max_tokens":32}"#
        )
        .is_err()
    );

    let first = br#"data: {"type":"message_start","message":{"usage":{"input_tokens":2,"cache_read_input_tokens":3,"output_tokens":0}}}

"#;
    let second = br#"data: {"type":"message_delta","usage":{"output_tokens":4}}

"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{}\r\n{:x}\r\n{}\r\n0\r\n\r\n",
        first.len(),
        std::str::from_utf8(first).expect("SSE"),
        second.len(),
        std::str::from_utf8(second).expect("SSE"),
    );
    let usage = parse_model_usage(response.as_bytes()).expect("stream usage");
    assert_eq!(
        usage,
        ModelUsage {
            input_tokens: 5,
            output_tokens: 4,
        }
    );
    assert!(parse_model_usage(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}").is_err());
}

fn event_stream_frame(headers: &[(&str, &str)], payload: &str) -> Vec<u8> {
    let mut encoded = Vec::new();
    for (name, value) in headers {
        encoded.push(u8::try_from(name.len()).expect("header name length"));
        encoded.extend_from_slice(name.as_bytes());
        encoded.push(7);
        encoded.extend_from_slice(
            &u16::try_from(value.len())
                .expect("header value length")
                .to_be_bytes(),
        );
        encoded.extend_from_slice(value.as_bytes());
    }
    let total = u32::try_from(16 + encoded.len() + payload.len()).expect("frame length");
    let mut frame = total.to_be_bytes().to_vec();
    frame.extend_from_slice(&u32::try_from(encoded.len()).expect("headers").to_be_bytes());
    // Both CRCs are zero: the decoder does not verify them, and a test that
    // supplied real ones would assert a property this code does not claim.
    frame.extend_from_slice(&[0; 4]);
    frame.extend_from_slice(&encoded);
    frame.extend_from_slice(payload.as_bytes());
    frame.extend_from_slice(&[0; 4]);
    frame
}

fn event_stream_response(body: &[u8]) -> Vec<u8> {
    let mut response =
        b"HTTP/1.1 200 OK\r\nContent-Type: application/vnd.amazon.eventstream\r\n\r\n".to_vec();
    response.extend_from_slice(body);
    response
}

#[test]
fn event_stream_usage_is_settled_and_bad_framing_fails_closed() {
    // Frame shapes are taken from the eventstream and Bedrock specifications
    // rather than a live capture: each event's JSON arrives base64-encoded in
    // a `bytes` envelope, and the settlement counts ride the terminal event
    // under the provider's own field names.
    let event = [(":message-type", "event"), (":event-type", "chunk")];
    let start = event_stream_frame(
        &event,
        r#"{"bytes":"eyJ0eXBlIjoibWVzc2FnZV9zdGFydCIsIm1lc3NhZ2UiOnsidXNhZ2UiOnsiaW5wdXRfdG9rZW5zIjoyLCJjYWNoZV9yZWFkX2lucHV0X3Rva2VucyI6Mywib3V0cHV0X3Rva2VucyI6MH19fQ=="}"#,
    );
    let stop = event_stream_frame(
        &event,
        r#"{"bytes":"eyJ0eXBlIjoibWVzc2FnZV9zdG9wIiwiYW1hem9uLWJlZHJvY2staW52b2NhdGlvbk1ldHJpY3MiOnsiaW5wdXRUb2tlbkNvdW50Ijo2LCJvdXRwdXRUb2tlbkNvdW50Ijo0fX0="}"#,
    );
    let mut body = start.clone();
    body.extend_from_slice(&stop);
    // The relayed events total five input tokens and the provider claims six.
    // Settlement takes the larger of the two accounts, never their sum.
    assert_eq!(
        parse_model_usage(&event_stream_response(&body)).expect("event stream usage"),
        ModelUsage {
            input_tokens: 6,
            output_tokens: 4,
        }
    );

    // A stream that stops mid-frame, a headers length that overruns its own
    // message, and a prelude with nothing behind it are all the same fault:
    // the bytes do not describe themselves consistently.
    let truncated = &body[..body.len() - 1];
    assert!(parse_model_usage(&event_stream_response(truncated)).is_err());
    let mut overrun = start.clone();
    overrun[7] = 0xff;
    assert!(parse_model_usage(&event_stream_response(&overrun)).is_err());
    assert!(parse_model_usage(&event_stream_response(&start[..8])).is_err());

    // An exception is not zero usage. Settling it as such would charge a
    // reservation against a response that never arrived.
    let exception = event_stream_frame(
        &[
            (":message-type", "exception"),
            (":exception-type", "throttlingException"),
        ],
        "{}",
    );
    let error = parse_model_usage(&event_stream_response(&exception))
        .expect_err("an exception is never usage");
    assert!(
        error.to_string().contains("throttlingException"),
        "the exception type names the fault: {error}"
    );
}

#[test]
fn response_relay_streams_chunks_and_stops_at_http_boundary() {
    struct ChunkReader {
        chunks: VecDeque<Vec<u8>>,
    }

    impl std::io::Read for ChunkReader {
        fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
            let chunk = self
                .chunks
                .pop_front()
                .expect("relay read beyond the complete HTTP response");
            output[..chunk.len()].copy_from_slice(&chunk);
            Ok(chunk.len())
        }
    }

    #[derive(Default)]
    struct FlushWriter {
        bytes: Vec<u8>,
        flushes: usize,
    }

    impl std::io::Write for FlushWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            self.flushes += 1;
            Ok(())
        }
    }

    let chunks = [
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhe".to_vec(),
        b"llo\r\n6\r\n wor".to_vec(),
        b"ld\r\n0\r\n\r\n".to_vec(),
    ];
    let expected = chunks.concat();
    let mut reader = ChunkReader {
        chunks: chunks.into(),
    };
    let mut writer = FlushWriter::default();
    let captured =
        relay_http_response(&mut reader, &mut writer, "test writer").expect("response relay");

    assert_eq!(captured.bytes, expected);
    assert_eq!(captured.guest_error, None);
    assert_eq!(writer.bytes, expected);
    assert_eq!(writer.flushes, 3);
}

#[test]
fn response_relay_drains_after_guest_delivery_fails() {
    struct ChunkReader {
        chunks: VecDeque<Vec<u8>>,
    }

    impl std::io::Read for ChunkReader {
        fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
            let chunk = self
                .chunks
                .pop_front()
                .expect("relay read beyond complete response");
            output[..chunk.len()].copy_from_slice(&chunk);
            Ok(chunk.len())
        }
    }

    struct BrokenWriter;

    impl std::io::Write for BrokenWriter {
        fn write(&mut self, _bytes: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let chunks = [
        b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nkee".to_vec(),
        b"l-pass".to_vec(),
    ];
    let expected = chunks.concat();
    let mut reader = ChunkReader {
        chunks: chunks.into(),
    };
    let response = relay_http_response(&mut reader, &mut BrokenWriter, "broken guest")
        .expect("upstream response remains recoverable");

    assert_eq!(response.bytes, expected);
    assert!(
        response
            .guest_error
            .is_some_and(|error| error.to_string().contains("broken guest"))
    );
    assert!(reader.chunks.is_empty());
}

#[test]
fn oauth_access_refreshes_inside_trusted_custody() {
    struct Refresher {
        calls: u64,
    }

    impl OAuthRefresher for Refresher {
        fn refresh(&mut self, refresh_token: &[u8]) -> Result<RefreshedToken, TlsError> {
            assert_eq!(refresh_token, b"refresh");
            self.calls += 1;
            Ok(RefreshedToken {
                access_token: SecretBytes::new(b"new-access".to_vec()),
                expires_at: 200,
            })
        }
    }

    let mut credential = OAuthCredential::new(
        SecretBytes::new(b"old-access".to_vec()),
        SecretBytes::new(b"refresh".to_vec()),
        100,
    );
    let mut refresher = Refresher { calls: 0 };

    let observed = credential
        .with_access_token(95, 10, &mut refresher, <[u8]>::to_vec)
        .expect("refresh succeeds");

    assert_eq!(observed, b"new-access");
    assert_eq!(refresher.calls, 1);
}

#[test]
fn runtime_artifacts_exclude_real_and_sentinel_credentials() {
    let real = "Basic keel-real-credential";
    let (connector, scope, _, redactor) =
        SystemEgressConnector::from_runtime_values_all(RuntimeCredentialValues {
            allow_git_push: true,
            git_credential: Some(real.to_owned()),
            git_host: Some("git.example".to_owned()),
            git_path: Some("/owner/repo.git".to_owned()),
            ..RuntimeCredentialValues::default()
        })
        .expect("runtime credential");
    let scope = scope.expect("Git credential scope");
    assert_eq!(scope.host, "git.example");
    let sentinel = scope.sentinel;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "keel-credential-artifacts-{}-{nonce:x}",
        std::process::id()
    ));
    let vertex = root.join("vertex");
    let transcript = root.join("transcript.txt");
    let audit = root.join("audit.ndjson");
    fs::create_dir_all(&vertex).expect("vertex filesystem");
    fs::write(
        vertex.join("runtime.env"),
        "SSL_CERT_FILE=/etc/ssl/certs/keel-ca.pem\n",
    )
    .expect("vertex runtime file");
    fs::write(&transcript, "guest services ready\n").expect("transcript");

    let writer = AuditWriter::spawn(
        &audit,
        "credential-artifact-test",
        RunKey::new([19; 32]),
        redactor,
    )
    .expect("audit writer");
    writer
        .record(AuditPayload {
            timestamp_ms: 1,
            event: "kernel.action".to_owned(),
            action_id: Some(1),
            fields: BTreeMap::from([(
                "diagnostic".to_owned(),
                format!("request carried {sentinel}; upstream carried {real}"),
            )]),
        })
        .expect("audit record");
    writer.shutdown().expect("audit shutdown");

    for artifact in [vertex.join("runtime.env"), transcript, audit.clone()] {
        assert_absent(&artifact, real);
        assert_absent(&artifact, &sentinel);
    }
    assert!(fs::read_to_string(&audit).unwrap().contains("[REDACTED]"));
    drop(connector);
    fs::remove_dir_all(root).expect("remove artifacts");
}

fn assert_absent(path: &Path, needle: &str) {
    let bytes = fs::read(path).expect("artifact");
    assert!(
        !bytes
            .windows(needle.len())
            .any(|window| window == needle.as_bytes()),
        "{} contains a credential form",
        path.display()
    );
}

/// AWS's published `get-vanilla` signing vector.
///
/// Everything else about the regional provider is documentation-derived and
/// unverifiable here. This is not: the HMAC chain either reproduces AWS's own
/// answer or it does not, so a drift in the derivation fails here rather than
/// as a `403` a live run has to explain.
#[test]
fn sigv4_derivation_reproduces_the_published_aws_vector() {
    let canonical_request = concat!(
        "GET\n/\n\n",
        "host:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\n",
        "host;x-amz-date\n",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/service/aws4_request\n{}",
        encode_lower_hex(super::digest(&super::SHA256, canonical_request.as_bytes()).as_ref())
    );
    assert_eq!(
        sigv4_signature(
            b"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "20150830",
            "us-east-1",
            "service",
            string_to_sign.as_bytes(),
        ),
        "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
    );
}

#[test]
fn canonical_uri_gives_a_model_identifier_one_spelling() {
    let expected = "/model/us.anthropic.claude-sonnet-4-20250514-v1%3A0/invoke";
    for path in [
        "/model/us.anthropic.claude-sonnet-4-20250514-v1:0/invoke",
        "/model/us.anthropic.claude-sonnet-4-20250514-v1%3A0/invoke",
        "/model/us.anthropic.claude-sonnet-4-20250514-v1%3a0/invoke",
    ] {
        assert_eq!(canonical_request_uri(path).expect("canonical"), expected);
    }
    // A query string is refused rather than canonically ordered, and any
    // escape other than a colon is refused rather than guessed at: both are
    // signature inputs, and a wrong guess is indistinguishable from a bad key.
    for path in [
        "/model/anthropic.claude/invoke?version=2",
        "/model/anthropic%2Fclaude/invoke",
        "/model/anthropic%/invoke",
    ] {
        assert!(canonical_request_uri(path).is_err(), "{path} was admitted");
    }
}

#[test]
fn credential_timestamps_round_trip_through_both_date_forms() {
    let (amz_date, date_stamp) = sigv4_timestamps(1_440_938_160);
    assert_eq!(amz_date, "20150830T123600Z");
    assert_eq!(date_stamp, "20150830");
    assert_eq!(
        parse_utc_timestamp("2015-08-30T12:36:00Z"),
        Some(1_440_938_160)
    );
    assert_eq!(
        parse_utc_timestamp("2015-08-30T12:36:00.512Z"),
        Some(1_440_938_160)
    );
    // `+00:00` is what the AWS CLI actually writes, and refusing it made every
    // signed run refuse. An offset is read, not assumed away in either
    // direction: an expiry an hour wrong signs with a lapsed credential or
    // refreshes in a loop.
    for (value, expected) in [
        ("2015-08-30T12:36:00+00:00", 1_440_938_160),
        ("2015-08-30T14:36:00+02:00", 1_440_938_160),
        ("2015-08-30T10:36:00-02:00", 1_440_938_160),
        ("2015-08-30T12:36:00.512+00:00", 1_440_938_160),
    ] {
        assert_eq!(parse_utc_timestamp(value), Some(expected), "{value}");
    }
    for value in [
        "2015-08-30T12:36:00",
        "2015-08-30T12:36:00+15:00",
        "2015-08-30T12:36:00+0000",
        "2015-13-30T12:36:00Z",
        "not-a-time",
    ] {
        assert_eq!(parse_utc_timestamp(value), None, "{value} was admitted");
    }
}

#[test]
fn credential_process_output_is_read_or_refused() {
    let credentials = parse_credential_process_output(
        br#"{"Version":1,"AccessKeyId":"ASIAEXAMPLE","SecretAccessKey":"secret",
                 "SessionToken":"token","Expiration":"2015-08-30T12:36:00Z"}"#,
    )
    .expect("credentials");
    assert_eq!(credentials.access_key_id, "ASIAEXAMPLE");
    assert_eq!(credentials.expires_at, Some(1_440_938_160));
    assert!(credentials.stale(1_440_938_160));
    assert!(!credentials.stale(1_440_000_000));
    for output in [
        br#"{"Version":2,"AccessKeyId":"a","SecretAccessKey":"b"}"#.as_slice(),
        br#"{"Version":1,"SecretAccessKey":"b"}"#.as_slice(),
        // An unreadable expiry fails closed. Treating it as absent would turn
        // a session credential into one Keel believes never lapses.
        br#"{"Version":1,"AccessKeyId":"a","SecretAccessKey":"b","Expiration":"soon"}"#.as_slice(),
        b"not json".as_slice(),
    ] {
        assert!(parse_credential_process_output(output).is_err());
    }
}

#[test]
fn a_signed_provider_discards_the_sentinel_instead_of_swapping_it() {
    let host = "bedrock-runtime.us-east-1.amazonaws.com";
    let mut vault = CredentialVault::new();
    vault.signer = Some(SigV4Signer {
        host: host.to_owned(),
        region: "us-east-1".to_owned(),
        source: AwsCredentialSource::Environment,
        credentials: super::Mutex::new(AwsCredentials {
            access_key_id: "ASIAEXAMPLE".to_owned(),
            secret_access_key: SecretBytes::new("secret".as_bytes()),
            session_token: Some(SecretBytes::new("session-token".as_bytes())),
            expires_at: None,
        }),
    });
    let target = ConnectionTarget {
        server_name: host.to_owned(),
        port: 443,
        resolved_ip: IpAddr::from(Ipv4Addr::new(93, 184, 216, 34)),
    };
    let request = format!(
        "POST /model/anthropic.claude/invoke HTTP/1.1\r\nHost: {host}\r\nAuthorization: \
             Bearer {}\r\nContent-Length: 2\r\n\r\n{{}}",
        SystemEgressConnector::BEDROCK_SENTINEL
    );
    let signed = String::from_utf8(
        vault
            .inject(&target, request.as_bytes())
            .expect("signed request"),
    )
    .expect("utf8");
    assert!(signed.contains("Authorization: AWS4-HMAC-SHA256 Credential=ASIAEXAMPLE/"));
    assert!(signed.contains("/us-east-1/bedrock/aws4_request"));
    assert!(signed.contains("SignedHeaders=content-type;host;x-amz-date;x-amz-security-token"));
    assert!(signed.contains("X-Amz-Security-Token: session-token"));
    // The point of signing: the guest's credential-shaped string is gone, not
    // exchanged for something that works.
    assert!(!signed.contains(SystemEgressConnector::BEDROCK_SENTINEL));
    assert!(signed.ends_with("\r\n\r\n{}"));

    // Static credentials have nowhere to refresh from, so an expiry is named
    // here rather than left to become a signature upstream rejects.
    vault.signer = Some(SigV4Signer {
        host: host.to_owned(),
        region: "us-east-1".to_owned(),
        source: AwsCredentialSource::Environment,
        credentials: super::Mutex::new(AwsCredentials {
            access_key_id: "ASIAEXAMPLE".to_owned(),
            secret_access_key: SecretBytes::new("secret".as_bytes()),
            session_token: None,
            expires_at: Some(0),
        }),
    });
    let error = vault
        .inject(&target, request.as_bytes())
        .expect_err("expired credentials");
    assert!(error.to_string().contains("expired"), "{error}");
}

#[test]
fn a_signed_request_commits_to_the_sanitized_body_and_not_the_one_received() {
    // Signing makes the sanitizer load-bearing: before D17 a scope mismatch was
    // still caught at swap time, and now the only thing standing between a
    // guest-supplied `mcp_servers` and upstream is that the signature covers the
    // stripped body. Asserting the stripped key is absent would not prove that —
    // it would pass on a request that signed the original bytes and sent the
    // sanitized ones, which upstream rejects, and on the reverse, which it does
    // not. So recompute the signature both ways and require the sanitized one.
    struct InvokeAuthorizer;

    impl EgressRequestAuthorizer for InvokeAuthorizer {
        fn authorize(
            &mut self,
            method: &str,
            path: &str,
            _body_digest: [u8; 32],
            model_budget: Option<ModelBudgetRequest>,
        ) -> Result<(), String> {
            assert_eq!(method, "POST");
            assert!(path.ends_with("/invoke"));
            assert!(model_budget.is_some());
            Ok(())
        }

        fn record_response(&mut self) -> Result<(), String> {
            Ok(())
        }
    }

    let host = "bedrock-runtime.us-east-1.amazonaws.com";
    let secret = b"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    let mut vault = CredentialVault::new();
    vault.signer = Some(SigV4Signer {
        host: host.to_owned(),
        region: "us-east-1".to_owned(),
        source: AwsCredentialSource::Environment,
        credentials: super::Mutex::new(AwsCredentials {
            access_key_id: "AKIDEXAMPLE".to_owned(),
            secret_access_key: SecretBytes::new(secret),
            session_token: None,
            expires_at: None,
        }),
    });
    let target = ConnectionTarget {
        server_name: host.to_owned(),
        port: 443,
        resolved_ip: IpAddr::from(Ipv4Addr::new(93, 184, 216, 34)),
    };
    let path = "/model/us.anthropic.claude-sonnet-4-5-20250929-v1:0/invoke";
    let body = br#"{"anthropic_version":"bedrock-2023-05-31","max_tokens":32,"mcp_servers":[{"url":"https://evil.example"}],"messages":[]}"#;
    // The guest also supplies its own payload hash, which is the header that
    // would carry a stale body forward if it were passed through.
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer {}\r\n\
             X-Amz-Content-Sha256: {}\r\nContent-Length: {}\r\n\r\n{}",
        SystemEgressConnector::BEDROCK_SENTINEL,
        encode_lower_hex(super::digest(&super::SHA256, body).as_ref()),
        body.len(),
        String::from_utf8_lossy(body),
    );
    let prepared = prepare_upstream_request_with_authorizer(
        &target,
        &vault,
        request.as_bytes(),
        &mut InvokeAuthorizer,
        false,
    )
    .expect("signed invoke request");
    let signed = String::from_utf8(prepared.bytes).expect("utf8");

    let amz_date = signed
        .lines()
        .find_map(|line| line.strip_prefix("X-Amz-Date: "))
        .expect("signed request carries its own timestamp")
        .to_owned();
    let date_stamp = &amz_date[..8];
    let canonical_uri = canonical_request_uri(path).expect("canonical uri");
    let signature_for = |payload: &[u8]| {
        let canonical_request = format!(
            "POST\n{canonical_uri}\n\ncontent-type:application/json\nhost:{host}\n\
                 x-amz-date:{amz_date}\n\ncontent-type;host;x-amz-date\n{}",
            encode_lower_hex(super::digest(&super::SHA256, payload).as_ref())
        );
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{amz_date}\n{date_stamp}/us-east-1/bedrock/aws4_request\n{}",
            encode_lower_hex(super::digest(&super::SHA256, canonical_request.as_bytes()).as_ref())
        );
        sigv4_signature(
            secret,
            date_stamp,
            "us-east-1",
            "bedrock",
            string_to_sign.as_bytes(),
        )
    };
    let sanitized = sanitize_model_request(&target, path, body).expect("invoke request");
    assert_eq!(sanitized.stripped, vec!["mcp_servers".to_owned()]);
    assert!(
        signed.contains(&format!("Signature={}", signature_for(&sanitized.body))),
        "the signature must cover the sanitized body: {signed}"
    );
    assert!(
        !signed.contains(&format!("Signature={}", signature_for(body))),
        "a signature over the body as received would be a signature over a request \
             this proxy never sent"
    );
    // The guest's hash header travels with nothing to authenticate it, so it
    // does not travel at all.
    assert!(!signed.contains("X-Amz-Content-Sha256"));
    assert!(!signed.contains("mcp_servers"));
}

#[derive(Default)]
struct PayloadRecorder {
    observed: Vec<(String, Vec<u8>)>,
}

impl EgressRequestAuthorizer for PayloadRecorder {
    fn observe_payload(&mut self, path: &str, body: &[u8]) {
        self.observed.push((path.to_owned(), body.to_vec()));
    }

    fn authorize(
        &mut self,
        _method: &str,
        _path: &str,
        _body_digest: [u8; 32],
        _model_budget: Option<ModelBudgetRequest>,
    ) -> Result<(), String> {
        Ok(())
    }

    fn record_response(&mut self) -> Result<(), String> {
        Ok(())
    }
}

#[test]
fn decrypted_non_model_payloads_are_shown_to_the_authorizer() {
    let target = ConnectionTarget {
        server_name: "paste.example".to_owned(),
        resolved_ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
        port: 443,
    };
    let mut recorder = PayloadRecorder::default();
    prepare_upstream_request_with_authorizer(
        &target,
        &CredentialVault::new(),
        b"POST /upload?id=7 HTTP/1.1\r\nHost: paste.example\r\nContent-Length: 5\r\n\r\nhello",
        &mut recorder,
        false,
    )
    .expect("authorized request");
    assert_eq!(
        recorder.observed,
        [("/upload?id=7".to_owned(), b"hello".to_vec())]
    );
}

#[test]
fn an_interrupted_event_stream_is_bounded_by_its_complete_frames() {
    let event = [(":message-type", "event"), (":event-type", "chunk")];
    let start = event_stream_frame(
        &event,
        r#"{"bytes":"eyJ0eXBlIjoibWVzc2FnZV9zdGFydCIsIm1lc3NhZ2UiOnsidXNhZ2UiOnsiaW5wdXRfdG9rZW5zIjoyLCJjYWNoZV9yZWFkX2lucHV0X3Rva2VucyI6Mywib3V0cHV0X3Rva2VucyI6MH19fQ=="}"#,
    );
    let delta = event_stream_frame(
        &event,
        r#"{"bytes":"eyJ0eXBlIjoiY29udGVudF9ibG9ja19kZWx0YSIsImRlbHRhIjp7InR5cGUiOiJ0aGlua2luZ19kZWx0YSIsInRoaW5raW5nIjoiYWJjZGVmZ2gifX0="}"#,
    );
    let mut body = start.clone();
    body.extend_from_slice(&delta);
    body.extend_from_slice(&delta[..delta.len() - 3]);
    assert_eq!(
        super::interrupted_usage_bound(&event_stream_response(&body)),
        Some(ModelUsage {
            input_tokens: 5,
            output_tokens: 8 + super::INTERRUPTED_OUTPUT_MARGIN_TOKENS,
        })
    );
    assert_eq!(
        super::interrupted_usage_bound(&event_stream_response(&delta)),
        None,
        "no opening usage event, so no bound"
    );
}

#[test]
fn tool_call_arguments_are_reassembled_from_streamed_and_complete_responses() {
    let streamed = concat!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n",
        "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
        "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"I will edit.\"}}\n\n",
        "data: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"tool_use\",\"name\":\"Write\",\"input\":{}}}\n\n",
        "data: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"file_path\\\":\\\"a.rs\\\",\"}}\n\n",
        "data: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"\\\"content\\\":\\\"fn a() {}\\\"}\"}}\n\n",
    );
    let mut arguments = super::tool_arguments(&super::model_response_blocks(streamed.as_bytes()));
    arguments.sort();
    assert_eq!(arguments, ["a.rs", "fn a() {}"]);

    let body = r#"{"content":[{"type":"text","text":"x"},{"type":"tool_use","input":{"command":"echo hi > f"}}]}"#;
    let complete = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    assert_eq!(
        super::tool_arguments(&super::model_response_blocks(complete.as_bytes())),
        ["echo hi > f"]
    );
}

#[test]
fn context_blocks_carried_back_share_the_response_digest() {
    let streamed = concat!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n",
        "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
        "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Reading \"}}\n\n",
        "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"it.\"}}\n\n",
        "data: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_01\",\"name\":\"Read\",\"input\":{}}}\n\n",
        "data: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"file_path\\\":\\\"a.rs\\\"}\"}}\n\n",
    );
    let response = super::model_response_blocks(streamed.as_bytes())
        .iter()
        .map(|block| super::context_block("response", None, block))
        .collect::<Vec<_>>();
    let request = serde_json::json!({
        "system": "You are a coding agent.",
        "tools": [{"name": "Read", "input_schema": {"type": "object"}}],
        "messages": [
            {"role": "user", "content": "read a.rs"},
            {"role": "assistant", "content": [
                {"type": "text", "text": "Reading it.", "cache_control": {"type": "ephemeral"}},
                {"type": "tool_use", "id": "toolu_01", "name": "Read", "input": {"file_path": "a.rs"}}
            ]},
            {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "toolu_01", "content": "fn a() {}"}
            ]}
        ]
    });
    let blocks = super::model_request_context(request.to_string().as_bytes());
    let places = blocks
        .iter()
        .map(|block| (block.place.as_str(), block.kind))
        .collect::<Vec<_>>();
    assert_eq!(
        places,
        [
            ("system", "text"),
            ("tools", "tool"),
            ("messages.0.user", "text"),
            ("messages.1.assistant", "text"),
            ("messages.1.assistant", "tool_use"),
            ("messages.2.user", "tool_result"),
        ]
    );
    assert_eq!(blocks[3].digest, response[0].digest, "cache marker ignored");
    assert_eq!(blocks[4].digest, response[1].digest);
    assert_eq!(blocks[4].tool_use.as_deref(), Some("toolu_01"));
    assert_eq!(blocks[5].tool_use.as_deref(), Some("toolu_01"));
    assert_eq!(blocks[1].tool_use, None);
    assert!(super::model_request_context(b"not json").is_empty());
}

#[test]
fn context_digests_ignore_object_key_order() {
    let emitted = serde_json::json!({
        "type": "tool_use", "id": "toolu_02", "name": "Edit",
        "input": {"file_path": "a.rs", "old_string": "x", "new_string": "y"}
    });
    let echoed = serde_json::json!({
        "input": {"new_string": "y", "file_path": "a.rs", "old_string": "x"},
        "name": "Edit", "id": "toolu_02", "type": "tool_use"
    });
    assert_eq!(
        super::context_block("response", None, &emitted).digest,
        super::context_block("messages.1.assistant", None, &echoed).digest
    );
}
