use super::*;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned, pki_types::ServerName};
use std::{
    io::{Cursor, Read as _},
    net::{Ipv4Addr, TcpListener, TcpStream},
    os::unix::net::UnixStream,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
};

#[test]
fn denied_tls_request_does_not_resolve_or_connect() {
    struct DenyingAuthorizer(Arc<AtomicBool>);

    impl EgressRequestAuthorizer for DenyingAuthorizer {
        fn authorize(
            &mut self,
            method: &str,
            path: &str,
            _body_digest: [u8; 32],
            model_budget: Option<ModelBudgetRequest>,
        ) -> Result<(), String> {
            assert_eq!(method, "POST");
            assert_eq!(path, "/v1/messages");
            assert!(model_budget.is_some());
            self.0.store(true, Ordering::Release);
            Err("test policy denied the exact request".to_owned())
        }

        fn record_response(&mut self) -> Result<(), String> {
            panic!("a denied request has no response to record")
        }
    }

    let ca = MitmCa::generate().unwrap();
    let front_config = ca.server_config("api.anthropic.com").unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(ca.certificate_der()).unwrap();
    let client_config = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots.clone())
            .with_no_client_auth(),
    );
    let upstream_config = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let authorization_seen = Arc::new(AtomicBool::new(false));
    let connected = Arc::new(AtomicBool::new(false));
    let front_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let front_address = front_listener.local_addr().unwrap();
    let front_authorized = Arc::clone(&authorization_seen);
    let front_connected = Arc::clone(&connected);
    let front = thread::spawn(move || {
        let (guest, _) = front_listener.accept().unwrap();
        let mut authorizer = DenyingAuthorizer(front_authorized);
        let destination = EgressDestination {
            server_name: "api.anthropic.com".to_owned(),
            port: 443,
        };
        let error = proxy_tls_http(
            guest,
            front_config,
            upstream_config,
            &destination,
            &CredentialVault::new(),
            &mut authorizer,
            false,
            || {
                front_connected.store(true, Ordering::Release);
                Err(TlsError("resolver must not run".to_owned()))
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains("test policy denied"));
    });

    let connection = ClientConnection::new(
        client_config,
        ServerName::try_from("api.anthropic.com".to_owned()).unwrap(),
    )
    .unwrap();
    let mut client = StreamOwned::new(connection, TcpStream::connect(front_address).unwrap());
    let body = br#"{"model":"claude-opus-5","max_tokens":32}"#;
    write!(
        client,
        "POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        String::from_utf8_lossy(body),
    )
    .unwrap();
    let mut response = Vec::new();
    let _ = client.read_to_end(&mut response);
    // The guest must receive the refusal as an answer it can render, not as a
    // reset that its API client would treat as a network fault and retry.
    let response = String::from_utf8(response).unwrap();
    assert!(
        response.starts_with("HTTP/1.1 403 Forbidden\r\n"),
        "{response}"
    );
    assert!(response.ends_with(REFUSAL_BODY), "{response}");
    front.join().unwrap();
    assert!(authorization_seen.load(Ordering::Acquire));
    assert!(!connected.load(Ordering::Acquire));
}

#[test]
fn cancelled_send_handoff_prevents_connector_invocation() {
    struct CancelledAuthorizer;

    impl EgressRequestAuthorizer for CancelledAuthorizer {
        fn authorize(
            &mut self,
            _method: &str,
            _path: &str,
            _body_digest: [u8; 32],
            _model_budget: Option<ModelBudgetRequest>,
        ) -> Result<(), String> {
            Ok(())
        }

        fn commit_request_send(&mut self) -> Result<(), String> {
            Err("origin disconnected".to_owned())
        }

        fn record_response(&mut self) -> Result<(), String> {
            panic!("an unsent request has no response")
        }
    }

    let (proxy_guest, mut client) = UnixStream::pair().unwrap();
    client
        .write_all(b"GET /status HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .unwrap();
    client.shutdown(std::net::Shutdown::Write).unwrap();
    let connected = Arc::new(AtomicBool::new(false));
    let attempted = Arc::clone(&connected);
    let error = proxy_plain_http_once(
        proxy_guest,
        &EgressDestination {
            server_name: "example.com".to_owned(),
            port: 80,
        },
        &CredentialVault::new(),
        &mut CancelledAuthorizer,
        move || {
            attempted.store(true, Ordering::Release);
            Err(TlsError("connector must not run".to_owned()))
        },
    )
    .unwrap_err();
    assert!(error.to_string().contains("origin disconnected"));
    assert!(!connected.load(Ordering::Acquire));
}

#[test]
fn no_upstream_response_does_not_record_provenance() {
    struct CountingAuthorizer(Arc<AtomicUsize>);

    impl EgressRequestAuthorizer for CountingAuthorizer {
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
            self.0.fetch_add(1, Ordering::AcqRel);
            Ok(())
        }
    }

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let upstream = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0_u8; 1024];
        assert!(stream.read(&mut request).unwrap() > 0);
        // Close without one response byte. Authorization alone must not taint
        // later model context as though external content had been delivered.
    });
    let (proxy_guest, mut client) = UnixStream::pair().unwrap();
    client
        .write_all(b"GET /status HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .unwrap();
    client.shutdown(std::net::Shutdown::Write).unwrap();
    let observations = Arc::new(AtomicUsize::new(0));
    let mut authorizer = CountingAuthorizer(Arc::clone(&observations));
    let error = proxy_plain_http_once(
        proxy_guest,
        &EgressDestination {
            server_name: "example.com".to_owned(),
            port: 80,
        },
        &CredentialVault::new(),
        &mut authorizer,
        || {
            Ok((
                TcpStream::connect(address).unwrap(),
                ConnectionTarget {
                    server_name: "example.com".to_owned(),
                    resolved_ip: Ipv4Addr::new(93, 184, 216, 34).into(),
                    port: 80,
                },
            ))
        },
    )
    .unwrap_err();
    assert!(error.to_string().contains("ended early"));
    assert_eq!(observations.load(Ordering::Acquire), 0);
    upstream.join().unwrap();
}

#[test]
fn provenance_is_recorded_before_first_response_byte_is_delivered() {
    struct OrderedWriter(Arc<AtomicBool>);

    impl std::io::Write for OrderedWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            assert!(self.0.load(Ordering::Acquire));
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let observed = Arc::new(AtomicBool::new(false));
    let callback = Arc::clone(&observed);
    let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
    let relayed = relay_http_response_with_observation(
        &mut Cursor::new(response),
        &mut OrderedWriter(Arc::clone(&observed)),
        "ordered response",
        move || {
            callback.store(true, Ordering::Release);
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(relayed.bytes, response);
    assert!(observed.load(Ordering::Acquire));
}

#[test]
fn system_connector_defers_dns_but_rejects_forbidden_results_before_connect() {
    let mut connector = SystemEgressConnector::new().unwrap();
    connector
        .connect("localhost", 80, "HTTP")
        .expect("local proxy setup must not perform DNS");
    let error = connect_system_target(&EgressDestination {
        server_name: "localhost".to_owned(),
        port: 80,
    })
    .expect_err("the post-authorization resolver must reject localhost");
    assert!(error.to_string().contains("forbidden address"));
    let Err(error) = connector.connect("example.com", 80, "CONNECT") else {
        panic!("uninspected CONNECT must be rejected");
    };
    assert!(error.contains("inspected TLS"));
}
