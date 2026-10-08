#![doc = "The run's model host is named by the caller, not assumed by the kernel."]

use keel_kernel::{
    EGRESS_ALLOWED, EgressConnector, EgressRequestAuthorizer, EgressSession, KernelBroker,
    ModelBudgetLimits, ModelBudgetRequest, Policy, ProvenanceMode, Violation,
};
use keel_provenance::SessionFacts;
use std::{
    collections::BTreeSet,
    io::{Read as _, Write as _},
    net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    os::unix::net::UnixStream,
    thread,
    time::Duration,
};

struct Connector {
    address: SocketAddr,
    requests: Vec<(&'static str, &'static str)>,
}

impl EgressConnector for Connector {
    fn connect(
        &mut self,
        _host: &str,
        _port: u16,
        _method: &str,
    ) -> Result<Box<dyn EgressSession>, String> {
        let stream = TcpStream::connect(self.address).map_err(|error| error.to_string())?;
        let (method, path) = self.requests.remove(0);
        Ok(Box::new(Session {
            stream,
            method,
            path,
        }))
    }
}

struct Session {
    stream: TcpStream,
    method: &'static str,
    path: &'static str,
}

impl EgressSession for Session {
    fn forward(
        self: Box<Self>,
        guest: UnixStream,
        authorizer: &mut dyn EgressRequestAuthorizer,
    ) -> Result<(), String> {
        // Nothing is relayed: the authorization decision and the provenance the
        // response carries are the whole subject, so both streams are dropped.
        let result = authorizer.authorize(
            self.method,
            self.path,
            [0; 32],
            Some(ModelBudgetRequest {
                input_tokens_upper_bound: 1_024,
                max_output_tokens: 1_024,
                input_microusd_per_token: 1,
                output_microusd_per_token: 1,
            }),
        );
        if result.is_ok() {
            authorizer.commit_request_send()?;
            // A response the guest would have received, which is what moves the
            // floor — or, for a model response, what must not move it.
            authorizer.record_response()?;
        }
        drop(self.stream);
        drop(guest);
        result
    }
}

struct Permissive;

impl Policy for Permissive {
    fn violations(
        &self,
        _action: &keel_kernel::Action,
        _: &SessionFacts,
    ) -> Result<Vec<Violation>, String> {
        Ok(Vec::new())
    }
}

/// Authorizes one HTTP request against a broker told that `model_host` is this
/// run's model endpoint, and reports how many actions it denied.
fn denials(model_host: &str, method: &'static str, path: &'static str) -> u64 {
    requests(model_host, vec![(method, path)])
}

/// Runs each request in order through one broker, on its own connection, and
/// reports how many actions that broker denied.
fn requests(model_host: &str, requests: Vec<(&'static str, &'static str)>) -> u64 {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("upstream listener");
    let address = listener.local_addr().expect("upstream address");
    let count = requests.len();
    let upstream = thread::spawn(move || {
        for _ in 0..count {
            if let Ok((stream, _)) = listener.accept() {
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .expect("upstream timeout");
            }
        }
    });
    let broker = KernelBroker::spawn_with_diagnostics(
        "model-provider".to_owned(),
        [model_host.to_owned()].into_iter().collect(),
        BTreeSet::new(),
        model_host.to_owned(),
        SessionFacts::default(),
        ProvenanceMode::Floor,
        Box::new(Permissive),
        Box::new(Connector { address, requests }),
        // No gate, so an action that needs an operator is denied rather than
        // waiting for one. Every allowance below is therefore an allowance the
        // policy reached on its own.
        Box::new(DiscardAudit),
        None,
        ModelBudgetLimits::default(),
        None,
    )
    .expect("broker");
    for _ in 0..count {
        let mut client = UnixStream::connect(broker.socket_path()).expect("broker connection");
        client.write_all(b"KEEL-EGRESS-V2\0").expect("marker");
        client
            .write_all(
                &u16::try_from(model_host.len())
                    .expect("host length")
                    .to_be_bytes(),
            )
            .expect("host length");
        client.write_all(model_host.as_bytes()).expect("host");
        client.write_all(&443_u16.to_be_bytes()).expect("port");
        client.write_all(&[2]).expect("method");
        client.flush().expect("request flush");
        let mut response = [0_u8; 2];
        client.read_exact(&mut response).expect("broker response");
        assert_eq!(response, [b'P', EGRESS_ALLOWED], "transport was refused");
        let mut drained = Vec::new();
        let _ = client.read_to_end(&mut drained);
    }
    upstream.join().expect("upstream thread");
    broker.shutdown().expect("broker shutdown").denied_actions
}

struct DiscardAudit;

impl keel_kernel::AuditSink for DiscardAudit {
    fn record(&mut self, _event: keel_kernel::AuditEvent) -> Result<(), String> {
        Ok(())
    }
}

#[test]
fn a_regional_provider_is_model_egress_rather_than_a_metadata_mismatch() {
    // The regression this exists for: the broker recognized one provider's
    // hostname, so a request to the other arrived with budget metadata the
    // kernel then read as a non-model endpoint supplying it. That is a hard
    // deny with no gate consulted, and the guest saw only a dropped
    // connection retried ten times. Both providers reserve budget now.
    assert_eq!(
        denials("api.anthropic.com", "POST", "/v1/messages"),
        0,
        "the first-party model endpoint was refused"
    );
    assert_eq!(
        denials(
            "bedrock-runtime.us-west-2.amazonaws.com",
            "POST",
            "/model/us.anthropic.claude-opus-5-20260101-v1:0/invoke"
        ),
        0,
        "a regional model endpoint was refused"
    );
    assert_eq!(
        denials(
            "bedrock-runtime.us-west-2.amazonaws.com",
            "POST",
            "/model/us.anthropic.claude-opus-5-20260101-v1:0/invoke-with-response-stream"
        ),
        0,
        "a regional streaming endpoint was refused"
    );
}

#[test]
fn a_model_response_does_not_lower_the_floor_for_the_next_turn() {
    // The regression this exists for: a model response was exempt from moving the
    // provenance floor by hostname, so on the other provider the harness's own
    // answer was read as fetched untrusted content. The floor fell to 0, egress
    // requires rank 2 in floor mode, and every turn after the first then needed an
    // operator — who could not type fast enough to beat the harness's own retry.
    // A conversation is not an escalation per message.
    for (host, path) in [
        ("api.anthropic.com", "/v1/messages"),
        (
            "bedrock-runtime.us-west-2.amazonaws.com",
            "/model/us.anthropic.claude-opus-5-20260101-v1:0/invoke-with-response-stream",
        ),
    ] {
        assert_eq!(
            requests(host, vec![("POST", path), ("POST", path)]),
            0,
            "{host} escalated the turn after its own response"
        );
    }
}

#[test]
fn a_control_plane_path_on_a_model_host_is_not_model_egress() {
    // The endpoint restriction has to hold for both providers, not just the one
    // the kernel used to know about. A permission classifier on the model host
    // is the path that matters: refusing it is what makes the operator gate the
    // only adjudicator.
    for path in ["/v1/complete", "/model/claude/converse", "/permissions"] {
        assert_eq!(
            denials("bedrock-runtime.us-west-2.amazonaws.com", "POST", path),
            1,
            "{path} was authorized as model egress"
        );
    }
    assert_eq!(
        denials("api.anthropic.com", "POST", "/v1/messages/batches"),
        1,
        "a batch path was authorized as model egress"
    );
}
