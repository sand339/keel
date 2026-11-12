#![doc = "An authorized request that is never sent is reported as unsent."]

use keel_kernel::{
    AuditEvent, AuditSink, EGRESS_ALLOWED, EgressConnector, EgressRequestAuthorizer, EgressSession,
    Gate, GateDecision, GateRequest, KernelBroker, ModelBudgetLimits, Policy, ProvenanceMode,
    ReportedOutcomeEvent, Violation,
};
use keel_provenance::SessionFacts;
use std::{
    collections::BTreeSet,
    io::{Read as _, Write as _},
    os::unix::net::UnixStream,
    sync::{Arc, Mutex},
};

const HOST: &str = "packages.example";

/// Authorizes one request, then either reports it unsent, as the trusted
/// proxy does when the credential layer refuses it, or lets it stand.
struct Session {
    refuse: bool,
}

impl EgressSession for Session {
    fn forward(
        self: Box<Self>,
        guest: UnixStream,
        authorizer: &mut dyn EgressRequestAuthorizer,
    ) -> Result<(), String> {
        authorizer.authorize("GET", "/", [0; 32], None)?;
        drop(guest);
        if self.refuse {
            authorizer.record_unsent();
            return Err("refused after authorization".to_owned());
        }
        authorizer.commit_request_send()
    }
}

struct Connector {
    refuse: bool,
}

impl EgressConnector for Connector {
    fn connect(
        &mut self,
        _host: &str,
        _port: u16,
        _method: &str,
    ) -> Result<Box<dyn EgressSession>, String> {
        Ok(Box::new(Session {
            refuse: self.refuse,
        }))
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

/// The operator approves: this test is about what follows an authorization.
struct ApproveGate;

impl Gate for ApproveGate {
    fn decide(&mut self, _request: GateRequest<'_>) -> GateDecision {
        GateDecision::Approve
    }
}

#[derive(Clone, Default)]
struct Recording {
    executed: Arc<Mutex<Vec<u64>>>,
    reported: Arc<Mutex<Vec<ReportedOutcomeEvent>>>,
}

impl AuditSink for Recording {
    fn record(&mut self, event: AuditEvent) -> Result<(), String> {
        if event.outcome.as_str() == "executed" {
            self.executed.lock().unwrap().push(event.action_id);
        }
        Ok(())
    }

    fn record_reported_outcome(&mut self, event: ReportedOutcomeEvent) -> Result<(), String> {
        self.reported.lock().unwrap().push(event);
        Ok(())
    }
}

/// Sends one request through a broker and returns the actions it recorded as
/// executed and the outcomes reported for them.
fn request(refuse: bool) -> (Vec<u64>, Vec<ReportedOutcomeEvent>) {
    let audit = Recording::default();
    let broker = KernelBroker::spawn_with_diagnostics(
        "unsent-request".to_owned(),
        [HOST.to_owned()].into_iter().collect(),
        BTreeSet::new(),
        "api.anthropic.com".to_owned(),
        SessionFacts::default(),
        ProvenanceMode::Floor,
        Box::new(Permissive),
        Box::new(Connector { refuse }),
        Box::new(audit.clone()),
        Some(Box::new(ApproveGate)),
        ModelBudgetLimits::default(),
        None,
    )
    .expect("broker");
    let mut client = UnixStream::connect(broker.socket_path()).expect("broker connection");
    client.write_all(b"KEEL-EGRESS-V2\0").expect("marker");
    client
        .write_all(
            &u16::try_from(HOST.len())
                .expect("host length")
                .to_be_bytes(),
        )
        .expect("host length");
    client.write_all(HOST.as_bytes()).expect("host");
    client.write_all(&443_u16.to_be_bytes()).expect("port");
    client.write_all(&[2]).expect("method");
    client.flush().expect("request flush");
    let mut response = [0_u8; 2];
    client.read_exact(&mut response).expect("broker response");
    assert_eq!(response, [b'P', EGRESS_ALLOWED], "transport was refused");
    let mut drained = Vec::new();
    let _ = client.read_to_end(&mut drained);
    broker.shutdown().expect("broker shutdown");
    let executed = audit.executed.lock().unwrap().clone();
    let reported = audit.reported.lock().unwrap().clone();
    (executed, reported)
}

/// The kernel writes `executed` when it authorizes a request. A request the
/// trusted proxy then refuses must not be left reading as sent: the same
/// action gets a reported outcome saying it never was.
#[test]
fn a_request_refused_after_authorization_is_reported_unsent() {
    let (executed, reported) = request(true);
    let request_action = *executed.last().expect("the request was authorized");
    assert_eq!(
        reported,
        [ReportedOutcomeEvent {
            action_id: request_action,
            reporter: "trusted-proxy",
            outcome: "unsent".to_owned(),
        }]
    );
}

#[test]
fn a_request_that_is_sent_carries_no_unsent_report() {
    let (executed, reported) = request(false);
    assert!(!executed.is_empty(), "the request was authorized");
    assert!(reported.is_empty(), "{reported:?}");
}
