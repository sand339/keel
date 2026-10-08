#![doc = "A push the operator approved, and the floor their approval does not move."]

use keel_kernel::{
    EGRESS_ALLOWED, EgressConnector, EgressRequestAuthorizer, EgressSession, GIT_ALLOWED,
    GIT_BROKER_MAGIC, GIT_REPORT_COMPLETED, GIT_REPORT_MAGIC, Gate, GateDecision, GateRequest,
    KernelBroker, ModelBudgetLimits, Policy, ProvenanceMode, Violation,
};
use keel_provenance::SessionFacts;
use std::{
    collections::BTreeSet,
    io::{Read as _, Write as _},
    net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    os::unix::net::UnixStream,
    path::Path,
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

/// The remote the acceptance run pushes to.
const REMOTE: &str = "https://github.com/example-org/keel-acceptance.git";
const MODEL_HOST: &str = "api.anthropic.com";

/// One thing the guest asks the broker for, in the order it asks.
enum Step {
    /// A plain branch push to `REMOTE`, which requires trusted admission.
    Push,
    /// A force push to `REMOTE`, which needs rank 2 and always gates.
    ForcePush,
    /// An HTTP request through the egress broker, answered by a response the
    /// kernel then classifies.
    Request {
        method: &'static str,
        path: &'static str,
    },
}

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
        // Nothing is relayed: the rank the response carries is the whole
        // subject, so both streams are dropped once it is recorded.
        let result = authorizer.authorize(self.method, self.path, [0; 32], None);
        if result.is_ok() {
            authorizer.commit_request_send()?;
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

/// Approves everything and records the rules it was shown, so a test can ask
/// how many times an operator was interrupted and what for.
struct CountingGate(Arc<Mutex<Vec<String>>>);

impl Gate for CountingGate {
    fn decide(&mut self, request: GateRequest<'_>) -> GateDecision {
        let rules = request
            .violations
            .iter()
            .map(|violation| violation.rule.clone())
            .collect::<Vec<_>>()
            .join(",");
        self.0.lock().expect("gate log").push(rules);
        GateDecision::Approve
    }

    fn authority(&self) -> &'static str {
        "test"
    }
}

struct DiscardAudit;

impl keel_kernel::AuditSink for DiscardAudit {
    fn record(&mut self, _event: keel_kernel::AuditEvent) -> Result<(), String> {
        Ok(())
    }
}

/// Runs the steps in order through one session and reports every gate
/// escalation, as the rules the operator was shown.
fn escalations(steps: &[Step]) -> Vec<String> {
    run(steps).0
}

/// Runs the steps and reports the floor they left the session at.
///
/// The floor is read directly rather than inferred from an escalation because
/// `github.com` is on this session's egress intent, so a request to it is rank 0
/// and a dropped floor costs nothing there. An escalation and a floor are
/// different claims, and only one of them is what these tests are about.
fn final_floor(steps: &[Step]) -> u8 {
    run(steps).1
}

fn run(steps: &[Step]) -> (Vec<String>, u8) {
    let requests = steps
        .iter()
        .filter_map(|step| match step {
            Step::Request { method, path } => Some((*method, *path)),
            Step::Push | Step::ForcePush => None,
        })
        .collect::<Vec<_>>();
    let count = requests.len();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("upstream listener");
    let address = listener.local_addr().expect("upstream address");
    let upstream = thread::spawn(move || {
        for _ in 0..count {
            if let Ok((stream, _)) = listener.accept() {
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .expect("upstream timeout");
            }
        }
    });
    let log = Arc::new(Mutex::new(Vec::new()));
    let broker = KernelBroker::spawn_with_diagnostics(
        "push-provenance".to_owned(),
        ["github.com".to_owned(), MODEL_HOST.to_owned()]
            .into_iter()
            .collect(),
        BTreeSet::new(),
        MODEL_HOST.to_owned(),
        SessionFacts::default(),
        ProvenanceMode::Floor,
        Box::new(Permissive),
        Box::new(Connector { address, requests }),
        Box::new(DiscardAudit),
        Some(Box::new(CountingGate(Arc::clone(&log)))),
        ModelBudgetLimits::default(),
        None,
    )
    .expect("broker");
    let mut pushes = Vec::new();
    for step in steps {
        match step {
            Step::Push => pushes.push(push(broker.socket_path(), false)),
            Step::ForcePush => pushes.push(push(broker.socket_path(), true)),
            Step::Request { .. } => request(broker.socket_path()),
        }
    }
    for action_id in pushes {
        report_push(broker.socket_path(), action_id);
    }
    upstream.join().expect("upstream thread");
    let report = broker.shutdown().expect("broker shutdown");
    let escalations = log.lock().expect("gate log").clone();
    (escalations, report.session_facts.floor)
}

/// Authorizes one non-force branch push to `REMOTE` and reports its outcome,
/// which is what tells the kernel this session's operator approved that remote.
fn push(path: &Path, force: bool) -> u64 {
    let mut client = UnixStream::connect(path).expect("broker connection");
    client.write_all(GIT_BROKER_MAGIC).expect("marker");
    write_string(&mut client, REMOTE);
    client.write_all(&u16::to_be_bytes(1)).expect("ref count");
    write_string(&mut client, "refs/heads/topic");
    client
        .write_all(&[u8::from(force), 0, 0, 0])
        .expect("flags");
    client.write_all(&[0_u8; 32]).expect("body digest");
    client.flush().expect("request flush");
    let mut response = [0_u8; 9];
    client.read_exact(&mut response).expect("broker response");
    assert_eq!(response[0], GIT_ALLOWED, "the push was refused");
    u64::from_be_bytes(response[1..].try_into().expect("action id"))
}

fn report_push(path: &Path, action_id: u64) {
    let mut client = UnixStream::connect(path).expect("broker connection");
    client.write_all(GIT_REPORT_MAGIC).expect("marker");
    client
        .write_all(&action_id.to_be_bytes())
        .expect("action id");
    client.write_all(&[GIT_REPORT_COMPLETED]).expect("outcome");
    client.flush().expect("report flush");
    let mut accepted = [0_u8; 1];
    client.read_exact(&mut accepted).expect("report response");
}

fn write_string(client: &mut UnixStream, value: &str) {
    client
        .write_all(&u16::try_from(value.len()).expect("length").to_be_bytes())
        .expect("length");
    client.write_all(value.as_bytes()).expect("value");
}

/// Opens one TLS transport to `github.com` through the egress broker, which the
/// connector answers with the next queued request and response.
fn request(path: &Path) {
    let mut client = UnixStream::connect(path).expect("broker connection");
    client.write_all(b"KEEL-EGRESS-V2\0").expect("marker");
    write_string(&mut client, "github.com");
    client.write_all(&443_u16.to_be_bytes()).expect("port");
    client.write_all(&[1]).expect("method");
    client.flush().expect("request flush");
    let mut response = [0_u8; 2];
    client.read_exact(&mut response).expect("broker response");
    assert_eq!(
        response,
        [b'P', EGRESS_ALLOWED],
        "the transport was refused"
    );
    let mut drained = Vec::new();
    let _ = client.read_to_end(&mut drained);
}

#[test]
fn a_push_report_from_an_approved_remote_does_not_escalate_the_next_request() {
    // The regression this exists for: the remote's answer to a push the
    // operator had just approved was classified as fetched untrusted content.
    // The floor fell to 0, and the relay's own next request — still part of the
    // same push — needed a second operator decision.
    assert_eq!(
        escalations(&[
            Step::Push,
            Step::Request {
                method: "GET",
                path: "/example-org/keel-acceptance.git/info/refs?service=git-receive-pack",
            },
            Step::Request {
                method: "POST",
                path: "/example-org/keel-acceptance.git/git-receive-pack",
            },
            Step::Request {
                method: "POST",
                path: "/example-org/keel-acceptance.git/git-receive-pack",
            },
        ]),
        vec!["admission:git-push".to_owned()],
        "an approved push's own protocol exchange asked for a second decision"
    );
}

#[test]
fn a_page_fetched_from_the_same_host_still_lowers_the_floor() {
    // The exemption is for the push protocol on a remote this session approved,
    // not for the host. Anything else GitHub serves is content the harness went
    // and read, and it has to keep costing the floor.
    assert_eq!(
        final_floor(&[
            Step::Push,
            Step::Request {
                method: "GET",
                path: "/example-org/keel-acceptance/issues/1",
            },
            Step::Request {
                method: "POST",
                path: "/example-org/keel-acceptance.git/git-receive-pack",
            },
        ]),
        0,
        "a fetched page was treated as the push protocol"
    );
}

#[test]
fn a_push_protocol_path_for_an_unapproved_remote_is_not_accepted_as_content() {
    // Without the push, nothing about this path is an operator's decision: the
    // harness can name any URL, and naming one that ends in `/git-receive-pack`
    // must not buy it a rank it was never granted.
    assert_eq!(
        final_floor(&[
            Step::Request {
                method: "POST",
                path: "/example-org/keel-acceptance.git/git-receive-pack",
            },
            Step::Request {
                method: "POST",
                path: "/example-org/keel-acceptance.git/git-receive-pack",
            },
        ]),
        3,
        "an unapproved receive-pack request reached response provenance"
    );
}

#[test]
fn an_approved_push_holds_the_floor_at_operator_rank() {
    // The companion to the two above: the exemption has to actually exempt
    // something, or asserting that everything else drops the floor proves nothing.
    // It holds the floor at 2 rather than leaving it at 3 — the remote's answer is
    // the operator's data, not their instruction — and 2 is what every rank-2
    // capability needs, so the push's own protocol exchange costs nothing.
    assert_eq!(
        final_floor(&[
            Step::Push,
            Step::Request {
                method: "POST",
                path: "/example-org/keel-acceptance.git/git-receive-pack",
            },
        ]),
        2,
        "an approved push's own protocol exchange dropped below operator rank"
    );
}

#[test]
fn approving_a_rank_shortfall_authorizes_that_action_and_not_the_session() {
    // The regression this exists for, observed live: approving one escalation
    // called `lift_floor`, which raised the session floor to the rank that action
    // needed. An operator who allowed a single egress thereby satisfied the rank
    // precondition of a force-push twenty-two records later, and that push gate
    // never named the poisoned issue as the rank-0 source. §6.3 is explicit that
    // approval does not lift the floor: approving an action does not remove the
    // untrusted content from the agent's context, so it cannot change what the
    // floor describes. Only `keel floor lift` moves it, gated and counted.
    let steps = [
        Step::Request {
            method: "GET",
            path: "/example-org/keel-acceptance/issues/1",
        },
        Step::ForcePush,
        Step::ForcePush,
    ];
    assert_eq!(
        final_floor(&steps),
        0,
        "a gate approval lifted the floor the issue had lowered"
    );
    // Each force-push is asked about on its own, and the shortfall is still one of
    // the reasons the operator is shown the second time.
    let shown = escalations(&steps);
    assert_eq!(shown.len(), 3, "an action went unasked: {shown:?}");
    assert!(
        shown[1..]
            .iter()
            .all(|rules| rules.contains("kernel:minimum-rank")),
        "the rank shortfall stopped being a reason: {shown:?}"
    );
}

#[test]
fn an_allowlisted_non_model_host_still_requires_trusted_admission() {
    // §7.1 sets rank 2 for egress to a host outside the run's intent, not for
    // every request. Requiring it of all of them read the table wrong and was
    // expensive: §6.2 expects a session to reach floor 0 on its first test run, so
    // an unconditional rank 2 escalates every network call after that. This is the
    // pressure that made a session-wide floor lift look necessary.
    assert_eq!(
        escalations(&[
            Step::Request {
                method: "GET",
                path: "/example-org/keel-acceptance/issues/1",
            },
            Step::Request {
                method: "GET",
                path: "/example-org/keel-acceptance/issues/2",
            },
        ]),
        vec!["admission:egress".to_owned(), "admission:egress".to_owned()],
        "launcher-declared egress bypassed trusted admission"
    );
}
