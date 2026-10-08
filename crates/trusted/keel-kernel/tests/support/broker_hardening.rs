use super::*;
use std::{
    collections::BTreeSet,
    io::ErrorKind,
    net::{Ipv4Addr, TcpListener},
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc::{Receiver, SyncSender, sync_channel},
    },
    thread,
    time::{Duration, Instant},
};

struct Allow;

impl Policy for Allow {
    fn violations(&self, _: &Action, _: &SessionFacts) -> Result<Vec<Violation>, String> {
        Ok(Vec::new())
    }
}

struct ApproveGate;

impl Gate for ApproveGate {
    fn decide(&mut self, _request: GateRequest<'_>) -> GateDecision {
        GateDecision::Approve
    }
}

struct UnusedConnector;

impl EgressConnector for UnusedConnector {
    fn connect(
        &mut self,
        _host: &str,
        _port: u16,
        _method: &str,
    ) -> Result<Box<dyn EgressSession>, String> {
        Err("unused connector".to_owned())
    }
}

fn open_relay(path: &Path) -> std::os::unix::net::UnixStream {
    let mut client = std::os::unix::net::UnixStream::connect(path).expect("broker connection");
    client
        .write_all(b"KEEL-EGRESS-V2\0\0\rrelay.example\x01\xbb\x02")
        .expect("egress request");
    client.flush().expect("request flush");
    let mut response = [0_u8; 2];
    client
        .read_exact(&mut response)
        .expect("transport response");
    assert_eq!(response, [EGRESS_PENDING, EGRESS_ALLOWED]);
    client
}

struct DelayedConnector {
    address: std::net::SocketAddr,
    authorized: Option<SyncSender<()>>,
    release: Option<Receiver<()>>,
}

struct LoopbackConnector {
    address: std::net::SocketAddr,
}

struct FailedForwardConnector;

struct FailedForwardSession;

impl EgressConnector for FailedForwardConnector {
    fn connect(
        &mut self,
        _host: &str,
        _port: u16,
        _method: &str,
    ) -> Result<Box<dyn EgressSession>, String> {
        Ok(Box::new(FailedForwardSession))
    }
}

impl EgressSession for FailedForwardSession {
    fn forward(
        self: Box<Self>,
        _guest: std::os::unix::net::UnixStream,
        authorizer: &mut dyn EgressRequestAuthorizer,
    ) -> Result<(), String> {
        authorizer.authorize("GET", "/status", [0_u8; 32], None)?;
        authorizer.commit_request_send()?;
        Err("upstream DNS resolution failed".to_owned())
    }
}

impl EgressConnector for LoopbackConnector {
    fn connect(
        &mut self,
        _host: &str,
        _port: u16,
        _method: &str,
    ) -> Result<Box<dyn EgressSession>, String> {
        Ok(Box::new(LoopbackSession {
            address: self.address,
        }))
    }
}

struct LoopbackSession {
    address: std::net::SocketAddr,
}

impl EgressSession for LoopbackSession {
    fn forward(
        self: Box<Self>,
        mut guest: std::os::unix::net::UnixStream,
        authorizer: &mut dyn EgressRequestAuthorizer,
    ) -> Result<(), String> {
        authorizer.authorize("GET", "/status", [0_u8; 32], None)?;
        authorizer.commit_request_send()?;
        let mut upstream =
            std::net::TcpStream::connect(self.address).map_err(|error| error.to_string())?;
        let mut request = [0_u8; 4];
        guest
            .read_exact(&mut request)
            .map_err(|error| error.to_string())?;
        upstream
            .write_all(&request)
            .map_err(|error| error.to_string())?;
        let mut response = [0_u8; 4];
        upstream
            .read_exact(&mut response)
            .map_err(|error| error.to_string())?;
        // Provenance is committed before the first response byte can reach the
        // guest, matching the production streaming contract.
        authorizer.record_response()?;
        guest
            .write_all(&response)
            .map_err(|error| error.to_string())
    }
}

impl EgressConnector for DelayedConnector {
    fn connect(
        &mut self,
        _host: &str,
        _port: u16,
        _method: &str,
    ) -> Result<Box<dyn EgressSession>, String> {
        match (self.authorized.take(), self.release.take()) {
            (Some(authorized), Some(release)) => Ok(Box::new(DelayedSession {
                address: self.address,
                authorized,
                release,
            })),
            (None, None) => Ok(Box::new(LoopbackSession {
                address: self.address,
            })),
            _ => Err("delayed connector synchronization is incomplete".to_owned()),
        }
    }
}

struct DelayedSession {
    address: std::net::SocketAddr,
    authorized: SyncSender<()>,
    release: Receiver<()>,
}

impl EgressSession for DelayedSession {
    fn forward(
        self: Box<Self>,
        _guest: std::os::unix::net::UnixStream,
        authorizer: &mut dyn EgressRequestAuthorizer,
    ) -> Result<(), String> {
        authorizer.authorize("GET", "/status", [0_u8; 32], None)?;
        self.authorized
            .send(())
            .map_err(|error| error.to_string())?;
        self.release.recv().map_err(|error| error.to_string())?;
        authorizer.commit_request_send()?;
        std::net::TcpStream::connect(self.address)
            .map(|_| ())
            .map_err(|error| error.to_string())
    }
}

#[test]
fn disconnect_after_approval_cancels_before_upstream_connect() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("upstream listener");
    let (authorized_tx, authorized_rx) = sync_channel(0);
    let (release_tx, release_rx) = sync_channel(0);
    let (gate, controller) = terminal_gate_channel();
    let broker = KernelBroker::spawn_with_audit_and_gate(
        "disconnect-before-connect".to_owned(),
        BTreeSet::new(),
        BTreeSet::new(),
        Box::new(DelayedConnector {
            address: listener.local_addr().expect("upstream address"),
            authorized: Some(authorized_tx),
            release: Some(release_rx),
        }),
        Box::new(DiscardAudit),
        Box::new(gate),
    )
    .expect("broker");
    let client = open_relay(broker.socket_path());
    controller
        .receive()
        .expect("exact request prompt")
        .decide(GateDecision::ApproveGrant)
        .expect("operator approval");
    authorized_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("exact authorization");
    assert_eq!(
        broker
            .state
            .lock()
            .expect("broker state")
            .kernel
            .egress_grants
            .len(),
        1,
        "grant is provisional until the send handoff"
    );
    client
        .shutdown(std::net::Shutdown::Write)
        .expect("originating half-close");
    thread::sleep(Duration::from_millis(100));
    release_tx.send(()).expect("release send boundary");
    drop(client);
    let deadline = Instant::now() + Duration::from_secs(1);
    while !broker
        .state
        .lock()
        .expect("broker state")
        .kernel
        .egress_grants
        .is_empty()
        && Instant::now() < deadline
    {
        thread::sleep(Duration::from_millis(10));
    }
    assert!(
        broker
            .state
            .lock()
            .expect("broker state")
            .kernel
            .egress_grants
            .is_empty(),
        "cancelled exact request left a reusable grant"
    );

    listener
        .set_nonblocking(true)
        .expect("nonblocking listener");
    assert_eq!(
        listener
            .accept()
            .expect_err("cancelled request connected upstream")
            .kind(),
        ErrorKind::WouldBlock
    );

    // The grant decision preceded the disconnect, but no request crossed the
    // external-send handoff. A retry must therefore prompt instead of reusing
    // stale authority from the abandoned request.
    let retry = open_relay(broker.socket_path());
    let retry_prompt = controller
        .receive_timeout(Duration::from_secs(1))
        .expect("gate channel")
        .expect("abandoned grant must not authorize a retry");
    retry_prompt
        .decide(GateDecision::Deny)
        .expect("deny retry prompt");
    drop(retry);
    broker.shutdown().expect("broker shutdown");
}

#[test]
fn failed_forwarding_revokes_the_originating_reusable_grant() {
    let (gate, controller) = terminal_gate_channel();
    let broker = KernelBroker::spawn_with_audit_and_gate(
        "failed-forward-grant".to_owned(),
        BTreeSet::new(),
        BTreeSet::new(),
        Box::new(FailedForwardConnector),
        Box::new(DiscardAudit),
        Box::new(gate),
    )
    .expect("broker");

    let first = open_relay(broker.socket_path());
    controller
        .receive()
        .expect("first exact request prompt")
        .decide(GateDecision::ApproveGrant)
        .expect("operator grant approval");
    drop(first);

    let deadline = Instant::now() + Duration::from_secs(1);
    while !broker
        .state
        .lock()
        .expect("broker state")
        .kernel
        .egress_grants
        .is_empty()
        && Instant::now() < deadline
    {
        thread::sleep(Duration::from_millis(10));
    }
    assert!(
        broker
            .state
            .lock()
            .expect("broker state")
            .kernel
            .egress_grants
            .is_empty(),
        "failed forwarding left its provisional grant reusable"
    );

    let retry = open_relay(broker.socket_path());
    controller
        .receive_timeout(Duration::from_secs(1))
        .expect("gate channel")
        .expect("failed forwarding must not authorize a retry")
        .decide(GateDecision::Deny)
        .expect("deny retry prompt");
    drop(retry);
    broker.shutdown().expect("broker shutdown");
}

#[test]
fn transport_setup_completes_before_the_exact_request_prompt() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("upstream listener");
    let address = listener.local_addr().expect("upstream address");
    let upstream = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("upstream connection");
        let mut request = [0_u8; 4];
        stream.read_exact(&mut request).expect("tunnel request");
        assert_eq!(&request, b"ping");
        stream.write_all(b"pong").expect("tunnel response");
    });
    let (gate, controller) = terminal_gate_channel();
    let broker = KernelBroker::spawn_with_audit_and_gate(
        "pending-before-gate".to_owned(),
        BTreeSet::new(),
        BTreeSet::new(),
        Box::new(LoopbackConnector { address }),
        Box::new(DiscardAudit),
        Box::new(gate),
    )
    .expect("broker");
    let mut client = open_relay(broker.socket_path());
    let pending = controller.receive().expect("exact request prompt");
    let target = String::from_utf8_lossy(&pending.payload().exact_target);
    assert!(target.contains("GET"));
    assert!(target.contains("/status"));
    assert!(!target.contains("CONNECT"));
    pending
        .decide(GateDecision::ApproveGrant)
        .expect("operator approval");
    client.write_all(b"ping").expect("tunnel write");
    let mut tunneled = [0_u8; 4];
    client
        .read_exact(&mut tunneled)
        .expect("tunnel response body");
    assert_eq!(&tunneled, b"pong");
    upstream.join().expect("upstream thread");
    assert_eq!(
        broker.shutdown().expect("broker shutdown").denied_actions,
        0
    );
}

#[test]
fn originating_half_close_cancels_late_decisions_and_retry_gets_a_fresh_action() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("upstream listener");
    let (gate, controller) = terminal_gate_channel();
    let broker = KernelBroker::spawn_with_audit_and_gate(
        "cancelled-prompt".to_owned(),
        BTreeSet::new(),
        BTreeSet::new(),
        Box::new(LoopbackConnector {
            address: listener.local_addr().expect("upstream address"),
        }),
        Box::new(DiscardAudit),
        Box::new(gate),
    )
    .expect("broker");
    let wait_until_inactive = |pending: &PendingApproval| {
        let deadline = Instant::now() + Duration::from_secs(1);
        while pending.is_active() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(!pending.is_active(), "peer loss must invalidate the prompt");
    };

    let first = open_relay(broker.socket_path());
    let first_pending = controller.receive().expect("first exact request prompt");
    let first_action = first_pending.payload().action_id;
    first.shutdown(std::net::Shutdown::Write).unwrap();
    wait_until_inactive(&first_pending);
    assert!(first_pending.decide(GateDecision::Approve).is_err());

    let second = open_relay(broker.socket_path());
    let second_pending = controller.receive().expect("second exact request prompt");
    let second_action = second_pending.payload().action_id;
    assert_ne!(second_action, first_action);
    second.shutdown(std::net::Shutdown::Write).unwrap();
    wait_until_inactive(&second_pending);
    assert!(second_pending.decide(GateDecision::ApproveGrant).is_err());

    let retry = open_relay(broker.socket_path());
    let retry_pending = controller
        .receive_timeout(Duration::from_secs(1))
        .expect("gate channel")
        .expect("cancelled grant must not suppress retry prompt");
    assert_ne!(retry_pending.payload().action_id, second_action);
    retry_pending.decide(GateDecision::Deny).unwrap();
    // Wait for the denial to reach the client, as a real one would, before
    // dropping it. A drop the broker notices first is recorded as the client
    // cancelling, not as the operator's denial, and then does not count
    // toward repeated-behavior review.
    let mut retry = retry;
    retry
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("retry read timeout");
    let _ = std::io::Read::read_to_end(&mut retry, &mut Vec::new());
    drop((first, second, retry));
    let report = broker.shutdown().expect("broker shutdown");
    assert_eq!(report.denied_actions, 3);
    assert_eq!(report.session_facts.recent_behavioral_denials_in_scope, 1);
}

#[test]
fn admitted_and_granted_paths_use_unconditional_execution_cancellation() {
    struct CountingExecutor(Arc<AtomicUsize>);

    impl Executor<()> for CountingExecutor {
        type Output = ();

        fn execute(&mut self, (): ()) -> Result<(), String> {
            self.0.fetch_add(1, Ordering::AcqRel);
            Ok(())
        }
    }

    let executions = Arc::new(AtomicUsize::new(0));
    let cancelled = AtomicBool::new(true);
    let mut inner = CountingExecutor(Arc::clone(&executions));
    let mut executor = CancellableExecutor {
        inner: &mut inner,
        cancelled: &cancelled,
    };
    assert!(executor.execute(()).is_err());
    assert_eq!(executions.load(Ordering::Acquire), 0);

    // The executor has no prompt/grant input: every policy route converges on
    // this check, so admission and a cached grant cannot bypass peer liveness.
    let mut permit_executor = EgressPermitExecutor;
    let mut executor = CancellableExecutor {
        inner: &mut permit_executor,
        cancelled: &cancelled,
    };
    assert!(executor.execute(()).is_err());
}

#[test]
fn peer_monitor_peeks_without_consuming_live_application_bytes() {
    let (mut broker_side, mut relay_side) = std::os::unix::net::UnixStream::pair().unwrap();
    let shutdown = Arc::new(AtomicBool::new(false));
    let monitor = PeerMonitor::start(&broker_side, &shutdown).expect("peer monitor");
    relay_side.write_all(b"x").expect("application byte");
    thread::sleep(Duration::from_millis(100));
    assert!(monitor.refresh_origin_state(&broker_side));
    assert!(!monitor.cancelled.load(Ordering::Acquire));
    let mut byte = [0_u8; 1];
    broker_side
        .read_exact(&mut byte)
        .expect("monitor must not consume data");
    assert_eq!(byte, *b"x");
}

#[test]
fn peer_monitor_treats_readable_eof_as_origin_loss() {
    let (broker_side, relay_side) = std::os::unix::net::UnixStream::pair().unwrap();
    let shutdown = Arc::new(AtomicBool::new(false));
    let monitor = PeerMonitor::start(&broker_side, &shutdown).expect("peer monitor");
    relay_side
        .shutdown(std::net::Shutdown::Write)
        .expect("relay half-close");
    let deadline = Instant::now() + Duration::from_secs(1);
    while !monitor.cancelled.load(Ordering::Acquire) && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    assert!(monitor.cancelled.load(Ordering::Acquire));
    assert!(!monitor.refresh_origin_state(&broker_side));
}

fn permit_state() -> BrokerState {
    BrokerState::new(
        "effect-permit-hardening".to_owned(),
        ["api.github.com".to_owned(), "github.com".to_owned()]
            .into_iter()
            .collect(),
        ["pr:create".to_owned()].into_iter().collect(),
        "api.anthropic.com".to_owned(),
        SessionFacts::default(),
        ProvenanceMode::Floor,
        Box::new(Allow),
        Box::new(UnusedConnector),
        Box::new(DiscardAudit),
        Box::new(ApproveGate),
        ModelBudgetLimits::default(),
    )
    .expect("broker state")
}

fn pr_permit(index: u8) -> EffectPermit {
    EffectPermit::GithubPullRequest {
        path: format!("/repos/acme/repo-{index}/pulls"),
        body_digest: [index; 32],
    }
}

#[test]
fn effect_permits_expire_and_are_bounded() {
    let mut state = permit_state();
    state.remember_effect_permit(1, pr_permit(1));
    state.pending_effects[0].expires_at = Instant::now()
        .checked_sub(Duration::from_millis(1))
        .expect("one millisecond is representable");
    assert!(!state.consume_effect_permit(
        &EgressAuthorizationTarget {
            host: "api.github.com".to_owned(),
            port: 443,
        },
        "/repos/acme/repo-1/pulls",
        &[1; 32],
    ));
    assert!(state.pending_effects.is_empty());

    for index in 0..=MAX_PENDING_EFFECT_PERMITS {
        let index = u8::try_from(index).expect("permit cap fits in u8");
        state.remember_effect_permit(u64::from(index), pr_permit(index));
    }
    assert_eq!(state.pending_effects.len(), MAX_PENDING_EFFECT_PERMITS);
    assert!(
        state
            .pending_effects
            .iter()
            .all(|permit| permit.action_id != 0)
    );
}

#[test]
fn failed_or_unreported_git_push_revokes_its_effect_permit() {
    let mut state = permit_state();
    state.remember_effect_permit(
        41,
        EffectPermit::GitPush {
            host: "github.com".to_owned(),
            path: "/acme/repo.git/git-receive-pack".to_owned(),
            body_digest: [7; 32],
        },
    );
    state.unreported_pushes.insert(41);
    state.record_push_outcome(41, "failed");
    assert!(state.pending_effects.is_empty());
    assert!(!state.unreported_pushes.contains(&41));

    state.remember_effect_permit(
        42,
        EffectPermit::GitPush {
            host: "github.com".to_owned(),
            path: "/acme/repo.git/git-receive-pack".to_owned(),
            body_digest: [8; 32],
        },
    );
    state.unreported_pushes.insert(42);
    state.close_unreported_pushes();
    assert!(state.pending_effects.is_empty());
    assert!(!state.unreported_pushes.contains(&42));
}

#[test]
fn response_handoff_is_exactly_one_use_and_cancellation_is_sticky() {
    let handoff = NetworkSendHandoff::new();
    handoff.commit().expect("first send commit");
    assert!(handoff.commit().is_err());
    handoff
        .response_recorded(&AtomicBool::new(false))
        .expect("response closes request");
    handoff.cancel();
    assert!(handoff.commit().is_err());
}
