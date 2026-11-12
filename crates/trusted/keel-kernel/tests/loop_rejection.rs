#![doc = "A refusal past the loop limit reaches the audit through the broker."]

use keel_kernel::{
    AuditEvent, AuditSink, EgressConnector, EgressSession, KernelBroker, ModelBudgetLimits, Policy,
    ProvenanceMode, StructuralRejectionEvent, Violation,
};
use keel_provenance::SessionFacts;
use std::{
    collections::BTreeSet,
    io::{Read as _, Write as _},
    os::unix::net::UnixStream,
    sync::{Arc, Mutex},
    thread,
};

/// The address every request names: one the connector refuses structurally.
const HOST: &str = "169.254.169.254";
/// One more than the broker's limit on identical actions within a minute.
const REQUESTS: usize = 1_003;
const SENDERS: usize = 8;

struct Connector;

impl EgressConnector for Connector {
    fn structurally_denied(&self, _host: &str, _port: u16, _method: &str) -> bool {
        true
    }

    fn connect(
        &mut self,
        _host: &str,
        _port: u16,
        _method: &str,
    ) -> Result<Box<dyn EgressSession>, String> {
        Err("a structurally denied destination is never connected".to_owned())
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

#[derive(Clone, Default)]
struct Recording {
    denied: Arc<Mutex<usize>>,
    rejected: Arc<Mutex<Vec<&'static str>>>,
}

impl AuditSink for Recording {
    fn record(&mut self, event: AuditEvent) -> Result<(), String> {
        if event.outcome.as_str() == "denied" {
            *self.denied.lock().unwrap() += 1;
        }
        Ok(())
    }

    fn record_structural_rejection(
        &mut self,
        event: StructuralRejectionEvent,
    ) -> Result<(), String> {
        self.rejected.lock().unwrap().push(event.rule);
        Ok(())
    }
}

/// The broker wraps its audit sink, and the wrapper once left structural
/// rejections to the trait's default, which discards them; a refusal past the
/// loop limit also returned before anything was written. A workload repeating
/// one refused request was then refused with no trace after the thousandth.
#[test]
fn every_refusal_of_a_repeated_request_is_recorded() {
    let audit = Recording::default();
    let broker = KernelBroker::spawn_with_diagnostics(
        "loop-rejection".to_owned(),
        BTreeSet::new(),
        BTreeSet::new(),
        "api.anthropic.com".to_owned(),
        SessionFacts::default(),
        ProvenanceMode::Floor,
        Box::new(Permissive),
        Box::new(Connector),
        Box::new(audit.clone()),
        None,
        ModelBudgetLimits::default(),
        None,
    )
    .expect("broker");
    // The limit counts identical actions within a minute, so the requests
    // are sent from several threads to land well inside one.
    let socket = broker.socket_path().to_path_buf();
    let senders = (0..SENDERS)
        .map(|sender| {
            let socket = socket.clone();
            thread::spawn(move || {
                for _ in 0..REQUESTS / SENDERS + usize::from(sender < REQUESTS % SENDERS) {
                    let mut client = UnixStream::connect(&socket).expect("broker connection");
                    client.write_all(b"KEEL-EGRESS-V2\0").expect("marker");
                    client
                        .write_all(
                            &u16::try_from(HOST.len())
                                .expect("host length")
                                .to_be_bytes(),
                        )
                        .expect("host length");
                    client.write_all(HOST.as_bytes()).expect("host");
                    client.write_all(&80_u16.to_be_bytes()).expect("port");
                    client.write_all(&[1]).expect("method");
                    client.flush().expect("request flush");
                    let mut answer = Vec::new();
                    let _ = client.read_to_end(&mut answer);
                }
            })
        })
        .collect::<Vec<_>>();
    for sender in senders {
        sender.join().expect("sender");
    }
    broker.shutdown().expect("broker shutdown");
    let denied = *audit.denied.lock().unwrap();
    let rejected = audit.rejected.lock().unwrap().clone();
    assert_eq!(
        denied + rejected.len(),
        REQUESTS,
        "{denied} denials and {} rejections for {REQUESTS} requests",
        rejected.len()
    );
    assert_eq!(denied, 1_000, "the loop limit");
    assert!(
        rejected.iter().all(|rule| *rule == "kernel:loop-detected"),
        "{rejected:?}"
    );
}
