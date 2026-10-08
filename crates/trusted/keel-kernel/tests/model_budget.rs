#![doc = "Model reservations have explicit, durable, fail-closed lifecycles."]

use keel_kernel::{
    AuditEvent, AuditSink, ContextBlock, ContextEvent, EGRESS_ALLOWED, EgressConnector,
    EgressRequestAuthorizer, EgressSession, EnforcementStateEvent, KernelBroker, ModelBudgetLimits,
    ModelBudgetRequest, ModelReservationEvent, ModelReservationOutcome, ModelReservationResolution,
    ModelUsage, Policy, ProvenanceMode, Violation,
};
use keel_provenance::SessionFacts;
use std::{
    collections::BTreeSet,
    io::{Read as _, Write as _},
    os::unix::net::UnixStream,
    sync::{Arc, Mutex},
};

const MODEL_HOST: &str = "api.anthropic.com";

#[derive(Default)]
struct Events {
    enforcement: Vec<EnforcementStateEvent>,
    reservations: Vec<ModelReservationEvent>,
    contexts: Vec<ContextEvent>,
    lifecycle_errors_remaining: usize,
    caller_errors: Vec<String>,
}

struct Log(Arc<Mutex<Events>>);

impl AuditSink for Log {
    fn record(&mut self, _event: AuditEvent) -> Result<(), String> {
        Ok(())
    }

    fn record_model_reservation(&mut self, event: ModelReservationEvent) -> Result<(), String> {
        let mut events = self.0.lock().expect("event log");
        if events.lifecycle_errors_remaining > 0 {
            events.lifecycle_errors_remaining -= 1;
            return Err("forced model lifecycle audit failure".to_owned());
        }
        events.reservations.push(event);
        Ok(())
    }

    fn record_context(&mut self, event: ContextEvent) -> Result<(), String> {
        self.0.lock().expect("event log").contexts.push(event);
        Ok(())
    }

    fn record_enforcement_state(&mut self, event: EnforcementStateEvent) -> Result<(), String> {
        self.0.lock().expect("event log").enforcement.push(event);
        Ok(())
    }
}

struct Permit;

impl Policy for Permit {
    fn violations(
        &self,
        _action: &keel_kernel::Action,
        _session: &SessionFacts,
    ) -> Result<Vec<Violation>, String> {
        Ok(Vec::new())
    }
}

#[derive(Clone, Copy)]
enum Behavior {
    Settle(ModelUsage),
    ReleaseUnsent,
    CommitConservative,
    CommitObserved(ModelUsage),
    SettleSlowly(ModelUsage),
    SettleTwice(ModelUsage),
    ReleaseAfterSend,
    SettleWithContext(ModelUsage),
}

fn block(place: &str, digest: u8) -> ContextBlock {
    ContextBlock {
        place: place.to_owned(),
        kind: "text",
        bytes: 10,
        digest: [digest; 8],
        tool_use: None,
    }
}

struct Connector {
    behavior: Behavior,
    events: Arc<Mutex<Events>>,
}

impl EgressConnector for Connector {
    fn connect(
        &mut self,
        _host: &str,
        _port: u16,
        _method: &str,
    ) -> Result<Box<dyn EgressSession>, String> {
        Ok(Box::new(Session {
            behavior: self.behavior,
            events: Arc::clone(&self.events),
        }))
    }
}

struct Session {
    behavior: Behavior,
    events: Arc<Mutex<Events>>,
}

impl EgressSession for Session {
    fn forward(
        self: Box<Self>,
        guest: UnixStream,
        authorizer: &mut dyn EgressRequestAuthorizer,
    ) -> Result<(), String> {
        if matches!(self.behavior, Behavior::SettleWithContext(_)) {
            authorizer.observe_model_context(
                false,
                vec![block("system", 1), block("messages.0.user", 2)],
            );
        }
        authorizer.authorize("POST", "/v1/messages", [0; 32], Some(model_request()))?;
        if matches!(self.behavior, Behavior::ReleaseUnsent) {
            authorizer.release_model_reservation()?;
            drop(guest);
            return Ok(());
        }
        authorizer.commit_request_send()?;
        match self.behavior {
            Behavior::Settle(usage) => {
                authorizer.mark_model_request_send_attempted()?;
                authorizer.record_model_usage(usage)?;
            }
            Behavior::SettleWithContext(usage) => {
                authorizer.mark_model_request_send_attempted()?;
                authorizer.record_model_usage(usage)?;
                authorizer.observe_model_context(true, vec![block("response", 3)]);
            }
            Behavior::ReleaseUnsent => unreachable!("handled before the send handoff"),
            Behavior::SettleSlowly(usage) => {
                authorizer.mark_model_request_send_attempted()?;
                std::thread::sleep(std::time::Duration::from_millis(300));
                authorizer.record_model_usage(usage)?;
            }
            Behavior::CommitObserved(usage) => {
                authorizer.mark_model_request_send_attempted()?;
                authorizer.commit_model_reservation_observed(usage)?;
            }
            Behavior::CommitConservative => {
                authorizer.mark_model_request_send_attempted()?;
                authorizer.commit_model_reservation_conservatively()?;
            }
            Behavior::SettleTwice(usage) => {
                authorizer.mark_model_request_send_attempted()?;
                authorizer.record_model_usage(usage)?;
                let error = authorizer
                    .record_model_usage(usage)
                    .expect_err("duplicate resolution must fail");
                self.events
                    .lock()
                    .expect("event log")
                    .caller_errors
                    .push(error);
            }
            Behavior::ReleaseAfterSend => {
                authorizer.mark_model_request_send_attempted()?;
                let error = authorizer
                    .release_model_reservation()
                    .expect_err("a possibly sent request cannot be refunded");
                self.events
                    .lock()
                    .expect("event log")
                    .caller_errors
                    .push(error);
                authorizer.commit_model_reservation_conservatively()?;
            }
        }
        authorizer.record_response()?;
        drop(guest);
        Ok(())
    }
}

fn model_request() -> ModelBudgetRequest {
    ModelBudgetRequest {
        input_tokens_upper_bound: 60,
        max_output_tokens: 30,
        input_microusd_per_token: 2,
        output_microusd_per_token: 5,
    }
}

fn spawn(
    limits: ModelBudgetLimits,
    behavior: Behavior,
    events: &Arc<Mutex<Events>>,
) -> Result<KernelBroker, String> {
    KernelBroker::spawn_with_diagnostics(
        "configured-model-budget".to_owned(),
        BTreeSet::from([MODEL_HOST.to_owned()]),
        BTreeSet::new(),
        MODEL_HOST.to_owned(),
        SessionFacts::default(),
        ProvenanceMode::Floor,
        Box::new(Permit),
        Box::new(Connector {
            behavior,
            events: Arc::clone(events),
        }),
        Box::new(Log(Arc::clone(events))),
        None,
        limits,
        None,
    )
}

fn request(socket: &std::path::Path) {
    let mut client = UnixStream::connect(socket).expect("broker connection");
    client.write_all(b"KEEL-EGRESS-V2\0").expect("marker");
    client
        .write_all(
            &u16::try_from(MODEL_HOST.len())
                .expect("host length")
                .to_be_bytes(),
        )
        .expect("host length");
    client.write_all(MODEL_HOST.as_bytes()).expect("host");
    client.write_all(&443_u16.to_be_bytes()).expect("port");
    client.write_all(&[2]).expect("method");
    client.flush().expect("request flush");
    let mut response = [0; 2];
    client.read_exact(&mut response).expect("broker response");
    assert_eq!(response, [b'P', EGRESS_ALLOWED]);
    let mut eof = Vec::new();
    client.read_to_end(&mut eof).expect("bridge completion");
}

fn tight_limits() -> ModelBudgetLimits {
    ModelBudgetLimits {
        token_limit: 100,
        cost_limit_microusd: 300,
    }
}

#[test]
fn configured_limits_are_settled_from_trusted_usage() {
    let events = Arc::new(Mutex::new(Events::default()));
    let limits = ModelBudgetLimits {
        token_limit: 170,
        cost_limit_microusd: 500,
    };
    let broker = spawn(
        limits,
        Behavior::Settle(ModelUsage {
            input_tokens: 10,
            output_tokens: 5,
        }),
        &events,
    )
    .expect("broker");

    // Each reservation is 90 tokens and 270 micro-USD. The second request
    // fits only if the first is reconciled to its actual 15 tokens / 45 micro-USD.
    request(broker.socket_path());
    request(broker.socket_path());
    broker.shutdown().expect("broker shutdown");

    let events = events.lock().expect("event log");
    assert_eq!(events.reservations.len(), 2);
    assert!(events.reservations.iter().all(|event| {
        event.outcome == ModelReservationOutcome::SettledActual
            && event.reserved_tokens == 90
            && event.reserved_cost_microusd == 270
            && event.actual_tokens == Some(15)
            && event.actual_cost_microusd == Some(45)
    }));
    assert_eq!(events.reservations[0].reservation_id.get(), 1);
    assert_eq!(events.reservations[1].reservation_id.get(), 2);
    assert_eq!(
        events
            .enforcement
            .iter()
            .map(|event| {
                event
                    .boundaries
                    .iter()
                    .find(|boundary| boundary.name == "model-budget")
                    .expect("model-budget boundary")
                    .detail
                    .as_str()
            })
            .collect::<Vec<_>>(),
        ["tokens=170 microusd=500", "tokens=170 microusd=500"]
    );
}

#[test]
fn only_a_proven_unsent_request_is_refunded() {
    let events = Arc::new(Mutex::new(Events::default()));
    let broker = spawn(tight_limits(), Behavior::ReleaseUnsent, &events).expect("broker");

    request(broker.socket_path());
    request(broker.socket_path());
    broker.shutdown().expect("broker shutdown");

    let events = events.lock().expect("event log");
    assert_eq!(events.reservations.len(), 2);
    assert!(
        events
            .reservations
            .iter()
            .all(|event| event.outcome == ModelReservationOutcome::ReleasedUnsent)
    );
}

#[test]
fn uncertain_send_keeps_the_conservative_charge() {
    let events = Arc::new(Mutex::new(Events::default()));
    let broker = spawn(tight_limits(), Behavior::CommitConservative, &events).expect("broker");

    request(broker.socket_path());
    request(broker.socket_path());
    let report = broker.shutdown().expect("broker shutdown");

    let events = events.lock().expect("event log");
    assert_eq!(events.reservations.len(), 1);
    assert_eq!(
        events.reservations[0].outcome,
        ModelReservationOutcome::CommittedConservative
    );
    assert_eq!(report.denied_actions, 1);
}

#[test]
fn audit_failure_happens_before_refund_and_keeps_budget_fail_closed() {
    let events = Arc::new(Mutex::new(Events {
        lifecycle_errors_remaining: 1,
        ..Events::default()
    }));
    let broker = spawn(tight_limits(), Behavior::ReleaseUnsent, &events).expect("broker");

    // The requested refund cannot become visible because its audit record
    // failed. Bridge cleanup closes the still-live reservation conservatively.
    request(broker.socket_path());
    request(broker.socket_path());
    let report = broker.shutdown().expect("broker shutdown");

    let events = events.lock().expect("event log");
    assert_eq!(events.reservations.len(), 1);
    assert_eq!(
        events.reservations[0].outcome,
        ModelReservationOutcome::CommittedConservative
    );
    assert_eq!(report.denied_actions, 1);
}

#[test]
fn duplicate_terminal_resolution_is_rejected() {
    let events = Arc::new(Mutex::new(Events::default()));
    let usage = ModelUsage {
        input_tokens: 10,
        output_tokens: 5,
    };
    let broker = spawn(tight_limits(), Behavior::SettleTwice(usage), &events).expect("broker");

    request(broker.socket_path());
    broker.shutdown().expect("broker shutdown");

    let events = events.lock().expect("event log");
    assert_eq!(events.reservations.len(), 1);
    assert!(events.caller_errors[0].contains("already resolved as settled-actual"));
}

#[test]
fn send_attempt_prevents_an_unsafe_refund() {
    let events = Arc::new(Mutex::new(Events::default()));
    let broker = spawn(tight_limits(), Behavior::ReleaseAfterSend, &events).expect("broker");

    request(broker.socket_path());
    broker.shutdown().expect("broker shutdown");

    let events = events.lock().expect("event log");
    assert_eq!(events.reservations.len(), 1);
    assert_eq!(
        events.reservations[0].outcome,
        ModelReservationOutcome::CommittedConservative
    );
    assert!(events.caller_errors[0].contains("cannot be released after a send attempt"));
}

#[test]
fn trusted_usage_over_the_reservation_is_charged_as_an_overrun() {
    let events = Arc::new(Mutex::new(Events::default()));
    let broker = spawn(
        tight_limits(),
        Behavior::Settle(ModelUsage {
            input_tokens: 100,
            output_tokens: 10,
        }),
        &events,
    )
    .expect("broker");

    request(broker.socket_path());
    request(broker.socket_path());
    let report = broker.shutdown().expect("broker shutdown");

    let events = events.lock().expect("event log");
    assert_eq!(events.reservations.len(), 1);
    assert_eq!(
        events.reservations[0].outcome,
        ModelReservationOutcome::Overrun
    );
    assert_eq!(events.reservations[0].actual_tokens, Some(110));
    assert_eq!(events.reservations[0].actual_cost_microusd, Some(250));
    assert_eq!(report.denied_actions, 1);
}

#[test]
fn zero_model_ceiling_is_rejected_before_the_broker_starts() {
    for limits in [
        ModelBudgetLimits {
            token_limit: 0,
            cost_limit_microusd: 1,
        },
        ModelBudgetLimits {
            token_limit: 1,
            cost_limit_microusd: 0,
        },
    ] {
        let events = Arc::new(Mutex::new(Events::default()));
        let error = spawn(limits, Behavior::ReleaseUnsent, &events)
            .err()
            .expect("invalid budget");
        assert_eq!(
            error,
            "model token and cost budgets must be greater than zero"
        );
        assert!(events.lock().expect("event log").enforcement.is_empty());
    }
}

#[test]
fn resolution_enum_remains_exhaustive_for_callers() {
    let outcomes = [
        ModelReservationResolution::ReleasedUnsent,
        ModelReservationResolution::SettledActual(ModelUsage {
            input_tokens: 1,
            output_tokens: 1,
        }),
        ModelReservationResolution::CommittedConservative,
        ModelReservationResolution::CommittedObserved(ModelUsage {
            input_tokens: 1,
            output_tokens: 1,
        }),
    ];
    assert_eq!(outcomes.len(), 4);
}

#[test]
fn an_interrupted_response_is_charged_its_observed_bound_not_the_reservation() {
    let events = Arc::new(Mutex::new(Events::default()));
    let limits = ModelBudgetLimits {
        token_limit: 200,
        cost_limit_microusd: 400,
    };
    let broker = spawn(
        limits,
        Behavior::CommitObserved(ModelUsage {
            input_tokens: 10,
            output_tokens: 5,
        }),
        &events,
    )
    .expect("broker");

    // A conservative commit would charge 270 of the 400 and refuse the
    // second request; the observed bound charges 45 and admits it.
    request(broker.socket_path());
    request(broker.socket_path());
    let report = broker.shutdown().expect("broker shutdown");

    let events = events.lock().expect("event log");
    assert_eq!(events.reservations.len(), 2);
    for reservation in &events.reservations {
        assert_eq!(
            reservation.outcome,
            ModelReservationOutcome::CommittedObserved
        );
        assert_eq!(reservation.actual_tokens, Some(15));
        assert_eq!(reservation.actual_cost_microusd, Some(45));
    }
    assert_eq!(report.denied_actions, 0);
}

#[test]
fn an_observed_bound_never_exceeds_the_reservation() {
    let events = Arc::new(Mutex::new(Events::default()));
    let broker = spawn(
        tight_limits(),
        Behavior::CommitObserved(ModelUsage {
            input_tokens: 1_000,
            output_tokens: 1_000,
        }),
        &events,
    )
    .expect("broker");

    request(broker.socket_path());
    broker.shutdown().expect("broker shutdown");

    let events = events.lock().expect("event log");
    assert_eq!(events.reservations.len(), 1);
    assert_eq!(
        events.reservations[0].outcome,
        ModelReservationOutcome::CommittedObserved
    );
    assert_eq!(events.reservations[0].actual_tokens, Some(90));
    assert_eq!(events.reservations[0].actual_cost_microusd, Some(270));
}

#[test]
fn a_request_that_fits_once_in_flight_reservations_settle_waits_instead_of_failing() {
    let events = Arc::new(Mutex::new(Events::default()));
    // Each reservation is 90 tokens and 270 micro-USD; two do not fit at once,
    // but one settled at 15 tokens and 45 micro-USD leaves room for another.
    let limits = ModelBudgetLimits {
        token_limit: 120,
        cost_limit_microusd: 330,
    };
    let broker = spawn(
        limits,
        Behavior::SettleSlowly(ModelUsage {
            input_tokens: 10,
            output_tokens: 5,
        }),
        &events,
    )
    .expect("broker");
    let socket = broker.socket_path().to_path_buf();
    let first = {
        let socket = socket.clone();
        std::thread::spawn(move || request(&socket))
    };
    std::thread::sleep(std::time::Duration::from_millis(100));
    request(&socket);
    first.join().expect("first request");
    let report = broker.shutdown().expect("broker shutdown");

    let events = events.lock().expect("event log");
    assert_eq!(events.reservations.len(), 2);
    assert!(
        events
            .reservations
            .iter()
            .all(|reservation| reservation.outcome == ModelReservationOutcome::SettledActual)
    );
    assert_eq!(
        report.denied_actions, 0,
        "the second request waited for room"
    );
}

#[test]
fn model_context_is_logged_per_request_and_described_once() {
    let events = Arc::new(Mutex::new(Events::default()));
    let limits = ModelBudgetLimits {
        token_limit: 1_000,
        cost_limit_microusd: 5_000,
    };
    let usage = ModelUsage {
        input_tokens: 10,
        output_tokens: 5,
    };
    let broker = spawn(limits, Behavior::SettleWithContext(usage), &events).expect("broker");
    request(broker.socket_path());
    request(broker.socket_path());
    broker.shutdown().expect("broker shutdown");

    let events = events.lock().expect("event log");
    let summary = events
        .contexts
        .iter()
        .map(|event| (event.phase, event.sequence.len(), event.described.len()))
        .collect::<Vec<_>>();
    assert_eq!(
        summary,
        [
            ("request", 2, 2),
            ("response", 1, 1),
            ("request", 2, 0),
            ("response", 1, 0)
        ]
    );
    assert_eq!(events.contexts[0].action_id, events.contexts[1].action_id);
    assert_ne!(events.contexts[0].action_id, events.contexts[2].action_id);
}
