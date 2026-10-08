use super::{
    ADMISSION_EGRESS_RULE, Action, ActionClass, Asserted, AuditEvent, AuditOutcome, AuditSink,
    BrokerState, ChannelDeclaration, ChannelRegistry, CredentialInjector, DenialOrigin, DenyGate,
    DiscardAudit, EGRESS_ALLOWED, EGRESS_HOST_RULE, EGRESS_PENDING, EXTERNAL_ALLOWED,
    EgressAuthorizationTarget, EgressConnector, EgressRequestAuthorizer, EgressSession,
    EnforcementBoundary, EnforcementState, EnforcementStateEvent, Executor, GIT_ALLOWED,
    GIT_BROKER_MAGIC, GIT_DENIED, GIT_REPORT_COMPLETED, GIT_REPORT_FAILED, GIT_REPORT_MAGIC, Gate,
    GateClass, GateDecision, GateRequest, IntentVerdict, Kernel, KernelBroker, KernelError,
    ModelBudgetLimits, ModelBudgetRequest, Policy, PrincipalId, Processed, ProtectedState,
    ProvenanceMode, REPEATED_DENIAL_RULE, ReportedOutcomeEvent, SessionFacts, SessionSnapshot,
    SessionState, SourceRef, Stamped, StructuralRejectionEvent, Target, TerminalGate, Violation,
    action_target_hash, intent_verdict, record_egress_failure, sha256, terminal_gate_channel,
    violation_rules,
};
use std::{
    collections::BTreeSet,
    io::ErrorKind,
    os::unix::fs::PermissionsExt as _,
    path::Path,
    sync::{Arc, Mutex},
};

#[test]
fn bridge_failures_are_recorded_as_one_private_readable_line() {
    let log = std::env::temp_dir().join(format!(
        "keel-egress-log-{}-{:x}.log",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |since| since.as_nanos())
    ));
    record_egress_failure(None, "api.anthropic.com:443", "dropped without a log");
    record_egress_failure(
        Some(&log),
        "api.anthropic.com:443",
        "credential sentinel\r\nhas no binding",
    );
    let contents = std::fs::read_to_string(&log).expect("diagnostics log");
    let mode = std::fs::metadata(&log)
        .expect("diagnostics metadata")
        .permissions()
        .mode()
        & 0o777;
    let _ = std::fs::remove_file(&log);

    assert_eq!(contents.lines().count(), 1);
    assert!(!contents.contains("dropped without a log"));
    assert!(contents.contains("egress api.anthropic.com:443 failed:"));
    assert!(contents.contains("credential sentinel  has no binding"));
    assert_eq!(mode, 0o600);
}

#[test]
fn expired_terminal_approval_fails_closed_and_rejects_late_input() {
    let (prompts, controller) = std::sync::mpsc::sync_channel(0);
    let mut gate = TerminalGate {
        prompts,
        decision_timeout: std::time::Duration::from_millis(10),
    };
    let action = Action {
        id: 1,
        asserted: read_action(),
        stamped: Stamped {
            principal: principal(),
            session: SessionSnapshot {
                floor: 3,
                denied_actions: 0,
                committed_actions: 0,
                action_limit: 10,
            },
            intent: super::IntentVerdict::NotApplicable,
            flow: super::FlowVerdict::NotChecked,
            origin: None,
            integrity: super::IntegrityVerdict::NotChecked,
        },
    };
    let violations = [Violation::new("test:review", "operator review")];

    std::thread::scope(|scope| {
        let worker = scope.spawn(|| {
            gate.decide(GateRequest {
                action: &action,
                violations: &violations,
                floor_history: &[],
                cancelled: None,
            })
        });
        let pending = controller.recv().expect("pending approval");
        assert!(pending.is_active());
        assert_eq!(
            worker.join().expect("gate thread"),
            GateDecision::Unavailable
        );
        assert!(!pending.is_active());
        assert_eq!(
            pending.decide(GateDecision::Approve),
            Err("kernel gate is no longer waiting".to_owned())
        );
    });
}

#[derive(Default)]
struct Harness {
    gate_decision: Option<GateDecision>,
    gate_actions: Vec<u64>,
    gate_session_grants: Vec<Option<Vec<u8>>>,
    injections: u64,
    executions: u64,
    audit: Vec<AuditEvent>,
    structural_rejections: Vec<StructuralRejectionEvent>,
}

impl Gate for Harness {
    fn decide(&mut self, request: GateRequest<'_>) -> GateDecision {
        self.gate_actions.push(request.action.id());
        self.gate_session_grants
            .push(request.to_payload().session_grant);
        self.gate_decision.unwrap_or(GateDecision::Deny)
    }
}

impl CredentialInjector for Harness {
    type Prepared = u64;

    fn inject(&mut self, action: &Action) -> Result<Self::Prepared, String> {
        self.injections += 1;
        Ok(action.id())
    }
}

impl Executor<u64> for Harness {
    type Output = u64;

    fn execute(&mut self, action_id: u64) -> Result<Self::Output, String> {
        self.executions += 1;
        Ok(action_id)
    }
}

impl AuditSink for Harness {
    fn record(&mut self, event: AuditEvent) -> Result<(), String> {
        self.audit.push(event);
        Ok(())
    }

    fn record_structural_rejection(
        &mut self,
        event: StructuralRejectionEvent,
    ) -> Result<(), String> {
        self.structural_rejections.push(event);
        Ok(())
    }
}

struct Allow;

impl Policy for Allow {
    fn violations(&self, _: &Action, _: &SessionFacts) -> Result<Vec<Violation>, String> {
        Ok(Vec::new())
    }
}

struct Escalate;

impl Policy for Escalate {
    fn violations(&self, _: &Action, _: &SessionFacts) -> Result<Vec<Violation>, String> {
        Ok(vec![Violation::new("test:review", "operator review")])
    }
}

struct ScopeAwareReview;

impl Policy for ScopeAwareReview {
    fn violations(&self, _: &Action, facts: &SessionFacts) -> Result<Vec<Violation>, String> {
        let mut violations = vec![Violation::new("test:review", "operator review")];
        if facts.recent_behavioral_denials_in_scope >= 3 {
            violations.push(Violation::new(
                REPEATED_DENIAL_RULE,
                "same action shape was denied repeatedly",
            ));
        }
        Ok(violations)
    }
}

struct RuleCapturingGate {
    decisions: Vec<GateDecision>,
    rules: Vec<Vec<String>>,
}

impl Gate for RuleCapturingGate {
    fn decide(&mut self, request: GateRequest<'_>) -> GateDecision {
        self.rules.push(violation_rules(request.violations));
        self.decisions.remove(0)
    }

    fn authority(&self) -> &'static str {
        "operator"
    }
}

struct Deny;

impl Policy for Deny {
    fn violations(&self, _: &Action, _: &SessionFacts) -> Result<Vec<Violation>, String> {
        Ok(vec![Violation::new(
            "deny:test",
            "non-overridable test constraint",
        )])
    }
}

struct OffIntentEgress;

impl Policy for OffIntentEgress {
    fn violations(&self, _: &Action, _: &SessionFacts) -> Result<Vec<Violation>, String> {
        Ok(vec![
            Violation::new(EGRESS_HOST_RULE, "host is outside structured intent"),
            Violation::new(ADMISSION_EGRESS_RULE, "non-model egress was not admitted"),
        ])
    }
}

fn principal() -> PrincipalId {
    PrincipalId::new("vertex-1").expect("valid principal")
}

fn registry() -> ChannelRegistry {
    ChannelRegistry::new(
        ["workspace", "git"],
        [
            ChannelDeclaration {
                name: "workspace".to_owned(),
                principal: principal(),
                gate_class: GateClass::Workspace,
            },
            ChannelDeclaration {
                name: "git".to_owned(),
                principal: principal(),
                gate_class: GateClass::Git,
            },
        ],
    )
    .expect("complete registry")
}

fn read_action() -> Asserted {
    Asserted {
        class: ActionClass::ReadWorkspace,
        target: Target::Workspace {
            path: "src/lib.rs".to_owned(),
        },
        declared_cost: None,
    }
}

fn stamped_action(id: u64, path: &str) -> Action {
    Action {
        id,
        asserted: Asserted {
            class: ActionClass::ReadWorkspace,
            target: Target::Workspace {
                path: path.to_owned(),
            },
            declared_cost: None,
        },
        stamped: Stamped {
            principal: principal(),
            session: SessionSnapshot {
                floor: 3,
                denied_actions: 0,
                committed_actions: 0,
                action_limit: 10,
            },
            intent: super::IntentVerdict::NotApplicable,
            flow: super::FlowVerdict::NotChecked,
            origin: None,
            integrity: super::IntegrityVerdict::NotChecked,
        },
    }
}

#[test]
fn startup_rejects_a_missing_channel_declaration() {
    let result = ChannelRegistry::new(
        ["workspace", "git"],
        [ChannelDeclaration {
            name: "workspace".to_owned(),
            principal: principal(),
            gate_class: GateClass::Workspace,
        }],
    );

    assert_eq!(
        result.expect_err("git must be required"),
        KernelError::MissingChannel("git".to_owned())
    );
}

#[test]
fn forged_principal_never_reaches_credentials_or_execution() {
    let mut kernel = Kernel::new(
        registry(),
        SessionState::new(10, 3).expect("session"),
        Allow,
        "test-session",
    )
    .expect("kernel");
    let mut harness = Harness::default();
    let mut injector = Harness::default();
    let mut executor = Harness::default();
    let mut audit = Harness::default();

    let result = kernel.process(
        "workspace",
        "forged-vertex",
        read_action(),
        &mut harness,
        &mut injector,
        &mut executor,
        &mut audit,
    );

    assert_eq!(result, Err(KernelError::PrincipalMismatch));
    assert_eq!(injector.injections, 0);
    assert_eq!(executor.executions, 0);
    assert_eq!(audit.structural_rejections.len(), 1);
    assert_eq!(
        audit.structural_rejections[0].rule,
        "kernel:principal-mismatch"
    );
}

#[test]
fn policy_violation_requires_gate_before_injection() {
    let mut kernel = Kernel::new(
        registry(),
        SessionState::new(10, 3).expect("session"),
        Escalate,
        "test-session",
    )
    .expect("kernel");
    let mut gate = Harness {
        gate_decision: Some(GateDecision::Approve),
        ..Harness::default()
    };
    let mut injector = Harness::default();
    let mut executor = Harness::default();
    let mut audit = Harness::default();

    let result = kernel
        .process(
            "workspace",
            "vertex-1",
            read_action(),
            &mut gate,
            &mut injector,
            &mut executor,
            &mut audit,
        )
        .expect("approved execution");

    assert_eq!(
        result,
        Processed {
            action_id: 1,
            output: 1
        }
    );
    assert_eq!(gate.gate_actions, [1]);
    assert_eq!(injector.injections, 1);
    assert_eq!(executor.executions, 1);
    assert_eq!(kernel.session().escalated_actions(), 1);
    assert_eq!(kernel.session().committed_actions(), 1);
    assert_eq!(audit.audit[0].outcome, AuditOutcome::Attempted);
    let event = audit.audit.last().expect("audit event");
    assert_eq!(event.rules, ["test:review"]);
    assert_eq!(event.outcome, AuditOutcome::Executed);
    assert_eq!(
        event.target_hash,
        action_target_hash(&stamped_action(1, "src/lib.rs"))
    );
    let telemetry = event.gate.as_ref().expect("gate telemetry");
    assert_eq!(telemetry.decision, GateDecision::Approve);
    assert_eq!(telemetry.floor_at_gate, 3);
    assert_eq!(telemetry.mode, ProvenanceMode::Floor);
    assert_eq!(telemetry.authority, "deny-only");
    assert!(!telemetry.prompt_presented);
}

#[test]
fn deny_policy_never_reaches_gate_injection_or_execution() {
    let mut kernel = Kernel::new(
        registry(),
        SessionState::new(10, 3).expect("session"),
        Deny,
        "test-session",
    )
    .expect("kernel");
    let mut gate = Harness {
        gate_decision: Some(GateDecision::Approve),
        ..Harness::default()
    };
    let mut injector = Harness::default();
    let mut executor = Harness::default();
    let mut audit = Harness::default();
    let result = kernel.process(
        "workspace",
        "vertex-1",
        read_action(),
        &mut gate,
        &mut injector,
        &mut executor,
        &mut audit,
    );
    assert_eq!(result, Err(KernelError::PolicyDenied));
    assert!(gate.gate_actions.is_empty());
    assert_eq!(injector.injections, 0);
    assert_eq!(executor.executions, 0);
    assert_eq!(audit.audit[0].outcome, AuditOutcome::Denied);
    assert_eq!(audit.audit[0].rules, ["deny:test"]);
}

#[test]
fn explicit_grant_choice_grants_bounded_same_host_egress_for_the_session() {
    let registry = ChannelRegistry::new(
        ["egress"],
        [ChannelDeclaration {
            name: "egress".to_owned(),
            principal: principal(),
            gate_class: GateClass::Egress,
        }],
    )
    .expect("registry");
    let mut kernel = Kernel::new(
        registry,
        SessionState::new(10, 3).expect("session"),
        OffIntentEgress,
        "test-session",
    )
    .expect("kernel");
    let mut gate = Harness {
        gate_decision: Some(GateDecision::ApproveGrant),
        ..Harness::default()
    };
    let mut injector = Harness::default();
    let mut executor = Harness::default();
    let mut audit = Harness::default();

    for path in ["/v1/messages", "/v1/models"] {
        kernel
            .process(
                "egress",
                "vertex-1",
                Asserted {
                    class: ActionClass::Egress,
                    target: Target::Network {
                        host: "platform.claude.com".to_owned(),
                        port: 443,
                        method: "POST".to_owned(),
                        path: path.to_owned(),
                    },
                    declared_cost: None,
                },
                &mut gate,
                &mut injector,
                &mut executor,
                &mut audit,
            )
            .expect("approved host remains usable");
    }

    assert_eq!(gate.gate_actions, [1]);
    let grant = gate.gate_session_grants[0]
        .as_deref()
        .expect("egress approval discloses its session grant");
    assert_eq!(
        std::str::from_utf8(grant).expect("grant is utf-8"),
        "host \"platform.claude.com\", port 443, method \"POST\"; expires after 15 minutes, \
         64 total actions, or a lower floor"
    );
    assert_eq!(kernel.session().escalated_actions(), 1);
    assert_eq!(kernel.session().committed_actions(), 2);
}

#[test]
fn successful_workspace_actions_update_session_facts() {
    let mut kernel = Kernel::new(
        registry(),
        SessionState::new(10, 3).expect("session"),
        Allow,
        "test-session",
    )
    .expect("kernel");
    let mut gate = Harness::default();
    let mut injector = Harness::default();
    let mut executor = Harness::default();
    let mut audit = Harness::default();

    for action in [
        read_action(),
        Asserted {
            class: ActionClass::WriteWorkspace,
            target: Target::Workspace {
                path: "notes.txt".to_owned(),
            },
            declared_cost: None,
        },
    ] {
        kernel
            .process(
                "workspace",
                "vertex-1",
                action,
                &mut gate,
                &mut injector,
                &mut executor,
                &mut audit,
            )
            .expect("workspace action");
    }

    let facts = kernel.session().facts();
    assert!(facts.files_written_by_this_vertex.contains("notes.txt"));
    assert_eq!(facts.writes_last_60s, 1);
    assert_eq!(facts.distinct_files_written_60s, 1);
}

#[test]
fn denied_gate_never_injects_credentials() {
    let mut kernel = Kernel::new(
        registry(),
        SessionState::new(10, 3).expect("session"),
        Escalate,
        "test-session",
    )
    .expect("kernel");
    let mut gate = Harness {
        gate_decision: Some(GateDecision::Deny),
        ..Harness::default()
    };
    let mut injector = Harness::default();
    let mut executor = Harness::default();
    let mut audit = Harness::default();

    let result = kernel.process(
        "workspace",
        "vertex-1",
        read_action(),
        &mut gate,
        &mut injector,
        &mut executor,
        &mut audit,
    );

    assert_eq!(result, Err(KernelError::GateDenied));
    assert_eq!(injector.injections, 0);
    assert_eq!(executor.executions, 0);
    assert_eq!(kernel.session().denied_actions(), 1);
    let telemetry = audit.audit[0].gate.as_ref().expect("gate telemetry");
    assert_eq!(telemetry.decision, GateDecision::Deny);
    assert_eq!(telemetry.floor_at_gate, 3);
    assert_eq!(telemetry.mode, ProvenanceMode::Floor);
}

#[test]
#[allow(clippy::too_many_lines)]
fn repeated_denial_review_is_scoped_and_cleared_by_exact_approval() {
    let mut kernel = Kernel::new(
        registry(),
        SessionState::new(20, 10).expect("session"),
        ScopeAwareReview,
        "scoped-denials",
    )
    .expect("kernel");
    let mut gate = RuleCapturingGate {
        decisions: vec![
            GateDecision::Deny,
            GateDecision::Deny,
            GateDecision::Deny,
            GateDecision::Approve,
            GateDecision::Approve,
        ],
        rules: Vec::new(),
    };
    let mut injector = Harness::default();
    let mut executor = Harness::default();
    let mut audit = Harness::default();
    let action = |path: &str| Asserted {
        class: ActionClass::WriteWorkspace,
        target: Target::Workspace {
            path: path.to_owned(),
        },
        declared_cost: None,
    };

    for _ in 0..3 {
        assert_eq!(
            kernel.process(
                "workspace",
                "vertex-1",
                action("same.txt"),
                &mut gate,
                &mut injector,
                &mut executor,
                &mut audit,
            ),
            Err(KernelError::GateDenied)
        );
    }

    kernel
        .process(
            "workspace",
            "vertex-1",
            action("different.txt"),
            &mut gate,
            &mut injector,
            &mut executor,
            &mut audit,
        )
        .expect("a different action scope is not escalated as repeated");
    assert!(
        !gate.rules[3]
            .iter()
            .any(|rule| rule == REPEATED_DENIAL_RULE)
    );

    kernel
        .process(
            "workspace",
            "vertex-1",
            action("same.txt"),
            &mut gate,
            &mut injector,
            &mut executor,
            &mut audit,
        )
        .expect("the exact repeated action can be reviewed and approved");
    assert!(
        gate.rules[4]
            .iter()
            .any(|rule| rule == REPEATED_DENIAL_RULE)
    );
    assert_eq!(
        kernel.session().facts().recent_behavioral_denials_in_scope,
        0,
        "an approval clears only the exact reviewed scope"
    );

    let denials = audit
        .audit
        .iter()
        .filter_map(|event| event.denial)
        .collect::<Vec<_>>();
    assert_eq!(denials.len(), 3);
    assert!(denials.iter().all(|denial| {
        denial.origin == DenialOrigin::Operator && denial.counted_for_repeated_review
    }));
    assert_eq!(
        denials
            .iter()
            .map(|denial| denial.scope)
            .collect::<BTreeSet<_>>()
            .len(),
        1
    );
    assert_eq!(
        denials
            .iter()
            .map(|denial| denial.recent_behavioral_denials_in_scope)
            .collect::<Vec<_>>(),
        [1, 2, 3]
    );
}

#[test]
fn budget_exhaustion_is_not_gate_overridable() {
    let mut kernel = Kernel::new(
        registry(),
        SessionState::new(1, 3).expect("session"),
        Allow,
        "test-session",
    )
    .expect("kernel");
    let mut gate = Harness::default();
    let mut injector = Harness::default();
    let mut executor = Harness::default();
    let mut audit = Harness::default();

    kernel
        .process(
            "workspace",
            "vertex-1",
            read_action(),
            &mut gate,
            &mut injector,
            &mut executor,
            &mut audit,
        )
        .expect("first action");
    let result = kernel.process(
        "workspace",
        "vertex-1",
        Asserted {
            class: ActionClass::ReadWorkspace,
            target: Target::Workspace {
                path: "src/main.rs".to_owned(),
            },
            declared_cost: None,
        },
        &mut gate,
        &mut injector,
        &mut executor,
        &mut audit,
    );

    assert_eq!(result, Err(KernelError::BudgetExhausted));
    assert!(gate.gate_actions.is_empty());
    assert_eq!(injector.injections, 1);
    assert_eq!(executor.executions, 1);
}

#[test]
fn repeated_action_loop_is_stopped_before_injection() {
    let mut kernel = Kernel::new(
        registry(),
        SessionState::new(10, 1).expect("session"),
        Allow,
        "test-session",
    )
    .expect("kernel");
    let mut gate = Harness::default();
    let mut injector = Harness::default();
    let mut executor = Harness::default();
    let mut audit = Harness::default();

    kernel
        .process(
            "workspace",
            "vertex-1",
            read_action(),
            &mut gate,
            &mut injector,
            &mut executor,
            &mut audit,
        )
        .expect("first action");
    let result = kernel.process(
        "workspace",
        "vertex-1",
        read_action(),
        &mut gate,
        &mut injector,
        &mut executor,
        &mut audit,
    );

    assert_eq!(result, Err(KernelError::LoopDetected));
    assert_eq!(injector.injections, 1);
    assert_eq!(executor.executions, 1);
    assert_eq!(
        audit.structural_rejections.last().map(|event| event.rule),
        Some("kernel:loop-detected")
    );
}

#[test]
fn identical_actions_outside_the_loop_window_are_not_a_loop() {
    let mut session = SessionState::new(10, 1).expect("session");
    let action = read_action();

    assert!(session.observe_action(&action, 0).is_ok());
    assert_eq!(
        session.observe_action(&action, 59_999),
        Err(KernelError::LoopDetected)
    );
    assert!(session.observe_action(&action, 120_000).is_ok());
}

#[test]
fn all_protected_kernel_state_is_never_policy_reachable() {
    for protected in [
        ProtectedState::Policy,
        ProtectedState::Audit,
        ProtectedState::Attestation,
        ProtectedState::Provenance,
        ProtectedState::Budget,
    ] {
        let mut kernel = Kernel::new(
            registry(),
            SessionState::new(10, 3).expect("session"),
            Allow,
            "test-session",
        )
        .expect("kernel");
        let mut gate = Harness {
            gate_decision: Some(GateDecision::Approve),
            ..Harness::default()
        };
        let mut injector = Harness::default();
        let mut executor = Harness::default();
        let mut audit = Harness::default();

        let result = kernel.process(
            "workspace",
            "vertex-1",
            Asserted {
                class: ActionClass::WriteWorkspace,
                target: Target::Protected(protected),
                declared_cost: None,
            },
            &mut gate,
            &mut injector,
            &mut executor,
            &mut audit,
        );

        assert_eq!(result, Err(KernelError::ProtectedStateMutation));
        assert!(gate.gate_actions.is_empty());
        assert_eq!(injector.injections, 0);
        assert_eq!(executor.executions, 0);
    }
}

#[test]
fn harmless_class_cannot_disguise_a_network_target() {
    let mut kernel = Kernel::new(
        registry(),
        SessionState::new(10, 3).expect("session"),
        Allow,
        "test-session",
    )
    .expect("kernel");
    let mut gate = Harness::default();
    let mut injector = Harness::default();
    let mut executor = Harness::default();
    let mut audit = Harness::default();

    let result = kernel.process(
        "workspace",
        "vertex-1",
        Asserted {
            class: ActionClass::ReadWorkspace,
            target: Target::Network {
                host: "example.com".to_owned(),
                port: 443,
                method: "GET".to_owned(),
                path: "/".to_owned(),
            },
            declared_cost: None,
        },
        &mut gate,
        &mut injector,
        &mut executor,
        &mut audit,
    );

    assert_eq!(result, Err(KernelError::TargetClassMismatch));
    assert_eq!(injector.injections, 0);
    assert_eq!(executor.executions, 0);
}

struct TestConnector {
    address: std::net::SocketAddr,
    observed_method: &'static str,
    observed_path: &'static str,
    model_budget: Option<ModelBudgetRequest>,
}

impl EgressConnector for TestConnector {
    fn connect(
        &mut self,
        _host: &str,
        _port: u16,
        _method: &str,
    ) -> Result<Box<dyn EgressSession>, String> {
        Ok(Box::new(TestSession {
            address: self.address,
            observed_method: self.observed_method,
            observed_path: self.observed_path,
            model_budget: self.model_budget.take(),
        }))
    }
}

struct TestSession {
    address: std::net::SocketAddr,
    observed_method: &'static str,
    observed_path: &'static str,
    model_budget: Option<ModelBudgetRequest>,
}

struct FailingShutdownAudit;

impl AuditSink for FailingShutdownAudit {
    fn record(&mut self, _event: AuditEvent) -> Result<(), String> {
        Ok(())
    }

    fn shutdown(&mut self) -> Result<(), String> {
        Err("forced audit shutdown failure".to_owned())
    }
}

impl EgressSession for TestSession {
    fn forward(
        self: Box<Self>,
        mut guest: std::os::unix::net::UnixStream,
        authorizer: &mut dyn EgressRequestAuthorizer,
    ) -> Result<(), String> {
        use std::{io, net::Shutdown, thread};

        authorizer.authorize(
            self.observed_method,
            self.observed_path,
            [0_u8; 32],
            self.model_budget,
        )?;
        authorizer.commit_request_send()?;
        let mut upstream =
            std::net::TcpStream::connect(self.address).map_err(|error| error.to_string())?;
        let mut guest_reader = guest.try_clone().map_err(|error| error.to_string())?;
        let guest_control = guest.try_clone().map_err(|error| error.to_string())?;
        let mut upstream_writer = upstream.try_clone().map_err(|error| error.to_string())?;
        let upload = thread::spawn(move || {
            let result = io::copy(&mut guest_reader, &mut upstream_writer);
            let _ = upstream_writer.shutdown(Shutdown::Write);
            result
        });
        let download = io::copy(&mut upstream, &mut guest);
        // Record before the guest sees end of stream, as trusted transport
        // does: a client that reads EOF may shut the broker down at once.
        let recorded = authorizer.record_response();
        let _ = guest.shutdown(Shutdown::Write);
        let _ = guest_control.shutdown(Shutdown::Read);
        let upload = upload
            .join()
            .map_err(|_| "test upload thread panicked".to_owned())?;
        download.and(upload).map_err(|error| error.to_string())?;
        recorded
    }
}

fn send_relay_request(client: &mut std::os::unix::net::UnixStream) {
    use std::io::Write as _;

    client
        .write_all(b"KEEL-EGRESS-V2\0\0\rrelay.example\x01\xbb\x02")
        .expect("egress request");
    client.flush().expect("request flush");
}

fn open_relay(path: &Path) -> std::os::unix::net::UnixStream {
    use std::io::Read as _;

    let mut client = std::os::unix::net::UnixStream::connect(path).expect("broker connection");
    send_relay_request(&mut client);
    let mut response = [0_u8; 2];
    client
        .read_exact(&mut response)
        .expect("transport response");
    assert_eq!(response, [EGRESS_PENDING, EGRESS_ALLOWED]);
    client
}

#[test]
fn transport_setup_completes_before_the_exact_request_prompt() {
    use std::{
        io::{Read as _, Write as _},
        net::{Ipv4Addr, TcpListener},
        thread,
        time::Duration,
    };

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
        Box::new(TestConnector {
            address,
            observed_method: "GET",
            observed_path: "/status",
            model_budget: None,
        }),
        Box::new(DiscardAudit),
        Box::new(gate),
    )
    .expect("broker");
    let mut client = open_relay(broker.socket_path());
    client
        .set_read_timeout(Some(Duration::from_millis(300)))
        .expect("client timeout");
    let pending = controller.receive().expect("exact request prompt");
    let target = String::from_utf8_lossy(&pending.payload().exact_target);
    assert!(target.contains("GET"));
    assert!(target.contains("/status"));
    assert!(!target.contains("CONNECT"));
    assert!(
        controller
            .receive_timeout(Duration::ZERO)
            .expect("gate channel")
            .is_none()
    );
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
    let report = broker.shutdown().expect("broker shutdown");
    assert_eq!(report.denied_actions, 0);
}

#[test]
fn originating_half_close_cancels_late_decisions_and_retry_gets_a_fresh_action() {
    use std::{
        net::{Ipv4Addr, TcpListener},
        thread,
        time::{Duration, Instant},
    };

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("upstream listener");
    let (gate, controller) = terminal_gate_channel();
    let broker = KernelBroker::spawn_with_audit_and_gate(
        "cancelled-prompt".to_owned(),
        BTreeSet::new(),
        BTreeSet::new(),
        Box::new(TestConnector {
            address: listener.local_addr().expect("upstream address"),
            observed_method: "GET",
            observed_path: "/status",
            model_budget: None,
        }),
        Box::new(DiscardAudit),
        Box::new(gate),
    )
    .expect("broker");
    let wait_until_inactive = |pending: &super::PendingApproval| {
        let deadline = Instant::now() + Duration::from_secs(1);
        while pending.is_active() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(!pending.is_active(), "peer loss must invalidate the prompt");
    };

    let first = open_relay(broker.socket_path());
    let first_pending = controller.receive().expect("first exact request prompt");
    let first_action = first_pending.payload().action_id;
    first
        .shutdown(std::net::Shutdown::Write)
        .expect("originating half-close");
    wait_until_inactive(&first_pending);
    assert_eq!(
        first_pending.decide(GateDecision::Approve),
        Err("kernel gate is no longer waiting".to_owned())
    );

    let second = open_relay(broker.socket_path());
    let second_pending = controller.receive().expect("second exact request prompt");
    let second_action = second_pending.payload().action_id;
    assert_ne!(
        second_action, first_action,
        "retry must allocate a fresh action"
    );
    second
        .shutdown(std::net::Shutdown::Write)
        .expect("second originating half-close");
    wait_until_inactive(&second_pending);
    assert_eq!(
        second_pending.decide(GateDecision::ApproveGrant),
        Err("kernel gate is no longer waiting".to_owned())
    );

    let retry = open_relay(broker.socket_path());
    let retry_pending = controller
        .receive_timeout(Duration::from_secs(1))
        .expect("gate channel")
        .expect("cancelled grant must not suppress the retry prompt");
    assert_ne!(retry_pending.payload().action_id, second_action);
    retry_pending
        .decide(GateDecision::Deny)
        .expect("deny retry prompt");
    // Wait for the denial to reach the client before dropping it; a drop the
    // broker notices first is recorded as the client cancelling instead.
    let mut retry = retry;
    retry
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("retry read timeout");
    let _ = std::io::Read::read_to_end(&mut retry, &mut Vec::new());
    drop(first);
    drop(second);
    drop(retry);

    let report = broker.shutdown().expect("broker shutdown");
    assert_eq!(report.denied_actions, 3);
    assert_eq!(report.session_facts.recent_behavioral_denials_in_scope, 1);
    assert_eq!(
        report.session_facts.denial_observations()[0].origin,
        DenialOrigin::Resource
    );
    assert_eq!(
        report.session_facts.denial_observations()[1].origin,
        DenialOrigin::Resource
    );
    assert_eq!(
        report.session_facts.denial_observations()[2].origin,
        DenialOrigin::Operator
    );
}

#[test]
fn broker_shutdown_cancels_a_pending_terminal_gate() {
    use std::{
        net::{Ipv4Addr, TcpListener},
        sync::mpsc::sync_channel,
        thread,
        time::Duration,
    };

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("upstream listener");
    let (gate, controller) = terminal_gate_channel();
    let broker = KernelBroker::spawn_with_audit_and_gate(
        "shutdown-prompt".to_owned(),
        BTreeSet::new(),
        BTreeSet::new(),
        Box::new(TestConnector {
            address: listener.local_addr().expect("upstream address"),
            observed_method: "GET",
            observed_path: "/status",
            model_budget: None,
        }),
        Box::new(DiscardAudit),
        Box::new(gate),
    )
    .expect("broker");
    let _client = open_relay(broker.socket_path());
    let pending = controller.receive().expect("exact request prompt");

    let (finished, completion) = sync_channel(0);
    thread::spawn(move || {
        let _ = finished.send(broker.shutdown());
    });
    let report = completion
        .recv_timeout(Duration::from_secs(1))
        .expect("broker shutdown waited for the approval deadline")
        .expect("broker shutdown");
    assert!(!pending.is_active());
    assert_eq!(
        pending.decide(GateDecision::ApproveGrant),
        Err("kernel gate is no longer waiting".to_owned())
    );
    assert_eq!(report.denied_actions, 1);
    assert_eq!(report.session_facts.recent_behavioral_denials_in_scope, 0);
}

#[test]
fn queued_egress_does_not_start_its_decision_clock_or_leave_a_prompt() {
    use std::{
        io::Read as _,
        net::{Ipv4Addr, TcpListener},
        thread,
        time::Duration,
    };

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("upstream listener");
    let (gate, controller) = terminal_gate_channel();
    let broker = KernelBroker::spawn_with_audit_and_gate(
        "serialized-prompts".to_owned(),
        BTreeSet::new(),
        BTreeSet::new(),
        Box::new(TestConnector {
            address: listener.local_addr().expect("upstream address"),
            observed_method: "GET",
            observed_path: "/status",
            model_budget: None,
        }),
        Box::new(DiscardAudit),
        Box::new(gate),
    )
    .expect("broker");
    let mut first = open_relay(broker.socket_path());
    let pending = controller.receive().expect("first exact request prompt");

    // Transport setup needs no operator, so it is not held behind the open
    // prompt. The queued exact request waits for the adjudication slot
    // without a prompt of its own.
    assert!(
        broker.state.try_lock().is_ok(),
        "an open operator prompt must not hold the broker state"
    );
    let queued = open_relay(broker.socket_path());
    assert!(
        controller
            .receive_timeout(Duration::from_millis(100))
            .expect("gate channel")
            .is_none(),
        "only one operator prompt may be open at a time"
    );
    drop(queued);
    thread::sleep(Duration::from_millis(100));

    pending
        .decide(GateDecision::Deny)
        .expect("deny first prompt");
    let mut decision = [0_u8; 1];
    assert_eq!(
        first
            .read_exact(&mut decision)
            .expect_err("denied exact request must close its transport")
            .kind(),
        ErrorKind::UnexpectedEof
    );
    assert!(
        controller
            .receive_timeout(Duration::from_millis(200))
            .expect("gate channel")
            .is_none(),
        "a disconnected queued request must not become a later prompt"
    );
    // The operator's denial, and the abandoned queued decision closed as
    // unavailable.
    assert_eq!(
        broker.shutdown().expect("broker shutdown").denied_actions,
        2
    );
}

#[test]
fn approved_broker_action_forwards_the_connected_stream() {
    use std::{
        io::{Read as _, Write as _},
        net::{Ipv4Addr, TcpListener},
        thread,
    };

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("upstream listener");
    let address = listener.local_addr().expect("upstream address");
    let upstream = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("upstream connection");
        let mut request = [0_u8; 4];
        stream.read_exact(&mut request).expect("tunnel request");
        assert_eq!(&request, b"ping");
        stream.write_all(b"pong").expect("tunnel response");
    });
    let broker = KernelBroker::spawn_with_audit_and_gate(
        "forward-test".to_owned(),
        ["relay.example".to_owned()].into_iter().collect(),
        BTreeSet::new(),
        Box::new(TestConnector {
            address,
            observed_method: "POST",
            observed_path: "/relay",
            model_budget: None,
        }),
        Box::new(DiscardAudit),
        Box::new(Harness {
            gate_decision: Some(GateDecision::Approve),
            ..Harness::default()
        }),
    )
    .expect("broker");
    let mut client = open_relay(broker.socket_path());
    client.write_all(b"ping").expect("tunnel write");
    let mut tunneled = Vec::new();
    client
        .read_to_end(&mut tunneled)
        .expect("tunnel response body");
    assert_eq!(tunneled, b"pong");
    upstream.join().expect("upstream thread");
    let report = broker.shutdown().expect("broker shutdown");
    assert_eq!(report.audit_events, 5);
    assert_eq!(report.denied_actions, 0);
    assert_eq!(report.execution_failures, 0);
    assert_eq!(report.session_facts.floor, 0);
    assert_eq!(report.session_facts.floor_history[0].rank, 0);
    assert_eq!(
        report.session_facts.floor_history[0].source,
        SourceRef::Host {
            host: "relay.example".to_owned(),
            path: "/relay".to_owned()
        }
    );
}

#[test]
fn idle_broker_client_does_not_block_a_valid_client() {
    use std::{
        io::{Read as _, Write as _},
        net::{Ipv4Addr, TcpListener},
        os::unix::net::UnixStream,
        thread,
        time::Duration,
    };

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("upstream listener");
    let address = listener.local_addr().expect("upstream address");
    let upstream = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("upstream connection");
        let mut request = [0_u8; 4];
        stream.read_exact(&mut request).expect("tunnel request");
        stream.write_all(b"pong").expect("tunnel response");
    });
    let broker = KernelBroker::spawn_with_audit_and_gate(
        "late-request".to_owned(),
        ["relay.example".to_owned()].into_iter().collect(),
        BTreeSet::new(),
        Box::new(TestConnector {
            address,
            // This test is about broker handshake concurrency, not a
            // second decrypted-request gate inside the connected tunnel.
            observed_method: "CONNECT",
            observed_path: "",
            model_budget: None,
        }),
        Box::new(DiscardAudit),
        Box::new(Harness {
            gate_decision: Some(GateDecision::Approve),
            ..Harness::default()
        }),
    )
    .expect("broker");
    // Hold one accepted client completely idle. A second client must still
    // be authorized without waiting for the first client's handshake
    // timeout.
    let idle = UnixStream::connect(broker.socket_path()).expect("idle broker connection");
    thread::sleep(Duration::from_millis(50));
    let mut client = open_relay(broker.socket_path());
    client
        .set_read_timeout(Some(Duration::from_millis(300)))
        .expect("client timeout");
    client.write_all(b"ping").expect("tunnel write");
    let mut tunneled = Vec::new();
    client
        .read_to_end(&mut tunneled)
        .expect("tunnel response body");
    assert_eq!(tunneled, b"pong");
    drop(idle);
    upstream.join().expect("upstream thread");
    let report = broker.shutdown().expect("broker shutdown");
    assert_eq!(report.denied_actions, 0);
    assert_eq!(report.execution_failures, 0);
}

#[test]
fn malformed_git_broker_request_fails_before_kernel_processing() {
    use std::{
        io::{Read as _, Write as _},
        os::unix::net::UnixStream,
    };

    let broker = KernelBroker::spawn(
        "malformed-git-request".to_owned(),
        BTreeSet::new(),
        Box::new(TestConnector {
            address: "127.0.0.1:9".parse().expect("socket address"),
            observed_method: "GET",
            observed_path: "/",
            model_budget: None,
        }),
    )
    .expect("broker");
    let mut client = UnixStream::connect(broker.socket_path()).expect("broker connection");
    client.write_all(b"KEEL-GIT-V1\0").expect("marker");
    client
        .write_all(&u16::to_be_bytes(6))
        .expect("remote length");
    client.write_all(b"origin").expect("remote");
    client.write_all(&u16::to_be_bytes(1)).expect("ref count");
    client.write_all(&u16::to_be_bytes(4)).expect("ref length");
    client.write_all(b"main").expect("invalid ref");
    client.flush().expect("request flush");
    let mut response = [0_u8; 1];
    client.read_exact(&mut response).expect("broker response");
    assert_eq!(response[0], GIT_DENIED);

    let report = broker.shutdown().expect("broker shutdown");
    assert_eq!(report.audit_events, 0);
    assert_eq!(report.denied_actions, 0);
}

/// Keeps only what the relay claimed, so a test can tell a kernel
/// authorization apart from a reported outcome.
struct OutcomeLog(Arc<Mutex<Vec<(u64, String)>>>);

impl AuditSink for OutcomeLog {
    fn record(&mut self, _event: AuditEvent) -> Result<(), String> {
        Ok(())
    }

    fn record_reported_outcome(&mut self, event: ReportedOutcomeEvent) -> Result<(), String> {
        self.0
            .lock()
            .map_err(|_| "outcome log is poisoned".to_owned())?
            .push((event.action_id, event.outcome));
        Ok(())
    }
}

fn git_broker(outcomes: &Arc<Mutex<Vec<(u64, String)>>>) -> KernelBroker {
    KernelBroker::spawn_with_session_policy(
        "git-outcome-report".to_owned(),
        BTreeSet::new(),
        BTreeSet::new(),
        SessionFacts::default(),
        ProvenanceMode::Floor,
        Box::new(Allow),
        Box::new(TestConnector {
            address: "127.0.0.1:9".parse().expect("socket address"),
            observed_method: "GET",
            observed_path: "/",
            model_budget: None,
        }),
        Box::new(OutcomeLog(Arc::clone(outcomes))),
        Some(Box::new(Harness {
            gate_decision: Some(GateDecision::Approve),
            ..Harness::default()
        })),
    )
    .expect("broker")
}

/// Authorizes one branch push and returns the correlation id the relay is
/// expected to report the outcome of that push against.
fn authorize_push(path: &Path) -> u64 {
    use std::io::{Read as _, Write as _};

    let mut client = std::os::unix::net::UnixStream::connect(path).expect("broker connection");
    client.write_all(GIT_BROKER_MAGIC).expect("marker");
    client
        .write_all(&u16::to_be_bytes(6))
        .expect("remote length");
    client.write_all(b"origin").expect("remote");
    client.write_all(&u16::to_be_bytes(1)).expect("ref count");
    client.write_all(&u16::to_be_bytes(16)).expect("ref length");
    client.write_all(b"refs/heads/topic").expect("ref");
    client.write_all(&[0, 0, 0, 0]).expect("flags");
    client.write_all(&[0_u8; 32]).expect("body digest");
    client.flush().expect("request flush");
    let mut response = [0_u8; 9];
    client.read_exact(&mut response).expect("broker response");
    assert_eq!(response[0], GIT_ALLOWED);
    u64::from_be_bytes(response[1..].try_into().expect("action id"))
}

#[test]
fn git_effect_permit_matches_exact_body_and_is_consumed_once() {
    let mut state = BrokerState::new(
        "effect-binding".to_owned(),
        ["github.com".to_owned()].into_iter().collect(),
        ["push:branch".to_owned()].into_iter().collect(),
        "api.anthropic.com".to_owned(),
        SessionFacts::default(),
        ProvenanceMode::Floor,
        Box::new(Allow),
        Box::new(TestConnector {
            address: "127.0.0.1:9".parse().expect("socket address"),
            observed_method: "POST",
            observed_path: "/owner/repo.git/git-receive-pack",
            model_budget: None,
        }),
        Box::new(DiscardAudit),
        Box::new(Harness {
            gate_decision: Some(GateDecision::Approve),
            ..Harness::default()
        }),
        ModelBudgetLimits::default(),
    )
    .expect("broker state");
    let digest = [7_u8; 32];
    assert!(
        state
            .authorize_git(
                Asserted {
                    class: ActionClass::GitPush,
                    target: Target::Git {
                        remote: "https://github.com/owner/repo.git".to_owned(),
                        refs: vec!["refs/heads/topic".to_owned()],
                        is_force: false,
                        is_default_branch: false,
                        touches_manifest: false,
                        manifest_diff: None,
                    },
                    declared_cost: None,
                },
                digest,
            )
            .is_some()
    );
    let target = EgressAuthorizationTarget {
        host: "github.com".to_owned(),
        port: 443,
    };
    assert!(
        state
            .authorize_http(
                &target,
                "POST",
                "/owner/repo.git/git-receive-pack",
                [8_u8; 32],
                None,
            )
            .is_err()
    );
    assert!(
        state
            .authorize_http(
                &target,
                "POST",
                "/owner/repo.git/git-receive-pack",
                digest,
                None,
            )
            .is_ok()
    );
    assert!(
        state
            .authorize_http(
                &target,
                "POST",
                "/owner/repo.git/git-receive-pack",
                digest,
                None,
            )
            .is_err()
    );
}

#[test]
fn github_pull_request_permit_matches_exact_request_and_is_consumed_once() {
    let mut state = BrokerState::new(
        "github-effect-binding".to_owned(),
        ["api.github.com".to_owned()].into_iter().collect(),
        ["pr:create".to_owned()].into_iter().collect(),
        "api.anthropic.com".to_owned(),
        SessionFacts::default(),
        ProvenanceMode::Floor,
        Box::new(Allow),
        Box::new(TestConnector {
            address: "127.0.0.1:9".parse().expect("socket address"),
            observed_method: "POST",
            observed_path: "/repos/acme/widget/pulls",
            model_budget: None,
        }),
        Box::new(DiscardAudit),
        Box::new(Harness {
            gate_decision: Some(GateDecision::Approve),
            ..Harness::default()
        }),
        ModelBudgetLimits::default(),
    )
    .expect("broker state");
    let body = serde_json::to_vec(&serde_json::json!({
        "title": "Bound request",
        "head": "topic",
        "base": "main",
        "body": "Description",
    }))
    .expect("request body");
    assert_eq!(
        state.authorize_external(Asserted {
            class: ActionClass::PullRequest,
            target: Target::External {
                service: "github".to_owned(),
                recipient: "acme/widget".to_owned(),
                operation: "create-pull-request".to_owned(),
                detail: serde_json::json!({
                    "title": "Bound request",
                    "head": "topic",
                    "base": "main",
                    "body": "Description",
                })
                .to_string(),
            },
            declared_cost: None,
        }),
        EXTERNAL_ALLOWED
    );
    let target = EgressAuthorizationTarget {
        host: "api.github.com".to_owned(),
        port: 443,
    };
    assert!(
        state
            .authorize_http(
                &target,
                "POST",
                "/repos/acme/widget/pulls",
                sha256(&body),
                None,
            )
            .is_ok()
    );
    assert!(
        state
            .authorize_http(
                &target,
                "POST",
                "/repos/acme/widget/pulls",
                sha256(&body),
                None,
            )
            .is_err()
    );
}

fn report_push(path: &Path, action_id: u64, completed: bool) -> u8 {
    use std::io::{Read as _, Write as _};

    let outcome = if completed {
        GIT_REPORT_COMPLETED
    } else {
        GIT_REPORT_FAILED
    };
    let mut client = std::os::unix::net::UnixStream::connect(path).expect("broker connection");
    client.write_all(GIT_REPORT_MAGIC).expect("marker");
    client
        .write_all(&action_id.to_be_bytes())
        .expect("action id");
    client.write_all(&[outcome]).expect("outcome");
    client.flush().expect("report flush");
    let mut response = [0_u8; 1];
    client.read_exact(&mut response).expect("broker response");
    response[0]
}

/// An outcome is only recorded for a push this kernel authorized, and only
/// once. Otherwise an untrusted relay could write outcomes for actions that
/// were never allowed, or overwrite one it already reported.
#[test]
fn a_git_outcome_report_is_accepted_once_per_authorized_push() {
    let outcomes = Arc::new(Mutex::new(Vec::new()));
    let broker = git_broker(&outcomes);
    let action_id = authorize_push(broker.socket_path());

    assert_eq!(
        report_push(broker.socket_path(), action_id, true),
        GIT_ALLOWED
    );
    // Already closed, then never authorized. Neither may reach the audit.
    assert_eq!(
        report_push(broker.socket_path(), action_id, false),
        GIT_DENIED
    );
    assert_eq!(
        report_push(broker.socket_path(), action_id.wrapping_add(1), true),
        GIT_DENIED
    );

    broker.shutdown().expect("broker shutdown");
    let recorded = Arc::into_inner(outcomes).expect("sole owner").into_inner();
    assert_eq!(
        recorded.expect("outcome log"),
        vec![(action_id, "completed".to_owned())]
    );
}

/// The guarantee that does not depend on the relay: every authorization the
/// kernel hands out is closed, so an authorization is never left standing as
/// the last word on whether a push landed.
#[test]
fn an_authorized_push_without_a_report_is_closed_as_unreported() {
    let outcomes = Arc::new(Mutex::new(Vec::new()));
    let broker = git_broker(&outcomes);
    let reported = authorize_push(broker.socket_path());
    let silent = authorize_push(broker.socket_path());
    assert_eq!(
        report_push(broker.socket_path(), reported, false),
        GIT_ALLOWED
    );

    broker.shutdown().expect("broker shutdown");
    let recorded = Arc::into_inner(outcomes).expect("sole owner").into_inner();
    assert_eq!(
        recorded.expect("outcome log"),
        vec![
            (reported, "failed".to_owned()),
            (silent, "unreported".to_owned()),
        ]
    );
}

/// A connector with the hardcoded network floor and trusted TLS custody,
/// so a boundary report can be asked to tell the two connectors apart.
struct MediatingConnector;

impl EgressConnector for MediatingConnector {
    fn structurally_denied(&self, _host: &str, _port: u16, _method: &str) -> bool {
        true
    }

    fn connect(
        &mut self,
        _host: &str,
        _port: u16,
        _method: &str,
    ) -> Result<Box<dyn EgressSession>, String> {
        Err("not used".to_owned())
    }

    fn ca_certificate_pem(&self) -> Option<String> {
        Some("-----BEGIN CERTIFICATE-----".to_owned())
    }
}

struct DurableAudit;

impl AuditSink for DurableAudit {
    fn record(&mut self, _event: AuditEvent) -> Result<(), String> {
        Ok(())
    }

    fn is_durable(&self) -> bool {
        true
    }
}

/// Records every enforcement-state event so a test can read the phases and
/// the boundary states a run actually published.
struct EnforcementLog(Arc<Mutex<Vec<EnforcementStateEvent>>>);

impl AuditSink for EnforcementLog {
    fn record(&mut self, _event: AuditEvent) -> Result<(), String> {
        Ok(())
    }

    fn record_enforcement_state(&mut self, event: EnforcementStateEvent) -> Result<(), String> {
        self.0
            .lock()
            .map_err(|_| "enforcement log is poisoned".to_owned())?
            .push(event);
        Ok(())
    }
}

fn boundary_state(boundaries: &[EnforcementBoundary], name: &str) -> (EnforcementState, String) {
    let boundary = boundaries
        .iter()
        .find(|boundary| boundary.name == name)
        .unwrap_or_else(|| panic!("boundary {name} is not reported"));
    (boundary.state, boundary.detail.clone())
}

fn broker_state(
    hosts: BTreeSet<String>,
    mode: ProvenanceMode,
    connector: Box<dyn EgressConnector>,
    audit: Box<dyn AuditSink>,
    gate: Box<dyn Gate>,
) -> BrokerState {
    BrokerState::new(
        "enforcement-state".to_owned(),
        hosts,
        BTreeSet::new(),
        "api.anthropic.com".to_owned(),
        SessionFacts::default(),
        mode,
        Box::new(Allow),
        connector,
        audit,
        gate,
        ModelBudgetLimits::default(),
    )
    .expect("broker state")
}

/// The test that gives the record its value: every reported field has to
/// move when the object that enforces it moves. A field that reads from
/// configuration instead of from enforcement would pass one half of this and
/// fail the other, which is exactly the drift the record exists to catch.
#[test]
fn every_reported_boundary_tracks_the_object_that_enforces_it() {
    let weak = broker_state(
        BTreeSet::new(),
        ProvenanceMode::GateContext,
        Box::new(TestConnector {
            address: "127.0.0.1:9".parse().expect("socket address"),
            observed_method: "GET",
            observed_path: "/",
            model_budget: None,
        }),
        Box::new(DiscardAudit),
        Box::new(DenyGate),
    )
    .enforcement_boundaries();
    let (gate, _) = terminal_gate_channel();
    let strong = broker_state(
        BTreeSet::from(["api.anthropic.com".to_owned()]),
        ProvenanceMode::Floor,
        Box::new(MediatingConnector),
        Box::new(DurableAudit),
        Box::new(gate),
    )
    .enforcement_boundaries();

    for name in ["network-floor", "tls-termination", "audit-chain"] {
        assert_eq!(boundary_state(&weak, name).0, EnforcementState::Absent);
        assert_eq!(boundary_state(&strong, name).0, EnforcementState::Active);
    }
    assert_eq!(
        boundary_state(&strong, "provenance").0,
        EnforcementState::Active
    );
    assert_eq!(
        boundary_state(&weak, "egress-allowlist").1,
        "hosts=0 []".to_owned()
    );
    assert_eq!(
        boundary_state(&strong, "egress-allowlist").1,
        "hosts=1 [api.anthropic.com]".to_owned()
    );
    assert_eq!(
        boundary_state(&weak, "operator-gate").1,
        "authority=deny-only".to_owned()
    );
    assert_eq!(
        boundary_state(&strong, "operator-gate").1,
        "authority=operator".to_owned()
    );
    // `gate-context` informs a decision without constraining one, so it is
    // reported as advisory rather than as a boundary that is up.
    assert_eq!(
        boundary_state(&weak, "provenance").0,
        EnforcementState::Advisory
    );
}

/// Every run opens and closes with a record, so an operator reading the
/// chain never has to infer which boundaries were standing.
#[test]
fn a_run_opens_and_closes_with_an_enforcement_state_record() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let broker = KernelBroker::spawn_with_audit(
        "enforcement-record".to_owned(),
        BTreeSet::from(["api.anthropic.com".to_owned()]),
        Box::new(TestConnector {
            address: "127.0.0.1:9".parse().expect("socket address"),
            observed_method: "GET",
            observed_path: "/",
            model_budget: None,
        }),
        Box::new(EnforcementLog(Arc::clone(&events))),
    )
    .expect("broker");
    broker.shutdown().expect("broker shutdown");

    let recorded = Arc::into_inner(events)
        .expect("sole owner")
        .into_inner()
        .expect("enforcement log");
    assert_eq!(
        recorded.iter().map(|event| event.phase).collect::<Vec<_>>(),
        vec!["start", "shutdown"]
    );
    for event in &recorded {
        assert_eq!(
            boundary_state(&event.boundaries, "channel-registry").1,
            "egress=egress external=external git=git operator=operator".to_owned()
        );
        assert_eq!(
            boundary_state(&event.boundaries, "capability-intent").1,
            "capabilities=0 []".to_owned()
        );
        assert_eq!(
            boundary_state(&event.boundaries, "protected-state").1,
            "policy,audit,attestation,provenance,budget".to_owned()
        );
    }
}

#[test]
fn broker_shutdown_propagates_durable_audit_failure() {
    let broker = KernelBroker::spawn_with_audit(
        "audit-shutdown-test".to_owned(),
        BTreeSet::new(),
        Box::new(TestConnector {
            address: "127.0.0.1:9".parse().expect("socket address"),
            observed_method: "GET",
            observed_path: "/",
            model_budget: None,
        }),
        Box::new(FailingShutdownAudit),
    )
    .expect("broker");
    let error = broker.shutdown().expect_err("audit shutdown must fail");
    assert!(error.contains("forced audit shutdown failure"));
}

#[test]
fn decrypted_model_endpoint_denial_is_audited_before_upstream_bytes() {
    use std::{
        io::{Read as _, Write as _},
        net::{Ipv4Addr, TcpListener},
        os::unix::net::UnixStream,
    };

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("upstream listener");
    let address = listener.local_addr().expect("upstream address");
    let broker = KernelBroker::spawn(
        "model-endpoint-denial".to_owned(),
        ["api.anthropic.com".to_owned()].into_iter().collect(),
        Box::new(TestConnector {
            address,
            observed_method: "POST",
            observed_path: "/v1/files",
            model_budget: None,
        }),
    )
    .expect("broker");
    let mut client = UnixStream::connect(broker.socket_path()).expect("broker connection");
    client.write_all(b"KEEL-EGRESS-V2\0").expect("marker");
    client
        .write_all(&u16::to_be_bytes(17))
        .expect("host length");
    client.write_all(b"api.anthropic.com").expect("host");
    client.write_all(&443_u16.to_be_bytes()).expect("port");
    client.write_all(&[2]).expect("method");
    client.flush().expect("request flush");
    let mut response = [0_u8; 2];
    client.read_exact(&mut response).expect("broker response");
    assert_eq!(response, [EGRESS_PENDING, EGRESS_ALLOWED]);
    let mut tunneled = Vec::new();
    client.read_to_end(&mut tunneled).expect("tunnel close");
    assert!(tunneled.is_empty());
    listener
        .set_nonblocking(true)
        .expect("nonblocking listener");
    assert_eq!(
        listener
            .accept()
            .expect_err("denied exact request must not connect upstream")
            .kind(),
        ErrorKind::WouldBlock
    );
    let report = broker.shutdown().expect("broker shutdown");
    assert_eq!(report.audit_events, 3);
    assert_eq!(report.denied_actions, 1);
    assert_eq!(report.execution_failures, 0);
}

#[test]
fn exhausted_model_budget_is_audited_before_upstream_bytes() {
    use std::{
        io::{Read as _, Write as _},
        net::{Ipv4Addr, TcpListener},
        os::unix::net::UnixStream,
    };

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("upstream listener");
    let address = listener.local_addr().expect("upstream address");
    let broker = KernelBroker::spawn(
        "model-budget-denial".to_owned(),
        ["api.anthropic.com".to_owned()].into_iter().collect(),
        Box::new(TestConnector {
            address,
            observed_method: "POST",
            observed_path: "/v1/messages",
            model_budget: Some(ModelBudgetRequest {
                input_tokens_upper_bound: 1_000_001,
                max_output_tokens: 1,
                input_microusd_per_token: 1,
                output_microusd_per_token: 1,
            }),
        }),
    )
    .expect("broker");
    let mut client = UnixStream::connect(broker.socket_path()).expect("broker connection");
    client.write_all(b"KEEL-EGRESS-V2\0").expect("marker");
    client
        .write_all(&u16::to_be_bytes(17))
        .expect("host length");
    client.write_all(b"api.anthropic.com").expect("host");
    client.write_all(&443_u16.to_be_bytes()).expect("port");
    client.write_all(&[2]).expect("method");
    client.flush().expect("request flush");
    let mut response = [0_u8; 2];
    client.read_exact(&mut response).expect("broker response");
    assert_eq!(response, [EGRESS_PENDING, EGRESS_ALLOWED]);
    let mut tunneled = Vec::new();
    client.read_to_end(&mut tunneled).expect("tunnel close");
    assert!(tunneled.is_empty());
    listener
        .set_nonblocking(true)
        .expect("nonblocking listener");
    assert_eq!(
        listener
            .accept()
            .expect_err("budget-denied request must not connect upstream")
            .kind(),
        ErrorKind::WouldBlock
    );
    let report = broker.shutdown().expect("broker shutdown");
    assert_eq!(report.audit_events, 3);
    assert_eq!(report.denied_actions, 1);
    assert_eq!(report.execution_failures, 0);
    assert_eq!(
        report.session_facts.recent_behavioral_denials_in_scope, 0,
        "resource exhaustion must not train the repeated-behavior rule"
    );
    assert_eq!(report.session_facts.denial_observations().len(), 1);
    assert_eq!(
        report.session_facts.denial_observations()[0].origin,
        DenialOrigin::Resource
    );
}

fn push(refs: &[&str], is_force: bool, is_default_branch: bool) -> Asserted {
    Asserted {
        class: ActionClass::GitPush,
        target: Target::Git {
            remote: "origin".to_owned(),
            refs: refs.iter().map(|name| (*name).to_owned()).collect(),
            is_force,
            is_default_branch,
            touches_manifest: false,
            manifest_diff: None,
        },
        declared_cost: None,
    }
}

#[test]
fn task_envelope_classifies_pushes_prs_and_egress() {
    let mut intent = keel_provenance::IntentFlags {
        allow_push_branch: true,
        allow_pr_create: true,
        allowed_egress_hosts: ["crates.io".to_owned(), "api.anthropic.com".to_owned()]
            .into_iter()
            .collect(),
        ..keel_provenance::IntentFlags::default()
    };
    let verdict = |asserted: &Asserted, intent: &keel_provenance::IntentFlags| {
        intent_verdict(asserted, intent)
    };
    assert_eq!(
        verdict(&push(&["refs/heads/topic"], false, false), &intent),
        IntentVerdict::Inside
    );
    assert_eq!(
        verdict(&push(&["refs/heads/main"], false, true), &intent),
        IntentVerdict::Outside("default-branch")
    );
    assert_eq!(
        verdict(&push(&["refs/heads/topic"], true, false), &intent),
        IntentVerdict::Outside("force-or-delete")
    );
    intent.push_refs = [
        "refs/heads/feature/*".to_owned(),
        "refs/heads/main".to_owned(),
    ]
    .into_iter()
    .collect();
    assert_eq!(
        verdict(&push(&["refs/heads/feature/x"], false, false), &intent),
        IntentVerdict::Inside
    );
    assert_eq!(
        verdict(&push(&["refs/heads/main"], false, true), &intent),
        IntentVerdict::Inside
    );
    assert_eq!(
        verdict(&push(&["refs/heads/topic"], false, false), &intent),
        IntentVerdict::Outside("ref-outside-envelope")
    );

    let pr = |base: &str| Asserted {
        class: ActionClass::PullRequest,
        target: Target::External {
            service: "github".to_owned(),
            recipient: "o/r".to_owned(),
            operation: "create-pull-request".to_owned(),
            detail: format!(r#"{{"title":"t","head":"h","base":"{base}","body":"b"}}"#),
        },
        declared_cost: None,
    };
    assert_eq!(verdict(&pr("dev"), &intent), IntentVerdict::Inside);
    intent.pr_targets = ["main".to_owned()].into_iter().collect();
    assert_eq!(verdict(&pr("main"), &intent), IntentVerdict::Inside);
    assert_eq!(
        verdict(&pr("dev"), &intent),
        IntentVerdict::Outside("pr-target")
    );

    let egress = |host: &str, method: &str| Asserted {
        class: ActionClass::Egress,
        target: Target::Network {
            host: host.to_owned(),
            port: 443,
            method: method.to_owned(),
            path: "/x".to_owned(),
        },
        declared_cost: None,
    };
    assert_eq!(
        verdict(&egress("crates.io", "GET"), &intent),
        IntentVerdict::Inside
    );
    assert_eq!(
        verdict(&egress("crates.io", "PUT"), &intent),
        IntentVerdict::Outside("registry-write")
    );
    assert_eq!(
        verdict(&egress("api.anthropic.com", "POST"), &intent),
        IntentVerdict::Inside
    );
    assert_eq!(
        verdict(&egress("paste.example", "POST"), &intent),
        IntentVerdict::Outside("egress-host")
    );
    assert_eq!(
        verdict(&read_action(), &intent),
        IntentVerdict::NotApplicable
    );
    let setup = Asserted {
        class: ActionClass::Egress,
        target: Target::Network {
            host: "paste.example".to_owned(),
            port: 443,
            method: "CONNECT".to_owned(),
            path: String::new(),
        },
        declared_cost: None,
    };
    assert_eq!(verdict(&setup, &intent), IntentVerdict::NotApplicable);
}

#[test]
fn declared_push_refs_narrow_push_branch_authority() {
    let mut facts = SessionFacts::default();
    facts.intent.task_admission = keel_provenance::TaskAdmission::Trusted;
    facts.intent.allow_push_branch = true;
    facts.intent.push_refs = ["refs/heads/feature/*".to_owned()].into_iter().collect();
    let mut state = BrokerState::new(
        "push-ref-scope".to_owned(),
        ["github.com".to_owned()].into_iter().collect(),
        ["push:ref:refs/heads/feature/*".to_owned()]
            .into_iter()
            .collect(),
        "api.anthropic.com".to_owned(),
        facts,
        ProvenanceMode::Floor,
        Box::new(Allow),
        Box::new(TestConnector {
            address: "127.0.0.1:9".parse().expect("socket address"),
            observed_method: "POST",
            observed_path: "/owner/repo.git/git-receive-pack",
            model_budget: None,
        }),
        Box::new(DiscardAudit),
        Box::new(Harness {
            gate_decision: Some(GateDecision::Deny),
            ..Harness::default()
        }),
        ModelBudgetLimits::default(),
    )
    .expect("broker state");
    let mut push_to = |name: &str| state.authorize_git(push(&[name], false, false), [1; 32]);
    assert!(
        push_to("refs/heads/feature/x").is_some(),
        "inside the declared scope"
    );
    assert!(
        push_to("refs/heads/topic").is_none(),
        "outside the declared scope reaches the gate, which denies"
    );
}

#[test]
fn payload_flow_is_judged_against_destination_clearance() {
    use super::{FlowVerdict, PayloadPolicy};
    use keel_provenance::{Confidentiality, PayloadIndex};

    let private =
        "Quarterly settlement reconciliation notes for the treasury migration, internal only.";
    let secret = "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY-not-a-real-one";
    let mut index = PayloadIndex::default();
    index.add(Confidentiality::Private, private.as_bytes());
    index.add(Confidentiality::Secret, secret.as_bytes());
    let policy = PayloadPolicy::new(
        index,
        vec![("api.github.com".to_owned(), "/repos/o/r/".to_owned())],
    );
    let model = "api.anthropic.com";

    assert_eq!(
        policy.judge(model, "/v1/messages", secret.as_bytes(), model),
        FlowVerdict::Cleared(0)
    );
    assert_eq!(
        policy.judge("paste.example", "/", b"nothing confidential here", model),
        FlowVerdict::Clean
    );
    assert!(matches!(
        policy.judge("api.github.com", "/repos/o/r/pulls", private.as_bytes(), model),
        FlowVerdict::Cleared(fragments) if fragments > 0
    ));
    assert!(matches!(
        policy.judge("paste.example", "/", private.as_bytes(), model),
        FlowVerdict::Leak {
            label: Confidentiality::Private,
            clearance: Confidentiality::Public,
            ..
        }
    ));
    let leaked = policy.judge(
        "api.github.com",
        "/repos/o/r/pulls",
        secret.as_bytes(),
        model,
    );
    assert!(
        leaked.describe().starts_with("secret-to-private:"),
        "{}",
        leaked.describe()
    );
    assert!(matches!(
        policy.judge(
            "api.github.com",
            "/repos/other/repo/pulls",
            private.as_bytes(),
            model
        ),
        FlowVerdict::Leak {
            clearance: Confidentiality::Public,
            ..
        }
    ));
}

#[test]
fn the_stamped_flow_verdict_reaches_the_audit_record() {
    let mut kernel = Kernel::new(
        registry(),
        SessionState::new(10, 3).expect("session"),
        Allow,
        "test-session",
    )
    .expect("kernel");
    let mut audit = Harness::default();
    let pending = kernel
        .begin_with_flow(
            "workspace",
            "vertex-1",
            read_action(),
            super::FlowVerdict::Clean,
            &mut audit,
        )
        .expect("begin");
    kernel
        .finish(
            pending,
            None,
            &mut Harness::default(),
            &mut Harness::default(),
            &mut audit,
        )
        .expect("finish");
    assert!(audit.audit.iter().all(|event| event.flow == "clean"));
    assert!(!audit.audit.is_empty());
}

#[test]
fn reported_origins_parse_into_a_bounded_summary() {
    use super::ReportedOrigin;

    let origin = ReportedOrigin::parse(
        br#"{"known":true,"workspace_code":true,"chain":[
            {"exe":"/usr/bin/git","argv":["git","push","origin","main","--force"],"workspace_code":false},
            {"exe":"/usr/bin/node","argv":["node","node_modules/evil/install.js"],"workspace_code":true},
            {"exe":"/usr/local/bin/claude\u001b[2J","argv":["claude"],"workspace_code":false}]}"#,
    );
    assert!(origin.known && origin.workspace_code);
    assert_eq!(
        origin.summary,
        "git push origin main <- *node node_modules/evil/install.js <- claude[2J"
    );
    assert_eq!(
        ReportedOrigin::parse(b"not json"),
        ReportedOrigin::default()
    );
}

#[test]
fn an_origin_frame_may_precede_any_broker_request() {
    use std::io::Write as _;

    let (mut client, mut server) = std::os::unix::net::UnixStream::pair().expect("pair");
    let origin = br#"{"known":true,"workspace_code":false,"chain":[{"exe":"/usr/bin/curl","argv":["curl"]}]}"#;
    client.write_all(super::ORIGIN_MAGIC).expect("magic");
    client
        .write_all(&u16::try_from(origin.len()).unwrap().to_be_bytes())
        .expect("length");
    client.write_all(origin).expect("origin");
    send_relay_request(&mut client);
    let (reported, request) = super::read_broker_request(&mut server).expect("request");
    assert_eq!(reported.expect("origin").summary, "curl");
    assert!(matches!(request, super::BrokerRequest::Egress(_)));

    let (mut client, mut server) = std::os::unix::net::UnixStream::pair().expect("pair");
    send_relay_request(&mut client);
    let (reported, _) = super::read_broker_request(&mut server).expect("request");
    assert!(reported.is_none(), "the frame is optional");
}

#[test]
fn a_push_reported_from_workspace_code_reaches_the_gate() {
    let mut facts = SessionFacts::default();
    facts.intent.task_admission = keel_provenance::TaskAdmission::Trusted;
    facts.intent.allow_push_branch = true;
    let mut state = BrokerState::new(
        "origin-scope".to_owned(),
        ["github.com".to_owned()].into_iter().collect(),
        ["push:branch".to_owned()].into_iter().collect(),
        "api.anthropic.com".to_owned(),
        facts,
        ProvenanceMode::Floor,
        Box::new(Allow),
        Box::new(TestConnector {
            address: "127.0.0.1:9".parse().expect("socket address"),
            observed_method: "POST",
            observed_path: "/owner/repo.git/git-receive-pack",
            model_budget: None,
        }),
        Box::new(DiscardAudit),
        Box::new(Harness {
            gate_decision: Some(GateDecision::Deny),
            ..Harness::default()
        }),
        ModelBudgetLimits::default(),
    )
    .expect("broker state");
    let cancelled = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut push_from = |workspace_code: bool| {
        let origin = super::ReportedOrigin {
            known: true,
            workspace_code,
            summary: "git push".to_owned(),
        };
        state.run_locked(
            &cancelled,
            |state| {
                state.begin_git(
                    push(&["refs/heads/topic"], false, false),
                    [1; 32],
                    Some(origin),
                    &cancelled,
                )
            },
            |state, begun, outcome| state.finish_git(begun, outcome, &cancelled),
        )
    };
    assert!(
        push_from(false).is_some(),
        "an ordinary branch push needs no prompt"
    );
    assert!(
        push_from(true).is_none(),
        "workspace code reaches the gate, which denies"
    );
}

#[test]
fn integrity_counts_added_lines_the_model_did_not_write() {
    use super::IntegrityVerdict;
    use keel_provenance::ModelOutputIndex;

    let mut output = ModelOutputIndex::default();
    output.add("serde = \"1.0.228\"");
    let diff = "diff --git a/Cargo.toml b/Cargo.toml\n--- a/Cargo.toml\n+++ b/Cargo.toml\n@@ -1 +1,3 @@\n [dependencies]\n+serde = \"1.0.228\"\n+evil-crate = \"6.6.6\"\n+}\n";
    assert_eq!(
        IntegrityVerdict::of_diff(diff, &output),
        IntegrityVerdict::Lines {
            added: 2,
            unaccounted: 1
        }
    );
    assert_eq!(
        IntegrityVerdict::of_diff(diff, &output)
            .describe()
            .as_deref(),
        Some("unaccounted:1/2")
    );
    assert_eq!(
        IntegrityVerdict::of_diff("+x\n# keel: diff truncated\n", &output),
        IntegrityVerdict::Uninspectable
    );
    assert_eq!(IntegrityVerdict::NotChecked.describe(), None);
}

#[test]
fn a_default_branch_push_may_carry_a_diff_without_a_manifest() {
    use std::io::Write as _;

    let request = |default_branch: u8, manifest: u8, diff: bool| {
        let (mut client, mut server) = std::os::unix::net::UnixStream::pair().expect("pair");
        let mut bytes = super::GIT_BROKER_MAGIC.to_vec();
        let remote = b"https://github.com/o/r.git";
        bytes.extend_from_slice(&u16::try_from(remote.len()).unwrap().to_be_bytes());
        bytes.extend_from_slice(remote);
        bytes.extend_from_slice(&1_u16.to_be_bytes());
        let reference = b"refs/heads/main";
        bytes.extend_from_slice(&u16::try_from(reference.len()).unwrap().to_be_bytes());
        bytes.extend_from_slice(reference);
        bytes.extend_from_slice(&[0, default_branch, manifest]);
        if diff {
            bytes.push(1);
            bytes.extend_from_slice(&4_u32.to_be_bytes());
            bytes.extend_from_slice(b"+x\n\n");
        } else {
            bytes.push(0);
        }
        bytes.extend_from_slice(&[0; 32]);
        client.write_all(&bytes).expect("request");
        super::read_broker_request(&mut server).map(|_| ())
    };
    assert!(
        request(1, 0, true).is_ok(),
        "default branch carries a full diff"
    );
    assert!(
        request(0, 1, true).is_ok(),
        "a protected path carries its diff"
    );
    assert!(
        request(0, 0, true).is_err(),
        "a diff with neither is malformed"
    );
    assert!(
        request(0, 1, false).is_err(),
        "a protected path needs its diff"
    );
}
