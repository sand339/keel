#![doc = "Acceptance tests for provenance context at trusted gates."]

use keel_kernel::{
    Action, ActionClass, Asserted, AuditEvent, AuditSink, ChannelDeclaration, ChannelRegistry,
    CredentialInjector, Executor, Gate, GateClass, GateDecision, GatePayload, GateRequest, Kernel,
    KernelError, Policy, PrincipalId, ProvenanceEvent, ProvenanceMode, SessionState, Target,
    Violation,
};
use keel_provenance::{ClassificationTable, GitClassifier, ResultObservation, SessionFacts};
use std::path::PathBuf;

#[derive(Default)]
struct Harness {
    payloads: Vec<GatePayload>,
    audit: Vec<AuditEvent>,
    provenance: Vec<ProvenanceEvent>,
}

impl Gate for Harness {
    fn decide(&mut self, request: GateRequest<'_>) -> GateDecision {
        self.payloads.push(request.to_payload());
        GateDecision::Approve
    }
}

impl CredentialInjector for Harness {
    type Prepared = ();

    fn inject(&mut self, _action: &Action) -> Result<Self::Prepared, String> {
        Ok(())
    }
}

impl Executor<()> for Harness {
    type Output = ();

    fn execute(&mut self, (): ()) -> Result<Self::Output, String> {
        Ok(())
    }
}

impl AuditSink for Harness {
    fn record(&mut self, event: AuditEvent) -> Result<(), String> {
        self.audit.push(event);
        Ok(())
    }

    fn record_provenance(&mut self, event: ProvenanceEvent) -> Result<(), String> {
        self.provenance.push(event);
        Ok(())
    }
}

struct Allow;

impl Policy for Allow {
    fn violations(&self, _: &Action, _: &SessionFacts) -> Result<Vec<Violation>, String> {
        Ok(Vec::new())
    }
}

fn gated_push(mode: ProvenanceMode) -> (GatePayload, AuditEvent, ProvenanceEvent) {
    let git = GitClassifier::new(".", Vec::<String>::new(), Vec::<PathBuf>::new()).unwrap();
    let table = ClassificationTable::builtin(Vec::<String>::new());
    let principal = PrincipalId::new("vertex-1").unwrap();
    let registry = ChannelRegistry::new(
        ["git"],
        [ChannelDeclaration {
            name: "git".to_owned(),
            principal,
            gate_class: GateClass::Git,
        }],
    )
    .unwrap();
    let mut kernel = Kernel::with_provenance_mode(
        registry,
        SessionState::new(10, 3).unwrap(),
        Allow,
        "session-1",
        mode,
    )
    .unwrap();
    let classified = table
        .classify(
            ResultObservation::EgressResponse {
                host: "evil.example".to_owned(),
                path: "/issue/1".to_owned(),
            },
            &git,
            kernel.session().facts(),
        )
        .unwrap();
    let mut provenance = Harness::default();
    kernel
        .observe_result(classified, 42, &mut provenance)
        .unwrap();
    let mut gate = Harness::default();
    let mut injector = Harness::default();
    let mut executor = Harness::default();
    let mut audit = Harness::default();
    kernel
        .process(
            "git",
            "vertex-1",
            Asserted {
                class: ActionClass::GitPush,
                target: Target::Git {
                    remote: "origin".to_owned(),
                    refs: vec!["refs/heads/main".to_owned()],
                    is_force: true,
                    is_default_branch: true,
                    touches_manifest: false,
                    manifest_diff: None,
                },
                declared_cost: None,
            },
            &mut gate,
            &mut injector,
            &mut executor,
            &mut audit,
        )
        .unwrap();
    (
        gate.payloads.remove(0),
        audit.audit.remove(0),
        provenance.provenance.remove(0),
    )
}

#[test]
fn floor_mode_escalates_rank_shortfall_with_exact_history() {
    let (payload, event, provenance) = gated_push(ProvenanceMode::Floor);

    assert_eq!(
        payload.floor_history,
        [b"rank 0 at 42: Host { host: \"evil.example\", path: \"/issue/1\" }".to_vec()]
    );
    assert_eq!((provenance.floor_before, provenance.floor_after), (3, 0));
    assert_eq!(event.rules, ["kernel:minimum-rank", "kernel:gate-required"]);
}

#[test]
fn gate_context_renders_same_history_without_rank_check() {
    let (payload, event, provenance) = gated_push(ProvenanceMode::GateContext);

    assert_eq!(
        payload.floor_history,
        [b"rank 0 at 42: Host { host: \"evil.example\", path: \"/issue/1\" }".to_vec()]
    );
    assert_eq!((provenance.floor_before, provenance.floor_after), (3, 0));
    assert_eq!(event.rules, ["kernel:gate-required"]);
}

#[test]
fn provenance_audit_failure_leaves_floor_unchanged() {
    let registry = ChannelRegistry::new(Vec::<String>::new(), Vec::new()).unwrap();
    let mut kernel =
        Kernel::new(registry, SessionState::new(1, 1).unwrap(), Allow, "session").unwrap();
    let table = ClassificationTable::builtin(Vec::<String>::new());
    let git = GitClassifier::new(".", Vec::<String>::new(), Vec::<PathBuf>::new()).unwrap();
    let result = table
        .classify(
            ResultObservation::ShellOutput {
                command: "untrusted".to_owned(),
            },
            &git,
            kernel.session().facts(),
        )
        .unwrap();
    let mut audit = FailingAudit;

    assert_eq!(
        kernel.observe_result(result, 1, &mut audit),
        Err(KernelError::Audit("disk full".to_owned()))
    );
    assert_eq!(kernel.session().floor(), 3);
}

struct FailingAudit;

impl AuditSink for FailingAudit {
    fn record(&mut self, _: AuditEvent) -> Result<(), String> {
        Ok(())
    }

    fn record_provenance(&mut self, _: ProvenanceEvent) -> Result<(), String> {
        Err("disk full".to_owned())
    }
}
