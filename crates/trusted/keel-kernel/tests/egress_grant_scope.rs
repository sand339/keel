#![doc = "A reusable egress grant covers only what the operator was shown."]

use keel_kernel::{
    Action, ActionClass, Asserted, AuditEvent, AuditSink, ChannelDeclaration, ChannelRegistry,
    CredentialInjector, Executor, Gate, GateClass, GateDecision, GateOutcome, GateRequest, Kernel,
    KernelError, Policy, PrincipalId, ProvenanceEvent, SessionState, Target, Violation,
};
use keel_provenance::{ClassificationTable, GitClassifier, ResultObservation, SessionFacts};
use std::path::PathBuf;

#[derive(Default)]
struct Harness {
    prompts: usize,
    rules: Vec<Vec<String>>,
}

impl Gate for Harness {
    fn decide(&mut self, _: GateRequest<'_>) -> GateDecision {
        self.prompts += 1;
        GateDecision::ApproveGrant
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
        self.rules.push(event.rules);
        Ok(())
    }

    fn record_provenance(&mut self, _: ProvenanceEvent) -> Result<(), String> {
        Ok(())
    }
}

struct OffIntent;

impl Policy for OffIntent {
    fn violations(&self, _: &Action, _: &SessionFacts) -> Result<Vec<Violation>, String> {
        Ok(vec![Violation::new(
            "intent:egress-host",
            "host is outside structured intent",
        )])
    }
}

fn kernel() -> Kernel<OffIntent> {
    let registry = ChannelRegistry::new(
        ["egress"],
        [ChannelDeclaration {
            name: "egress".to_owned(),
            principal: PrincipalId::new("vertex-1").unwrap(),
            gate_class: GateClass::Egress,
        }],
    )
    .unwrap();
    Kernel::new(
        registry,
        SessionState::new(100, 50).unwrap(),
        OffIntent,
        "s",
    )
    .unwrap()
}

fn asserted(method: &str, path: &str) -> Asserted {
    Asserted {
        class: ActionClass::Egress,
        target: Target::Network {
            host: "registry.example".to_owned(),
            port: 443,
            method: method.to_owned(),
            path: path.to_owned(),
        },
        declared_cost: None,
    }
}

fn poison(kernel: &mut Kernel<OffIntent>) {
    let git = GitClassifier::new(".", Vec::<String>::new(), Vec::<PathBuf>::new()).unwrap();
    let poisoned = ClassificationTable::builtin(Vec::<String>::new())
        .classify(
            ResultObservation::EgressResponse {
                host: "evil.example".to_owned(),
                path: "/issue/1".to_owned(),
            },
            &git,
            kernel.session().facts(),
        )
        .unwrap();
    kernel
        .observe_result(poisoned, 1, &mut Harness::default())
        .unwrap();
}

fn request(kernel: &mut Kernel<OffIntent>, gate: &mut Harness, method: &str, path: &str) {
    let mut effects = Harness::default();
    let mut executor = Harness::default();
    let mut audit = Harness::default();
    kernel
        .process(
            "egress",
            "vertex-1",
            Asserted {
                class: ActionClass::Egress,
                target: Target::Network {
                    host: "registry.example".to_owned(),
                    port: 443,
                    method: method.to_owned(),
                    path: path.to_owned(),
                },
                declared_cost: None,
            },
            gate,
            &mut effects,
            &mut executor,
            &mut audit,
        )
        .unwrap();
}

#[test]
fn grant_is_bound_to_the_approved_method() {
    let mut kernel = kernel();
    let mut gate = Harness::default();

    request(&mut kernel, &mut gate, "GET", "/a");
    request(&mut kernel, &mut gate, "GET", "/b");
    assert_eq!(gate.prompts, 1);
    request(&mut kernel, &mut gate, "POST", "/upload");
    assert_eq!(gate.prompts, 2, "a GET grant must not authorize a POST");
}

#[test]
fn grant_does_not_waive_a_floor_that_dropped_after_approval() {
    let mut kernel = kernel();
    let mut gate = Harness::default();
    request(&mut kernel, &mut gate, "GET", "/a");
    assert_eq!(gate.prompts, 1);

    poison(&mut kernel);

    request(&mut kernel, &mut gate, "GET", "/b");
    assert_eq!(
        gate.prompts, 2,
        "lower-ranked influence must reach the operator"
    );
    request(&mut kernel, &mut gate, "GET", "/c");
    assert_eq!(
        gate.prompts, 2,
        "the grant re-approved at the new floor applies"
    );
}

#[test]
fn approval_does_not_cover_a_floor_that_dropped_while_the_operator_decided() {
    let mut kernel = kernel();
    let mut audit = Harness::default();
    let pending = kernel
        .begin("egress", "vertex-1", asserted("GET", "/a"), &mut audit)
        .unwrap();
    assert!(pending.needs_gate());
    let shown = pending.gate_request().violations.len();
    let outcome = GateOutcome::decide(&mut Harness::default(), pending.gate_request());

    // Another request read poisoned content while the prompt was open.
    poison(&mut kernel);

    let result = kernel.finish(
        pending,
        Some(outcome),
        &mut Harness::default(),
        &mut Harness::default(),
        &mut audit,
    );
    assert_eq!(result.unwrap_err(), KernelError::GateDenied);
    assert_eq!(shown, 1, "the operator saw only the off-intent host");
    assert_eq!(
        audit.rules.last().unwrap(),
        &["kernel:changed-during-approval".to_owned()]
    );
}
