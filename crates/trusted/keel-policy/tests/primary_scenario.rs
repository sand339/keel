#![doc = "End-to-end poisoned-source acceptance scenario."]

use keel_audit::{AuditRecord, AuditWriter, KernelAudit, Redactor, RunKey, read_verified_file};
use keel_kernel::{
    Action, ActionClass, Asserted, AuditSink, ChannelDeclaration, ChannelRegistry,
    CredentialInjector, Executor, Gate, GateClass, GateDecision, GatePayload, GateRequest, Kernel,
    KernelError, PrincipalId, ProvenanceMode, SessionState, Target,
};
use keel_policy::StatefulPolicy;
use keel_provenance::{ClassificationTable, GitClassifier, ResultObservation, SessionFacts};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Default)]
struct DenyingGate {
    payload: Option<GatePayload>,
}

impl Gate for DenyingGate {
    fn decide(&mut self, request: GateRequest<'_>) -> GateDecision {
        self.payload = Some(request.to_payload());
        GateDecision::Deny
    }
}

struct NeverExecute;

impl CredentialInjector for NeverExecute {
    type Prepared = ();

    fn inject(&mut self, _: &Action) -> Result<Self::Prepared, String> {
        panic!("denied action reached credential injection")
    }
}

impl Executor<()> for NeverExecute {
    type Output = ();

    fn execute(&mut self, (): ()) -> Result<Self::Output, String> {
        panic!("denied action reached execution")
    }
}

#[test]
fn poisoned_issue_then_force_push_is_denied_with_complete_provenance() {
    run_primary_scenario(ProvenanceMode::Floor);
}

#[test]
fn gate_context_preserves_primary_history_without_rank_check() {
    let floor_history = run_primary_scenario(ProvenanceMode::Floor);
    let context_history = run_primary_scenario(ProvenanceMode::GateContext);
    assert_eq!(context_history, floor_history);
}

fn run_primary_scenario(mode: ProvenanceMode) -> Vec<Vec<u8>> {
    let rank_check = mode == ProvenanceMode::Floor;
    let mut facts = SessionFacts::default();
    facts.own_domains.insert("keel.example".to_owned());
    facts.intent.allow_push_branch = true;
    let session = SessionState::resume(10, 3, facts).expect("session");
    let principal = PrincipalId::new("vertex-1").expect("principal");
    let registry = ChannelRegistry::new(
        ["git"],
        [ChannelDeclaration {
            name: "git".to_owned(),
            principal,
            gate_class: GateClass::Git,
        }],
    )
    .expect("registry");
    let mut kernel = Kernel::with_provenance_mode(
        registry,
        session,
        StatefulPolicy::new().expect("policy"),
        "primary-scenario",
        mode,
    )
    .expect("kernel");

    let (path, key) = audit_artifact();
    let writer = AuditWriter::spawn(
        &path,
        "primary-scenario",
        RunKey::new(key),
        Redactor::new(Vec::<String>::new()).expect("redactor"),
    )
    .expect("audit writer");
    let mut audit = KernelAudit::new(writer);
    observe_issue(&mut kernel, &mut audit);

    let mut gate = DenyingGate::default();
    let mut injector = NeverExecute;
    let mut executor = NeverExecute;
    let result = kernel.process(
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
    );
    assert_eq!(result, Err(KernelError::GateDenied));
    assert_eq!(kernel.session().floor(), 0);
    assert_eq!(kernel.session().denied_actions(), 1);

    let payload = gate.payload.expect("gate payload");
    let rules = payload
        .reasons
        .iter()
        .map(|reason| reason.rule.as_str())
        .collect::<Vec<_>>();
    assert!(rules.contains(&"push-after-unowned-host"));
    assert_eq!(rules.contains(&"kernel:minimum-rank"), rank_check);
    assert!(rules.contains(&"kernel:gate-required"));
    let history = payload
        .floor_history
        .iter()
        .map(|entry| String::from_utf8_lossy(entry))
        .collect::<Vec<_>>();
    assert!(history[0].contains("Mcp") && history[0].contains("get_issue acme/app#42"));
    assert!(history[1].contains("api.github.com") && history[1].contains("issues/42"));

    audit.shutdown().expect("audit shutdown");
    let records = read_verified_file(&path, &RunKey::new(key)).expect("verified audit");
    assert_eq!(
        records
            .iter()
            .map(|record| record.payload.event.as_str())
            .collect::<Vec<_>>(),
        ["kernel.provenance", "kernel.provenance", "kernel.action"]
    );
    assert_eq!(records[0].payload.fields["floor_before"], "3");
    assert_eq!(records[0].payload.fields["floor_after"], "0");
    assert!(records[0].payload.fields["source"].contains("issues/42"));
    assert!(records[1].payload.fields["source"].contains("get_issue acme/app#42"));
    assert_eq!(records[2].payload.fields["outcome"], "denied");
    assert!(records[2].payload.fields["rules"].contains("push-after-unowned-host"));
    assert_audit_mode(&records[2], mode, rank_check);
    assert_eq!(records[2].payload.fields["gate_decision"], "deny");
    fs::remove_file(path).expect("remove audit");
    payload.floor_history
}

fn assert_audit_mode(record: &AuditRecord, mode: ProvenanceMode, rank_check: bool) {
    assert_eq!(
        record.payload.fields["rules"].contains("kernel:minimum-rank"),
        rank_check
    );
    assert_eq!(record.payload.fields["provenance_mode"], mode_name(mode));
}

const fn mode_name(mode: ProvenanceMode) -> &'static str {
    match mode {
        ProvenanceMode::Floor => "floor",
        ProvenanceMode::GateContext => "gate-context",
    }
}

fn observe_issue(kernel: &mut Kernel<StatefulPolicy>, audit: &mut KernelAudit) {
    let table = ClassificationTable::builtin(Vec::<String>::new());
    let git = GitClassifier::new(".", Vec::<String>::new(), Vec::<PathBuf>::new()).expect("git");
    for (timestamp, observation) in [
        (
            41,
            ResultObservation::EgressResponse {
                host: "api.github.com".to_owned(),
                path: "/repos/acme/app/issues/42".to_owned(),
            },
        ),
        (
            42,
            ResultObservation::McpResult {
                server: "github".to_owned(),
                tool: "get_issue acme/app#42".to_owned(),
            },
        ),
    ] {
        let classified = table
            .classify(observation, &git, kernel.session().facts())
            .expect("classification");
        kernel
            .observe_result(classified, timestamp, audit)
            .expect("audited observation");
    }
}

fn audit_artifact() -> (PathBuf, [u8; 32]) {
    // The audit writer creates its file exclusively, so two tests in this binary
    // that read the clock in the same tick collide and one fails to spawn a
    // writer. A counter makes the name unique regardless of clock granularity;
    // the timestamp stays only to keep the artifacts sortable.
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
    (
        std::env::temp_dir().join(format!(
            "keel-primary-scenario-{}-{nonce}-{sequence}.ndjson",
            std::process::id()
        )),
        [19; 32],
    )
}
