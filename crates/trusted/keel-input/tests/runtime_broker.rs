#![doc = "Integration tests for trusted runtime intent and broker framing."]

use keel_audit::{AuditRecord, RunKey, verify_file};
use keel_input::{RuntimeIntent, terminal_gate_channel};
use keel_kernel::{
    EGRESS_ALLOWED, EGRESS_DENIED, GIT_ALLOWED, GIT_BROKER_MAGIC, GIT_DENIED, GateDecision,
};
use keel_provenance::{FloorState, PersistedMode, SessionFacts, SourceRef};
use std::{
    ffi::OsString,
    fs,
    io::{Read as _, Write as _},
    os::unix::net::UnixStream,
    path::Path,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

fn scratch(name: &str) -> std::path::PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("keel-{name}-{nonce:x}"))
}

fn intent(root: &Path, session: &str, allow: &str) -> RuntimeIntent {
    let path = root.join("request.json");
    let policy_hash = fs::read_to_string(root.join("policy/bundle.sha256"))
        .ok()
        .map_or_else(|| "null".to_owned(), |hash| format!("\"{}\"", hash.trim()));
    fs::write(
        &path,
        format!(
            r#"{{"session_id":"{session}","allow":{allow},"policy_bundle_hash":{policy_hash},"provenance":"gate-context","harness":"none","harness_args":[]}}"#
        ),
    )
    .unwrap();
    RuntimeIntent::from_runtime_arguments(&[
        OsString::from("run"),
        OsString::from("--request"),
        path.into_os_string(),
    ])
    .unwrap()
}

fn egress(path: &Path, host: &str) -> u8 {
    let mut stream = UnixStream::connect(path).unwrap();
    stream.write_all(b"KEEL-EGRESS-V2\0").unwrap();
    stream
        .write_all(&u16::try_from(host.len()).unwrap().to_be_bytes())
        .unwrap();
    stream.write_all(host.as_bytes()).unwrap();
    stream.write_all(&443_u16.to_be_bytes()).unwrap();
    stream.write_all(&[2]).unwrap();
    stream.flush().unwrap();
    let mut response = [0; 2];
    stream.read_exact(&mut response).unwrap();
    assert_eq!(response[0], b'P');
    response[1]
}

fn write_wire_string(stream: &mut UnixStream, value: &str) {
    stream
        .write_all(&u16::try_from(value.len()).unwrap().to_be_bytes())
        .unwrap();
    stream.write_all(value.as_bytes()).unwrap();
}

#[test]
fn trusted_admission_rechecks_v8_isolation_and_downgrade_grant() {
    let root = scratch("v8-admission");
    fs::create_dir(&root).unwrap();
    let path = root.join("request.json");
    let parse = |body: &str| {
        fs::write(&path, body).unwrap();
        RuntimeIntent::from_runtime_arguments(&[
            OsString::from("run"),
            OsString::from("--request"),
            path.clone().into_os_string(),
        ])
    };
    assert!(
        parse(
            r#"{"session_id":"v8","allow":[],"provenance":"floor","isolation":"vm-v8","harness":"v8","harness_args":["agent.ts"]}"#
        )
        .is_ok()
    );
    assert!(
        parse(
            r#"{"session_id":"v8","allow":[],"provenance":"floor","isolation":"v8-sandboxed","harness":"v8","harness_args":["agent.ts"]}"#
        )
        .is_err()
    );
    assert!(
        parse(
            r#"{"session_id":"v8","allow":["isolation:v8-sandboxed"],"provenance":"floor","isolation":"v8-sandboxed","harness":"v8","harness_args":["agent.ts"]}"#
        )
        .is_ok()
    );
    assert!(
        parse(
            r#"{"session_id":"v8","allow":["isolation:v8-sandboxed"],"provenance":"floor","isolation":"v8-sandboxed","harness":"claude","harness_args":[]}"#
        )
        .is_err()
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn private_issue_reads_are_a_distinct_visible_task_capability() {
    let root = scratch("private-issue-admission");
    fs::create_dir(&root).unwrap();
    let parsed = intent(
        &root,
        "private-issue-admission",
        r#"["github:read-private-issues"]"#,
    );
    let admission = parsed.task_admission().expect("task admission");
    assert!(admission.contains("github:read-private-issues"));
    assert!(admission.contains("egress:api.github.com"));
    assert!(!admission.contains("pr:create"));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn ref_and_pr_target_scopes_are_admitted_task_authority() {
    let root = scratch("scoped-authority");
    fs::create_dir(&root).unwrap();
    let admission = intent(
        &root,
        "scoped-authority",
        r#"["push:ref:refs/heads/feature/*","pr:create","pr:target:main"]"#,
    )
    .task_admission()
    .expect("scoped authority needs admission");
    assert!(admission.contains("push:ref:refs/heads/feature/*"));
    assert!(admission.contains("pr:target:main"));

    let path = root.join("request.json");
    for allow in [
        r#"["pr:target:main"]"#,
        r#"["push:ref:refs/heads/../main"]"#,
        r#"["push:ref:main"]"#,
        r#"["push:ref:refs/heads/a b"]"#,
    ] {
        fs::write(
            &path,
            format!(
                r#"{{"session_id":"bad","allow":{allow},"provenance":"floor","harness":"none","harness_args":[]}}"#
            ),
        )
        .unwrap();
        assert!(
            RuntimeIntent::from_runtime_arguments(&[
                OsString::from("run"),
                OsString::from("--request"),
                path.clone().into_os_string(),
            ])
            .is_err(),
            "{allow}"
        );
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn untrusted_model_budget_can_narrow_but_elevation_requires_admission() {
    let root = scratch("model-budget-admission");
    fs::create_dir(&root).unwrap();
    let path = root.join("request.json");
    let parse = |body: &str| {
        fs::write(&path, body).unwrap();
        RuntimeIntent::from_runtime_arguments(&[
            OsString::from("run"),
            OsString::from("--request"),
            path.clone().into_os_string(),
        ])
        .unwrap()
    };

    let narrowed = parse(
        r#"{"session_id":"narrow","allow":[],"provenance":"floor","harness":"none","harness_args":[],"model_token_budget":500000,"model_cost_budget_microusd":5000000}"#,
    );
    assert!(narrowed.task_admission().is_none());

    let elevated = parse(
        r#"{"session_id":"elevated","allow":[],"provenance":"floor","harness":"none","harness_args":[],"model_token_budget":2000000,"model_cost_budget_microusd":25000000}"#,
    );
    let admission = elevated
        .task_admission()
        .expect("an elevated untrusted budget requires trusted admission");
    assert!(admission.contains("token ceiling=2000000"));
    assert!(admission.contains("cost ceiling=25000000 micro-USD (USD 25.000000)"));
    assert_eq!(
        elevated.start_kernel_broker().err().unwrap(),
        "elevated model budget requires trusted task admission"
    );

    for field in ["model_token_budget", "model_cost_budget_microusd"] {
        let body = format!(
            r#"{{"session_id":"zero","allow":[],"provenance":"floor","harness":"none","harness_args":[],"{field}":0}}"#
        );
        fs::write(&path, body).unwrap();
        assert!(
            RuntimeIntent::from_runtime_arguments(&[
                OsString::from("run"),
                OsString::from("--request"),
                path.clone().into_os_string(),
            ])
            .is_err()
        );
    }

    fs::remove_dir_all(root).unwrap();
}

fn push(path: &Path, force: bool) -> u8 {
    let mut stream = UnixStream::connect(path).unwrap();
    stream.write_all(GIT_BROKER_MAGIC).unwrap();
    write_wire_string(&mut stream, "origin");
    stream.write_all(&1_u16.to_be_bytes()).unwrap();
    write_wire_string(&mut stream, "refs/heads/topic");
    stream.write_all(&[u8::from(force), 0, 0, 0]).unwrap();
    stream.write_all(&[0_u8; 32]).unwrap();
    stream.flush().unwrap();
    let mut response = [0];
    stream.read_exact(&mut response).unwrap();
    response[0]
}

fn push_branch(path: &Path) -> u8 {
    push(path, false)
}

#[test]
fn structured_intent_ignores_unsigned_floor_and_controls_egress() {
    let root = scratch("runtime-intent");
    fs::create_dir(&root).unwrap();
    let mut facts = SessionFacts::default();
    facts.record_floor_observation(
        0,
        SourceRef::Host {
            host: "evil.example".to_owned(),
            path: "/issue/1".to_owned(),
        },
        1,
    );
    FloorState::capture("session-1", PersistedMode::Floor, &facts)
        .save(&root.join("floor.json"))
        .unwrap();
    let broker = intent(
        &root,
        "session-1",
        r#"["egress:Docs.Example","push:branch","pr:create"]"#,
    )
    .start_kernel_broker()
    .unwrap();
    assert!(broker.ca_certificate_pem().is_some());
    // CONNECT establishes only the local inspected-TLS endpoint. It must not
    // resolve or connect upstream before the proxy sees and authorizes the
    // decrypted request; that ordering is covered in keel-secrets by
    // `denied_tls_request_does_not_resolve_or_connect`.
    assert_eq!(egress(broker.socket_path(), "evil.example"), EGRESS_ALLOWED);
    let audit_path = broker.audit_path().to_owned();
    let key_path = broker.audit_key_path().to_owned();
    let report = broker.shutdown().unwrap();
    assert_eq!(report.session_facts.floor, 0);
    assert!(report.session_facts.intent.allow_push_branch);
    assert!(report.session_facts.intent.allow_pr_create);
    let expected_hosts = ["api.github.com", "docs.example"]
        .map(str::to_owned)
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();
    let expected_egress = expected_hosts.iter().cloned().collect::<Vec<_>>().join(",");
    assert_eq!(
        report.session_facts.intent.allowed_egress_hosts,
        expected_hosts
    );
    let key = RunKey::from_hex(&fs::read_to_string(&key_path).unwrap()).unwrap();
    // The local transport setup, bracketed by the enforcement state the run
    // opened and closed with.
    assert_eq!(verify_file(&audit_path, &key).unwrap(), 4);
    let records = fs::read_to_string(&audit_path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<AuditRecord>(line).unwrap())
        .collect::<Vec<_>>();
    let enforcement = records
        .iter()
        .filter(|record| record.payload.event == "kernel.enforcement-state")
        .collect::<Vec<_>>();
    assert_eq!(
        enforcement
            .iter()
            .map(|record| record.payload.fields["phase"].as_str())
            .collect::<Vec<_>>(),
        ["start", "shutdown"]
    );
    // The real runtime's boundaries, read back from the chain rather than from
    // the launcher: the mediating connector terminates TLS and denies the
    // metadata address, and `gate-context` is reported as advisory rather than
    // as a floor that is up.
    for record in enforcement {
        assert_eq!(
            record.payload.fields["boundary.network-floor"],
            "active: link-local, loopback, and private ranges before policy"
        );
        assert!(record.payload.fields["boundary.tls-termination"].starts_with("active:"));
        assert!(record.payload.fields["boundary.audit-chain"].starts_with("active:"));
        assert!(record.payload.fields["boundary.provenance"].starts_with("advisory:"));
        assert!(record.payload.fields["boundary.egress-allowlist"].contains(&expected_egress));
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn harness_compaction_cannot_reset_kernel_owned_floor() {
    let root = scratch("harness-compaction");
    fs::create_dir(&root).unwrap();
    let source = SourceRef::Host {
        host: "api.github.com".to_owned(),
        path: "/repos/example/project/issues/7".to_owned(),
    };
    let mut facts = SessionFacts::default();
    facts.record_floor_observation(0, source.clone(), 42);
    FloorState::capture("compacted-session", PersistedMode::Floor, &facts)
        .save(&root.join("floor.json"))
        .unwrap();

    let broker = intent(&root, "compacted-session", "[]")
        .start_kernel_broker()
        .unwrap();
    fs::write(
        root.join("harness-session.json"),
        r#"{"compacted":true,"summary":"forget prior issue","claimed_floor":3}"#,
    )
    .unwrap();
    let report = broker.shutdown().unwrap();

    assert_eq!(report.session_facts.floor, 0);
    assert_eq!(report.session_facts.floor_history.len(), 1);
    assert_eq!(
        report.session_facts.floor_history[0].source,
        SourceRef::File {
            path: "workspace://direct-exposure".to_owned(),
            author: None,
        }
    );
    assert_ne!(report.session_facts.floor_history[0].source, source);
    let persisted = FloorState::load(&root.join("floor.json"), "compacted-session")
        .unwrap()
        .unwrap();
    assert_eq!(persisted.floor(), 0);
    assert_eq!(persisted.resume_facts().floor_history.len(), 1);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn malformed_broker_request_fails_before_kernel_processing() {
    let root = scratch("malformed-broker");
    fs::create_dir(&root).unwrap();
    let broker = intent(&root, "session-2", "[]")
        .start_kernel_broker()
        .unwrap();
    let mut stream = UnixStream::connect(broker.socket_path()).unwrap();
    stream.write_all(b"not-a-request").unwrap();
    stream.flush().unwrap();
    let mut response = [0];
    stream.read_exact(&mut response).unwrap();
    assert_eq!(response[0], EGRESS_DENIED);
    let report = broker.shutdown().unwrap();
    assert_eq!(report.audit_events, 0);
    assert!(!report.session_facts.intent.allow_push_branch);
    fs::remove_dir_all(root).unwrap();
}

/// Mediated Git needs the trusted relay's own connection to the remote, so the
/// configured credential host must be in the run's egress intent without the
/// operator naming it twice. A credential scope only exists in the process
/// environment, and a trusted crate cannot mutate its own environment, so the
/// body runs in a re-executed child.
#[test]
fn git_credential_host_joins_the_run_egress_intent() {
    let status = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "--ignored",
            "--nocapture",
            "git_credential_host_is_allowed_without_an_egress_capability",
        ])
        .env("KEEL_GIT_AUTHORIZATION", "Basic test-credential")
        .env("KEEL_GIT_CREDENTIAL_HOST", "git.example")
        .env("KEEL_GIT_CREDENTIAL_PATH", "/owner/repo.git")
        .status()
        .unwrap();
    assert!(status.success(), "re-executed credential-scope test failed");
}

#[test]
fn github_private_read_and_pr_authority_are_not_implicit() {
    let status = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "--ignored",
            "--nocapture",
            "github_private_read_and_pr_authority_are_split_in_runtime",
        ])
        .env("KEEL_GIT_AUTHORIZATION", "Basic test-credential")
        .env("KEEL_GIT_CREDENTIAL_HOST", "github.com")
        .env("KEEL_GIT_CREDENTIAL_PATH", "/owner/repo.git")
        .env("GH_TOKEN", "github-test-token")
        .env_remove("GITHUB_TOKEN")
        .status()
        .unwrap();
    assert!(status.success(), "re-executed GitHub authority test failed");
}

#[test]
#[ignore = "re-executed by github_private_read_and_pr_authority_are_not_implicit"]
fn github_private_read_and_pr_authority_are_split_in_runtime() {
    let root = scratch("github-authority-split");
    fs::create_dir(&root).unwrap();

    let private_read = intent(&root, "private-read", r#"["github:read-private-issues"]"#)
        .start_kernel_broker()
        .unwrap();
    assert_eq!(private_read.github_private_repository(), Some("owner/repo"));
    assert!(private_read.git_sentinel().is_none());
    let private_read_audit = private_read.audit_path().to_owned();
    let private_read_report = private_read.shutdown().unwrap();
    assert!(!private_read_report.session_facts.intent.allow_pr_create);
    assert!(
        private_read_report
            .session_facts
            .intent
            .allowed_egress_hosts
            .contains("api.github.com")
    );
    assert!(
        !private_read_report
            .session_facts
            .intent
            .allowed_egress_hosts
            .contains("github.com"),
        "repository identity must not activate Git transport authority"
    );
    assert!(
        fs::read_to_string(private_read_audit)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<AuditRecord>(line).unwrap())
            .filter(|record| record.payload.event == "kernel.enforcement-state")
            .any(|record| record.payload.fields["boundary.capability-intent"]
                .contains("github:read-private-issues"))
    );

    let pr = intent(&root, "pr-only", r#"["pr:create"]"#)
        .start_kernel_broker()
        .unwrap();
    assert!(pr.github_private_repository().is_none());
    assert!(pr.git_sentinel().is_none());
    let pr_report = pr.shutdown().unwrap();
    assert!(pr_report.session_facts.intent.allow_pr_create);
    assert!(
        !pr_report
            .session_facts
            .intent
            .allowed_egress_hosts
            .contains("github.com")
    );

    let push = intent(&root, "push-only", r#"["push:branch"]"#)
        .start_kernel_broker()
        .unwrap();
    assert!(push.git_sentinel().is_some());
    assert!(push.github_private_repository().is_none());
    assert!(
        push.shutdown()
            .unwrap()
            .session_facts
            .intent
            .allowed_egress_hosts
            .contains("github.com")
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
#[ignore = "re-executed by git_credential_host_joins_the_run_egress_intent"]
fn git_credential_host_is_allowed_without_an_egress_capability() {
    let root = scratch("git-credential-host");
    fs::create_dir(&root).unwrap();
    let broker = intent(&root, "git-host", r#"["push:branch"]"#)
        .start_kernel_broker()
        .unwrap();
    // Both CONNECT requests establish only local inspected-TLS endpoints. DNS,
    // TCP, and the host-intent decision are deliberately deferred until the
    // exact decrypted request is available to policy. The trusted proxy's
    // denial-before-resolve ordering has a regression test in keel-secrets.
    assert_eq!(egress(broker.socket_path(), "git.example"), EGRESS_ALLOWED);
    assert_eq!(
        egress(broker.socket_path(), "other.example"),
        EGRESS_ALLOWED
    );
    let report = broker.shutdown().unwrap();
    assert!(
        report
            .session_facts
            .intent
            .allowed_egress_hosts
            .contains("git.example")
    );

    let no_authority = intent(&root, "git-host-no-authority", "[]")
        .start_kernel_broker()
        .unwrap();
    assert!(no_authority.git_sentinel().is_none());
    let no_authority_report = no_authority.shutdown().unwrap();
    assert!(
        !no_authority_report
            .session_facts
            .intent
            .allowed_egress_hosts
            .contains("git.example")
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn runtime_cedar_policy_requires_structured_branch_intent() {
    let denied_root = scratch("cedar-push-denied");
    fs::create_dir(&denied_root).unwrap();
    let denied = intent(&denied_root, "push-denied", "[]")
        .start_kernel_broker()
        .unwrap();
    assert_eq!(push_branch(denied.socket_path()), GIT_DENIED);
    assert_eq!(denied.shutdown().unwrap().denied_actions, 1);

    let allowed_root = scratch("cedar-push-allowed");
    fs::create_dir(&allowed_root).unwrap();
    let (gate, controller) = terminal_gate_channel();
    let allowed = intent(&allowed_root, "push-allowed", r#"["push:branch"]"#)
        .start_kernel_broker_with_gate(gate)
        .unwrap();
    let socket = allowed.socket_path().to_owned();
    let worker = std::thread::spawn(move || push_branch(&socket));
    let pending = controller.receive().unwrap();
    assert!(
        pending
            .payload()
            .reasons
            .iter()
            .any(|reason| reason.rule == "admission:git-push")
    );
    pending.decide(GateDecision::Approve).unwrap();
    assert_eq!(worker.join().unwrap(), GIT_ALLOWED);
    assert_eq!(allowed.shutdown().unwrap().denied_actions, 0);

    fs::remove_dir_all(denied_root).unwrap();
    fs::remove_dir_all(allowed_root).unwrap();
}

#[test]
fn runtime_cedar_force_push_constraint_cannot_be_approved() {
    let root = scratch("cedar-force-deny");
    fs::create_dir(&root).unwrap();
    let (gate, controller) = terminal_gate_channel();
    let broker = intent(
        &root,
        "force-denied",
        r#"["push:branch","deny:force-push"]"#,
    )
    .start_kernel_broker_with_gate(gate)
    .unwrap();
    let socket = broker.socket_path().to_owned();
    let worker = std::thread::spawn(move || push_branch(&socket));
    controller
        .receive()
        .unwrap()
        .decide(GateDecision::Approve)
        .unwrap();
    assert_eq!(worker.join().unwrap(), GIT_ALLOWED);
    assert_eq!(push(broker.socket_path(), true), GIT_DENIED);
    let report = broker.shutdown().unwrap();
    assert!(report.session_facts.intent.deny_force_push);
    assert_eq!(report.denied_actions, 1);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn accepted_policy_bundle_replaces_the_default_session_policy() {
    let root = scratch("policy-bundle");
    let policy = root.join("policy");
    fs::create_dir_all(&policy).unwrap();
    let schema = include_str!("../../keel-policy/policy/default/schema.cedarschema");
    let policies = format!(
        "{}\n@id(\"deny:policy:no-push\")\nforbid \
         (principal, action == Action::\"push\", resource) when {{\n    true\n}};\n",
        include_str!("../../keel-policy/policy/default/policies.cedar")
    );
    fs::write(policy.join("schema.cedarschema"), schema).unwrap();
    fs::write(policy.join("policies.cedar"), policies).unwrap();
    fs::write(
        policy.join("bundle.sha256"),
        "b91babc4465a0a1c70f85848a563c03adbd42d4606fea7d2a096dd2feb80d867",
    )
    .unwrap();
    let broker = intent(&root, "policy", r#"["push:branch"]"#)
        .start_kernel_broker()
        .unwrap();
    assert_eq!(push_branch(broker.socket_path()), GIT_DENIED);
    assert_eq!(broker.shutdown().unwrap().denied_actions, 1);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn policy_bundle_is_pinned_independently_of_its_directory() {
    let root = scratch("policy-tamper");
    let policy = root.join("policy");
    fs::create_dir_all(&policy).unwrap();
    fs::write(
        policy.join("schema.cedarschema"),
        include_str!("../../keel-policy/policy/default/schema.cedarschema"),
    )
    .unwrap();
    fs::write(
        policy.join("policies.cedar"),
        include_str!("../../keel-policy/policy/default/policies.cedar"),
    )
    .unwrap();
    fs::write(
        policy.join("bundle.sha256"),
        include_str!("../../keel-policy/policy/default/bundle.sha256"),
    )
    .unwrap();
    let intent = intent(&root, "policy-tamper", "[]");
    fs::write(
        policy.join("policies.cedar"),
        "permit (principal, action, resource);",
    )
    .unwrap();
    assert!(intent.start_kernel_broker().is_err());
    fs::remove_dir_all(root).unwrap();
}
