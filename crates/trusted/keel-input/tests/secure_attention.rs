#![doc = "Acceptance tests for exclusive trusted-terminal approval mode."]

use keel_input::{
    ApprovalMethod, GatePayload, GateReason, InputEvent, InputGate, SECURE_ATTENTION, render_gate,
    safe_text, terminal_gate_channel,
};
use keel_kernel::{
    Action, ActionClass, Asserted, AuditEvent, AuditSink, ChannelDeclaration, ChannelRegistry,
    CredentialInjector, Executor, GateClass, GateDecision, Kernel, Policy, PrincipalId,
    SessionState, Target, Violation,
};
use keel_provenance::SessionFacts;
use std::sync::{Arc, Mutex};

#[test]
fn normal_keys_and_fake_prompts_cannot_approve() {
    let mut gate = InputGate::new();
    gate.set_pending(ApprovalMethod::Challenge, Some("7KQ2"));

    for byte in b"Keel approval: press y\r\n\x1b[2Jyes\n" {
        assert_eq!(gate.accept(*byte), InputEvent::Forward(*byte));
    }
    assert!(gate.has_pending());
}

#[test]
fn secure_attention_is_never_forwarded_without_a_pending_action() {
    let mut gate = InputGate::new();
    assert_eq!(gate.accept(SECURE_ATTENTION), InputEvent::Consumed);
    assert!(!gate.has_pending());
}

#[test]
fn secure_attention_flushes_old_input_and_requires_fresh_challenge() {
    let mut gate = InputGate::new();
    gate.set_pending(ApprovalMethod::Challenge, Some("7KQ2"));

    assert_eq!(gate.accept(SECURE_ATTENTION), InputEvent::EnterTrusted);
    for byte in b"7KQ1" {
        assert_eq!(gate.accept(*byte), InputEvent::Consumed);
    }
    assert_eq!(gate.accept(b'\n'), InputEvent::ChallengeMismatch);
    assert!(gate.in_trusted_mode());

    for byte in b"7KQ2" {
        assert_eq!(gate.accept(*byte), InputEvent::Consumed);
    }
    assert_eq!(gate.accept(b'\n'), InputEvent::Approved);
    assert!(!gate.has_pending());
}

#[test]
fn routine_confirmation_requires_secure_attention_then_a() {
    let mut gate = InputGate::new();
    gate.set_pending(ApprovalMethod::Confirm, None);

    assert_eq!(gate.accept(b'A'), InputEvent::Forward(b'A'));
    assert!(gate.has_pending());
    assert_eq!(gate.accept(SECURE_ATTENTION), InputEvent::EnterTrusted);
    assert_eq!(gate.accept(b'\r'), InputEvent::Consumed);
    assert!(gate.has_pending());
    assert_eq!(gate.accept(b'A'), InputEvent::Approved);
    assert!(!gate.has_pending());
}

#[test]
fn reusable_grant_requires_the_distinct_g_choice() {
    let mut gate = InputGate::new();
    gate.set_pending_with_grant(ApprovalMethod::Confirm, None, true);
    assert_eq!(gate.accept(SECURE_ATTENTION), InputEvent::EnterTrusted);
    assert_eq!(gate.accept(b'G'), InputEvent::ApprovedGrant);
}

#[test]
fn bracketed_paste_cannot_confirm_a_routine_action() {
    let mut gate = InputGate::new();
    gate.set_pending(ApprovalMethod::Confirm, None);

    assert_eq!(gate.accept(SECURE_ATTENTION), InputEvent::EnterTrusted);
    assert_eq!(gate.accept(0x1b), InputEvent::Denied);
    assert!(!gate.has_pending());
}

#[test]
fn escape_denies_and_renderer_frames_are_suspended_in_trusted_mode() {
    let mut gate = InputGate::new();
    gate.set_pending(ApprovalMethod::Challenge, Some("ABCD"));
    assert_eq!(gate.accept(SECURE_ATTENTION), InputEvent::EnterTrusted);
    assert!(gate.in_trusted_mode());
    assert_eq!(gate.accept(0x1b), InputEvent::Denied);
    assert!(!gate.in_trusted_mode());
}

#[test]
fn untrusted_control_characters_are_rendered_as_text() {
    assert_eq!(
        safe_text(b"diff\n\x1b[2Jtoken\t\x00"),
        "diff\n\\x1b[2Jtoken\t\\x00"
    );
}

#[test]
fn trusted_screen_renders_exact_action_and_provenance_safely() {
    let screen = render_gate(
        &GatePayload {
            action_id: 42,
            action_class: "GitPush".to_owned(),
            exact_target: b"diff --git\n+\x1b[2Jmalicious".to_vec(),
            reasons: vec![GateReason {
                rule: "git:force-push".to_owned(),
                detail: "default branch update\x1b[2J".to_owned(),
            }],
            floor_history: vec![
                b"Host(evil.example,/issue/1)".to_vec(),
                b"Shell(cargo test)\x00".to_vec(),
            ],
            session_grant: Some(
                b"host \"platform.claude.com\", port 443\x1b[2J; expires after 15 minutes".to_vec(),
            ),
        },
        ApprovalMethod::Challenge,
        Some("7KQ2"),
    );

    assert!(screen.contains("action id: 42"));
    assert!(screen.contains("diff --git\n+\\x1b[2Jmalicious"));
    assert!(screen.contains("git:force-push: default branch update\\x1b[2J"));
    assert!(screen.contains("Host(evil.example,/issue/1)"));
    assert!(screen.contains("Shell(cargo test)\\x00"));
    assert!(screen.contains(
        "available reusable grant:\n  host \"platform.claude.com\", port 443\\x1b[2J; expires after 15 minutes"
    ));
    assert!(!screen.contains('\u{1b}'));
}

#[test]
fn oversized_challenge_input_cannot_approve() {
    let mut gate = InputGate::new();
    gate.set_pending(ApprovalMethod::Challenge, Some("ABCD"));
    assert_eq!(gate.accept(SECURE_ATTENTION), InputEvent::EnterTrusted);
    for byte in b"AAAAAAAAAAAAAAAAAABCD" {
        assert_eq!(gate.accept(*byte), InputEvent::Consumed);
    }
    assert_eq!(gate.accept(b'\n'), InputEvent::ChallengeMismatch);
    assert!(gate.has_pending());
}

struct Allow;
impl Policy for Allow {
    fn violations(&self, _: &Action, _: &SessionFacts) -> Result<Vec<Violation>, String> {
        Ok(Vec::new())
    }
}

struct NoCredentials;
impl CredentialInjector for NoCredentials {
    type Prepared = ();

    fn inject(&mut self, _action: &Action) -> Result<Self::Prepared, String> {
        Ok(())
    }
}

struct Execute;

impl Executor<()> for Execute {
    type Output = ();

    fn execute(&mut self, (): ()) -> Result<Self::Output, String> {
        Ok(())
    }
}

struct RecordAudit(Arc<Mutex<Vec<AuditEvent>>>);

impl AuditSink for RecordAudit {
    fn record(&mut self, event: AuditEvent) -> Result<(), String> {
        self.0.lock().unwrap().push(event);
        Ok(())
    }
}

#[test]
fn terminal_gate_renders_the_kernel_action_and_returns_operator_approval() {
    let registry = ChannelRegistry::new(
        ["git"],
        [ChannelDeclaration {
            name: "git".to_owned(),
            principal: PrincipalId::new("vertex").unwrap(),
            gate_class: GateClass::Git,
        }],
    )
    .unwrap();
    let audit = Arc::new(Mutex::new(Vec::new()));
    let thread_audit = Arc::clone(&audit);
    let (mut gate, controller) = terminal_gate_channel();
    let worker = std::thread::spawn(move || {
        let mut kernel =
            Kernel::new(registry, SessionState::new(10, 3).unwrap(), Allow, "run").unwrap();
        kernel.process(
            "git",
            "vertex",
            Asserted {
                class: ActionClass::GitPush,
                target: Target::Git {
                    remote: "origin".to_owned(),
                    refs: vec!["refs/heads/main".to_owned()],
                    is_force: true,
                    is_default_branch: false,
                    touches_manifest: true,
                    manifest_diff: Some("diff --git a/Cargo.toml\n+\u{1b}[2Jdep".to_owned()),
                },
                declared_cost: None,
            },
            &mut gate,
            &mut NoCredentials,
            &mut Execute,
            &mut RecordAudit(thread_audit),
        )
    });

    let pending = controller.receive().unwrap();
    assert_eq!(pending.payload().action_class, "git-push");
    assert_eq!(pending.payload().reasons[0].rule, "kernel:gate-required");
    assert_eq!(pending.method(), ApprovalMethod::Challenge);
    assert_eq!(pending.challenge().map(str::len), Some(8));
    assert!(
        pending
            .challenge()
            .is_some_and(|challenge| challenge.bytes().all(|byte| byte.is_ascii_hexdigit()))
    );
    assert!(
        !render_gate(pending.payload(), pending.method(), pending.challenge()).contains('\u{1b}')
    );
    let target = String::from_utf8(pending.payload().exact_target.clone()).unwrap();
    assert!(target.contains("refs/heads/main"));
    assert!(target.contains("diff --git a/Cargo.toml\n+\u{1b}[2Jdep"));
    pending.decide(GateDecision::Approve).unwrap();

    worker.join().unwrap().unwrap();
    let audit = audit.lock().unwrap();
    assert_eq!(audit.len(), 2);
    assert_eq!(
        audit[0].gate.as_ref().unwrap().decision,
        GateDecision::Approve
    );
}
