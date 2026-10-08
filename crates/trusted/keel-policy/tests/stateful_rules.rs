#![doc = "Acceptance scenarios for the Phase 0 stateful Cedar rules."]

use keel_policy::{
    Action, ArgumentBinding, ArgumentClassifier, ArgumentRole, ArgumentSelector, CommandProfile,
    Decision, FloorObservation, PathAccess, SessionFacts, SourceRef, StatefulPolicy,
    default_artifact_hash, resolve_contained_path,
};
use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

fn baseline() -> SessionFacts {
    let mut facts = SessionFacts::default();
    facts.own_domains = ["keel.example".to_owned()].into();
    facts.intent.allow_push_branch = true;
    facts
}

#[test]
fn rule_one_escalates_bulk_writes_to_preexisting_files() {
    let policy = StatefulPolicy::new().expect("the shipped bundle must parse and validate");
    let mut facts = baseline();
    facts.distinct_files_written_60s = 20;
    facts.target_created_by_vertex = false;

    assert_eq!(
        policy.decide(Action::Write, &facts).unwrap(),
        Decision::Escalate
    );

    facts.distinct_files_written_60s = 19;
    assert_eq!(
        policy.decide(Action::Write, &facts).unwrap(),
        Decision::Allow
    );
}

#[test]
fn rule_two_escalates_writes_after_registry_contact() {
    let policy = StatefulPolicy::new().expect("the shipped bundle must parse and validate");
    let mut facts = baseline();
    facts.registries_contacted = true;

    assert_eq!(
        policy.decide(Action::Write, &facts).unwrap(),
        Decision::Escalate
    );
    assert_eq!(
        policy.decide(Action::Read, &facts).unwrap(),
        Decision::Allow
    );

    facts.registries_contacted = false;
    assert_eq!(
        policy.decide(Action::Write, &facts).unwrap(),
        Decision::Allow
    );
}

#[test]
fn rule_three_escalates_only_after_three_denials_in_the_current_scope() {
    let policy = StatefulPolicy::new().expect("the shipped bundle must parse and validate");
    let mut facts = baseline();
    facts.denied_actions = 99;

    assert_eq!(
        policy.decide(Action::Read, &facts).unwrap(),
        Decision::Allow
    );

    facts.recent_behavioral_denials_in_scope = 3;
    assert_eq!(
        policy.decide(Action::Read, &facts).unwrap(),
        Decision::Escalate
    );

    facts.recent_behavioral_denials_in_scope = 2;
    assert_eq!(
        policy.decide(Action::Read, &facts).unwrap(),
        Decision::Allow
    );
}

#[test]
fn rule_five_requires_structured_intent_for_branch_pushes() {
    let policy = StatefulPolicy::new().expect("the shipped bundle must parse and validate");
    let mut facts = baseline();
    facts.intent.allow_push_branch = false;

    assert_eq!(
        policy.decide(Action::Push, &facts).unwrap(),
        Decision::Escalate
    );
    facts.intent.allow_push_branch = true;
    assert_eq!(
        policy.decide(Action::Push, &facts).unwrap(),
        Decision::Allow
    );
}

#[test]
fn rule_four_escalates_push_after_reading_an_unowned_host() {
    let policy = StatefulPolicy::new().expect("the shipped bundle must parse and validate");
    let mut facts = baseline();
    facts.sources_read = [
        SourceRef::File {
            path: "src/lib.rs".to_owned(),
            author: Some("Ada".to_owned()),
        },
        SourceRef::Host {
            host: "evil.example".to_owned(),
            path: "/issue/1".to_owned(),
        },
    ]
    .into();

    assert_eq!(
        policy.decide(Action::Push, &facts).unwrap(),
        Decision::Escalate
    );
    assert_eq!(
        policy.decide(Action::Write, &facts).unwrap(),
        Decision::Allow
    );

    facts.sources_read = [SourceRef::Host {
        host: "keel.example".to_owned(),
        path: "/docs".to_owned(),
    }]
    .into();
    assert_eq!(
        policy.decide(Action::Push, &facts).unwrap(),
        Decision::Allow
    );
}

#[test]
fn scenario_matrix_detects_accidental_over_and_under_permissiveness() {
    let policy = StatefulPolicy::new().expect("the shipped bundle must parse and validate");
    policy
        .analyze_scenarios()
        .expect("the complete boundary matrix must match");
}

#[test]
fn every_phase_two_fact_has_a_valid_cedar_representation() {
    let policy = StatefulPolicy::new().expect("the shipped bundle must parse and validate");
    let mut facts = baseline();
    facts
        .files_created_by_this_vertex
        .insert("new.txt".to_owned());
    facts
        .files_written_by_this_vertex
        .insert("new.txt".to_owned());
    facts.hosts_contacted.insert("crates.io".to_owned());
    facts.registries_contacted = true;
    facts.writes_last_60s = 1;
    facts.denied_actions = 4;
    facts.recent_behavioral_denials_in_scope = 2;
    facts.escalated_actions = 2;
    facts.floor = 0;
    facts.intent.allow_push_branch = true;
    facts.intent.allow_pr_create = true;
    facts
        .intent
        .allowed_egress_hosts
        .insert("docs.rs".to_owned());
    let source = SourceRef::Shell {
        command: "git status".to_owned(),
    };
    facts.sources_read.insert(source.clone());
    facts.floor_history.push(FloorObservation {
        rank: 0,
        source,
        timestamp_ms: 42,
    });

    policy
        .evaluate(Action::Read, &facts)
        .expect("all raw facts must enter Cedar context");
}

#[test]
fn evaluation_returns_every_violated_rule() {
    let policy = StatefulPolicy::new().expect("the shipped bundle must parse and validate");
    let mut facts = baseline();
    facts.recent_behavioral_denials_in_scope = 3;
    facts.distinct_files_written_60s = 20;
    facts.sources_read = [SourceRef::Host {
        host: "evil.example".to_owned(),
        path: "/payload".to_owned(),
    }]
    .into();
    facts.target_created_by_vertex = false;

    let evaluation = policy
        .evaluate(Action::Push, &facts)
        .expect("complete Cedar decision");
    let rules = evaluation
        .violations
        .iter()
        .map(|violation| violation.rule.as_str())
        .collect::<Vec<_>>();

    assert!(rules.contains(&"repeated-denials-same-scope"));
    assert!(rules.contains(&"push-after-unowned-host"));
}

#[test]
fn loader_requires_the_pinned_content_hash() {
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("policy/default");
    let policy =
        StatefulPolicy::load(&source, default_artifact_hash()).expect("shipped artifact is pinned");
    assert_eq!(policy.artifact_hash(), default_artifact_hash());

    let copy = scratch_directory("tampered-policy");
    fs::create_dir_all(&copy).expect("create scratch artifact");
    for name in ["schema.cedarschema", "policies.cedar", "bundle.sha256"] {
        fs::copy(source.join(name), copy.join(name)).expect("copy artifact file");
    }
    fs::write(
        copy.join("policies.cedar"),
        "permit (principal, action, resource);\n",
    )
    .expect("tamper artifact");

    let Err(error) = StatefulPolicy::load(&copy, default_artifact_hash()) else {
        panic!("changed policy content must fail");
    };
    assert!(error.to_string().contains("content hash"));
    fs::remove_dir_all(copy).expect("remove scratch artifact");
}

#[test]
fn command_arguments_receive_reviewed_path_roles() {
    let classifier = ArgumentClassifier::new([CommandProfile {
        program: "cp".to_owned(),
        bindings: vec![
            ArgumentBinding {
                selector: ArgumentSelector::Index(0),
                role: ArgumentRole::ReadPath,
            },
            ArgumentBinding {
                selector: ArgumentSelector::Index(1),
                role: ArgumentRole::WritePath,
            },
        ],
    }])
    .expect("valid profile");
    let arguments = vec!["source.txt".to_owned(), "dest.txt".to_owned()];

    let arguments_with_roles = classifier
        .classify("cp", &arguments)
        .expect("declared command");

    assert_eq!(arguments_with_roles[0].role, ArgumentRole::ReadPath);
    assert_eq!(arguments_with_roles[1].role, ArgumentRole::WritePath);
    assert!(classifier.classify("unknown", &[]).is_err());
}

#[cfg(unix)]
#[test]
fn real_path_resolution_rejects_symlink_escape() {
    use std::os::unix::fs::symlink;

    let root = scratch_directory("path-containment");
    let workspace = root.join("workspace");
    let outside = root.join("outside");
    fs::create_dir_all(&workspace).expect("create workspace");
    fs::create_dir_all(&outside).expect("create outside");
    fs::write(outside.join("secret"), "nope").expect("create outside file");
    symlink(&outside, workspace.join("escape")).expect("create escape symlink");
    symlink(outside.join("missing"), workspace.join("dangling-escape"))
        .expect("create dangling escape symlink");

    let read_error = resolve_contained_path(
        &workspace,
        PathBuf::from("escape/secret").as_path(),
        PathAccess::Read,
    )
    .expect_err("read symlink must not escape");
    let write_error = resolve_contained_path(
        &workspace,
        PathBuf::from("escape/new").as_path(),
        PathAccess::Write,
    )
    .expect_err("write parent symlink must not escape");
    resolve_contained_path(
        &workspace,
        PathBuf::from("dangling-escape").as_path(),
        PathAccess::Write,
    )
    .expect_err("dangling target symlink must not be treated as a new file");

    assert!(read_error.to_string().contains("escapes workspace"));
    assert!(write_error.to_string().contains("escapes workspace"));
    fs::remove_dir_all(root).expect("remove scratch tree");
}

fn scratch_directory(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("keel-{label}-{}-{nonce}", std::process::id()))
}
