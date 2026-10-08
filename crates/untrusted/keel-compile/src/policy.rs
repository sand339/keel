//! Full natural-language policy artifact compiler.

use crate::{ArtifactStatus, CompileError};
use cedar_policy::{
    Authorizer, Context, Decision, Effect, Entities, EntityUid, PolicySet, Request, Schema,
    ValidationMode, Validator,
};
use regorus::Engine;
use ring::digest::{SHA256, digest};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::BTreeSet,
    fmt::Write as _,
    fs,
    io::Write as _,
    path::Path,
    process::{Command, Stdio},
    str::FromStr,
    thread,
    time::{Duration, Instant},
};

const FORMAT: &str = "keel-policy-v2";
const HASH_DOMAIN: &[u8] = b"keel-policy-v2\0";
const BUNDLE_HASH_DOMAIN: &[u8] = b"keel-policy-v1\0";
const TRANSLATOR_SYSTEM: &str = "Translate the policy into Keel's closed policy IR. Never invent \
a repository, host, rule, or tool. Grants are push:branch, pr:create, \
github:read-private-issues, egress:EXACT_DNS_HOST, isolation:v8-sandboxed, and deny:force-push. \
push:ref:refs/heads/PATTERN limits pushes to branches matching PATTERN (a trailing * matches any \
suffix) and is the only way to admit a default-branch push. pr:target:BRANCH limits pull \
requests to that base branch and requires pr:create. workspace:public declares that the \
repository's committed content is public, so Keel does not treat it as confidential. \
github:read-private-issues permits authenticated reads of individual issues only in the exact \
GitHub repository; it does not imply PR creation or push authority. \
isolation:v8-sandboxed means the operator explicitly permits Keel's lower-assurance host V8 mode. \
push:branch exactly represents ordinary, non-force \
pushes to non-default branches as normal session activity; default-branch, manifest, and force \
pushes remain intrinsically gated, so do not add a blocker for ordinary non-default-branch \
wording. An explicit requirement to never push the default branch is not representable and must \
be a blocker. Rules restrict exactly one action and use only the supplied condition variants. \
Use effect deny for words like never/prohibit, otherwise escalate. Put anything not exactly \
representable in blockers. Tool annotations may only identify exact executable basenames and \
path arguments. Return only the schema object.";
const MAX_ARTIFACT_BYTES: usize = 2 * 1024 * 1024;
const MAX_RULES: usize = 64;
const MAX_TOOLS: usize = 64;
const SCHEMA: &str = include_str!("../../../trusted/keel-policy/policy/default/schema.cedarschema");
const DEFAULT_POLICIES: &str =
    include_str!("../../../trusted/keel-policy/policy/default/policies.cedar");

/// Model- or parser-proposed policy interpretation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PolicyTranslation {
    /// Optional exact GitHub repository in `owner/name` form.
    pub repository: Option<String>,
    /// Closed runtime capabilities granted by the policy.
    #[serde(default)]
    pub grants: Vec<String>,
    /// Deterministic stateful restrictions.
    #[serde(default)]
    pub rules: Vec<RuleSpec>,
    /// Reviewed command argument annotations.
    #[serde(default)]
    pub tools: Vec<ToolAnnotation>,
    /// Clauses the translator could not represent.
    #[serde(default)]
    pub blockers: Vec<String>,
    /// Explanatory notes shown to the operator.
    #[serde(default)]
    pub notes: Vec<String>,
}

/// Whether a generated violation may be approved or must be denied.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuleEffect {
    /// Show a trusted approval gate.
    Escalate,
    /// Deny before the approval gate.
    Deny,
}

/// Closed action vocabulary available to generated rules.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleAction {
    /// Workspace read.
    Read,
    /// Workspace write.
    Write,
    /// Git push.
    Push,
    /// Command execution.
    Run,
    /// Local commit.
    Commit,
    /// Outbound request.
    Egress,
    /// Pull-request operation.
    PullRequest,
    /// External publication.
    Publish,
    /// Deletion.
    Delete,
    /// Provenance-floor lift.
    LiftFloor,
}

impl RuleAction {
    fn cedar(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Push => "push",
            Self::Run => "run",
            Self::Commit => "commit",
            Self::Egress => "egress",
            Self::PullRequest => "pull_request",
            Self::Publish => "publish",
            Self::Delete => "delete",
            Self::LiftFloor => "lift_floor",
        }
    }
}

/// One state predicate supported by both generated Cedar and the Rego oracle.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum RuleCondition {
    /// Match every action of the rule's action class.
    Always,
    /// Match when the provenance floor is below `rank`.
    FloorBelow {
        /// Required floor, from zero through three.
        rank: u8,
    },
    /// Match at or above a recent write count.
    WritesAtLeast {
        /// Inclusive count threshold.
        count: u32,
    },
    /// Match at or above a recent distinct-file count.
    DistinctFilesAtLeast {
        /// Inclusive count threshold.
        count: u32,
    },
    /// Match at or above a denial count.
    DenialsAtLeast {
        /// Inclusive count threshold.
        count: u32,
    },
    /// Match at or above an escalation count.
    EscalationsAtLeast {
        /// Inclusive count threshold.
        count: u32,
    },
    /// Match after any package registry was contacted.
    RegistryContacted,
    /// Match when a write target was not created by this vertex.
    TargetNotCreatedByVertex,
    /// Match when the read-set includes a host outside owned domains.
    SourceOutsideOwnDomains,
    /// Match a raw Git force update.
    ForcePush,
}

/// One generated stateful policy rule.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuleSpec {
    /// Stable lowercase rule identifier.
    pub id: String,
    /// Gate or hard-deny behavior.
    pub effect: RuleEffect,
    /// Action class constrained by the rule.
    pub action: RuleAction,
    /// Predicates combined with logical AND.
    pub when: Vec<RuleCondition>,
    /// Human-readable reason preserved for review.
    pub reason: String,
}

/// Security role assigned to one command argument.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ToolArgumentRole {
    /// Existing path whose contents are read.
    ReadPath,
    /// Existing or new path that may be changed.
    WritePath,
    /// Existing path that may be removed.
    DeletePath,
}

/// Location of one annotated command argument.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ToolArgumentSelector {
    /// Zero-based argument index.
    Index {
        /// Argument index excluding the executable.
        index: usize,
    },
    /// Value immediately following an exact flag.
    FlagValue {
        /// Exact flag spelling.
        flag: String,
    },
}

/// One reviewed argument annotation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ToolArgument {
    /// How the argument is located.
    pub selector: ToolArgumentSelector,
    /// Filesystem role assigned to the argument.
    pub role: ToolArgumentRole,
}

/// Reviewed annotations for one exact executable name.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ToolAnnotation {
    /// Exact executable basename.
    pub program: String,
    /// Path-bearing argument declarations.
    pub arguments: Vec<ToolArgument>,
}

/// Facts used by generated differential scenarios.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ScenarioFacts {
    floor: u8,
    writes_last_60s: u32,
    distinct_files_written_60s: u32,
    denied_actions: u32,
    escalated_actions: u32,
    registries_contacted: bool,
    target_created_by_vertex: bool,
    own_domains: Vec<String>,
    source_hosts: Vec<String>,
    target_is_force_push: bool,
}

impl Default for ScenarioFacts {
    fn default() -> Self {
        Self {
            floor: 3,
            writes_last_60s: 0,
            distinct_files_written_60s: 0,
            denied_actions: 0,
            escalated_actions: 0,
            registries_contacted: false,
            target_created_by_vertex: true,
            own_domains: vec!["owner.example".to_owned()],
            source_hosts: Vec::new(),
            target_is_force_push: false,
        }
    }
}

/// One generated scenario evaluated by Cedar and Rego.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VerificationScenario {
    /// Stable scenario name.
    pub name: String,
    /// Action submitted to both engines.
    pub action: RuleAction,
    /// Complete bounded fact input.
    pub facts: ScenarioFacts,
    /// Independently computed expected violation IDs.
    pub expected_violations: Vec<String>,
}

/// Reproducible verification evidence stored with an artifact.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct VerificationReport {
    /// Number of scenarios checked.
    pub scenarios: usize,
    /// Cedar parsed and passed strict schema validation.
    pub cedar_valid: bool,
    /// Rego parsed and evaluated.
    pub rego_valid: bool,
    /// Both engines agreed with each other and the independent model.
    pub differential_passed: bool,
    /// Generated rules contain only restrictions, never permits.
    pub restriction_only: bool,
    /// Every rule has a triggering and one-condition-near-miss scenario.
    pub rule_coverage_complete: bool,
}

/// Content-hashed natural-language policy and generated runtime bundle.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PolicyArtifact {
    format: String,
    status: ArtifactStatus,
    source: String,
    translation: PolicyTranslation,
    schema: String,
    cedar: String,
    rego: String,
    scenarios: Vec<VerificationScenario>,
    verification: VerificationReport,
    bundle_hash: String,
    created_at_ms: u64,
    accepted_at_ms: Option<u64>,
    hash: String,
}

impl PolicyArtifact {
    /// Compiles and verifies a draft from an untrusted translation.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid source, translation, generated policy, or
    /// differential verification.
    pub fn draft(
        source: &str,
        mut translation: PolicyTranslation,
        created_at_ms: u64,
    ) -> Result<Self, CompileError> {
        validate_source(source)?;
        validate_translation(&mut translation)?;
        let cedar = generate_cedar(&translation.rules);
        let rego = generate_rego(&translation.rules);
        let scenarios = generate_scenarios(&translation.rules);
        let verification = verify_bundle(&cedar, &rego, &translation.rules, &scenarios)?;
        let bundle_hash = bundle_hash(SCHEMA, &cedar);
        let mut artifact = Self {
            format: FORMAT.to_owned(),
            status: ArtifactStatus::Draft,
            source: source.to_owned(),
            translation,
            schema: SCHEMA.to_owned(),
            cedar,
            rego,
            scenarios,
            verification,
            bundle_hash,
            created_at_ms,
            accepted_at_ms: None,
            hash: String::new(),
        };
        artifact.rehash()?;
        Ok(artifact)
    }

    /// Loads and verifies an artifact from JSON.
    ///
    /// # Errors
    ///
    /// Returns an error for I/O, size, JSON, hash, or verification failures.
    pub fn load(path: &Path) -> Result<Self, CompileError> {
        let bytes = fs::read(path)
            .map_err(|error| CompileError::new(format!("cannot read policy: {error}")))?;
        if bytes.len() > MAX_ARTIFACT_BYTES {
            return Err(CompileError::new("policy artifact exceeds 2 MiB"));
        }
        let artifact: Self = serde_json::from_slice(&bytes)
            .map_err(|error| CompileError::new(format!("invalid policy artifact: {error}")))?;
        artifact.verify()?;
        Ok(artifact)
    }

    /// Writes formatted, verified JSON.
    ///
    /// # Errors
    ///
    /// Returns an error when verification, serialization, or writing fails.
    pub fn save(&self, path: &Path) -> Result<(), CompileError> {
        self.verify()?;
        if let Some(parent) = path.parent().filter(|path| !path.as_os_str().is_empty()) {
            fs::create_dir_all(parent)
                .map_err(|error| CompileError::new(format!("create output directory: {error}")))?;
        }
        fs::write(
            path,
            serde_json::to_vec_pretty(self)
                .map_err(|error| CompileError::new(format!("serialize policy: {error}")))?,
        )
        .map_err(|error| CompileError::new(format!("write policy: {error}")))
    }

    /// Accepts a blocker-free, freshly reverified draft.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid, blocked, or previously accepted input.
    pub fn accept(&mut self, accepted_at_ms: u64) -> Result<(), CompileError> {
        self.verify()?;
        if self.status != ArtifactStatus::Draft {
            return Err(CompileError::new("policy is already accepted"));
        }
        if !self.translation.blockers.is_empty() {
            return Err(CompileError::new(
                "policy has unresolved blockers and cannot be accepted",
            ));
        }
        self.status = ArtifactStatus::Accepted;
        self.accepted_at_ms = Some(accepted_at_ms);
        self.rehash()
    }

    /// Returns true when the artifact is accepted and verified.
    ///
    /// # Errors
    ///
    /// Returns an error when artifact verification fails.
    pub fn is_accepted(&self) -> Result<bool, CompileError> {
        self.verify()?;
        Ok(self.status == ArtifactStatus::Accepted && self.translation.blockers.is_empty())
    }

    /// Returns whether unrepresented clauses prevent acceptance.
    #[must_use]
    pub fn has_blockers(&self) -> bool {
        !self.translation.blockers.is_empty()
    }

    /// Returns the exact repository scope.
    #[must_use]
    pub fn repository(&self) -> Option<&str> {
        self.translation.repository.as_deref()
    }

    /// Returns the closed runtime capability set.
    #[must_use]
    pub fn capabilities(&self) -> &[String] {
        &self.translation.grants
    }

    /// Returns the complete Cedar schema.
    #[must_use]
    pub fn schema(&self) -> &str {
        &self.schema
    }

    /// Returns the complete Cedar policy bundle.
    #[must_use]
    pub fn cedar(&self) -> &str {
        &self.cedar
    }

    /// Returns the content hash that acceptance is recorded against.
    #[must_use]
    pub fn hash(&self) -> &str {
        &self.hash
    }

    /// Returns the trusted runtime bundle digest.
    #[must_use]
    pub fn bundle_hash(&self) -> &str {
        &self.bundle_hash
    }

    /// Writes the exact runtime bundle files into a session-private directory.
    ///
    /// # Errors
    ///
    /// Returns an error unless the artifact is accepted and the bundle files
    /// can be created.
    pub fn materialize_bundle(&self, directory: &Path) -> Result<(), CompileError> {
        if !self.is_accepted()? {
            return Err(CompileError::new(
                "policy is still a draft; accept it before use",
            ));
        }
        fs::create_dir_all(directory)
            .map_err(|error| CompileError::new(format!("create policy bundle: {error}")))?;
        fs::write(directory.join("schema.cedarschema"), &self.schema)
            .and_then(|()| fs::write(directory.join("policies.cedar"), &self.cedar))
            .and_then(|()| fs::write(directory.join("bundle.sha256"), &self.bundle_hash))
            .map_err(|error| CompileError::new(format!("write policy bundle: {error}")))
    }

    /// Renders the interpretation, generated rules, and verification evidence.
    #[must_use]
    pub fn review(&self) -> String {
        let mut output = format!(
            "Keel policy {}\nstatus: {:?}\nhash: {}\nbundle: {}\nrepository: {}\n",
            self.format,
            self.status,
            self.hash,
            self.bundle_hash,
            self.repository().unwrap_or("(none)")
        );
        output.push_str("capabilities:\n");
        render_list(&mut output, &self.translation.grants);
        output.push_str("rules:\n");
        if self.translation.rules.is_empty() {
            output.push_str("  (none)\n");
        } else {
            for rule in &self.translation.rules {
                let _ = writeln!(
                    output,
                    "  - {}: {:?} {:?} when {:?} — {}",
                    rule.id, rule.effect, rule.action, rule.when, rule.reason
                );
            }
        }
        output.push_str("tool annotations:\n");
        if self.translation.tools.is_empty() {
            output.push_str("  (none)\n");
        } else {
            for tool in &self.translation.tools {
                let _ = writeln!(output, "  - {}: {:?}", tool.program, tool.arguments);
            }
        }
        output.push_str("blockers:\n");
        render_list(&mut output, &self.translation.blockers);
        output.push_str("notes:\n");
        render_list(&mut output, &self.translation.notes);
        let _ = writeln!(
            output,
            "verification:\n  Cedar strict validation: {}\n  Rego oracle: {}\n  differential scenarios: {}/{}\n  restriction-only: {}\n  rule coverage: {}",
            self.verification.cedar_valid,
            self.verification.rego_valid,
            if self.verification.differential_passed {
                self.verification.scenarios
            } else {
                0
            },
            self.verification.scenarios,
            self.verification.restriction_only,
            self.verification.rule_coverage_complete
        );
        output.push_str("source:\n");
        output.push_str(&self.source);
        output.push('\n');
        output
    }

    /// Produces a line-oriented review diff against another artifact.
    #[must_use]
    pub fn diff(&self, newer: &Self) -> String {
        let old = self.review();
        let new = newer.review();
        let old_lines = old.lines().collect::<BTreeSet<_>>();
        let new_lines = new.lines().collect::<BTreeSet<_>>();
        let mut output = String::new();
        for line in old_lines.difference(&new_lines) {
            let _ = writeln!(output, "- {line}");
        }
        for line in new_lines.difference(&old_lines) {
            let _ = writeln!(output, "+ {line}");
        }
        if output.is_empty() {
            output.push_str("(no semantic review changes)\n");
        }
        output
    }

    fn verify(&self) -> Result<(), CompileError> {
        if self.format != FORMAT || self.schema != SCHEMA {
            return Err(CompileError::new("unsupported policy format or schema"));
        }
        validate_source(&self.source)?;
        let mut translation = self.translation.clone();
        validate_translation(&mut translation)?;
        if translation != self.translation
            || generate_cedar(&translation.rules) != self.cedar
            || generate_rego(&translation.rules) != self.rego
            || generate_scenarios(&translation.rules) != self.scenarios
        {
            return Err(CompileError::new(
                "policy generated content does not match its interpretation",
            ));
        }
        let report = verify_bundle(&self.cedar, &self.rego, &translation.rules, &self.scenarios)?;
        if report != self.verification || bundle_hash(&self.schema, &self.cedar) != self.bundle_hash
        {
            return Err(CompileError::new(
                "policy verification evidence does not match content",
            ));
        }
        match self.status {
            ArtifactStatus::Draft if self.accepted_at_ms.is_some() => {
                return Err(CompileError::new("draft policy has an acceptance time"));
            }
            ArtifactStatus::Accepted if self.accepted_at_ms.is_none() => {
                return Err(CompileError::new(
                    "accepted policy lacks an acceptance time",
                ));
            }
            _ => {}
        }
        if artifact_hash(self)? != self.hash {
            return Err(CompileError::new(
                "policy artifact hash does not match content",
            ));
        }
        Ok(())
    }

    fn rehash(&mut self) -> Result<(), CompileError> {
        self.hash.clear();
        self.hash = artifact_hash(self)?;
        Ok(())
    }
}

/// Loads a translator JSON file.
///
/// # Errors
///
/// Returns an error when the file cannot be read or decoded.
pub fn load_policy_translation(path: &Path) -> Result<PolicyTranslation, CompileError> {
    serde_json::from_slice(
        &fs::read(path).map_err(|error| CompileError::new(format!("read translation: {error}")))?,
    )
    .map_err(|error| CompileError::new(format!("invalid policy translation: {error}")))
}

/// Uses a tool-disabled host Claude process to propose the closed IR.
///
/// # Errors
///
/// Returns an error for invalid input, process failure, timeout, or malformed
/// structured output.
pub fn translate_policy_with_claude(source: &str) -> Result<PolicyTranslation, CompileError> {
    validate_source(source)?;
    let schema = translation_schema();
    let mut child =
        Command::new(std::env::var_os("KEEL_POLICY_TRANSLATOR").unwrap_or_else(|| "claude".into()))
            .args([
                "--bare",
                "--print",
                "--output-format",
                "json",
                "--json-schema",
                &schema,
                "--system-prompt",
                TRANSLATOR_SYSTEM,
                "--tools",
                "",
                "--permission-prompts",
                "none",
                "--no-session-persistence",
                "--max-budget-usd",
                "0.10",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| CompileError::new(format!("start policy translator: {error}")))?;
    child
        .stdin
        .take()
        .ok_or_else(|| CompileError::new("policy translator stdin unavailable"))?
        .write_all(source.as_bytes())
        .map_err(|error| CompileError::new(format!("write policy: {error}")))?;
    let started = Instant::now();
    while child
        .try_wait()
        .map_err(|error| CompileError::new(format!("policy translator: {error}")))?
        .is_none()
    {
        if started.elapsed() >= Duration::from_secs(45) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(CompileError::new(
                "policy translator did not answer within 45 seconds",
            ));
        }
        thread::sleep(Duration::from_millis(20));
    }
    let output = child
        .wait_with_output()
        .map_err(|error| CompileError::new(format!("policy translator: {error}")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let detail = if stderr.trim().is_empty() {
            translator_failure_detail(&stdout)
        } else {
            stderr.trim().to_owned()
        };
        return Err(CompileError::new(format!(
            "policy translator exited with {}: {}",
            output.status, detail
        )));
    }
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|error| CompileError::new(format!("invalid translator response: {error}")))?;
    let structured = envelope
        .get("structured_output")
        .cloned()
        .or_else(|| envelope.get("result").cloned())
        .unwrap_or(envelope);
    match structured {
        serde_json::Value::String(value) => serde_json::from_str(&value),
        value => serde_json::from_value(value),
    }
    .map_err(|error| CompileError::new(format!("invalid policy translation: {error}")))
}

fn translator_failure_detail(stdout: &str) -> String {
    let parsed = serde_json::from_str::<serde_json::Value>(stdout).ok();
    let errors = parsed
        .as_ref()
        .and_then(|value| value.get("errors"))
        .and_then(serde_json::Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(serde_json::Value::as_str)
                .collect::<Vec<_>>()
                .join("; ")
        })
        .filter(|value| !value.is_empty());
    let reason = parsed
        .as_ref()
        .and_then(|value| value.get("terminal_reason"))
        .and_then(serde_json::Value::as_str);
    errors
        .or_else(|| reason.map(ToOwned::to_owned))
        .unwrap_or_else(|| "translator returned no diagnostic".to_owned())
}

fn validate_source(source: &str) -> Result<(), CompileError> {
    if source.trim().is_empty() || source.len() > 64 * 1024 || source.contains('\0') {
        return Err(CompileError::new(
            "policy must contain 1-65536 bytes and no NUL",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn validate_translation(translation: &mut PolicyTranslation) -> Result<(), CompileError> {
    if translation.rules.len() > MAX_RULES || translation.tools.len() > MAX_TOOLS {
        return Err(CompileError::new(
            "policy exceeds 64 rules or tool annotations",
        ));
    }
    translation.repository = translation
        .repository
        .as_deref()
        .map(normalize_repository)
        .transpose()?;
    let mut grants = BTreeSet::new();
    for grant in &translation.grants {
        grants.insert(normalize_capability(grant)?);
    }
    translation.grants = grants.into_iter().collect();
    let mut ids = BTreeSet::new();
    for rule in &mut translation.rules {
        rule.id = normalize_id(&rule.id)?;
        if !ids.insert(rule.id.clone()) {
            return Err(CompileError::new(format!(
                "duplicate policy rule `{}`",
                rule.id
            )));
        }
        if rule.when.is_empty() {
            return Err(CompileError::new(format!(
                "policy rule `{}` has no conditions",
                rule.id
            )));
        }
        validate_message(&rule.reason, "rule reason")?;
        for condition in &rule.when {
            match condition {
                RuleCondition::FloorBelow { rank } if *rank > 3 => {
                    return Err(CompileError::new("provenance rank must be 0 through 3"));
                }
                RuleCondition::WritesAtLeast { count }
                | RuleCondition::DistinctFilesAtLeast { count }
                | RuleCondition::DenialsAtLeast { count }
                | RuleCondition::EscalationsAtLeast { count }
                    if *count == 0 || *count > 1_000_000 =>
                {
                    return Err(CompileError::new(
                        "count thresholds must be 1 through 1000000",
                    ));
                }
                RuleCondition::ForcePush if rule.action != RuleAction::Push => {
                    return Err(CompileError::new(
                        "force-push condition is valid only for push rules",
                    ));
                }
                RuleCondition::TargetNotCreatedByVertex if rule.action != RuleAction::Write => {
                    return Err(CompileError::new(
                        "target-created condition is valid only for write rules",
                    ));
                }
                _ => {}
            }
        }
    }
    translation
        .rules
        .sort_by(|left, right| left.id.cmp(&right.id));
    let mut programs = BTreeSet::new();
    for tool in &translation.tools {
        if !valid_program(&tool.program) || !programs.insert(tool.program.clone()) {
            return Err(CompileError::new("invalid or duplicate tool annotation"));
        }
        let mut selectors = BTreeSet::new();
        for argument in &tool.arguments {
            let key = match &argument.selector {
                ToolArgumentSelector::Index { index } if *index <= 1024 => format!("i:{index}"),
                ToolArgumentSelector::FlagValue { flag }
                    if flag.starts_with('-')
                        && flag.len() <= 64
                        && !flag.chars().any(char::is_control) =>
                {
                    format!("f:{flag}")
                }
                _ => return Err(CompileError::new("invalid tool argument selector")),
            };
            if !selectors.insert(key) {
                return Err(CompileError::new("duplicate tool argument selector"));
            }
        }
    }
    translation
        .tools
        .sort_by(|left, right| left.program.cmp(&right.program));
    for value in translation.blockers.iter().chain(&translation.notes) {
        validate_message(value, "policy message")?;
    }
    if translation.grants.is_empty() && translation.rules.is_empty() {
        translation
            .blockers
            .push("policy contains no supported grants or rules".to_owned());
    }
    let needs_repository = translation.grants.iter().any(|grant| {
        matches!(
            grant.as_str(),
            "push:branch" | "pr:create" | "github:read-private-issues"
        ) || grant.starts_with("push:ref:")
            || grant.starts_with("pr:target:")
    });
    if translation
        .grants
        .iter()
        .any(|grant| grant.starts_with("pr:target:"))
        && !translation.grants.iter().any(|grant| grant == "pr:create")
    {
        translation
            .blockers
            .push("pr:target narrows pr:create and requires it".to_owned());
    }
    if needs_repository && translation.repository.is_none() {
        translation.blockers.push(
            "repository-scoped grants require an exact GitHub owner/name repository".to_owned(),
        );
    }
    translation.blockers.sort();
    translation.blockers.dedup();
    translation.notes.sort();
    translation.notes.dedup();
    Ok(())
}

fn normalize_repository(value: &str) -> Result<String, CompileError> {
    let value = value
        .trim()
        .trim_start_matches("https://github.com/")
        .trim_end_matches(".git")
        .trim_matches('/');
    let parts = value.split('/').collect::<Vec<_>>();
    if parts.len() != 2 || !parts.iter().all(|part| valid_name(part, 100)) {
        return Err(CompileError::new(
            "repository must be an exact GitHub owner/name",
        ));
    }
    Ok(value.to_ascii_lowercase())
}

fn normalize_capability(value: &str) -> Result<String, CompileError> {
    if let Some(scope) = crate::scoped_grant(value) {
        return scope;
    }
    let value = value.trim().to_ascii_lowercase();
    if matches!(
        value.as_str(),
        "push:branch"
            | "pr:create"
            | "github:read-private-issues"
            | "deny:force-push"
            | "isolation:v8-sandboxed"
            | "workspace:public"
    ) {
        return Ok(value);
    }
    let host = value
        .strip_prefix("egress:")
        .ok_or_else(|| CompileError::new(format!("unsupported grant `{value}`")))?;
    if host.len() > 253
        || host.parse::<std::net::IpAddr>().is_ok()
        || host.contains('*')
        || !host.contains('.')
        || host.split('.').any(|label| !valid_name(label, 63))
    {
        return Err(CompileError::new(format!(
            "egress grant requires an exact DNS host, got `{host}`"
        )));
    }
    Ok(value)
}

fn normalize_id(value: &str) -> Result<String, CompileError> {
    let value = value.trim().to_ascii_lowercase().replace('_', "-");
    if !valid_name(&value, 64) {
        return Err(CompileError::new("invalid policy rule id"));
    }
    Ok(value)
}

fn valid_name(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && !value.starts_with(['-', '.'])
        && !value.ends_with(['-', '.'])
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn valid_program(value: &str) -> bool {
    valid_name(value, 128) && !value.contains('/')
}

fn validate_message(value: &str, name: &str) -> Result<(), CompileError> {
    if value.trim().is_empty() || value.len() > 512 || value.chars().any(char::is_control) {
        return Err(CompileError::new(format!("invalid {name}")));
    }
    Ok(())
}

fn rule_id(rule: &RuleSpec) -> String {
    match rule.effect {
        RuleEffect::Escalate => format!("policy:{}", rule.id),
        RuleEffect::Deny => format!("deny:policy:{}", rule.id),
    }
}

fn generate_cedar(rules: &[RuleSpec]) -> String {
    let mut output = DEFAULT_POLICIES.to_owned();
    for rule in rules {
        let _ = write!(
            output,
            "\n@id(\"{}\")\nforbid (principal, action == Action::\"{}\", resource) when {{\n    ",
            rule_id(rule),
            rule.action.cedar()
        );
        for (index, condition) in rule.when.iter().enumerate() {
            if index > 0 {
                output.push_str(" &&\n    ");
            }
            output.push_str(&cedar_condition(condition));
        }
        output.push_str("\n};\n");
    }
    output
}

fn cedar_condition(condition: &RuleCondition) -> String {
    match condition {
        RuleCondition::Always => "true".to_owned(),
        RuleCondition::FloorBelow { rank } => format!("context.floor < {rank}"),
        RuleCondition::WritesAtLeast { count } => {
            format!("context.writes_last_60s >= {count}")
        }
        RuleCondition::DistinctFilesAtLeast { count } => {
            format!("context.distinct_files_written_60s >= {count}")
        }
        RuleCondition::DenialsAtLeast { count } => format!("context.denied_actions >= {count}"),
        RuleCondition::EscalationsAtLeast { count } => {
            format!("context.escalated_actions >= {count}")
        }
        RuleCondition::RegistryContacted => "context.registries_contacted".to_owned(),
        RuleCondition::TargetNotCreatedByVertex => "!context.target_created_by_vertex".to_owned(),
        RuleCondition::SourceOutsideOwnDomains => {
            "!context.own_domains.containsAll(context.source_hosts)".to_owned()
        }
        RuleCondition::ForcePush => "context.target_is_force_push".to_owned(),
    }
}

fn generate_rego(rules: &[RuleSpec]) -> String {
    let mut output = "package keel.policy\n\n\
        violations[\"__keel_never__\"] {\n  false\n}\n\n"
        .to_owned();
    for rule in rules {
        let _ = writeln!(output, "violations[\"{}\"] {{", rule_id(rule));
        let _ = writeln!(output, "  input.action == \"{}\"", rule.action.cedar());
        for condition in &rule.when {
            let _ = writeln!(output, "  {}", rego_condition(condition));
        }
        output.push_str("}\n\n");
    }
    output
}

fn rego_condition(condition: &RuleCondition) -> String {
    match condition {
        RuleCondition::Always => "true".to_owned(),
        RuleCondition::FloorBelow { rank } => format!("input.facts.floor < {rank}"),
        RuleCondition::WritesAtLeast { count } => {
            format!("input.facts.writes_last_60s >= {count}")
        }
        RuleCondition::DistinctFilesAtLeast { count } => {
            format!("input.facts.distinct_files_written_60s >= {count}")
        }
        RuleCondition::DenialsAtLeast { count } => {
            format!("input.facts.denied_actions >= {count}")
        }
        RuleCondition::EscalationsAtLeast { count } => {
            format!("input.facts.escalated_actions >= {count}")
        }
        RuleCondition::RegistryContacted => "input.facts.registries_contacted".to_owned(),
        RuleCondition::TargetNotCreatedByVertex => {
            "not input.facts.target_created_by_vertex".to_owned()
        }
        RuleCondition::SourceOutsideOwnDomains => {
            "count({x | x := input.facts.source_hosts[_]}) > \
             count({x | x := input.facts.source_hosts[_]; input.facts.own_domains[_] == x})"
                .to_owned()
        }
        RuleCondition::ForcePush => "input.facts.target_is_force_push".to_owned(),
    }
}

fn generate_scenarios(rules: &[RuleSpec]) -> Vec<VerificationScenario> {
    let mut scenarios = Vec::new();
    for action in [
        RuleAction::Read,
        RuleAction::Write,
        RuleAction::Push,
        RuleAction::Run,
        RuleAction::Commit,
        RuleAction::Egress,
        RuleAction::PullRequest,
        RuleAction::Publish,
        RuleAction::Delete,
        RuleAction::LiftFloor,
    ] {
        push_scenario(
            &mut scenarios,
            format!("baseline-{}", action.cedar()),
            action,
            ScenarioFacts::default(),
            rules,
        );
    }
    for rule in rules {
        let mut facts = ScenarioFacts::default();
        for condition in &rule.when {
            apply_trigger(condition, &mut facts);
        }
        push_scenario(
            &mut scenarios,
            format!("{}-trigger", rule.id),
            rule.action,
            facts.clone(),
            rules,
        );
        for (index, condition) in rule.when.iter().enumerate() {
            let mut miss = facts.clone();
            apply_miss(condition, &mut miss);
            push_scenario(
                &mut scenarios,
                format!("{}-near-miss-{index}", rule.id),
                rule.action,
                miss,
                rules,
            );
        }
    }
    scenarios
}

fn push_scenario(
    scenarios: &mut Vec<VerificationScenario>,
    name: String,
    action: RuleAction,
    facts: ScenarioFacts,
    rules: &[RuleSpec],
) {
    let expected_violations = rules
        .iter()
        .filter(|rule| rule.action == action && rule_matches(rule, &facts))
        .map(rule_id)
        .collect();
    scenarios.push(VerificationScenario {
        name,
        action,
        facts,
        expected_violations,
    });
}

fn apply_trigger(condition: &RuleCondition, facts: &mut ScenarioFacts) {
    match condition {
        RuleCondition::Always => {}
        RuleCondition::FloorBelow { rank } => facts.floor = rank.saturating_sub(1),
        RuleCondition::WritesAtLeast { count } => facts.writes_last_60s = *count,
        RuleCondition::DistinctFilesAtLeast { count } => {
            facts.distinct_files_written_60s = *count;
        }
        RuleCondition::DenialsAtLeast { count } => facts.denied_actions = *count,
        RuleCondition::EscalationsAtLeast { count } => facts.escalated_actions = *count,
        RuleCondition::RegistryContacted => facts.registries_contacted = true,
        RuleCondition::TargetNotCreatedByVertex => facts.target_created_by_vertex = false,
        RuleCondition::SourceOutsideOwnDomains => {
            facts.source_hosts = vec!["outside.example".to_owned()];
        }
        RuleCondition::ForcePush => facts.target_is_force_push = true,
    }
}

fn apply_miss(condition: &RuleCondition, facts: &mut ScenarioFacts) {
    match condition {
        RuleCondition::Always => {}
        RuleCondition::FloorBelow { rank } => facts.floor = *rank,
        RuleCondition::WritesAtLeast { count } => facts.writes_last_60s = count.saturating_sub(1),
        RuleCondition::DistinctFilesAtLeast { count } => {
            facts.distinct_files_written_60s = count.saturating_sub(1);
        }
        RuleCondition::DenialsAtLeast { count } => facts.denied_actions = count.saturating_sub(1),
        RuleCondition::EscalationsAtLeast { count } => {
            facts.escalated_actions = count.saturating_sub(1);
        }
        RuleCondition::RegistryContacted => facts.registries_contacted = false,
        RuleCondition::TargetNotCreatedByVertex => facts.target_created_by_vertex = true,
        RuleCondition::SourceOutsideOwnDomains => facts.source_hosts.clear(),
        RuleCondition::ForcePush => facts.target_is_force_push = false,
    }
}

fn rule_matches(rule: &RuleSpec, facts: &ScenarioFacts) -> bool {
    rule.when.iter().all(|condition| match condition {
        RuleCondition::Always => true,
        RuleCondition::FloorBelow { rank } => facts.floor < *rank,
        RuleCondition::WritesAtLeast { count } => facts.writes_last_60s >= *count,
        RuleCondition::DistinctFilesAtLeast { count } => facts.distinct_files_written_60s >= *count,
        RuleCondition::DenialsAtLeast { count } => facts.denied_actions >= *count,
        RuleCondition::EscalationsAtLeast { count } => facts.escalated_actions >= *count,
        RuleCondition::RegistryContacted => facts.registries_contacted,
        RuleCondition::TargetNotCreatedByVertex => !facts.target_created_by_vertex,
        RuleCondition::SourceOutsideOwnDomains => facts
            .source_hosts
            .iter()
            .any(|host| !facts.own_domains.contains(host)),
        RuleCondition::ForcePush => facts.target_is_force_push,
    })
}

fn verify_bundle(
    cedar: &str,
    rego: &str,
    rules: &[RuleSpec],
    scenarios: &[VerificationScenario],
) -> Result<VerificationReport, CompileError> {
    let (schema, warnings) = Schema::from_cedarschema_str(SCHEMA)
        .map_err(|error| CompileError::new(format!("Cedar schema: {error}")))?;
    if warnings.count() != 0 {
        return Err(CompileError::new("Cedar schema emitted warnings"));
    }
    let policies = PolicySet::from_str(cedar)
        .map_err(|error| CompileError::new(format!("Cedar parse: {error}")))?;
    let validation = Validator::new(schema.clone()).validate(&policies, ValidationMode::Strict);
    if !validation.validation_passed_without_warnings() {
        return Err(CompileError::new(format!(
            "Cedar validation: {}",
            validation
                .validation_errors()
                .map(ToString::to_string)
                .chain(validation.validation_warnings().map(ToString::to_string))
                .collect::<Vec<_>>()
                .join("; ")
        )));
    }
    let generated_ids = rules.iter().map(rule_id).collect::<BTreeSet<_>>();
    let restriction_only = policies.policies().all(|policy| {
        policy.effect() == Effect::Forbid
            || !policy
                .annotation("id")
                .is_some_and(|id| generated_ids.contains(id))
    });
    if !restriction_only {
        return Err(CompileError::new("generated policy contains a permit rule"));
    }
    let mut engine = Engine::new();
    engine.set_rego_v0(true);
    engine
        .add_policy("policy.rego".to_owned(), rego.to_owned())
        .map_err(|error| CompileError::new(format!("Rego parse: {error}")))?;
    for scenario in scenarios {
        let cedar_result = evaluate_cedar(&schema, &policies, scenario)?;
        let rego_result = evaluate_rego(&mut engine, scenario)?;
        if cedar_result != rego_result || cedar_result != scenario.expected_violations {
            return Err(CompileError::new(format!(
                "differential mismatch in `{}`: Cedar={cedar_result:?}, Rego={rego_result:?}, expected={:?}",
                scenario.name, scenario.expected_violations
            )));
        }
    }
    let rule_coverage_complete = rules.iter().all(|rule| {
        scenarios
            .iter()
            .any(|scenario| scenario.name == format!("{}-trigger", rule.id))
            && (rule.when == [RuleCondition::Always]
                || scenarios.iter().any(|scenario| {
                    scenario
                        .name
                        .starts_with(&format!("{}-near-miss-", rule.id))
                }))
    });
    if !rule_coverage_complete {
        return Err(CompileError::new(
            "generated scenario coverage is incomplete",
        ));
    }
    Ok(VerificationReport {
        scenarios: scenarios.len(),
        cedar_valid: true,
        rego_valid: true,
        differential_passed: true,
        restriction_only,
        rule_coverage_complete,
    })
}

fn evaluate_cedar(
    schema: &Schema,
    policies: &PolicySet,
    scenario: &VerificationScenario,
) -> Result<Vec<String>, CompileError> {
    let action = EntityUid::from_str(&format!(r#"Action::"{}""#, scenario.action.cedar()))
        .map_err(|error| CompileError::new(format!("Cedar action: {error}")))?;
    let facts = &scenario.facts;
    let context = Context::from_json_value(
        json!({
            "files_created_by_this_vertex": [],
            "files_written_by_this_vertex": [],
            "hosts_contacted": [],
            "registries_contacted": facts.registries_contacted,
            "writes_last_60s": facts.writes_last_60s,
            "denied_actions": facts.denied_actions,
            "recent_behavioral_denials_in_scope": 0,
            "escalated_actions": facts.escalated_actions,
            "distinct_files_written_60s": facts.distinct_files_written_60s,
            "floor": facts.floor,
            "floor_history": [],
            "own_domains": facts.own_domains,
            "source_hosts": facts.source_hosts,
            "sources_read": [],
            "intent": {
                "allow_push_branch": true,
                "allow_pr_create": true,
                "deny_force_push": false,
                "allowed_egress_hosts": [],
            },
            "target_is_force_push": facts.target_is_force_push,
            "target_created_by_vertex": facts.target_created_by_vertex,
        }),
        Some((schema, &action)),
    )
    .map_err(|error| CompileError::new(format!("Cedar context: {error}")))?;
    let request = Request::new(
        EntityUid::from_str(r#"Vertex::"current""#)
            .map_err(|error| CompileError::new(format!("Cedar principal: {error}")))?,
        action,
        EntityUid::from_str(r#"Target::"current""#)
            .map_err(|error| CompileError::new(format!("Cedar target: {error}")))?,
        context,
        Some(schema),
    )
    .map_err(|error| CompileError::new(format!("Cedar request: {error}")))?;
    let response = Authorizer::new().is_authorized(&request, policies, &Entities::empty());
    if let Some(error) = response.diagnostics().errors().next() {
        return Err(CompileError::new(format!("Cedar evaluation: {error}")));
    }
    if response.decision() == Decision::Allow {
        return Ok(Vec::new());
    }
    let mut ids = response
        .diagnostics()
        .reason()
        .filter_map(|id| policies.annotation(id, "id"))
        .filter(|id| id.starts_with("policy:") || id.starts_with("deny:policy:"))
        .map(str::to_owned)
        .collect::<Vec<_>>();
    ids.sort();
    ids.dedup();
    Ok(ids)
}

fn evaluate_rego(
    engine: &mut Engine,
    scenario: &VerificationScenario,
) -> Result<Vec<String>, CompileError> {
    engine
        .set_input_json(
            &serde_json::to_string(&json!({
                "action": scenario.action.cedar(),
                "facts": scenario.facts,
            }))
            .map_err(|error| CompileError::new(format!("Rego input: {error}")))?,
        )
        .map_err(|error| CompileError::new(format!("Rego input: {error}")))?;
    let value = engine
        .eval_rule("data.keel.policy.violations".to_owned())
        .map_err(|error| CompileError::new(format!("Rego evaluation: {error}")))?;
    let mut ids = value
        .as_set()
        .map_err(|error| CompileError::new(format!("Rego violations: {error}")))?
        .iter()
        .map(|value| {
            value
                .as_string()
                .map(std::string::ToString::to_string)
                .map_err(|error| CompileError::new(format!("Rego violation id: {error}")))
        })
        .collect::<Result<Vec<_>, _>>()?;
    ids.sort();
    Ok(ids)
}

fn artifact_hash(artifact: &PolicyArtifact) -> Result<String, CompileError> {
    let mut copy = artifact.clone();
    copy.hash.clear();
    let bytes = serde_json::to_vec(&copy)
        .map_err(|error| CompileError::new(format!("hash policy: {error}")))?;
    Ok(hash_framed(HASH_DOMAIN, &[&bytes]))
}

fn bundle_hash(schema: &str, policies: &str) -> String {
    hash_framed(
        BUNDLE_HASH_DOMAIN,
        &[schema.as_bytes(), policies.as_bytes()],
    )
}

fn hash_framed(domain: &[u8], fields: &[&[u8]]) -> String {
    let mut bytes = domain.to_vec();
    for field in fields {
        bytes.extend_from_slice(&(field.len() as u64).to_be_bytes());
        bytes.extend_from_slice(field);
    }
    digest(&SHA256, &bytes)
        .as_ref()
        .iter()
        .fold(String::new(), |mut output, byte| {
            let _ = write!(output, "{byte:02x}");
            output
        })
}

fn render_list(output: &mut String, values: &[String]) {
    if values.is_empty() {
        output.push_str("  (none)\n");
    } else {
        for value in values {
            let _ = writeln!(output, "  - {value}");
        }
    }
}

#[allow(clippy::too_many_lines)]
fn translation_schema() -> String {
    let no_value_condition = |kind: &str| {
        json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {"kind": {"const": kind}},
            "required": ["kind"]
        })
    };
    let ranked_condition = json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "kind": {"const": "floor-below"},
            "rank": {"type": "integer", "minimum": 0, "maximum": 3}
        },
        "required": ["kind", "rank"]
    });
    let counted_condition = |kind: &str| {
        json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "kind": {"const": kind},
                "count": {"type": "integer", "minimum": 1, "maximum": 1_000_000}
            },
            "required": ["kind", "count"]
        })
    };
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "repository": {"anyOf": [{"type": "string"}, {"type": "null"}]},
            "grants": {"type": "array", "items": {"anyOf": [
                {"enum": ["push:branch", "pr:create", "github:read-private-issues", "deny:force-push", "isolation:v8-sandboxed", "workspace:public"]},
                {"type": "string", "pattern": "^egress:[A-Za-z0-9._-]+$"},
                {"type": "string", "pattern": "^(push:ref:refs/heads/|pr:target:)[A-Za-z0-9._/-]+\\*?$"}
            ]}},
            "rules": {"type": "array", "items": {
                "type": "object", "additionalProperties": false,
                "properties": {
                    "id": {"type": "string"},
                    "effect": {"enum": ["escalate", "deny"]},
                    "action": {"enum": ["read", "write", "push", "run", "commit", "egress", "pull_request", "publish", "delete", "lift_floor"]},
                    "when": {
                        "type": "array",
                        "minItems": 1,
                        "items": {"oneOf": [
                            no_value_condition("always"),
                            ranked_condition,
                            counted_condition("writes-at-least"),
                            counted_condition("distinct-files-at-least"),
                            counted_condition("denials-at-least"),
                            counted_condition("escalations-at-least"),
                            no_value_condition("registry-contacted"),
                            no_value_condition("target-not-created-by-vertex"),
                            no_value_condition("source-outside-own-domains"),
                            no_value_condition("force-push")
                        ]}
                    },
                    "reason": {"type": "string"}
                },
                "required": ["id", "effect", "action", "when", "reason"]
            }},
            "tools": {"type": "array", "items": {
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "program": {"type": "string"},
                    "arguments": {"type": "array", "items": {
                        "type": "object",
                        "additionalProperties": false,
                        "properties": {
                            "selector": {"oneOf": [
                                {
                                    "type": "object",
                                    "additionalProperties": false,
                                    "properties": {
                                        "kind": {"const": "index"},
                                        "index": {"type": "integer", "minimum": 0, "maximum": 1024}
                                    },
                                    "required": ["kind", "index"]
                                },
                                {
                                    "type": "object",
                                    "additionalProperties": false,
                                    "properties": {
                                        "kind": {"const": "flag-value"},
                                        "flag": {"type": "string"}
                                    },
                                    "required": ["kind", "flag"]
                                }
                            ]},
                            "role": {"enum": ["read-path", "write-path", "delete-path"]}
                        },
                        "required": ["selector", "role"]
                    }}
                },
                "required": ["program", "arguments"]
            }},
            "blockers": {"type": "array", "items": {"type": "string"}},
            "notes": {"type": "array", "items": {"type": "string"}}
        },
        "required": ["repository", "grants", "rules", "tools", "blockers", "notes"]
    }).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn translation() -> PolicyTranslation {
        PolicyTranslation {
            repository: Some("example-org/keel-live-test".to_owned()),
            grants: vec!["push:branch".to_owned(), "egress:docs.rs".to_owned()],
            rules: vec![
                RuleSpec {
                    id: "low-floor-push".to_owned(),
                    effect: RuleEffect::Escalate,
                    action: RuleAction::Push,
                    when: vec![RuleCondition::FloorBelow { rank: 2 }],
                    reason: "Review pushes after lower-trust input".to_owned(),
                },
                RuleSpec {
                    id: "never-force".to_owned(),
                    effect: RuleEffect::Deny,
                    action: RuleAction::Push,
                    when: vec![RuleCondition::ForcePush],
                    reason: "Force pushes are prohibited".to_owned(),
                },
            ],
            tools: vec![ToolAnnotation {
                program: "cp".to_owned(),
                arguments: vec![
                    ToolArgument {
                        selector: ToolArgumentSelector::Index { index: 0 },
                        role: ToolArgumentRole::ReadPath,
                    },
                    ToolArgument {
                        selector: ToolArgumentSelector::Index { index: 1 },
                        role: ToolArgumentRole::WritePath,
                    },
                ],
            }],
            blockers: Vec::new(),
            notes: Vec::new(),
        }
    }

    #[test]
    fn draft_is_differentially_verified_and_hash_bound() {
        let mut artifact =
            PolicyArtifact::draft("A complete test policy.", translation(), 10).unwrap();
        assert!(artifact.verification.differential_passed);
        assert!(artifact.verification.scenarios >= 14);
        artifact.accept(20).unwrap();
        assert!(artifact.is_accepted().unwrap());
    }

    #[test]
    fn branch_scopes_keep_case_and_reject_traversal() {
        let mut value = translation();
        value.grants.extend([
            "push:ref:refs/heads/Feature/*".to_owned(),
            "pr:create".to_owned(),
            "pr:target:main".to_owned(),
        ]);
        let artifact =
            PolicyArtifact::draft("Push Feature branches, PR to main.", value, 10).unwrap();
        assert!(
            artifact
                .capabilities()
                .contains(&"push:ref:refs/heads/Feature/*".to_owned())
        );
        assert!(!artifact.has_blockers());

        for bad in [
            "push:ref:refs/heads/../main",
            "pr:target:a b",
            "push:ref:main",
        ] {
            let mut value = translation();
            value.grants.push(bad.to_owned());
            assert!(
                PolicyArtifact::draft("Bad scope.", value, 10).is_err(),
                "{bad}"
            );
        }
        let mut value = translation();
        value.grants.push("pr:target:main".to_owned());
        assert!(
            PolicyArtifact::draft("Target without create.", value, 10)
                .unwrap()
                .has_blockers()
        );
    }

    #[test]
    fn host_v8_is_a_closed_reviewable_grant() {
        let mut value = translation();
        value.grants.push("isolation:v8-sandboxed".to_owned());
        let artifact =
            PolicyArtifact::draft("Allow lower-assurance v8-sandboxed isolation.", value, 10)
                .unwrap();
        assert!(
            artifact
                .capabilities()
                .contains(&"isolation:v8-sandboxed".to_owned())
        );
    }

    #[test]
    fn private_issue_reads_are_a_closed_repository_scoped_grant() {
        let mut value = translation();
        value.grants.push("github:read-private-issues".to_owned());
        let artifact = PolicyArtifact::draft("Allow private issue reads.", value, 10).unwrap();
        assert!(
            artifact
                .capabilities()
                .contains(&"github:read-private-issues".to_owned())
        );

        let mut unscoped = translation();
        unscoped.repository = None;
        unscoped.grants = vec!["github:read-private-issues".to_owned()];
        let artifact = PolicyArtifact::draft("Allow private issue reads.", unscoped, 10).unwrap();
        assert!(artifact.has_blockers());
    }

    #[test]
    fn tampering_invalidates_artifact() {
        let mut artifact =
            PolicyArtifact::draft("A complete test policy.", translation(), 10).unwrap();
        artifact
            .cedar
            .push_str("\npermit(principal, action, resource);");
        assert!(artifact.accept(20).is_err());
    }

    #[test]
    fn invalid_condition_combinations_fail_closed() {
        let mut invalid = translation();
        invalid.rules[0].action = RuleAction::Read;
        invalid.rules[0].when = vec![RuleCondition::ForcePush];
        assert!(PolicyArtifact::draft("Invalid force-push condition.", invalid, 10).is_err());
    }

    #[test]
    fn blockers_without_rules_still_produce_a_reviewable_draft() {
        let blocked = PolicyTranslation {
            repository: None,
            grants: Vec::new(),
            rules: Vec::new(),
            tools: Vec::new(),
            blockers: vec!["A clause could not be represented".to_owned()],
            notes: Vec::new(),
        };
        let artifact = PolicyArtifact::draft("An unrepresentable policy.", blocked, 10).unwrap();
        assert!(artifact.has_blockers());
        let path = std::env::temp_dir().join(format!(
            "keel-blocked-policy-{}-{}.json",
            std::process::id(),
            artifact.hash
        ));
        artifact.save(&path).unwrap();
        let mut loaded = PolicyArtifact::load(&path).unwrap();
        let error = loaded.accept(20).unwrap_err();
        assert!(error.to_string().contains("unresolved blockers"));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn every_condition_variant_passes_differential_verification() {
        let conditions = [
            (RuleAction::Read, RuleCondition::Always),
            (RuleAction::Read, RuleCondition::FloorBelow { rank: 2 }),
            (RuleAction::Run, RuleCondition::WritesAtLeast { count: 3 }),
            (
                RuleAction::Commit,
                RuleCondition::DistinctFilesAtLeast { count: 4 },
            ),
            (
                RuleAction::Egress,
                RuleCondition::DenialsAtLeast { count: 2 },
            ),
            (
                RuleAction::Publish,
                RuleCondition::EscalationsAtLeast { count: 5 },
            ),
            (RuleAction::PullRequest, RuleCondition::RegistryContacted),
            (RuleAction::Write, RuleCondition::TargetNotCreatedByVertex),
            (RuleAction::Delete, RuleCondition::SourceOutsideOwnDomains),
            (RuleAction::Push, RuleCondition::ForcePush),
        ];
        let rules = conditions
            .into_iter()
            .enumerate()
            .map(|(index, (action, condition))| RuleSpec {
                id: format!("condition-{index}"),
                effect: RuleEffect::Escalate,
                action,
                when: vec![condition],
                reason: format!("Verify condition variant {index}"),
            })
            .collect();
        let complete = PolicyTranslation {
            repository: None,
            grants: Vec::new(),
            rules,
            tools: Vec::new(),
            blockers: Vec::new(),
            notes: Vec::new(),
        };

        let artifact =
            PolicyArtifact::draft("Exercise every closed policy condition.", complete, 10).unwrap();
        assert!(artifact.verification.differential_passed);
        assert!(artifact.verification.rule_coverage_complete);
        assert_eq!(artifact.verification.scenarios, 30);
    }

    #[test]
    fn review_diff_names_semantic_changes() {
        let old = PolicyArtifact::draft("Old policy.", translation(), 10).unwrap();
        let mut changed = translation();
        changed.rules[0].when = vec![RuleCondition::FloorBelow { rank: 3 }];
        let new = PolicyArtifact::draft("New policy.", changed, 11).unwrap();
        let diff = old.diff(&new);
        assert!(diff.contains("FloorBelow { rank: 2 }"));
        assert!(diff.contains("FloorBelow { rank: 3 }"));
    }

    #[test]
    fn translator_failure_reports_the_structured_stdout_error() {
        let output =
            r#"{"terminal_reason":"budget_exhausted","errors":["Reached maximum budget ($0.1)"]}"#;
        assert_eq!(
            translator_failure_detail(output),
            "Reached maximum budget ($0.1)"
        );
        assert_eq!(
            translator_failure_detail(r#"{"terminal_reason":"authentication_failed"}"#),
            "authentication_failed"
        );
        assert_eq!(
            translator_failure_detail(""),
            "translator returned no diagnostic"
        );
    }

    #[test]
    fn translator_schema_closes_every_nested_policy_shape() {
        let schema: serde_json::Value = serde_json::from_str(&translation_schema()).unwrap();
        let conditions =
            &schema["properties"]["rules"]["items"]["properties"]["when"]["items"]["oneOf"];
        assert_eq!(conditions.as_array().unwrap().len(), 10);
        assert_eq!(
            schema["properties"]["tools"]["items"]["required"],
            json!(["program", "arguments"])
        );
        assert_eq!(
            schema["properties"]["tools"]["items"]["properties"]["arguments"]["items"]["required"],
            json!(["selector", "role"])
        );
        assert!(
            schema["properties"]["grants"]["items"]["anyOf"][0]["enum"]
                .as_array()
                .unwrap()
                .contains(&json!("github:read-private-issues"))
        );
    }

    #[test]
    fn translator_knows_the_exact_branch_grant_semantics() {
        assert!(TRANSLATOR_SYSTEM.contains("ordinary, non-force"));
        assert!(TRANSLATOR_SYSTEM.contains("non-default branches"));
        assert!(TRANSLATOR_SYSTEM.contains("do not add a blocker"));
        assert!(TRANSLATOR_SYSTEM.contains("never push the default branch"));
        assert!(TRANSLATOR_SYSTEM.contains("github:read-private-issues"));
        assert!(TRANSLATOR_SYSTEM.contains("does not imply PR creation or push authority"));
    }
}
