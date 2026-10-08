#![forbid(unsafe_code)]
#![doc = "Trusted Cedar policy evaluator for Keel."]

use cedar_policy::{
    Authorizer, Context, Decision as CedarDecision, Entities, EntityUid, PolicySet, Request,
    Schema, ValidationMode, Validator,
};
use keel_kernel::{
    Action as KernelAction, ActionClass, Policy as KernelPolicy, Violation as KernelViolation,
};
pub use keel_provenance::{
    DenialObservation, DenialOrigin, DenialScope, FloorObservation, IntentFlags, SessionFacts,
    SourceRef,
};
use ring::digest::{SHA256, digest};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    error::Error,
    fmt, fs,
    path::{Component, Path, PathBuf},
    str::FromStr,
};

const SCHEMA: &str = include_str!("../policy/default/schema.cedarschema");
const POLICIES: &str = include_str!("../policy/default/policies.cedar");
const DEFAULT_ARTIFACT_HASH: &str =
    "a990d884d19fab84b67b4b403d37fb938d3f120b41580694b245d87ddb09b50b";
const HASH_DOMAIN: &[u8] = b"keel-policy-v1\0";

/// Returns the digest pinned for Keel's built-in default policy artifact.
///
/// # Panics
///
/// Panics only if the compile-time digest constant is malformed.
#[must_use]
pub fn default_artifact_hash() -> ArtifactHash {
    ArtifactHash::parse(DEFAULT_ARTIFACT_HASH).expect("built-in artifact hash must be valid")
}

/// A pinned SHA-256 digest for a policy artifact.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct ArtifactHash([u8; 32]);

impl ArtifactHash {
    /// Parses a lowercase or uppercase hexadecimal SHA-256 digest.
    ///
    /// # Errors
    ///
    /// Returns an error unless the input contains exactly 64 hexadecimal
    /// characters.
    pub fn parse(value: &str) -> Result<Self, PolicyError> {
        let value = value.trim();
        if value.len() != 64 {
            return Err(PolicyError(
                "artifact hash must contain 64 hexadecimal characters".to_owned(),
            ));
        }
        let mut bytes = [0_u8; 32];
        for (index, byte) in bytes.iter_mut().enumerate() {
            let offset = index * 2;
            *byte = u8::from_str_radix(&value[offset..offset + 2], 16)
                .map_err(|error| PolicyError::new("artifact hash", error))?;
        }
        Ok(Self(bytes))
    }
}

impl fmt::Debug for ArtifactHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&hex_hash(&self.0))
    }
}

impl fmt::Display for ArtifactHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&hex_hash(&self.0))
    }
}

/// Deliberately loaded and content-verified Cedar source bundle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyArtifact {
    schema: String,
    policies: String,
    hash: ArtifactHash,
}

impl PolicyArtifact {
    /// Loads `schema.cedarschema`, `policies.cedar`, and `bundle.sha256` from a
    /// directory and verifies both the manifest and caller-pinned digest.
    ///
    /// # Errors
    ///
    /// Returns an error for a missing file, malformed hash, caller/manifest
    /// mismatch, or content mismatch.
    pub fn load(directory: &Path, expected: ArtifactHash) -> Result<Self, PolicyError> {
        let schema = fs::read_to_string(directory.join("schema.cedarschema"))
            .map_err(|error| PolicyError::new("read schema", error))?;
        let policies = fs::read_to_string(directory.join("policies.cedar"))
            .map_err(|error| PolicyError::new("read policies", error))?;
        let manifest = fs::read_to_string(directory.join("bundle.sha256"))
            .map_err(|error| PolicyError::new("read bundle hash", error))?;
        let declared = ArtifactHash::parse(&manifest)?;
        if declared != expected {
            return Err(PolicyError(format!(
                "policy artifact manifest {declared} does not match pinned hash {expected}"
            )));
        }
        Self::verify(schema, policies, expected)
    }

    fn verify(
        schema: String,
        policies: String,
        expected: ArtifactHash,
    ) -> Result<Self, PolicyError> {
        let actual = hash_sources(&schema, &policies);
        if actual != expected {
            return Err(PolicyError(format!(
                "policy artifact content hash {actual} does not match pinned hash {expected}"
            )));
        }
        Ok(Self {
            schema,
            policies,
            hash: actual,
        })
    }

    /// Returns the verified artifact digest.
    #[must_use]
    pub const fn hash(&self) -> ArtifactHash {
        self.hash
    }
}

/// An action covered by the Phase 0 stateful-policy spike.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Action {
    /// A workspace read.
    Read,
    /// A workspace write.
    Write,
    /// A Git push.
    Push,
    /// A command execution.
    Run,
    /// A local Git commit.
    Commit,
    /// An outbound network request.
    Egress,
    /// A pull-request operation.
    PullRequest,
    /// An external publication.
    Publish,
    /// A workspace deletion.
    Delete,
    /// A provenance-floor lift.
    LiftFloor,
}

impl Action {
    const fn cedar_id(self) -> &'static str {
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

/// The policy outcome used by the kernel's escalation pipeline.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Decision {
    /// Continue without operator intervention.
    Allow,
    /// Require an operator decision.
    Escalate,
}

/// One Cedar rule contributing to an escalation.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PolicyViolation {
    /// Stable Cedar policy identifier.
    pub rule: String,
}

/// Complete policy evaluation. Automatic execution is allowed only when
/// `violations` is empty.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyEvaluation {
    /// Every rule that rejected the action.
    pub violations: Vec<PolicyViolation>,
}

impl PolicyEvaluation {
    /// Converts the complete violation set to the legacy binary decision.
    #[must_use]
    pub const fn decision(&self) -> Decision {
        if self.violations.is_empty() {
            Decision::Allow
        } else {
            Decision::Escalate
        }
    }
}

/// A policy parse, validation, request, or evaluation failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyError(String);

impl PolicyError {
    fn new(context: &str, error: impl fmt::Display) -> Self {
        Self(format!("{context}: {error}"))
    }
}

impl fmt::Display for PolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for PolicyError {}

/// Parsed and strictly validated Phase 0 policy bundle.
pub struct StatefulPolicy {
    policies: PolicySet,
    schema: Schema,
    baseline: Option<(PolicySet, Schema)>,
    artifact_hash: ArtifactHash,
}

impl StatefulPolicy {
    /// Parses the schema and policy bundle and rejects any validation error or
    /// warning.
    ///
    /// # Errors
    ///
    /// Returns an error if Cedar cannot parse or strictly validate the schema
    /// and policy bundle.
    pub fn new() -> Result<Self, PolicyError> {
        let expected = ArtifactHash::parse(DEFAULT_ARTIFACT_HASH)?;
        let artifact = PolicyArtifact::verify(SCHEMA.to_owned(), POLICIES.to_owned(), expected)?;
        Self::from_artifact(&artifact, false)
    }

    /// Loads a deliberately selected, caller-pinned policy artifact.
    ///
    /// # Errors
    ///
    /// Returns an error when the artifact files, hashes, schema, or policies
    /// fail validation.
    pub fn load(directory: &Path, expected: ArtifactHash) -> Result<Self, PolicyError> {
        Self::from_artifact(&PolicyArtifact::load(directory, expected)?, true)
    }

    fn from_artifact(
        artifact: &PolicyArtifact,
        retain_builtin_baseline: bool,
    ) -> Result<Self, PolicyError> {
        Self::from_sources(
            &artifact.schema,
            &artifact.policies,
            retain_builtin_baseline,
        )
    }

    fn from_sources(
        schema_source: &str,
        policy_source: &str,
        retain_builtin_baseline: bool,
    ) -> Result<Self, PolicyError> {
        let (policies, schema) = parse_policy_sources(schema_source, policy_source)?;
        let baseline = retain_builtin_baseline
            .then(|| parse_policy_sources(SCHEMA, POLICIES))
            .transpose()?;
        Ok(Self {
            policies,
            schema,
            baseline,
            artifact_hash: hash_sources(schema_source, policy_source),
        })
    }

    /// Returns the digest of the loaded policy source.
    #[must_use]
    pub const fn artifact_hash(&self) -> ArtifactHash {
        self.artifact_hash
    }

    /// Evaluates an action using raw session facts represented as Cedar context
    /// attributes and source entities.
    ///
    /// # Errors
    ///
    /// Returns an error if the facts cannot be represented by the schema or
    /// Cedar reports an evaluation error.
    pub fn evaluate(
        &self,
        action: Action,
        facts: &SessionFacts,
    ) -> Result<PolicyEvaluation, PolicyError> {
        self.evaluate_target(action, facts, false)
    }

    fn evaluate_target(
        &self,
        action: Action,
        facts: &SessionFacts,
        target_is_force_push: bool,
    ) -> Result<PolicyEvaluation, PolicyError> {
        let mut violations = evaluate_policy_set(
            &self.policies,
            &self.schema,
            action,
            facts,
            target_is_force_push,
        )?;
        if let Some((policies, schema)) = &self.baseline {
            violations.extend(evaluate_policy_set(
                policies,
                schema,
                action,
                facts,
                target_is_force_push,
            )?);
        }
        violations.sort();
        violations.dedup();
        Ok(PolicyEvaluation { violations })
    }

    /// Evaluates an action and returns its binary compatibility decision.
    ///
    /// # Errors
    ///
    /// Returns an error if Cedar cannot completely evaluate the request.
    pub fn decide(&self, action: Action, facts: &SessionFacts) -> Result<Decision, PolicyError> {
        self.evaluate(action, facts)
            .map(|evaluation| evaluation.decision())
    }

    /// Exhaustively checks the boundary values used by the five Phase 2
    /// rules. This catches accidental over- and under-permissiveness in the
    /// shipped finite scenario model.
    ///
    /// # Errors
    ///
    /// Returns an error if a scenario cannot be evaluated or its decision does
    /// not match the independently computed expectation.
    pub fn analyze_scenarios(&self) -> Result<(), PolicyError> {
        for distinct_writes in [19, 20] {
            for recent_behavioral_denials in [2, 3] {
                for target_created in [false, true] {
                    for registry in [false, true] {
                        for allow_push in [false, true] {
                            for host_case in [HostCase::None, HostCase::Owned, HostCase::Unowned] {
                                for action in [Action::Read, Action::Write, Action::Push] {
                                    let mut facts = SessionFacts::default();
                                    facts.recent_behavioral_denials_in_scope =
                                        recent_behavioral_denials;
                                    facts.distinct_files_written_60s = distinct_writes;
                                    facts.own_domains = ["keel.example".to_owned()].into();
                                    facts.sources_read = host_case.sources();
                                    facts.target_created_by_vertex = target_created;
                                    facts.registries_contacted = registry;
                                    facts.intent.allow_push_branch = allow_push;
                                    let actual = self.decide(action, &facts)?;
                                    let expected = if recent_behavioral_denials >= 3
                                        || (action == Action::Write
                                            && (registry
                                                || (distinct_writes >= 20 && !target_created)))
                                        || (action == Action::Push
                                            && (!allow_push || host_case == HostCase::Unowned))
                                    {
                                        Decision::Escalate
                                    } else {
                                        Decision::Allow
                                    };
                                    if actual != expected {
                                        return Err(PolicyError(format!(
                                            "scenario mismatch: action={action:?}, facts={facts:?}, expected={expected:?}, actual={actual:?}"
                                        )));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

fn parse_policy_sources(
    schema_source: &str,
    policy_source: &str,
) -> Result<(PolicySet, Schema), PolicyError> {
    review_context_booleans(schema_source)?;
    let (schema, schema_warnings) = Schema::from_cedarschema_str(schema_source)
        .map_err(|error| PolicyError::new("schema", error))?;
    let warnings = schema_warnings.collect::<Vec<_>>();
    if !warnings.is_empty() {
        return Err(PolicyError::new(
            "schema warnings",
            warnings
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("; "),
        ));
    }
    let policies = PolicySet::from_str(policy_source)
        .map_err(|error| PolicyError::new("policy parse", error))?;
    let validation = Validator::new(schema.clone()).validate(&policies, ValidationMode::Strict);
    if !validation.validation_passed_without_warnings() {
        return Err(PolicyError::new(
            "policy validation",
            validation
                .validation_errors()
                .map(ToString::to_string)
                .chain(validation.validation_warnings().map(ToString::to_string))
                .collect::<Vec<_>>()
                .join("; "),
        ));
    }
    Ok((policies, schema))
}

fn evaluate_policy_set(
    policies: &PolicySet,
    schema: &Schema,
    action: Action,
    facts: &SessionFacts,
    target_is_force_push: bool,
) -> Result<Vec<PolicyViolation>, PolicyError> {
    let action_uid = EntityUid::from_str(&format!(r#"Action::"{}""#, action.cedar_id()))
        .map_err(|error| PolicyError::new("action uid", error))?;
    let (context_value, entities_value) = cedar_values(facts, target_is_force_push);
    let context = Context::from_json_value(context_value, Some((schema, &action_uid)))
        .map_err(|error| PolicyError::new("request context", error))?;
    let entities = Entities::from_json_value(entities_value, Some(schema))
        .map_err(|error| PolicyError::new("source entities", error))?;
    let request = Request::new(
        EntityUid::from_str(r#"Vertex::"current""#)
            .map_err(|error| PolicyError::new("principal uid", error))?,
        action_uid,
        EntityUid::from_str(r#"Target::"current""#)
            .map_err(|error| PolicyError::new("resource uid", error))?,
        context,
        Some(schema),
    )
    .map_err(|error| PolicyError::new("request", error))?;
    let response = Authorizer::new().is_authorized(&request, policies, &entities);
    let errors = response
        .diagnostics()
        .errors()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    if !errors.is_empty() {
        return Err(PolicyError::new("authorization", errors.join("; ")));
    }
    let mut violations = if response.decision() == CedarDecision::Deny {
        response
            .diagnostics()
            .reason()
            .map(|rule| PolicyViolation {
                rule: policies
                    .annotation(rule, "id")
                    .map_or_else(|| rule.to_string(), str::to_owned),
            })
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    if response.decision() == CedarDecision::Deny && violations.is_empty() {
        violations.push(PolicyViolation {
            rule: "cedar:default-deny".to_owned(),
        });
    }
    Ok(violations)
}

impl KernelPolicy for StatefulPolicy {
    fn violations(
        &self,
        action: &KernelAction,
        facts: &SessionFacts,
    ) -> Result<Vec<KernelViolation>, String> {
        let target_is_force_push = matches!(
            action.asserted().target,
            keel_kernel::Target::Git { is_force: true, .. }
        );
        let action = match action.asserted().class {
            ActionClass::ReadWorkspace => Action::Read,
            ActionClass::WriteWorkspace | ActionClass::WriteOutsideWorkspace => Action::Write,
            ActionClass::RunCommand => Action::Run,
            ActionClass::GitCommit => Action::Commit,
            ActionClass::GitPush => Action::Push,
            ActionClass::Egress => Action::Egress,
            ActionClass::PullRequest => Action::PullRequest,
            ActionClass::Publish => Action::Publish,
            ActionClass::DeleteOutsideWorkspace => Action::Delete,
            ActionClass::LiftFloor => Action::LiftFloor,
        };
        self.evaluate_target(action, facts, target_is_force_push)
            .map(|evaluation| {
                evaluation
                    .violations
                    .into_iter()
                    .map(|violation| {
                        KernelViolation::new(
                            violation.rule,
                            "stateful Cedar policy requires operator approval",
                        )
                    })
                    .collect()
            })
            .map_err(|error| error.to_string())
    }
}

/// Security meaning assigned to a command argument.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArgumentRole {
    /// Argument is not a filesystem path.
    Opaque,
    /// Path whose content will be read.
    ReadPath,
    /// Path whose content may be created or changed.
    WritePath,
    /// Path that may be removed.
    DeletePath,
}

/// How a declared command locates an argument.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ArgumentSelector {
    /// Zero-based index in the exact argument vector.
    Index(usize),
    /// Value immediately following an exact flag.
    FlagValue(String),
}

/// One reviewed command-argument annotation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArgumentBinding {
    /// Argument location.
    pub selector: ArgumentSelector,
    /// Security role assigned at that location.
    pub role: ArgumentRole,
}

/// Reviewed annotations for one executable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandProfile {
    /// Exact executable name accepted by the mediator.
    pub program: String,
    /// Path-bearing argument declarations.
    pub bindings: Vec<ArgumentBinding>,
}

/// One argument after role classification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClassifiedArgument {
    /// Index in the original argument vector.
    pub index: usize,
    /// Exact argument value.
    pub value: String,
    /// Reviewed security role.
    pub role: ArgumentRole,
}

/// Startup-validated command argument classifier.
#[derive(Clone, Debug)]
pub struct ArgumentClassifier {
    profiles: BTreeMap<String, CommandProfile>,
}

impl ArgumentClassifier {
    /// Registers reviewed command profiles.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty or duplicate program declaration, an
    /// opaque binding, or a duplicate selector.
    pub fn new(profiles: impl IntoIterator<Item = CommandProfile>) -> Result<Self, PolicyError> {
        let mut by_program = BTreeMap::new();
        for profile in profiles {
            if profile.program.is_empty() {
                return Err(PolicyError(
                    "command profile has an empty program".to_owned(),
                ));
            }
            if profile
                .bindings
                .iter()
                .any(|binding| binding.role == ArgumentRole::Opaque)
            {
                return Err(PolicyError(format!(
                    "command profile `{}` declares an opaque binding",
                    profile.program
                )));
            }
            for (index, binding) in profile.bindings.iter().enumerate() {
                if profile.bindings[..index]
                    .iter()
                    .any(|other| other.selector == binding.selector)
                {
                    return Err(PolicyError(format!(
                        "command profile `{}` repeats an argument selector",
                        profile.program
                    )));
                }
            }
            let name = profile.program.clone();
            if by_program.insert(name.clone(), profile).is_some() {
                return Err(PolicyError(format!("duplicate command profile `{name}`")));
            }
        }
        Ok(Self {
            profiles: by_program,
        })
    }

    /// Classifies every exact argument, leaving undeclared arguments opaque.
    ///
    /// # Errors
    ///
    /// Returns an error for an undeclared program, a missing flag value, or
    /// conflicting bindings that resolve to the same argument.
    pub fn classify(
        &self,
        program: &str,
        arguments: &[String],
    ) -> Result<Vec<ClassifiedArgument>, PolicyError> {
        let profile = self
            .profiles
            .get(program)
            .ok_or_else(|| PolicyError(format!("unclassified command `{program}`")))?;
        let mut roles = vec![ArgumentRole::Opaque; arguments.len()];
        for binding in &profile.bindings {
            let index = match &binding.selector {
                ArgumentSelector::Index(index) => {
                    if *index >= arguments.len() {
                        continue;
                    }
                    *index
                }
                ArgumentSelector::FlagValue(flag) => {
                    let Some(flag_index) = arguments.iter().position(|argument| argument == flag)
                    else {
                        continue;
                    };
                    flag_index
                        .checked_add(1)
                        .filter(|index| *index < arguments.len())
                        .ok_or_else(|| {
                            PolicyError(format!("command `{program}` flag `{flag}` has no value"))
                        })?
                }
            };
            if roles[index] != ArgumentRole::Opaque && roles[index] != binding.role {
                return Err(PolicyError(format!(
                    "command `{program}` assigns conflicting roles to argument {index}"
                )));
            }
            roles[index] = binding.role;
        }
        Ok(arguments
            .iter()
            .zip(roles)
            .enumerate()
            .map(|(index, (value, role))| ClassifiedArgument {
                index,
                value: value.clone(),
                role,
            })
            .collect())
    }
}

/// Filesystem operation used during real-path containment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathAccess {
    /// Target must already exist and will be read.
    Read,
    /// Target may be newly created.
    Write,
    /// Target must already exist and may be removed.
    Delete,
}

/// Canonical path proven to be within a canonical workspace root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContainedPath {
    canonical: PathBuf,
    access: PathAccess,
}

impl ContainedPath {
    /// Returns the canonical target path.
    #[must_use]
    pub fn as_path(&self) -> &Path {
        &self.canonical
    }

    /// Returns the operation used to resolve this path.
    #[must_use]
    pub const fn access(&self) -> PathAccess {
        self.access
    }
}

/// Resolves a path through symlinks and proves it remains under the workspace.
///
/// Missing write targets are resolved through their nearest existing parent.
/// The executor must use this returned path directly and retain the containing
/// directory handle to close the later open-time race.
///
/// # Errors
///
/// Returns an error when the workspace or required target cannot be resolved,
/// a missing write target uses parent traversal, or the resolved target escapes
/// the workspace.
pub fn resolve_contained_path(
    workspace: &Path,
    candidate: &Path,
    access: PathAccess,
) -> Result<ContainedPath, PolicyError> {
    let workspace = fs::canonicalize(workspace)
        .map_err(|error| PolicyError::new("canonicalize workspace", error))?;
    let joined = if candidate.is_absolute() {
        candidate.to_path_buf()
    } else {
        workspace.join(candidate)
    };
    let canonical = if path_entry_exists(&joined) || access != PathAccess::Write {
        fs::canonicalize(&joined).map_err(|error| PolicyError::new("canonicalize target", error))?
    } else {
        resolve_missing_write(&joined)?
    };
    if !canonical.starts_with(&workspace) {
        return Err(PolicyError(format!(
            "resolved path `{}` escapes workspace `{}`",
            canonical.display(),
            workspace.display()
        )));
    }
    Ok(ContainedPath { canonical, access })
}

fn resolve_missing_write(path: &Path) -> Result<PathBuf, PolicyError> {
    if path
        .components()
        .any(|component| component == Component::ParentDir)
    {
        return Err(PolicyError(
            "missing write target contains parent traversal".to_owned(),
        ));
    }
    let mut existing = path;
    let mut missing = Vec::new();
    while !path_entry_exists(existing) {
        let name = existing.file_name().ok_or_else(|| {
            PolicyError("missing write target has no existing ancestor".to_owned())
        })?;
        missing.push(name.to_owned());
        existing = existing.parent().ok_or_else(|| {
            PolicyError("missing write target has no existing ancestor".to_owned())
        })?;
    }
    let mut resolved = fs::canonicalize(existing)
        .map_err(|error| PolicyError::new("canonicalize write parent", error))?;
    for component in missing.into_iter().rev() {
        resolved.push(component);
    }
    Ok(resolved)
}

fn path_entry_exists(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

fn hash_sources(schema: &str, policies: &str) -> ArtifactHash {
    let mut framed = Vec::with_capacity(HASH_DOMAIN.len() + schema.len() + policies.len() + 16);
    framed.extend_from_slice(HASH_DOMAIN);
    framed.extend_from_slice(&(schema.len() as u64).to_be_bytes());
    framed.extend_from_slice(schema.as_bytes());
    framed.extend_from_slice(&(policies.len() as u64).to_be_bytes());
    framed.extend_from_slice(policies.as_bytes());
    let hash = digest(&SHA256, &framed);
    let mut bytes = [0_u8; 32];
    bytes.copy_from_slice(hash.as_ref());
    ArtifactHash(bytes)
}

fn hex_hash(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn review_context_booleans(schema: &str) -> Result<(), PolicyError> {
    const RAW_BOOLEAN_FACTS: [&str; 6] = [
        "allow_pr_create",
        "allow_push_branch",
        "deny_force_push",
        "registries_contacted",
        "target_created_by_vertex",
        "target_is_force_push",
    ];
    if !schema.contains("context: {") {
        return Err(PolicyError(
            "policy review: context schema is missing".to_owned(),
        ));
    }
    for line in schema.lines().map(str::trim) {
        if let Some((name, value_type)) = line.split_once(':')
            && value_type.trim().trim_end_matches(',') == "Bool"
            && !RAW_BOOLEAN_FACTS.contains(&name.trim())
        {
            return Err(PolicyError(format!(
                "policy review: pre-digested boolean context `{}` is prohibited",
                name.trim()
            )));
        }
    }
    Ok(())
}

fn cedar_values(facts: &SessionFacts, target_is_force_push: bool) -> (Value, Value) {
    let mut all_sources = facts.sources_read.clone();
    all_sources.extend(
        facts
            .floor_history
            .iter()
            .map(|observation| observation.source.clone()),
    );
    let source_ids = all_sources
        .iter()
        .enumerate()
        .map(|(index, source)| (source.clone(), format!("source-{index}")))
        .collect::<BTreeMap<_, _>>();
    let source_ref = |source: &SourceRef| {
        json!({"__entity": {
            "type": "SourceRef",
            "id": source_ids.get(source).expect("source id"),
        }})
    };
    let source_refs = facts
        .sources_read
        .iter()
        .map(source_ref)
        .collect::<Vec<_>>();
    let mut source_hosts = Vec::new();
    let mut entities = Vec::with_capacity(all_sources.len() + facts.floor_history.len());

    for source in &all_sources {
        let id = source_ids.get(source).expect("source id");
        if let SourceRef::Host { host, .. } = source {
            source_hosts.push(host);
        }
        let (kind, host, path, author, server, tool, command) = source_attributes(source);
        entities.push(json!({
            "uid": {"type": "SourceRef", "id": id},
            "attrs": {
                "kind": kind,
                "host": host,
                "path": path,
                "author": author,
                "server": server,
                "tool": tool,
                "command": command,
            },
            "parents": [],
        }));
    }
    let floor_history = facts
        .floor_history
        .iter()
        .enumerate()
        .map(|(index, observation)| {
            let id = format!("floor-{index}");
            entities.push(json!({
                "uid": {"type": "FloorObservation", "id": id},
                "attrs": {
                    "rank": observation.rank,
                    "source": source_ref(&observation.source),
                    "timestamp_ms": observation.timestamp_ms,
                },
                "parents": [],
            }));
            json!({"__entity": {"type": "FloorObservation", "id": id}})
        })
        .collect::<Vec<_>>();

    (
        json!({
            "files_created_by_this_vertex": facts.files_created_by_this_vertex,
            "files_written_by_this_vertex": facts.files_written_by_this_vertex,
            "hosts_contacted": facts.hosts_contacted,
            "registries_contacted": facts.registries_contacted,
            "writes_last_60s": facts.writes_last_60s,
            "denied_actions": facts.denied_actions,
            "recent_behavioral_denials_in_scope": facts.recent_behavioral_denials_in_scope,
            "escalated_actions": facts.escalated_actions,
            "distinct_files_written_60s": facts.distinct_files_written_60s,
            "floor": facts.floor,
            "floor_history": floor_history,
            "own_domains": facts.own_domains,
            "source_hosts": source_hosts,
            "sources_read": source_refs,
            "intent": {
                "allow_push_branch": facts.intent.allow_push_branch,
                "allow_pr_create": facts.intent.allow_pr_create,
                "deny_force_push": facts.intent.deny_force_push,
                "allowed_egress_hosts": facts.intent.allowed_egress_hosts,
            },
            "target_is_force_push": target_is_force_push,
            "target_created_by_vertex": facts.target_created_by_vertex,
        }),
        Value::Array(entities),
    )
}

fn source_attributes(source: &SourceRef) -> (&str, &str, &str, &str, &str, &str, &str) {
    match source {
        SourceRef::File { path, author } => (
            "File",
            "",
            path,
            author.as_deref().unwrap_or(""),
            "",
            "",
            "",
        ),
        SourceRef::Host { host, path } => ("Host", host, path, "", "", "", ""),
        SourceRef::Mcp { server, tool } => ("Mcp", "", "", "", server, tool, ""),
        SourceRef::Shell { command } => ("Shell", "", "", "", "", "", command),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HostCase {
    None,
    Owned,
    Unowned,
}

impl HostCase {
    fn sources(self) -> std::collections::BTreeSet<SourceRef> {
        match self {
            Self::None => std::collections::BTreeSet::new(),
            Self::Owned => [SourceRef::Host {
                host: "keel.example".to_owned(),
                path: "/issue/1".to_owned(),
            }]
            .into(),
            Self::Unowned => [SourceRef::Host {
                host: "evil.example".to_owned(),
                path: "/payload".to_owned(),
            }]
            .into(),
        }
    }
}

#[cfg(test)]
mod review_tests {
    use super::{Action, POLICIES, SCHEMA, StatefulPolicy};
    use keel_provenance::SessionFacts;

    #[test]
    fn rejects_a_rule_supplied_as_a_pre_digested_boolean() {
        let broken_schema = SCHEMA.replace(
            "target_created_by_vertex: Bool,",
            "target_created_by_vertex: Bool,\n        push_after_unowned_host: Bool,",
        );
        let broken_policy = format!(
            "{POLICIES}\nforbid (principal, action, resource) when {{\n    context.push_after_unowned_host\n}};"
        );
        let Err(error) = StatefulPolicy::from_sources(&broken_schema, &broken_policy, false) else {
            panic!("pre-digested policy booleans must fail review");
        };
        assert!(
            error
                .to_string()
                .contains("pre-digested boolean context `push_after_unowned_host`")
        );
    }

    #[test]
    fn force_push_constraint_reads_the_raw_target_fact() {
        let policy = StatefulPolicy::new().unwrap();
        let mut facts = SessionFacts::default();
        facts.intent.allow_push_branch = true;
        facts.intent.deny_force_push = true;
        assert!(
            policy
                .evaluate_target(Action::Push, &facts, false)
                .unwrap()
                .violations
                .is_empty()
        );
        assert_eq!(
            policy
                .evaluate_target(Action::Push, &facts, true)
                .unwrap()
                .violations[0]
                .rule,
            "deny:force-push"
        );
    }

    #[test]
    fn custom_policy_cannot_remove_builtin_restrictions() {
        let policy =
            StatefulPolicy::from_sources(SCHEMA, "permit (principal, action, resource);", true)
                .unwrap();
        let facts = SessionFacts::default();
        assert_eq!(
            policy.evaluate(Action::Push, &facts).unwrap().violations[0].rule,
            "push-without-structured-intent"
        );
    }
}
