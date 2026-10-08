#![forbid(unsafe_code)]
#![doc = "Untrusted natural-language policy compilation for Keel."]

mod policy;

pub use policy::{
    PolicyArtifact, PolicyTranslation, RuleAction, RuleCondition, RuleEffect, RuleSpec,
    ToolAnnotation, ToolArgument, ToolArgumentRole, ToolArgumentSelector, VerificationReport,
    VerificationScenario, load_policy_translation, translate_policy_with_claude,
};

use ring::digest::{SHA256, digest};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    error::Error,
    fmt::{self, Write as _},
    fs,
    io::Write as _,
    path::Path,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

/// Identifies this crate as outside the trusted computing base.
pub const TRUST_CLASS: &str = "untrusted";

const FORMAT: &str = "keel-session-policy-v1";
const HASH_DOMAIN: &[u8] = b"keel-session-policy-v1\0";
const MAX_SOURCE_BYTES: usize = 16 * 1024;
const MAX_FIELD_BYTES: usize = 512;

/// One model-proposed interpretation. This is untrusted until validated and
/// accepted into a content-hashed artifact.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SessionPolicyTranslation {
    /// Optional exact GitHub repository in `owner/name` form.
    pub repository: Option<String>,
    /// Proposed grants using Keel's closed capability vocabulary.
    pub grants: Vec<String>,
    /// Proposed non-overridable constraints using Keel's closed vocabulary.
    #[serde(default)]
    pub constraints: Vec<String>,
    /// Clauses that could not be represented safely.
    #[serde(default)]
    pub blockers: Vec<String>,
    /// Non-security explanatory notes shown during review.
    #[serde(default)]
    pub notes: Vec<String>,
}

/// Lifecycle state for one policy artifact.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ArtifactStatus {
    /// Generated interpretation that cannot affect a run.
    Draft,
    /// Deliberately accepted interpretation eligible for `keel run --policy`.
    Accepted,
}

/// Validated deterministic interpretation of natural-language intent.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Interpretation {
    /// Optional exact GitHub repository in `owner/name` form.
    pub repository: Option<String>,
    /// Sorted, deduplicated runtime capabilities.
    pub capabilities: Vec<String>,
    /// Clauses that prevent acceptance.
    pub blockers: Vec<String>,
    /// Explanatory notes shown during review.
    pub notes: Vec<String>,
    /// Policy lifetime. V1 deliberately supports only the current run.
    pub lifetime: String,
}

/// Content-hashed natural-language session policy.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SessionPolicyArtifact {
    /// Stable artifact format identifier.
    pub format: String,
    /// Whether this is a draft or deliberately accepted artifact.
    pub status: ArtifactStatus,
    /// Exact operator text that was translated.
    pub source: String,
    /// Validated interpretation consumed by the CLI.
    pub interpretation: Interpretation,
    /// Creation time as Unix milliseconds.
    pub created_at_ms: u64,
    /// Acceptance time as Unix milliseconds.
    pub accepted_at_ms: Option<u64>,
    /// SHA-256 over every other artifact field.
    pub hash: String,
}

/// Policy translation, validation, artifact, or model error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompileError(String);

impl CompileError {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for CompileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for CompileError {}

impl SessionPolicyArtifact {
    /// Builds a validated draft from untrusted translator output.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed source text, repository scope, host
    /// names, capabilities, or translator fields.
    pub fn draft(
        source: &str,
        translation: SessionPolicyTranslation,
        created_at_ms: u64,
    ) -> Result<Self, CompileError> {
        validate_source(source)?;
        let repository = translation
            .repository
            .as_deref()
            .map(normalize_repository)
            .transpose()?;
        let mut capabilities = BTreeSet::new();
        for grant in translation.grants {
            capabilities.insert(normalize_capability(&grant)?);
        }
        for constraint in translation.constraints {
            capabilities.insert(normalize_constraint(&constraint)?);
        }
        let mut blockers = validate_messages(translation.blockers, "blocker")?;
        let notes = validate_messages(translation.notes, "note")?;
        let needs_repository = capabilities.iter().any(|capability| {
            matches!(
                capability.as_str(),
                "push:branch" | "pr:create" | "github:read-private-issues"
            ) || capability.starts_with("push:ref:")
                || capability.starts_with("pr:target:")
        });
        if capabilities
            .iter()
            .any(|capability| capability.starts_with("pr:target:"))
            && !capabilities.contains("pr:create")
        {
            blockers.push("pr:target narrows pr:create and requires it".to_owned());
        }
        if needs_repository && repository.is_none() {
            blockers.push(
                "repository-scoped grants require an exact GitHub repository in owner/name form"
                    .to_owned(),
            );
        }
        add_independent_safety_blockers(
            source,
            capabilities.contains("deny:force-push"),
            &mut blockers,
        );
        blockers.sort();
        blockers.dedup();
        if capabilities.is_empty() {
            blockers.push("the policy contains no supported grants".to_owned());
        }
        let mut artifact = Self {
            format: FORMAT.to_owned(),
            status: ArtifactStatus::Draft,
            source: source.to_owned(),
            interpretation: Interpretation {
                repository,
                capabilities: capabilities.into_iter().collect(),
                blockers,
                notes,
                lifetime: "session".to_owned(),
            },
            created_at_ms,
            accepted_at_ms: None,
            hash: String::new(),
        };
        artifact.rehash()?;
        Ok(artifact)
    }

    /// Reads and verifies a policy artifact.
    ///
    /// # Errors
    ///
    /// Returns an error for I/O, JSON, format, or hash failures.
    pub fn load(path: &Path) -> Result<Self, CompileError> {
        let bytes = fs::read(path)
            .map_err(|error| CompileError::new(format!("cannot read policy artifact: {error}")))?;
        if bytes.len() > MAX_SOURCE_BYTES * 4 {
            return Err(CompileError::new("policy artifact is too large"));
        }
        let artifact: Self = serde_json::from_slice(&bytes)
            .map_err(|error| CompileError::new(format!("invalid policy artifact: {error}")))?;
        artifact.verify()?;
        Ok(artifact)
    }

    /// Writes the artifact as formatted JSON.
    ///
    /// # Errors
    ///
    /// Returns an error for serialization or I/O failures.
    pub fn save(&self, path: &Path) -> Result<(), CompileError> {
        self.verify()?;
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent).map_err(|error| {
                CompileError::new(format!("cannot create policy directory: {error}"))
            })?;
        }
        let bytes = serde_json::to_vec_pretty(self)
            .map_err(|error| CompileError::new(format!("cannot serialize policy: {error}")))?;
        fs::write(path, bytes)
            .map_err(|error| CompileError::new(format!("cannot write policy artifact: {error}")))
    }

    /// Accepts a blocker-free draft and refreshes its content hash.
    ///
    /// # Errors
    ///
    /// Returns an error unless this is a valid draft with no unresolved
    /// blockers.
    pub fn accept(&mut self, accepted_at_ms: u64) -> Result<(), CompileError> {
        self.verify()?;
        if self.status != ArtifactStatus::Draft {
            return Err(CompileError::new("policy artifact is already accepted"));
        }
        if !self.interpretation.blockers.is_empty() {
            return Err(CompileError::new(
                "policy has unresolved blockers and cannot be accepted",
            ));
        }
        self.status = ArtifactStatus::Accepted;
        self.accepted_at_ms = Some(accepted_at_ms);
        self.rehash()
    }

    /// Returns accepted runtime capabilities.
    ///
    /// # Errors
    ///
    /// Returns an error for a draft, invalid artifact, or unresolved blocker.
    pub fn accepted_capabilities(&self) -> Result<&[String], CompileError> {
        self.verify()?;
        if self.status != ArtifactStatus::Accepted {
            return Err(CompileError::new(
                "policy is still a draft; run `keel policy accept` first",
            ));
        }
        if !self.interpretation.blockers.is_empty() {
            return Err(CompileError::new("accepted policy contains blockers"));
        }
        Ok(&self.interpretation.capabilities)
    }

    /// Returns the exact repository scope, when one was requested.
    #[must_use]
    pub fn repository(&self) -> Option<&str> {
        self.interpretation.repository.as_deref()
    }

    /// Renders the full interpretation for operator review.
    #[must_use]
    pub fn review(&self) -> String {
        let mut output = format!(
            "Keel policy {}\nstatus: {:?}\nhash: {}\nlifetime: current session\n",
            self.format, self.status, self.hash
        );
        let _ = write!(
            output,
            "repository: {}\ngrants:\n",
            self.repository().unwrap_or("(none)")
        );
        let grants = self
            .interpretation
            .capabilities
            .iter()
            .filter(|capability| !capability.starts_with("deny:"))
            .collect::<Vec<_>>();
        if grants.is_empty() {
            output.push_str("  (none)\n");
        } else {
            for capability in grants {
                let _ = writeln!(output, "  - {capability}");
            }
        }
        output.push_str("blockers:\n");
        if self.interpretation.blockers.is_empty() {
            output.push_str("  (none)\n");
        } else {
            for blocker in &self.interpretation.blockers {
                let _ = writeln!(output, "  - {blocker}");
            }
        }
        let constraints = self
            .interpretation
            .capabilities
            .iter()
            .filter(|capability| capability.starts_with("deny:"))
            .collect::<Vec<_>>();
        if !constraints.is_empty() {
            output.push_str("non-overridable constraints:\n");
            for constraint in constraints {
                let _ = writeln!(output, "  - {constraint}");
            }
        }
        if !self.interpretation.notes.is_empty() {
            output.push_str("notes:\n");
            for note in &self.interpretation.notes {
                let _ = writeln!(output, "  - {note}");
            }
        }
        output.push_str("source:\n");
        output.push_str(&self.source);
        output.push('\n');
        output
    }

    fn verify(&self) -> Result<(), CompileError> {
        if self.format != FORMAT {
            return Err(CompileError::new("unsupported policy artifact format"));
        }
        validate_source(&self.source)?;
        if self.interpretation.lifetime != "session" {
            return Err(CompileError::new(
                "unsupported policy lifetime; expected session",
            ));
        }
        if let Some(repository) = &self.interpretation.repository
            && normalize_repository(repository)? != *repository
        {
            return Err(CompileError::new("repository scope is not canonical"));
        }
        let capabilities = self
            .interpretation
            .capabilities
            .iter()
            .map(|capability| normalize_rule(capability))
            .collect::<Result<BTreeSet<_>, _>>()?;
        if capabilities.iter().cloned().collect::<Vec<_>>() != self.interpretation.capabilities {
            return Err(CompileError::new(
                "policy capabilities must be sorted and deduplicated",
            ));
        }
        validate_messages(self.interpretation.blockers.clone(), "blocker")?;
        validate_messages(self.interpretation.notes.clone(), "note")?;
        match self.status {
            ArtifactStatus::Draft if self.accepted_at_ms.is_some() => {
                return Err(CompileError::new(
                    "draft policy cannot have an acceptance time",
                ));
            }
            ArtifactStatus::Accepted if self.accepted_at_ms.is_none() => {
                return Err(CompileError::new(
                    "accepted policy is missing its acceptance time",
                ));
            }
            _ => {}
        }
        let expected = artifact_hash(self)?;
        if !constant_time_eq(expected.as_bytes(), self.hash.as_bytes()) {
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

/// Runs the host Claude CLI as an untrusted translator with tools disabled and
/// structured output constrained to [`SessionPolicyTranslation`].
///
/// # Errors
///
/// Returns an error if Claude cannot start, rejects the request, or emits an
/// invalid structured result.
pub fn translate_with_claude(source: &str) -> Result<SessionPolicyTranslation, CompileError> {
    validate_source(source)?;
    let schema = r#"{"type":"object","additionalProperties":false,"properties":{"repository":{"anyOf":[{"type":"string"},{"type":"null"}]},"grants":{"type":"array","items":{"anyOf":[{"enum":["push:branch","pr:create","github:read-private-issues","isolation:v8-sandboxed","workspace:public"]},{"type":"string","pattern":"^egress:[A-Za-z0-9._-]+$"},{"type":"string","pattern":"^(push:ref:refs/heads/|pr:target:)[A-Za-z0-9._/-]+\\*?$"}]}},"constraints":{"type":"array","items":{"enum":["deny:force-push"]}},"blockers":{"type":"array","items":{"type":"string"}},"notes":{"type":"array","items":{"type":"string"}}},"required":["repository","grants","constraints","blockers","notes"]}"#;
    let system = "Translate the operator's policy into Keel's closed session-policy schema. \
Allowed grants are exactly push:branch, pr:create, github:read-private-issues, \
isolation:v8-sandboxed, and egress:EXACT_DNS_HOST. github:read-private-issues permits only \
authenticated reads of individual issues in the exact GitHub repository; it does not imply PR \
creation or push authority. isolation:v8-sandboxed is granted only when the operator explicitly \
permits Keel's lower-assurance host V8 isolation mode. Repository-scoped grants require \
an exact GitHub repository as owner/name. The only constraint is deny:force-push, used when the \
operator says force pushes must never be allowed. Never invent a repository or host. Never translate \
an allowed force push, default-branch push, merge, publication, deletion, wildcard/broad internet access, \
credential access, filesystem scope, permanent grants, or ambiguous language into a grant; put \
each such clause in blockers. Session is the only lifetime. Notes may explain conservative \
interpretation. Return only the schema object.";
    let mut child =
        Command::new(std::env::var_os("KEEL_POLICY_TRANSLATOR").unwrap_or_else(|| "claude".into()))
            .args([
                "--print",
                "--output-format",
                "json",
                "--json-schema",
                schema,
                "--system-prompt",
                system,
                "--tools",
                "",
                "--permission-prompts",
                "none",
                "--no-session-persistence",
                "--max-budget-usd",
                "0.05",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| {
                CompileError::new(format!("cannot start policy translator: {error}"))
            })?;
    child
        .stdin
        .take()
        .ok_or_else(|| CompileError::new("policy translator stdin is unavailable"))?
        .write_all(source.as_bytes())
        .map_err(|error| CompileError::new(format!("cannot send policy text: {error}")))?;
    let started = Instant::now();
    loop {
        if child
            .try_wait()
            .map_err(|error| CompileError::new(format!("policy translator failed: {error}")))?
            .is_some()
        {
            break;
        }
        if started.elapsed() >= Duration::from_secs(30) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(CompileError::new(
                "policy translator did not answer within 30 seconds",
            ));
        }
        thread::sleep(Duration::from_millis(20));
    }
    let output = child
        .wait_with_output()
        .map_err(|error| CompileError::new(format!("policy translator failed: {error}")))?;
    if !output.status.success() {
        return Err(CompileError::new(format!(
            "policy translator exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    parse_claude_output(&output.stdout)
}

/// Translates straightforward policy language locally and uses Claude only
/// when the closed grammar cannot account for the request.
///
/// The local path recognizes exact GitHub repository scopes, ordinary
/// non-default branch pushes, pull-request creation, private GitHub issue
/// reads, and exact DNS hosts. It never guesses through a negative or
/// dangerous clause.
///
/// # Errors
///
/// Returns an error only when the source itself is malformed.
pub fn translate(source: &str) -> Result<SessionPolicyTranslation, CompileError> {
    let mut local = translate_locally(source)?;
    if !local.grants.is_empty() || !local.constraints.is_empty() || !local.blockers.is_empty() {
        return Ok(local);
    }
    match translate_with_claude(source) {
        Ok(translation) => Ok(translation),
        Err(error) => {
            local.blockers.push(format!(
                "automatic translation was unavailable and the local grammar could not interpret this policy: {error}"
            ));
            Ok(local)
        }
    }
}

/// Parses a raw translator JSON file. This supports testing and alternate
/// model frontends without changing the artifact validator.
///
/// # Errors
///
/// Returns an error unless the file contains exactly a [`SessionPolicyTranslation`].
pub fn load_translation(path: &Path) -> Result<SessionPolicyTranslation, CompileError> {
    let bytes = fs::read(path)
        .map_err(|error| CompileError::new(format!("cannot read translation: {error}")))?;
    serde_json::from_slice(&bytes)
        .map_err(|error| CompileError::new(format!("invalid translation: {error}")))
}

fn parse_claude_output(bytes: &[u8]) -> Result<SessionPolicyTranslation, CompileError> {
    let envelope: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|error| CompileError::new(format!("invalid Claude response: {error}")))?;
    let structured = envelope
        .get("structured_output")
        .cloned()
        .or_else(|| envelope.get("result").cloned())
        .unwrap_or(envelope);
    match structured {
        serde_json::Value::String(json) => serde_json::from_str(&json),
        value => serde_json::from_value(value),
    }
    .map_err(|error| CompileError::new(format!("invalid translator result: {error}")))
}

fn translate_locally(source: &str) -> Result<SessionPolicyTranslation, CompileError> {
    validate_source(source)?;
    let lower = source.to_ascii_lowercase();
    let normalized = lower.replace(['-', '_'], " ");
    let deny_force_push = ["never force push", "do not force push", "don't force push"]
        .iter()
        .any(|phrase| normalized.contains(phrase));
    let negative = ["never", "do not", "don't", "must not", "deny "]
        .iter()
        .any(|phrase| lower.contains(phrase))
        && !deny_force_push;
    let mut blockers = Vec::new();
    if negative {
        blockers.push(
            "negative clauses require an enforceable deny rule and cannot become a v1 grant"
                .to_owned(),
        );
    }
    let repository = extract_repository(source);
    let mut grants = BTreeSet::new();
    if !negative
        && lower.contains("push")
        && ["ordinary", "feature branch", "non-default", "non default"]
            .iter()
            .any(|phrase| lower.contains(phrase))
    {
        grants.insert("push:branch".to_owned());
    }
    if !negative
        && [
            "create pull request",
            "creating pull request",
            "open pull request",
            "creating pr",
            "create pr",
            "open pr",
            "pr creation",
        ]
        .iter()
        .any(|phrase| lower.contains(phrase))
    {
        grants.insert("pr:create".to_owned());
    }
    if !negative
        && (lower.contains("github:read-private-issues")
            || [
                "read private issue",
                "read private github issue",
                "reads of private issue",
                "access private issue",
                "access private github issue",
                "access to private issue",
                "access to private github issue",
                "private issue read",
                "private github issue read",
            ]
            .iter()
            .any(|phrase| normalized.contains(phrase)))
    {
        grants.insert("github:read-private-issues".to_owned());
    }
    if !negative {
        for host in extract_hosts(source) {
            grants.insert(format!("egress:{host}"));
        }
        if lower.contains("github api") {
            grants.insert("egress:api.github.com".to_owned());
        }
        if (lower.contains("v8-sandboxed") || lower.contains("v8 sandboxed"))
            && ["allow", "permit", "may use", "can use"]
                .iter()
                .any(|phrase| lower.contains(phrase))
        {
            grants.insert("isolation:v8-sandboxed".to_owned());
        }
    }
    Ok(SessionPolicyTranslation {
        repository,
        grants: grants.into_iter().collect(),
        constraints: if deny_force_push {
            vec!["deny:force-push".to_owned()]
        } else {
            Vec::new()
        },
        blockers,
        notes: vec![
            "compiled by Keel's conservative local grammar; no model decision is used at runtime"
                .to_owned(),
        ],
    })
}

fn extract_repository(source: &str) -> Option<String> {
    source.split_whitespace().find_map(|word| {
        let candidate = word
            .trim_matches(|character: char| {
                matches!(
                    character,
                    ',' | ';' | ':' | '(' | ')' | '[' | ']' | '{' | '}' | '"' | '\''
                )
            })
            .trim_end_matches('.');
        let candidate = candidate
            .strip_prefix("https://github.com/")
            .unwrap_or(candidate)
            .trim_end_matches(".git");
        (candidate.matches('/').count() == 1)
            .then(|| normalize_repository(candidate).ok())
            .flatten()
    })
}

fn extract_hosts(source: &str) -> BTreeSet<String> {
    let words = source
        .split_whitespace()
        .map(|word| {
            word.trim_matches(|character: char| {
                matches!(
                    character,
                    ',' | ';' | ':' | '(' | ')' | '[' | ']' | '{' | '}' | '"' | '\''
                )
            })
            .trim_end_matches('.')
            .to_ascii_lowercase()
        })
        .collect::<Vec<_>>();
    words
        .iter()
        .enumerate()
        .filter_map(|(index, word)| {
            let context_start = index.saturating_sub(3);
            let contextual = words[context_start..index].iter().any(|word| {
                matches!(
                    word.as_str(),
                    "access"
                        | "accessing"
                        | "allow"
                        | "connect"
                        | "connecting"
                        | "egress"
                        | "host"
                        | "reach"
                        | "reaching"
                )
            });
            if !contextual || word.contains('@') {
                return None;
            }
            let candidate = word
                .strip_prefix("https://")
                .or_else(|| word.strip_prefix("http://"))
                .unwrap_or(word)
                .split('/')
                .next()
                .unwrap_or_default();
            normalize_host(candidate).ok()
        })
        .collect()
}

fn validate_source(source: &str) -> Result<(), CompileError> {
    if source.trim().is_empty() || source.len() > MAX_SOURCE_BYTES || source.contains('\0') {
        return Err(CompileError::new(
            "policy text must contain 1-16384 bytes and no NUL",
        ));
    }
    Ok(())
}

fn normalize_repository(value: &str) -> Result<String, CompileError> {
    let value = value
        .trim()
        .trim_start_matches("https://github.com/")
        .trim_end_matches(".git")
        .trim_matches('/');
    let mut parts = value.split('/');
    let (Some(owner), Some(name), None) = (parts.next(), parts.next(), parts.next()) else {
        return Err(CompileError::new(
            "repository must be an exact GitHub owner/name",
        ));
    };
    if !valid_repo_component(owner) || !valid_repo_component(name) {
        return Err(CompileError::new(
            "repository must be an exact GitHub owner/name",
        ));
    }
    Ok(format!("{owner}/{name}").to_ascii_lowercase())
}

fn valid_repo_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 100
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

/// Branch-scoped grants keep their case, because Git ref names are case
/// sensitive. They narrow `push:branch` and `pr:create` in the trusted
/// envelope; the trusted runtime re-validates them.
pub(crate) fn scoped_grant(value: &str) -> Option<Result<String, CompileError>> {
    let value = value.trim();
    let scope = value
        .strip_prefix("push:ref:refs/heads/")
        .or_else(|| value.strip_prefix("pr:target:"))?;
    let body = scope.strip_suffix('*').unwrap_or(scope);
    let valid = !body.is_empty()
        && scope.len() <= 200
        && !body.contains("..")
        && !body.starts_with('/')
        && body
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'_' | b'.'));
    Some(if valid {
        Ok(value.to_owned())
    } else {
        Err(CompileError::new(format!(
            "invalid branch scope in `{value}`"
        )))
    })
}

fn normalize_capability(value: &str) -> Result<String, CompileError> {
    if let Some(scope) = scoped_grant(value) {
        return scope;
    }
    let value = value.trim().to_ascii_lowercase();
    if matches!(
        value.as_str(),
        "push:branch"
            | "pr:create"
            | "github:read-private-issues"
            | "isolation:v8-sandboxed"
            | "workspace:public"
    ) {
        return Ok(value);
    }
    let Some(host) = value.strip_prefix("egress:") else {
        return Err(CompileError::new(format!(
            "unsupported policy grant `{value}`"
        )));
    };
    Ok(format!("egress:{}", normalize_host(host)?))
}

fn normalize_constraint(value: &str) -> Result<String, CompileError> {
    let value = value.trim().to_ascii_lowercase();
    if value == "deny:force-push" {
        Ok(value)
    } else {
        Err(CompileError::new(format!(
            "unsupported policy constraint `{value}`"
        )))
    }
}

fn normalize_rule(value: &str) -> Result<String, CompileError> {
    if value.trim().to_ascii_lowercase().starts_with("deny:") {
        normalize_constraint(value)
    } else {
        normalize_capability(value)
    }
}

fn normalize_host(value: &str) -> Result<String, CompileError> {
    let host = value.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty()
        || host.len() > 253
        || host == "localhost"
        || host.parse::<std::net::IpAddr>().is_ok()
        || host.contains('*')
        || !host.contains('.')
        || !host
            .rsplit('.')
            .next()
            .is_some_and(|label| label.bytes().any(|byte| byte.is_ascii_alphabetic()))
        || host.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(CompileError::new(format!(
            "egress grant requires one exact public DNS host, got `{value}`"
        )));
    }
    Ok(host)
}

fn validate_messages(values: Vec<String>, kind: &str) -> Result<Vec<String>, CompileError> {
    for value in &values {
        if value.trim().is_empty()
            || value.len() > MAX_FIELD_BYTES
            || value.chars().any(char::is_control)
        {
            return Err(CompileError::new(format!("invalid policy {kind}")));
        }
    }
    Ok(values)
}

fn add_independent_safety_blockers(
    source: &str,
    denies_force_push: bool,
    blockers: &mut Vec<String>,
) {
    let normalized = source
        .to_ascii_lowercase()
        .replace(['-', '_', '/', '\n'], " ");
    let risky = [
        (
            ["force push", "forcepush"].as_slice(),
            "force-push clauses are not expressible in the v1 session policy",
        ),
        (
            ["default branch", "main branch", "master branch"].as_slice(),
            "default-branch push clauses are not expressible in the v1 session policy",
        ),
        (
            ["merge pull", "merge pr"].as_slice(),
            "merge clauses are not expressible in the v1 session policy",
        ),
        (
            ["publish", "release"].as_slice(),
            "publication clauses are not expressible in the v1 session policy",
        ),
        (
            ["any host", "all hosts", "whole internet", "all internet"].as_slice(),
            "broad network grants are prohibited; name exact DNS hosts",
        ),
        (
            ["permanent", "forever"].as_slice(),
            "v1 policies are limited to one Keel session",
        ),
    ];
    for (index, (needles, message)) in risky.into_iter().enumerate() {
        if index == 0 && denies_force_push {
            continue;
        }
        if needles.iter().any(|needle| normalized.contains(needle)) {
            blockers.push(message.to_owned());
        }
    }
}

fn artifact_hash(artifact: &SessionPolicyArtifact) -> Result<String, CompileError> {
    let mut unhashed = artifact.clone();
    unhashed.hash.clear();
    let payload = serde_json::to_vec(&unhashed)
        .map_err(|error| CompileError::new(format!("cannot hash policy: {error}")))?;
    let mut framed = Vec::with_capacity(HASH_DOMAIN.len() + payload.len() + 8);
    framed.extend_from_slice(HASH_DOMAIN);
    framed.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    framed.extend_from_slice(&payload);
    Ok(hex(digest(&SHA256, &framed).as_ref()))
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .fold(0_u8, |difference, (left, right)| {
                difference | (left ^ right)
            })
            == 0
}

#[cfg(test)]
mod tests {
    use super::{ArtifactStatus, SessionPolicyArtifact, SessionPolicyTranslation};
    use std::fs;

    fn translation() -> SessionPolicyTranslation {
        SessionPolicyTranslation {
            repository: Some("example-org/keel-live-test".to_owned()),
            grants: vec![
                "push:branch".to_owned(),
                "egress:Docs.RS".to_owned(),
                "pr:create".to_owned(),
            ],
            constraints: Vec::new(),
            blockers: Vec::new(),
            notes: vec!["ordinary pushes only".to_owned()],
        }
    }

    #[test]
    fn draft_accept_and_reload_preserve_exact_interpretation() {
        let mut artifact = SessionPolicyArtifact::draft(
            "Allow ordinary feature pushes, PR creation, and docs.rs access in example-org/keel-live-test.",
            translation(),
            10,
        )
        .unwrap();
        assert_eq!(artifact.status, ArtifactStatus::Draft);
        assert_eq!(
            artifact.interpretation.capabilities,
            ["egress:docs.rs", "pr:create", "push:branch"]
        );
        artifact.accept(20).unwrap();

        let path = std::env::temp_dir().join(format!(
            "keel-policy-artifact-{}-{}.json",
            std::process::id(),
            artifact.created_at_ms
        ));
        artifact.save(&path).unwrap();
        let loaded = SessionPolicyArtifact::load(&path).unwrap();
        fs::remove_file(path).unwrap();
        assert_eq!(loaded, artifact);
        assert_eq!(
            loaded.accepted_capabilities().unwrap(),
            ["egress:docs.rs", "pr:create", "push:branch"]
        );
    }

    #[test]
    fn dangerous_or_broad_language_blocks_acceptance() {
        for source in [
            "Allow force-pushes to example-org/keel-live-test.",
            "Allow pushes to the default branch in example-org/keel-live-test.",
            "Allow access to the whole internet.",
            "Allow release publication forever.",
        ] {
            let mut artifact = SessionPolicyArtifact::draft(source, translation(), 10).unwrap();
            assert!(!artifact.interpretation.blockers.is_empty(), "{source}");
            assert!(artifact.accept(20).is_err(), "{source}");
        }
    }

    #[test]
    fn malformed_or_unscoped_grants_fail_closed() {
        let mut missing_repository = translation();
        missing_repository.repository = None;
        let mut artifact =
            SessionPolicyArtifact::draft("Allow ordinary branch pushes.", missing_repository, 10)
                .unwrap();
        assert!(artifact.accept(20).is_err());

        let mut wildcard = translation();
        wildcard.grants = vec!["egress:*.example.com".to_owned()];
        assert!(SessionPolicyArtifact::draft("Allow example access.", wildcard, 10).is_err());

        let mut unknown = translation();
        unknown.grants = vec!["push:force".to_owned()];
        assert!(SessionPolicyArtifact::draft("Allow pushes.", unknown, 10).is_err());
    }

    #[test]
    fn content_changes_invalidate_the_hash() {
        let mut artifact =
            SessionPolicyArtifact::draft("Allow docs.", translation(), 10).expect("draft");
        artifact
            .interpretation
            .capabilities
            .push("egress:evil.test".to_owned());
        assert!(artifact.accept(20).is_err());
    }

    #[test]
    fn local_translation_handles_the_supported_closed_vocabulary() {
        let translation = super::translate_locally(
            "For this session, allow ordinary pushes to feature branches and creating pull \
             requests in example-org/keel-live-test, plus access to docs.rs.",
        )
        .unwrap();
        assert_eq!(
            translation.grants,
            ["egress:docs.rs", "pr:create", "push:branch"]
        );
        assert_eq!(
            translation.repository.as_deref(),
            Some("example-org/keel-live-test")
        );
        assert!(translation.blockers.is_empty());
    }

    #[test]
    fn local_translation_requires_explicit_words_for_host_v8() {
        let translation =
            super::translate_locally("For this session, allow the v8-sandboxed isolation mode.")
                .unwrap();
        assert_eq!(translation.grants, ["isolation:v8-sandboxed"]);
        assert!(translation.blockers.is_empty());
    }

    #[test]
    fn private_issue_reads_are_explicit_and_repository_scoped() {
        let translation = super::translate_locally(
            "Allow authenticated reads of private issues in example-org/keel-live-test.",
        )
        .unwrap();
        assert_eq!(translation.grants, ["github:read-private-issues"]);
        assert_eq!(
            translation.repository.as_deref(),
            Some("example-org/keel-live-test")
        );

        let mut artifact = SessionPolicyArtifact::draft(
            "Allow private issue reads.",
            SessionPolicyTranslation {
                repository: None,
                grants: vec!["github:read-private-issues".to_owned()],
                constraints: Vec::new(),
                blockers: Vec::new(),
                notes: Vec::new(),
            },
            10,
        )
        .unwrap();
        assert!(artifact.accept(20).is_err());
    }

    #[test]
    fn local_translation_never_turns_a_negative_clause_into_a_grant() {
        let translation = super::translate_locally(
            "Allow ordinary pushes in example-org/keel-live-test, but never force-push.",
        )
        .unwrap();
        assert_eq!(translation.grants, ["push:branch"]);
        assert_eq!(translation.constraints, ["deny:force-push"]);
        assert!(translation.blockers.is_empty());
    }

    #[test]
    fn local_translation_does_not_treat_arbitrary_dotted_text_as_a_host() {
        let translation = super::translate_locally(
            "Use version v1.2 while allowing ordinary feature branch pushes in example-org/repo.",
        )
        .unwrap();
        assert_eq!(translation.grants, ["push:branch"]);
    }
}
