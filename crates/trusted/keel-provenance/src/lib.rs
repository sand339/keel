#![forbid(unsafe_code)]
#![doc = "Trusted provenance accounting for Keel."]

use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt, fs,
    io::Write as _,
    path::{Component, Path, PathBuf},
    process::Command,
};

/// Window in which repeated denials of the same action scope are considered
/// one behavioral pattern.
pub const BEHAVIORAL_DENIAL_WINDOW_MS: u64 = 15 * 60 * 1_000;

/// Identifies this crate as part of the trusted computing base.
pub const TRUSTED_CRATE: &str = "keel-provenance";

mod payload;
mod scope;

pub use payload::{Confidentiality, FragmentCounts, ModelOutputIndex, PayloadIndex, classify_path};
pub use scope::Scope;

/// Constructs Git with repository-controlled execution hooks and ambient
/// credentials disabled.
///
/// Trusted host code must use this constructor whenever it inspects a
/// workspace that untrusted code can modify. In particular, `core.fsmonitor`
/// from `.git/config` must never become host code execution.
#[must_use]
pub fn trusted_git_command() -> Command {
    let mut command = Command::new("/usr/bin/git");
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_ASKPASS", "/usr/bin/false")
        .env("GIT_PAGER", "cat")
        .args([
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "credential.helper=",
            "-c",
            "core.sshCommand=false",
        ]);
    command
}

/// Trusted provenance ranks, ordered from untrusted to operator instruction.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum Rank {
    /// Content whose producer is not trusted.
    UntrustedContent = 0,
    /// Output inherited from an attested agent vertex.
    AgentDerived = 1,
    /// Operator-authored or explicitly trusted data.
    OperatorData = 2,
    /// Instructions captured directly by the trusted input path.
    TrustedInstruction = 3,
}

impl Rank {
    /// Returns the rank as its stable numeric representation.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// A provenance configuration or classification failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProvenanceError(String);

impl ProvenanceError {
    fn new(context: &str, detail: impl fmt::Display) -> Self {
        Self(format!("{context}: {detail}"))
    }
}

impl fmt::Display for ProvenanceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for ProvenanceError {}

/// A concrete source delivered to a vertex.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SourceRef {
    /// Workspace content, with optional unauthenticated Git author metadata.
    File {
        /// Workspace-relative path.
        path: String,
        /// Informational Git author text; never a trust signal.
        author: Option<String>,
    },
    /// A remote HTTP response.
    Host {
        /// Normalized host name.
        host: String,
        /// Request path that produced the response.
        path: String,
    },
    /// The result of an MCP tool call.
    Mcp {
        /// MCP server identity.
        server: String,
        /// Exact tool name.
        tool: String,
    },
    /// Output returned by a shell command.
    Shell {
        /// Exact structured command rendered as text for provenance.
        command: String,
    },
}

/// One source observation that lowered or confirmed the session floor.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FloorObservation {
    /// Rank assigned by the trusted provenance classifier.
    pub rank: u8,
    /// Concrete source that produced the observation.
    pub source: SourceRef,
    /// Observation time in Unix milliseconds.
    pub timestamp_ms: u64,
}

/// One classified result crossing into kernel-owned session state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProvenanceEvent {
    /// Rank assigned by the trusted classifier.
    pub rank: u8,
    /// Floor before the result was delivered.
    pub floor_before: u8,
    /// Floor after applying the classification.
    pub floor_after: u8,
    /// Concrete source that produced the result.
    pub source: SourceRef,
    /// Observation time in Unix milliseconds.
    pub timestamp_ms: u64,
}

/// Trusted review state for a run's declared task authority.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum TaskAdmission {
    /// The run requested no extra task authority.
    NotRequired,
    /// No trusted-terminal review covered the authority.
    #[default]
    Absent,
    /// The trusted terminal admitted the authority.
    Trusted,
}

/// Trusted classification of why an action was denied.
///
/// Keeping this as a closed enum prevents policy from inferring security
/// meaning from an error string. Resource failures are deliberately excluded
/// from repeated-behavior accounting: exhausting a budget or losing a
/// provider connection is not evidence that the agent repeated a denied
/// action.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DenialOrigin {
    /// The operator explicitly rejected a gate.
    Operator,
    /// A stateful or declarative policy rejected the action.
    Policy,
    /// A non-overrideable structural check rejected the action.
    Structural,
    /// A budget, quota, provider, or other resource failure rejected it.
    Resource,
}

impl DenialOrigin {
    /// Whether this denial contributes to same-scope behavioral review.
    #[must_use]
    pub const fn counts_toward_behavioral_review(self) -> bool {
        !matches!(self, Self::Resource)
    }
}

/// Opaque digest of a canonical action class and target.
///
/// The trusted caller constructs the canonical action description and hashes
/// it before creating this value. Session state therefore never retains the
/// possibly sensitive target text used to group related denials.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DenialScope([u8; 32]);

impl DenialScope {
    /// Wraps a domain-separated digest produced by trusted action
    /// canonicalization.
    #[must_use]
    pub const fn from_digest(digest: [u8; 32]) -> Self {
        Self(digest)
    }

    /// Returns the opaque digest for audit correlation.
    #[must_use]
    pub const fn digest(self) -> [u8; 32] {
        self.0
    }
}

/// One typed denial retained in the bounded same-scope review window.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DenialObservation {
    /// Trusted classification of the denial.
    pub origin: DenialOrigin,
    /// Privacy-preserving digest of the canonical action scope.
    pub scope: DenialScope,
    /// Denial time in Unix milliseconds.
    pub timestamp_ms: u64,
}

/// Structured launch intent supplied through the trusted input path.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct IntentFlags {
    /// A trusted-terminal admission covered this task's declared authority.
    pub task_admission: TaskAdmission,
    /// Permit an otherwise alerting push to a non-default branch.
    pub allow_push_branch: bool,
    /// Permit an otherwise alerting pull-request creation.
    pub allow_pr_create: bool,
    /// Refuse force pushes without offering an operator override.
    pub deny_force_push: bool,
    /// Hosts explicitly allowed for non-gated egress.
    pub allowed_egress_hosts: BTreeSet<String>,
    /// Admitted push ref patterns (`push:ref:`); a trailing `*` matches any
    /// suffix. Empty means `push:branch`'s every-non-default-branch envelope.
    pub push_refs: BTreeSet<String>,
    /// Admitted pull-request base branches (`pr:target:`); empty means any.
    pub pr_targets: BTreeSet<String>,
    /// A triage run's declared scope; outside it, egress is refused without
    /// a prompt.
    pub scope: Option<Scope>,
}

/// Kernel-owned state used by provenance and stateful policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionFacts {
    /// Files first created by this vertex.
    pub files_created_by_this_vertex: BTreeSet<String>,
    /// Files successfully written by this vertex.
    pub files_written_by_this_vertex: BTreeSet<String>,
    /// Hosts contacted by authorized requests.
    pub hosts_contacted: BTreeSet<String>,
    /// Whether a package registry has been contacted.
    pub registries_contacted: bool,
    /// Successful workspace writes in the trailing minute.
    pub writes_last_60s: u32,
    /// Distinct files successfully written in the trailing minute.
    pub distinct_files_written_60s: u32,
    /// Actions denied in this session.
    pub denied_actions: u32,
    /// Behavioral denials of the action currently being evaluated, within the
    /// trailing fifteen-minute window.
    ///
    /// Trusted action canonicalization must refresh this value with
    /// [`Self::select_denial_scope`] before policy evaluation.
    pub recent_behavioral_denials_in_scope: u32,
    /// Actions sent to the trusted gate in this session.
    pub escalated_actions: u32,
    /// Current monotonic provenance floor.
    pub floor: u8,
    /// Concrete observations supporting the floor, most recent first.
    pub floor_history: Vec<FloorObservation>,
    /// Concrete sources delivered to the vertex.
    pub sources_read: BTreeSet<SourceRef>,
    /// Structured operator intent captured at launch.
    pub intent: IntentFlags,
    /// Hosts controlled by the operator for source policy.
    pub own_domains: BTreeSet<String>,
    /// Whether the current policy target was created by this vertex.
    pub target_created_by_vertex: bool,
    write_observations: Vec<(u64, String)>,
    write_floors: BTreeMap<String, u8>,
    lifted_floor: Option<u8>,
    observations_since_lift: usize,
    denial_observations: Vec<DenialObservation>,
    selected_denial_scope: Option<DenialScope>,
}

impl Default for SessionFacts {
    fn default() -> Self {
        Self {
            files_created_by_this_vertex: BTreeSet::new(),
            files_written_by_this_vertex: BTreeSet::new(),
            hosts_contacted: BTreeSet::new(),
            registries_contacted: false,
            writes_last_60s: 0,
            distinct_files_written_60s: 0,
            denied_actions: 0,
            recent_behavioral_denials_in_scope: 0,
            escalated_actions: 0,
            floor: 3,
            floor_history: Vec::new(),
            sources_read: BTreeSet::new(),
            intent: IntentFlags::default(),
            own_domains: BTreeSet::new(),
            target_created_by_vertex: true,
            write_observations: Vec::new(),
            write_floors: BTreeMap::new(),
            lifted_floor: None,
            observations_since_lift: 0,
            denial_observations: Vec::new(),
            selected_denial_scope: None,
        }
    }
}

impl SessionFacts {
    /// Records an unscoped denial in the cumulative audit counter.
    ///
    /// New authorization paths should use [`Self::record_scoped_denial`]. This
    /// compatibility method cannot affect repeated-behavior policy because it
    /// carries neither a trusted origin nor a canonical action scope.
    pub fn record_denial(&mut self) {
        self.denied_actions = self.denied_actions.saturating_add(1);
    }

    /// Records one typed denial and refreshes policy context for its scope.
    pub fn record_scoped_denial(
        &mut self,
        origin: DenialOrigin,
        scope: DenialScope,
        timestamp_ms: u64,
    ) {
        self.record_denial();
        self.prune_denial_observations(timestamp_ms);
        self.denial_observations.push(DenialObservation {
            origin,
            scope,
            timestamp_ms,
        });
        self.select_denial_scope(scope, timestamp_ms);
    }

    /// Selects the canonical action scope being evaluated and refreshes its
    /// trailing-window denial count for Cedar context.
    pub fn select_denial_scope(&mut self, scope: DenialScope, timestamp_ms: u64) {
        self.prune_denial_observations(timestamp_ms);
        self.selected_denial_scope = Some(scope);
        self.recent_behavioral_denials_in_scope = self.behavioral_denial_count(scope, timestamp_ms);
    }

    /// Clears behavioral denials for exactly one reviewed action scope.
    ///
    /// Cumulative `denied_actions` remains an immutable audit statistic and
    /// resource observations are retained until they age out.
    pub fn clear_behavioral_denials_in_scope(&mut self, scope: DenialScope, timestamp_ms: u64) {
        self.prune_denial_observations(timestamp_ms);
        self.denial_observations.retain(|observation| {
            observation.scope != scope || !observation.origin.counts_toward_behavioral_review()
        });
        if self.selected_denial_scope == Some(scope) {
            self.recent_behavioral_denials_in_scope = 0;
        }
    }

    /// Returns typed denial observations still retained in the active window.
    #[must_use]
    pub fn denial_observations(&self) -> &[DenialObservation] {
        &self.denial_observations
    }

    fn behavioral_denial_count(&self, scope: DenialScope, timestamp_ms: u64) -> u32 {
        let cutoff = timestamp_ms.saturating_sub(BEHAVIORAL_DENIAL_WINDOW_MS);
        u32::try_from(
            self.denial_observations
                .iter()
                .filter(|observation| {
                    observation.scope == scope
                        && observation.origin.counts_toward_behavioral_review()
                        && observation.timestamp_ms >= cutoff
                        && observation.timestamp_ms <= timestamp_ms
                })
                .count(),
        )
        .unwrap_or(u32::MAX)
    }

    fn prune_denial_observations(&mut self, timestamp_ms: u64) {
        let cutoff = timestamp_ms.saturating_sub(BEHAVIORAL_DENIAL_WINDOW_MS);
        self.denial_observations
            .retain(|observation| observation.timestamp_ms >= cutoff);
    }

    /// Records a trusted escalation without allowing counter wraparound.
    pub fn record_escalation(&mut self) {
        self.escalated_actions = self.escalated_actions.saturating_add(1);
    }

    /// Records a successfully contacted host.
    pub fn record_host(&mut self, host: impl Into<String>, is_registry: bool) {
        self.hosts_contacted.insert(host.into());
        self.registries_contacted |= is_registry;
    }

    /// Records a concrete source delivered to the vertex.
    pub fn record_source(&mut self, source: SourceRef) {
        self.sources_read.insert(source);
    }

    /// Records a successful write and recomputes the trailing-minute counters.
    pub fn record_write(
        &mut self,
        path: impl Into<String>,
        created_by_vertex: bool,
        timestamp_ms: u64,
    ) {
        let path = path.into();
        if created_by_vertex {
            self.files_created_by_this_vertex.insert(path.clone());
        }
        self.files_written_by_this_vertex.insert(path.clone());
        self.write_floors.insert(path.clone(), self.floor);
        self.write_observations.push((timestamp_ms, path));
        let cutoff = timestamp_ms.saturating_sub(60_000);
        self.write_observations
            .retain(|(observed_at, _)| *observed_at >= cutoff);
        self.writes_last_60s = u32::try_from(self.write_observations.len()).unwrap_or(u32::MAX);
        self.distinct_files_written_60s = u32::try_from(
            self.write_observations
                .iter()
                .map(|(_, path)| path)
                .collect::<BTreeSet<_>>()
                .len(),
        )
        .unwrap_or(u32::MAX);
    }

    /// Returns the session floor captured when this vertex last wrote a path.
    #[must_use]
    pub fn writer_floor(&self, path: &str) -> Option<u8> {
        self.write_floors.get(path).copied()
    }

    /// Records a classified source and monotonically lowers the floor.
    pub fn record_floor_observation(&mut self, rank: u8, source: SourceRef, timestamp_ms: u64) {
        self.floor = self.floor.min(rank);
        self.observations_since_lift = self.observations_since_lift.saturating_add(1);
        self.sources_read.insert(source.clone());
        self.floor_history.insert(
            0,
            FloorObservation {
                rank,
                source,
                timestamp_ms,
            },
        );
    }

    /// Applies an approved operator attestation without discarding provenance.
    pub fn lift_floor(&mut self, requested_floor: u8) {
        self.floor = self.floor.max(requested_floor.min(3));
        self.lifted_floor = Some(self.floor);
        self.observations_since_lift = 0;
    }
}

/// Provenance behavior recorded with a durable session floor.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PersistedMode {
    /// Apply rank checks against the monotonic floor.
    Floor,
    /// Render provenance at gates without rank checks.
    GateContext,
}

/// Durable, non-authoritative floor snapshot keyed to one harness session.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FloorState {
    session_id: String,
    floor: u8,
    provenance: PersistedMode,
    floor_history: Vec<FloorObservation>,
    #[serde(default)]
    write_floors: BTreeMap<String, u8>,
    #[serde(default)]
    lifted_floor: Option<u8>,
    #[serde(default)]
    observations_since_lift: Option<usize>,
}

impl FloorState {
    /// Captures resumable state while converting current-vertex writes to
    /// prior-vertex `agent_derived` ranks.
    #[must_use]
    pub fn capture(session_id: &str, provenance: PersistedMode, facts: &SessionFacts) -> Self {
        Self {
            session_id: session_id.to_owned(),
            floor: facts.floor,
            provenance,
            floor_history: facts.floor_history.clone(),
            write_floors: facts
                .write_floors
                .iter()
                .map(|(path, rank)| (path.clone(), (*rank).min(1)))
                .collect(),
            lifted_floor: facts.lifted_floor,
            observations_since_lift: facts.lifted_floor.map(|_| facts.observations_since_lift),
        }
    }

    /// Returns the current attested floor.
    #[must_use]
    pub const fn floor(&self) -> u8 {
        self.floor
    }

    /// Returns the provenance mode associated with this session.
    #[must_use]
    pub const fn provenance(&self) -> PersistedMode {
        self.provenance
    }

    /// Loads and validates a floor snapshot, returning `None` when absent.
    ///
    /// # Errors
    ///
    /// Returns an error for I/O, malformed JSON, another session identifier,
    /// invalid ranks, or a floor inconsistent with its history.
    pub fn load(path: &Path, session_id: &str) -> Result<Option<Self>, ProvenanceError> {
        match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(ProvenanceError::new(
                    "read floor state",
                    "snapshot must not be a symbolic link",
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(ProvenanceError::new("read floor state", error)),
        }
        let bytes = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) => return Err(ProvenanceError::new("read floor state", error)),
        };
        if bytes.len() > 1024 * 1024 {
            return Err(ProvenanceError::new(
                "read floor state",
                "snapshot exceeds 1 MiB",
            ));
        }
        let state: Self = serde_json::from_slice(&bytes)
            .map_err(|error| ProvenanceError::new("parse floor state", error))?;
        state.validate(session_id)?;
        Ok(Some(state))
    }

    /// Atomically writes a mode-0600 floor snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid state or any create, write, sync, or
    /// rename failure.
    pub fn save(&self, path: &Path) -> Result<(), ProvenanceError> {
        self.validate(&self.session_id)?;
        let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = options
            .open(&temporary)
            .map_err(|error| ProvenanceError::new("create floor state", error))?;
        let result = serde_json::to_writer(&mut file, self)
            .and_then(|()| file.write_all(b"\n").map_err(serde_json::Error::io))
            .and_then(|()| file.sync_all().map_err(serde_json::Error::io))
            .map_err(|error| ProvenanceError::new("write floor state", error))
            .and_then(|()| {
                fs::rename(&temporary, path)
                    .map_err(|error| ProvenanceError::new("commit floor state", error))
            })
            .and_then(|()| {
                fs::File::open(path.parent().unwrap_or_else(|| Path::new(".")))
                    .and_then(|directory| directory.sync_all())
                    .map_err(|error| ProvenanceError::new("sync floor state directory", error))
            });
        if result.is_err() {
            let _ = fs::remove_file(temporary);
        }
        result
    }

    /// Reconstructs facts from this snapshot for offline inspection and tests.
    ///
    /// Production broker admission deliberately does not call this method:
    /// session storage is untrusted and cannot restore authorization.
    #[must_use]
    pub fn resume_facts(&self) -> SessionFacts {
        SessionFacts {
            floor: self.floor,
            floor_history: self.floor_history.clone(),
            sources_read: self
                .floor_history
                .iter()
                .map(|observation| observation.source.clone())
                .collect(),
            write_floors: self.write_floors.clone(),
            lifted_floor: self.lifted_floor,
            observations_since_lift: self.observations_since_lift.unwrap_or(0),
            ..SessionFacts::default()
        }
    }

    fn validate(&self, expected_session_id: &str) -> Result<(), ProvenanceError> {
        validate_session_id(expected_session_id)?;
        if self.session_id != expected_session_id {
            return Err(ProvenanceError::new(
                "floor state",
                "snapshot belongs to another session",
            ));
        }
        if self.floor > 3
            || self
                .floor_history
                .iter()
                .any(|observation| observation.rank > 3)
            || self.write_floors.values().any(|rank| *rank > 1)
            || self.lifted_floor.is_some_and(|rank| rank > 3)
        {
            return Err(ProvenanceError::new(
                "floor state",
                "snapshot contains an invalid rank",
            ));
        }
        let observations = self
            .observations_since_lift
            .unwrap_or(self.floor_history.len());
        if observations > self.floor_history.len()
            || self.lifted_floor.is_some() != self.observations_since_lift.is_some()
        {
            return Err(ProvenanceError::new(
                "floor state",
                "snapshot contains an invalid lift epoch",
            ));
        }
        let observed_floor = self
            .floor_history
            .iter()
            .take(observations)
            .fold(self.lifted_floor.unwrap_or(3), |floor, observation| {
                floor.min(observation.rank)
            });
        if self.floor != observed_floor {
            return Err(ProvenanceError::new(
                "floor state",
                "floor does not match observation history",
            ));
        }
        Ok(())
    }
}

fn validate_session_id(session_id: &str) -> Result<(), ProvenanceError> {
    if session_id.is_empty()
        || session_id == "."
        || session_id == ".."
        || session_id.contains(['/', '\\'])
        || session_id.chars().any(char::is_control)
    {
        return Err(ProvenanceError::new("session id", "identifier is unsafe"));
    }
    Ok(())
}

/// Exact metadata observed at a trusted result boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResultObservation {
    /// A workspace file read.
    WorkspaceFile {
        /// Workspace-relative path.
        path: String,
    },
    /// Shell or test output.
    ShellOutput {
        /// Exact structured command rendered as text.
        command: String,
    },
    /// Output from `git status`.
    GitStatus,
    /// Output derived from exact commit object identifiers.
    GitHistory {
        /// Commits whose authors determine the result rank.
        commits: Vec<String>,
    },
    /// One MCP tool result.
    McpResult {
        /// MCP server identity.
        server: String,
        /// Exact tool name.
        tool: String,
    },
    /// A model API response body.
    ModelResponse,
    /// A non-model HTTP response body.
    EgressResponse {
        /// Normalized host name.
        host: String,
        /// Exact request path.
        path: String,
    },
    /// A harness-owned transcript or session file.
    HarnessTranscript {
        /// Workspace-relative or harness-relative path.
        path: String,
    },
}

/// A complete result classification ready for kernel-owned accounting.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClassifiedResult {
    /// Assigned rank, or `None` for a model response that does not move floor.
    rank: Option<Rank>,
    /// Concrete source added to the read set when the result is classified.
    source: Option<SourceRef>,
}

impl ClassifiedResult {
    /// Creates a classification from trusted rank and source metadata.
    #[must_use]
    pub fn new(rank: Rank, source: SourceRef) -> Self {
        Self {
            rank: Some(rank),
            source: Some(source),
        }
    }

    /// Returns the assigned rank, if the result moves provenance.
    #[must_use]
    pub const fn rank(&self) -> Option<Rank> {
        self.rank
    }

    /// Returns the concrete source, if the result enters the read set.
    #[must_use]
    pub const fn source(&self) -> Option<&SourceRef> {
        self.source.as_ref()
    }

    /// Applies this trusted classification to kernel-owned session facts.
    pub fn apply(self, facts: &mut SessionFacts, timestamp_ms: u64) {
        match (self.rank, self.source) {
            (Some(rank), Some(source)) => {
                facts.record_floor_observation(rank.as_u8(), source, timestamp_ms);
            }
            (None | Some(_), None) => {}
            (_, Some(source)) => facts.record_source(source),
        }
    }
}

/// Startup-validated implementation of every rule in the §6.2 result table.
#[derive(Clone, Debug)]
pub struct ClassificationTable {
    trusted_mcp_servers: BTreeSet<String>,
}

impl ClassificationTable {
    /// Creates the complete built-in result table.
    #[must_use]
    pub fn builtin(trusted_mcp_servers: impl IntoIterator<Item = String>) -> Self {
        Self {
            trusted_mcp_servers: trusted_mcp_servers.into_iter().collect(),
        }
    }

    /// Classifies exact result metadata without pre-evaluating a policy rule.
    ///
    /// # Errors
    ///
    /// Returns an error if Git metadata is unavailable or malformed.
    pub fn classify(
        &self,
        observation: ResultObservation,
        git: &GitClassifier,
        facts: &SessionFacts,
    ) -> Result<ClassifiedResult, ProvenanceError> {
        let classified = match observation {
            ResultObservation::WorkspaceFile { path } => {
                let (rank, author) = git.classify_file(&path, facts)?;
                ClassifiedResult {
                    rank: Some(rank),
                    source: Some(SourceRef::File { path, author }),
                }
            }
            ResultObservation::ShellOutput { command } => ClassifiedResult {
                rank: Some(Rank::UntrustedContent),
                source: Some(SourceRef::Shell { command }),
            },
            ResultObservation::GitStatus => ClassifiedResult {
                rank: Some(Rank::OperatorData),
                source: Some(SourceRef::Shell {
                    command: "git status".to_owned(),
                }),
            },
            ResultObservation::GitHistory { commits } => ClassifiedResult {
                rank: Some(git.classify_commits(&commits)?),
                source: Some(SourceRef::Shell {
                    command: format!("git history {}", commits.join(" ")),
                }),
            },
            ResultObservation::McpResult { server, tool } => ClassifiedResult {
                rank: Some(if self.trusted_mcp_servers.contains(&server) {
                    Rank::OperatorData
                } else {
                    Rank::UntrustedContent
                }),
                source: Some(SourceRef::Mcp { server, tool }),
            },
            ResultObservation::ModelResponse => ClassifiedResult {
                rank: None,
                source: None,
            },
            ResultObservation::EgressResponse { host, path } => ClassifiedResult {
                rank: Some(Rank::UntrustedContent),
                source: Some(SourceRef::Host { host, path }),
            },
            ResultObservation::HarnessTranscript { path } => ClassifiedResult {
                rank: Some(
                    facts
                        .writer_floor(&path)
                        .map_or(Rank::UntrustedContent, rank_from_u8),
                ),
                source: Some(SourceRef::File { path, author: None }),
            },
        };
        Ok(classified)
    }
}

fn rank_from_u8(rank: u8) -> Rank {
    match rank {
        3 => Rank::TrustedInstruction,
        2 => Rank::OperatorData,
        1 => Rank::AgentDerived,
        _ => Rank::UntrustedContent,
    }
}

/// Fail-closed classifier preserving the former Git classifier API.
#[derive(Clone, Debug)]
pub struct GitClassifier {
    workspace: PathBuf,
}

impl GitClassifier {
    /// Validates a workspace and additional rank-zero path prefixes.
    ///
    /// # Errors
    ///
    /// Returns an error unless the workspace is an existing directory and
    /// every configured prefix is a safe relative path.
    pub fn new(
        workspace: impl AsRef<Path>,
        _operator_identities: impl IntoIterator<Item = String>,
        rank_zero_paths: impl IntoIterator<Item = PathBuf>,
    ) -> Result<Self, ProvenanceError> {
        let workspace = fs::canonicalize(workspace)
            .map_err(|error| ProvenanceError::new("workspace", error))?;
        if !workspace.is_dir() {
            return Err(ProvenanceError::new("workspace", "path is not a directory"));
        }
        for path in rank_zero_paths {
            validate_relative_path(&path)?;
        }
        Ok(Self { workspace })
    }

    /// Classifies a workspace read using write inheritance before Git state.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsafe path or unavailable Git metadata.
    pub fn classify_file(
        &self,
        path: &str,
        facts: &SessionFacts,
    ) -> Result<(Rank, Option<String>), ProvenanceError> {
        let relative = Path::new(path);
        validate_relative_path(relative)?;
        let _ = &self.workspace;
        Ok((
            facts
                .writer_floor(path)
                .map_or(Rank::UntrustedContent, rank_from_u8),
            None,
        ))
    }

    /// Validates exact commit identifiers and classifies their content fail
    /// closed at rank zero.
    ///
    /// Git author name and email are commit-controlled text, not operator
    /// authentication. This compatibility API therefore never raises rank.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty set or unsafe object id.
    pub fn classify_commits(&self, commits: &[String]) -> Result<Rank, ProvenanceError> {
        if commits.is_empty() {
            return Err(ProvenanceError::new("Git history", "commit set is empty"));
        }
        for commit in commits {
            if !(7..=64).contains(&commit.len())
                || !commit.bytes().all(|byte| byte.is_ascii_hexdigit())
            {
                return Err(ProvenanceError::new(
                    "Git history",
                    "commit id is not hexadecimal",
                ));
            }
        }
        Ok(Rank::UntrustedContent)
    }
}

fn validate_relative_path(path: &Path) -> Result<(), ProvenanceError> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(ProvenanceError::new(
            "workspace path",
            "path must contain only normal relative components",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        BEHAVIORAL_DENIAL_WINDOW_MS, ClassificationTable, DenialOrigin, DenialScope, GitClassifier,
        Rank, ResultObservation, SessionFacts, SourceRef,
    };
    use std::{
        fs,
        path::Path,
        process::Command,
        time::{SystemTime, UNIX_EPOCH},
    };

    #[test]
    fn write_window_tracks_total_and_distinct_paths() {
        let mut facts = SessionFacts::default();
        facts.record_write("a", true, 1_000);
        facts.record_write("a", true, 2_000);
        facts.record_write("b", false, 62_000);

        assert_eq!(facts.writes_last_60s, 2);
        assert_eq!(facts.distinct_files_written_60s, 2);
        assert_eq!(facts.files_created_by_this_vertex, ["a".to_owned()].into());
        assert_eq!(
            facts.files_written_by_this_vertex,
            ["a".to_owned(), "b".to_owned()].into()
        );
    }

    #[test]
    fn floor_observation_preserves_concrete_source() {
        let mut facts = SessionFacts::default();
        let source = SourceRef::Mcp {
            server: "github".to_owned(),
            tool: "issue_read".to_owned(),
        };
        facts.record_floor_observation(0, source.clone(), 42);

        assert_eq!(facts.floor, 0);
        assert!(facts.sources_read.contains(&source));
        assert_eq!(facts.floor_history[0].source, source);
    }

    #[test]
    fn denial_review_is_typed_scoped_and_time_bounded() {
        let mut facts = SessionFacts::default();
        let first = DenialScope::from_digest([1; 32]);
        let second = DenialScope::from_digest([2; 32]);
        let observed_at = 10_000;

        for origin in [
            DenialOrigin::Operator,
            DenialOrigin::Policy,
            DenialOrigin::Structural,
            DenialOrigin::Resource,
        ] {
            facts.record_scoped_denial(origin, first, observed_at);
        }
        facts.record_scoped_denial(DenialOrigin::Operator, second, observed_at);

        assert_eq!(facts.denied_actions, 5);
        facts.select_denial_scope(first, observed_at);
        assert_eq!(facts.recent_behavioral_denials_in_scope, 3);
        facts.select_denial_scope(second, observed_at);
        assert_eq!(facts.recent_behavioral_denials_in_scope, 1);

        facts.select_denial_scope(first, observed_at + BEHAVIORAL_DENIAL_WINDOW_MS + 1);
        assert_eq!(facts.recent_behavioral_denials_in_scope, 0);
        assert!(facts.denial_observations().is_empty());
        assert_eq!(facts.denied_actions, 5);
    }

    #[test]
    fn approving_one_scope_does_not_clear_another_or_lifetime_audit_count() {
        let mut facts = SessionFacts::default();
        let first = DenialScope::from_digest([1; 32]);
        let second = DenialScope::from_digest([2; 32]);

        facts.record_scoped_denial(DenialOrigin::Operator, first, 1_000);
        facts.record_scoped_denial(DenialOrigin::Policy, first, 1_001);
        facts.record_scoped_denial(DenialOrigin::Operator, second, 1_002);
        facts.clear_behavioral_denials_in_scope(first, 1_003);

        facts.select_denial_scope(first, 1_003);
        assert_eq!(facts.recent_behavioral_denials_in_scope, 0);
        facts.select_denial_scope(second, 1_003);
        assert_eq!(facts.recent_behavioral_denials_in_scope, 1);
        assert_eq!(facts.denied_actions, 3);
    }

    #[test]
    fn fixed_result_rules_match_the_classification_table() {
        let workspace = scratch("fixed-rules");
        fs::create_dir(&workspace).unwrap();
        let git = GitClassifier::new(&workspace, [], []).unwrap();
        let table = ClassificationTable::builtin(["trusted-mcp".to_owned()]);
        let facts = SessionFacts::default();

        let cases = [
            (
                ResultObservation::ShellOutput {
                    command: "cargo test".to_owned(),
                },
                Some(Rank::UntrustedContent),
            ),
            (ResultObservation::GitStatus, Some(Rank::OperatorData)),
            (
                ResultObservation::McpResult {
                    server: "trusted-mcp".to_owned(),
                    tool: "read".to_owned(),
                },
                Some(Rank::OperatorData),
            ),
            (
                ResultObservation::McpResult {
                    server: "other-mcp".to_owned(),
                    tool: "read".to_owned(),
                },
                Some(Rank::UntrustedContent),
            ),
            (
                ResultObservation::EgressResponse {
                    host: "example.com".to_owned(),
                    path: "/".to_owned(),
                },
                Some(Rank::UntrustedContent),
            ),
            (ResultObservation::ModelResponse, None),
        ];
        for (observation, expected) in cases {
            assert_eq!(
                table.classify(observation, &git, &facts).unwrap().rank(),
                expected
            );
        }
        fs::remove_dir(workspace).unwrap();
    }

    #[test]
    fn git_authorship_is_not_treated_as_authenticated_provenance() {
        let workspace = scratch("git");
        fs::create_dir(&workspace).unwrap();
        git(&workspace, &["init", "-q"]);
        git(&workspace, &["config", "user.name", "Operator"]);
        git(
            &workspace,
            &["config", "user.email", "operator@example.com"],
        );
        fs::write(workspace.join("owned.txt"), "owned\n").unwrap();
        git(&workspace, &["add", "owned.txt"]);
        git(&workspace, &["commit", "-q", "-m", "owned"]);
        let owned_commit = git(&workspace, &["rev-parse", "HEAD"]);
        let classifier = GitClassifier::new(
            &workspace,
            ["operator@example.com".to_owned()],
            [Path::new("generated").to_path_buf()],
        )
        .unwrap();
        let table = ClassificationTable::builtin([]);
        let facts = SessionFacts::default();

        assert_eq!(
            table
                .classify(
                    ResultObservation::WorkspaceFile {
                        path: "owned.txt".to_owned(),
                    },
                    &classifier,
                    &facts,
                )
                .unwrap()
                .rank(),
            Some(Rank::UntrustedContent)
        );
        assert_eq!(
            classifier.classify_file("Cargo.lock", &facts).unwrap().0,
            Rank::UntrustedContent
        );
        assert_eq!(
            classifier.classify_file("untracked.txt", &facts).unwrap().0,
            Rank::UntrustedContent
        );
        fs::write(workspace.join("owned.txt"), "dirty\n").unwrap();
        assert_eq!(
            classifier.classify_file("owned.txt", &facts).unwrap().0,
            Rank::UntrustedContent
        );

        git(&workspace, &["config", "user.name", "Other"]);
        git(&workspace, &["config", "user.email", "other@example.com"]);
        fs::write(workspace.join("other.txt"), "other\n").unwrap();
        git(&workspace, &["add", "other.txt"]);
        git(&workspace, &["commit", "-q", "-m", "other"]);
        let other_commit = git(&workspace, &["rev-parse", "HEAD"]);
        assert_eq!(
            classifier
                .classify_commits(std::slice::from_ref(&owned_commit))
                .unwrap(),
            Rank::UntrustedContent
        );
        assert_eq!(
            classifier
                .classify_commits(&[owned_commit, other_commit.clone()])
                .unwrap(),
            Rank::UntrustedContent
        );
        assert_eq!(
            table
                .classify(
                    ResultObservation::GitHistory {
                        commits: vec![other_commit],
                    },
                    &classifier,
                    &facts,
                )
                .unwrap()
                .rank(),
            Some(Rank::UntrustedContent)
        );

        fs::remove_dir_all(workspace).unwrap();
    }

    fn git(workspace: &Path, arguments: &[&str]) -> String {
        let output = Command::new("git")
            .arg("-C")
            .arg(workspace)
            .args(arguments)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }

    fn scratch(label: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("keel-provenance-{label}-{nonce:x}"))
    }
}
