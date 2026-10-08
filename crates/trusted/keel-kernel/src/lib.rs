#![forbid(unsafe_code)]
#![doc = "Trusted authorization kernel for Keel."]

pub use keel_provenance::ProvenanceEvent;
use keel_provenance::{
    ClassifiedResult, Confidentiality, DenialOrigin, DenialScope, FloorObservation, IntentFlags,
    ModelOutputIndex, PayloadIndex, Rank, SessionFacts, SourceRef, TaskAdmission,
};
use nix::{
    errno::Errno,
    poll::{PollFd, PollFlags, poll},
    sys::socket::{MsgFlags, recv},
};
use ring::{
    digest::{SHA256, digest},
    rand::{SecureRandom, SystemRandom},
};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    error::Error,
    fmt, fs,
    hash::{DefaultHasher, Hash, Hasher},
    io::{ErrorKind, Read as _, Write as _},
    os::{
        fd::{AsFd as _, AsRawFd as _},
        unix::{
            fs::{OpenOptionsExt as _, PermissionsExt as _},
            net::{UnixListener, UnixStream},
        },
    },
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering},
        mpsc::{Receiver, RecvTimeoutError, SyncSender, sync_channel},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

static BROKER_PATH_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// A verified vertex identity.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PrincipalId(String);

impl PrincipalId {
    /// Validates a principal identifier.
    ///
    /// # Errors
    ///
    /// Returns [`KernelError::InvalidPrincipal`] for an empty identifier or
    /// one containing control characters.
    pub fn new(value: impl Into<String>) -> Result<Self, KernelError> {
        let value = value.into();
        if value.is_empty() || value.chars().any(char::is_control) {
            return Err(KernelError::InvalidPrincipal);
        }
        Ok(Self(value))
    }

    /// Returns the principal as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The kernel-visible class of an attempted action.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ActionClass {
    /// Read workspace content.
    ReadWorkspace,
    /// Write workspace content.
    WriteWorkspace,
    /// Execute a command.
    RunCommand,
    /// Create a local Git commit.
    GitCommit,
    /// Update a remote Git ref.
    GitPush,
    /// Open an outbound connection.
    Egress,
    /// Create or merge a pull request.
    PullRequest,
    /// Publish or send content externally.
    Publish,
    /// Write outside the mounted workspace.
    WriteOutsideWorkspace,
    /// Delete outside the mounted workspace.
    DeleteOutsideWorkspace,
    /// Raise a session's provenance floor.
    LiftFloor,
}

/// Kernel state that a guest can never modify.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ProtectedState {
    /// Loaded policy artifacts.
    Policy,
    /// The append-only audit stream.
    Audit,
    /// Boot attestation evidence.
    Attestation,
    /// Provenance history.
    Provenance,
    /// Session budget counters.
    Budget,
}

/// A concrete action target.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum Target {
    /// A path within the workspace.
    Workspace {
        /// Workspace-relative path.
        path: String,
    },
    /// A command and its exact arguments.
    Command {
        /// Executable name or path.
        program: String,
        /// Argument vector without shell re-parsing.
        arguments: Vec<String>,
    },
    /// An outbound HTTP request.
    Network {
        /// Normalized server name.
        host: String,
        /// Resolved destination port.
        port: u16,
        /// HTTP method.
        method: String,
        /// Exact request path.
        path: String,
    },
    /// A remote Git update.
    Git {
        /// Remote name or URL.
        remote: String,
        /// Ref names being updated.
        refs: Vec<String>,
        /// Whether any update is non-fast-forward.
        is_force: bool,
        /// Whether the default branch is updated.
        is_default_branch: bool,
        /// Whether the update changes a dependency manifest or lockfile.
        touches_manifest: bool,
        /// Exact diff rendered by the trusted gate.
        manifest_diff: Option<String>,
    },
    /// An external service operation.
    External {
        /// Service or protocol name.
        service: String,
        /// Exact recipient or publication destination.
        recipient: String,
        /// Operation requested from the service.
        operation: String,
        /// Exact operation content rendered at the trusted gate.
        detail: String,
    },
    /// A request to raise the current provenance floor.
    FloorLift {
        /// Harness session receiving the operator attestation.
        session_id: String,
        /// Requested floor, from zero through three.
        requested_floor: u8,
    },
    /// A direct attempt to mutate trusted kernel state.
    Protected(ProtectedState),
}

impl Target {
    const fn kind(&self) -> &'static str {
        match self {
            Self::Workspace { .. } => "workspace",
            Self::Command { .. } => "command",
            Self::Network { .. } => "network",
            Self::Git { .. } => "git",
            Self::External { .. } => "external",
            Self::FloorLift { .. } => "floor-lift",
            Self::Protected(_) => "protected",
        }
    }
}

impl ActionClass {
    /// Returns the stable audit name for this action class.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReadWorkspace => "read-workspace",
            Self::WriteWorkspace => "write-workspace",
            Self::RunCommand => "run-command",
            Self::GitCommit => "git-commit",
            Self::GitPush => "git-push",
            Self::Egress => "egress",
            Self::PullRequest => "pull-request",
            Self::Publish => "publish",
            Self::WriteOutsideWorkspace => "write-outside-workspace",
            Self::DeleteOutsideWorkspace => "delete-outside-workspace",
            Self::LiftFloor => "lift-floor",
        }
    }

    const fn accepts_target(self, target: &Target) -> bool {
        match self {
            Self::ReadWorkspace | Self::WriteWorkspace => {
                matches!(target, Target::Workspace { .. } | Target::Protected(_))
            }
            Self::RunCommand => matches!(target, Target::Command { .. } | Target::Protected(_)),
            Self::GitCommit | Self::GitPush => {
                matches!(target, Target::Git { .. } | Target::Protected(_))
            }
            Self::Egress => matches!(target, Target::Network { .. } | Target::Protected(_)),
            Self::PullRequest | Self::Publish => {
                matches!(target, Target::External { .. } | Target::Protected(_))
            }
            Self::WriteOutsideWorkspace | Self::DeleteOutsideWorkspace => {
                matches!(target, Target::Workspace { .. } | Target::Protected(_))
            }
            Self::LiftFloor => matches!(target, Target::FloorLift { .. } | Target::Protected(_)),
        }
    }
}

/// An action assertion received from an untrusted channel.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Asserted {
    /// Action class claimed by the channel.
    pub class: ActionClass,
    /// Concrete target supplied by the channel.
    pub target: Target,
    /// Forgeable cost estimate used only for telemetry.
    pub declared_cost: Option<u64>,
}

/// A snapshot of kernel-owned session facts attached to an action.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionSnapshot {
    /// Current provenance floor, from zero through three.
    pub floor: u8,
    /// Actions denied in this session.
    pub denied_actions: u64,
    /// Actions committed against the session budget.
    pub committed_actions: u64,
    /// Maximum actions allowed by the session budget.
    pub action_limit: u64,
}

/// A kernel-verified assertion.
///
/// Its fields are deliberately private. Code outside this crate can inspect a
/// stamp but cannot construct one.
///
/// ```compile_fail
/// let forged = keel_kernel::Stamped {
///     principal: todo!(),
///     session: todo!(),
///     intent: todo!(),
///     flow: todo!(),
///     origin: todo!(),
///     integrity: todo!(),
/// };
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Stamped {
    principal: PrincipalId,
    session: SessionSnapshot,
    intent: IntentVerdict,
    flow: FlowVerdict,
    origin: Option<ReportedOrigin>,
    integrity: IntegrityVerdict,
}

/// Facts the trusted relay establishes about a request before it begins.
#[derive(Clone, Debug, Default)]
pub struct RelayFacts {
    /// Payload confidentiality verdict.
    pub flow: FlowVerdict,
    /// Guest-reported origin, if one accompanied the request.
    pub origin: Option<ReportedOrigin>,
    /// Whether content pushed into a protected place is the model's own.
    pub integrity: IntegrityVerdict,
}

/// Whether the lines a push adds to a protected place were written by the
/// model in this run. Lines from builds, install hooks, downloads, or other
/// processes are unaccounted. Recorded in shadow; no decision reads it.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum IntegrityVerdict {
    /// The action adds nothing to a protected place.
    #[default]
    NotChecked,
    /// The protected diff was truncated or binary and could not be read.
    Uninspectable,
    /// Lines added to protected places, and how many the model did not write.
    Lines {
        /// Added lines long enough to judge.
        added: u32,
        /// Of those, lines the model never emitted.
        unaccounted: u32,
    },
}

impl IntegrityVerdict {
    /// Stable audit spelling, or `None` when nothing was checked.
    #[must_use]
    pub fn describe(self) -> Option<String> {
        match self {
            Self::NotChecked => None,
            Self::Uninspectable => Some("uninspectable".to_owned()),
            Self::Lines {
                added,
                unaccounted: 0,
            } => Some(format!("accounted:{added}")),
            Self::Lines { added, unaccounted } => {
                Some(format!("unaccounted:{unaccounted}/{added}"))
            }
        }
    }

    /// Judges the lines a protected diff adds against the model's output.
    #[must_use]
    pub fn of_diff(diff: &str, model_output: &ModelOutputIndex) -> Self {
        if diff.contains("# keel: diff truncated") || diff.contains("GIT binary patch") {
            return Self::Uninspectable;
        }
        let (mut added, mut unaccounted) = (0_u32, 0_u32);
        for line in diff.lines().filter(|line| !line.starts_with("+++")) {
            let Some(line) = line.strip_prefix('+') else {
                continue;
            };
            if let Some(accounted) = model_output.accounts_for(line) {
                added = added.saturating_add(1);
                unaccounted = unaccounted.saturating_add(u32::from(!accounted));
            }
        }
        Self::Lines { added, unaccounted }
    }
}

/// Marker for an optional origin frame that may precede any broker request.
pub const ORIGIN_MAGIC: &[u8] = b"KEEL-ORIGIN-V1\0";
/// Largest accepted origin frame.
pub const MAX_ORIGIN_BYTES: usize = 4_096;

/// The guest's account of which process opened a mediated channel.
///
/// It is reported by guest code and never verified. Policy uses it only to
/// add violations; it can never remove one or raise a rank.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ReportedOrigin {
    /// Whether the guest found the owning process.
    pub known: bool,
    /// Whether the owner or an ancestor ran workspace-controlled code.
    pub workspace_code: bool,
    /// Bounded, printable rendering of the ancestry, nearest first; `*`
    /// marks workspace code.
    pub summary: String,
}

impl ReportedOrigin {
    /// Parses a bounded origin frame body. Anything malformed yields an
    /// unknown origin rather than an error, because an origin can only narrow.
    #[must_use]
    pub fn parse(bytes: &[u8]) -> Self {
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(bytes) else {
            return Self::default();
        };
        let flag = |name: &str| value.get(name).and_then(serde_json::Value::as_bool);
        let mut summary = String::new();
        for process in value
            .get("chain")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
            .take(6)
        {
            let text = |field: &str| process.get(field).and_then(serde_json::Value::as_str);
            let name = text("exe").map_or("?", |exe| exe.rsplit('/').next().unwrap_or(exe));
            let arguments = process
                .get("argv")
                .and_then(serde_json::Value::as_array)
                .into_iter()
                .flatten()
                .skip(1)
                .take(3)
                .filter_map(serde_json::Value::as_str)
                .map(|argument| {
                    // A harness's `bash -c` preamble would swamp the gate.
                    if argument.chars().count() > 40 {
                        format!("{}...", argument.chars().take(40).collect::<String>())
                    } else {
                        argument.to_owned()
                    }
                })
                .collect::<Vec<_>>()
                .join(" ");
            if !summary.is_empty() {
                summary.push_str(" <- ");
            }
            if process
                .get("workspace_code")
                .and_then(serde_json::Value::as_bool)
                == Some(true)
            {
                summary.push('*');
            }
            summary.push_str(name);
            if !arguments.is_empty() {
                summary.push(' ');
                summary.push_str(&arguments);
            }
        }
        summary = summary
            .chars()
            .filter(|character| !character.is_control())
            .take(240)
            .collect();
        Self {
            known: flag("known") == Some(true),
            workspace_code: flag("workspace_code") == Some(true),
            summary,
        }
    }
}

/// Whether an outgoing payload carries admitted confidential content to a
/// destination not cleared for it. Recorded in shadow; no decision reads it.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum FlowVerdict {
    /// The action has no inspected payload.
    #[default]
    NotChecked,
    /// No admitted confidential fragment was found.
    Clean,
    /// Confidential fragments were found, and the destination may receive them.
    Cleared(u32),
    /// Confidential fragments were found above the destination's clearance.
    Leak {
        /// The most confidential label present.
        label: Confidentiality,
        /// What the destination may receive.
        clearance: Confidentiality,
        /// Matching fingerprints.
        fragments: u32,
    },
}

impl FlowVerdict {
    /// Stable audit spelling.
    #[must_use]
    pub fn describe(self) -> String {
        let name = |label: Confidentiality| match label {
            Confidentiality::Public => "public",
            Confidentiality::Private => "private",
            Confidentiality::Secret => "secret",
        };
        match self {
            Self::NotChecked => "not-checked".to_owned(),
            Self::Clean => "clean".to_owned(),
            Self::Cleared(fragments) => format!("cleared:{fragments}"),
            Self::Leak {
                label,
                clearance,
                fragments,
            } => format!("{}-to-{}:{fragments}", name(label), name(clearance)),
        }
    }
}

/// Admitted confidential content and the destinations cleared to receive it.
#[derive(Debug, Default)]
pub struct PayloadPolicy {
    index: PayloadIndex,
    /// `(host, path prefix)` pairs cleared for private content: the
    /// workspace's own remote repository.
    private_sinks: Vec<(String, String)>,
}

impl PayloadPolicy {
    /// Combines an admission-time index with the destinations cleared for
    /// private content.
    #[must_use]
    pub const fn new(index: PayloadIndex, private_sinks: Vec<(String, String)>) -> Self {
        Self {
            index,
            private_sinks,
        }
    }

    /// Judges one decrypted request. The model endpoint receives the full
    /// context by design, so it is cleared for everything and not scanned.
    #[must_use]
    pub fn judge(&self, host: &str, path: &str, body: &[u8], model_host: &str) -> FlowVerdict {
        if host == model_host {
            return FlowVerdict::Cleared(0);
        }
        let clearance = if self
            .private_sinks
            .iter()
            .any(|(sink, prefix)| sink == host && path.starts_with(prefix.as_str()))
        {
            Confidentiality::Private
        } else {
            Confidentiality::Public
        };
        let (target, payload) = (self.index.scan(path.as_bytes()), self.index.scan(body));
        let fragments = target.private + target.secret + payload.private + payload.secret;
        match target.label().max(payload.label()) {
            None => FlowVerdict::Clean,
            Some(label) if label <= clearance => FlowVerdict::Cleared(fragments),
            Some(label) => FlowVerdict::Leak {
                label,
                clearance,
                fragments,
            },
        }
    }
}

/// Whether an action falls inside the operator-admitted task envelope.
///
/// Recorded for every action. Outside verdicts for pushes to unadmitted refs
/// and pull requests to unadmitted bases also gate; the rest are recorded in
/// shadow until the action-centric rules are enforced.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntentVerdict {
    /// The action class has no envelope: it produces no external effect.
    NotApplicable,
    /// The operator admitted this exact kind of effect.
    Inside,
    /// The effect is outside the envelope, for the named reason.
    Outside(&'static str),
}

impl IntentVerdict {
    /// Stable audit spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotApplicable => "not-applicable",
            Self::Inside => "inside",
            Self::Outside(reason) => reason,
        }
    }
}

impl Stamped {
    /// Returns the channel-bound principal.
    #[must_use]
    pub const fn principal(&self) -> &PrincipalId {
        &self.principal
    }

    /// Returns the session facts captured for this action.
    #[must_use]
    pub const fn session(&self) -> SessionSnapshot {
        self.session
    }

    /// Returns the kernel's task-envelope verdict for this action.
    #[must_use]
    pub const fn intent(&self) -> IntentVerdict {
        self.intent
    }

    /// Returns the kernel's payload-flow verdict for this action.
    #[must_use]
    pub const fn flow(&self) -> FlowVerdict {
        self.flow
    }

    /// Returns the kernel's protected-content integrity verdict.
    #[must_use]
    pub const fn integrity(&self) -> IntegrityVerdict {
        self.integrity
    }

    /// Returns the guest-reported origin received with this action, if any.
    #[must_use]
    pub const fn reported_origin(&self) -> Option<&ReportedOrigin> {
        self.origin.as_ref()
    }
}

/// A complete action considered by policy and the trusted gate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Action {
    id: u64,
    asserted: Asserted,
    stamped: Stamped,
}

impl Action {
    /// Returns the session-unique action identifier.
    #[must_use]
    pub const fn id(&self) -> u64 {
        self.id
    }

    /// Returns the untrusted portion of the action.
    #[must_use]
    pub const fn asserted(&self) -> &Asserted {
        &self.asserted
    }

    /// Returns the kernel-authenticated portion of the action.
    #[must_use]
    pub const fn stamped(&self) -> &Stamped {
        &self.stamped
    }
}

/// Returns the SHA-256 digest of an action's class and exact target.
#[must_use]
pub fn action_target_hash(action: &Action) -> [u8; 32] {
    let mut encoded = Vec::new();
    encoded.push(action_class_tag(action.asserted.class));
    encode_target(&mut encoded, &action.asserted.target);
    let hash = digest(&SHA256, &encoded);
    let mut output = [0_u8; 32];
    output.copy_from_slice(hash.as_ref());
    output
}

fn encode_target(output: &mut Vec<u8>, target: &Target) {
    match target {
        Target::Workspace { path } => {
            output.push(0);
            encode_bytes(output, path.as_bytes());
        }
        Target::Command { program, arguments } => {
            output.push(1);
            encode_bytes(output, program.as_bytes());
            output.extend_from_slice(&(arguments.len() as u64).to_be_bytes());
            for argument in arguments {
                encode_bytes(output, argument.as_bytes());
            }
        }
        Target::Network {
            host,
            port,
            method,
            path,
        } => {
            output.push(2);
            encode_bytes(output, host.as_bytes());
            output.extend_from_slice(&port.to_be_bytes());
            encode_bytes(output, method.as_bytes());
            encode_bytes(output, path.as_bytes());
        }
        Target::Git {
            remote,
            refs,
            is_force,
            is_default_branch,
            touches_manifest,
            manifest_diff,
        } => {
            output.push(3);
            encode_bytes(output, remote.as_bytes());
            output.extend_from_slice(&(refs.len() as u64).to_be_bytes());
            for reference in refs {
                encode_bytes(output, reference.as_bytes());
            }
            output.extend_from_slice(&[
                u8::from(*is_force),
                u8::from(*is_default_branch),
                u8::from(*touches_manifest),
            ]);
            match manifest_diff {
                Some(diff) => {
                    output.push(1);
                    encode_bytes(output, diff.as_bytes());
                }
                None => output.push(0),
            }
        }
        Target::External {
            service,
            recipient,
            operation,
            detail,
        } => {
            output.push(4);
            encode_bytes(output, service.as_bytes());
            encode_bytes(output, recipient.as_bytes());
            encode_bytes(output, operation.as_bytes());
            encode_bytes(output, detail.as_bytes());
        }
        Target::FloorLift {
            session_id,
            requested_floor,
        } => {
            output.push(5);
            encode_bytes(output, session_id.as_bytes());
            output.push(*requested_floor);
        }
        Target::Protected(state) => {
            output.extend_from_slice(&[6, protected_state_tag(*state)]);
        }
    }
}

fn encode_bytes(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u64).to_be_bytes());
    output.extend_from_slice(value);
}

const fn action_class_tag(class: ActionClass) -> u8 {
    match class {
        ActionClass::ReadWorkspace => 0,
        ActionClass::WriteWorkspace => 1,
        ActionClass::RunCommand => 2,
        ActionClass::GitCommit => 3,
        ActionClass::GitPush => 4,
        ActionClass::Egress => 5,
        ActionClass::PullRequest => 6,
        ActionClass::Publish => 7,
        ActionClass::WriteOutsideWorkspace => 8,
        ActionClass::DeleteOutsideWorkspace => 9,
        ActionClass::LiftFloor => 10,
    }
}

/// Every state I11 rejects before policy and gate evaluation.
///
/// The exhaustive match below is what keeps this honest: a new variant of
/// `ProtectedState` does not compile until it is named here, so the reported set
/// cannot fall behind the enforced one.
const PROTECTED_STATES: [ProtectedState; 5] = [
    ProtectedState::Policy,
    ProtectedState::Audit,
    ProtectedState::Attestation,
    ProtectedState::Provenance,
    ProtectedState::Budget,
];

const fn protected_state_name(state: ProtectedState) -> &'static str {
    match state {
        ProtectedState::Policy => "policy",
        ProtectedState::Audit => "audit",
        ProtectedState::Attestation => "attestation",
        ProtectedState::Provenance => "provenance",
        ProtectedState::Budget => "budget",
    }
}

const fn protected_state_tag(state: ProtectedState) -> u8 {
    match state {
        ProtectedState::Policy => 0,
        ProtectedState::Audit => 1,
        ProtectedState::Attestation => 2,
        ProtectedState::Provenance => 3,
        ProtectedState::Budget => 4,
    }
}

/// The mediation path assigned to an authenticated channel.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GateClass {
    /// Workspace reads and writes.
    Workspace,
    /// Structured command execution.
    Command,
    /// Outbound network requests.
    Egress,
    /// Git operations.
    Git,
    /// External publication and pull-request operations.
    External,
    /// Trusted operator input.
    Operator,
}

impl GateClass {
    /// Returns the stable audit spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Workspace => "workspace",
            Self::Command => "command",
            Self::Egress => "egress",
            Self::Git => "git",
            Self::External => "external",
            Self::Operator => "operator",
        }
    }

    const fn accepts(self, class: ActionClass) -> bool {
        match self {
            Self::Workspace => matches!(
                class,
                ActionClass::ReadWorkspace
                    | ActionClass::WriteWorkspace
                    | ActionClass::WriteOutsideWorkspace
                    | ActionClass::DeleteOutsideWorkspace
            ),
            Self::Command => matches!(class, ActionClass::RunCommand),
            Self::Egress => matches!(class, ActionClass::Egress),
            Self::Git => matches!(class, ActionClass::GitCommit | ActionClass::GitPush),
            Self::External => {
                matches!(class, ActionClass::PullRequest | ActionClass::Publish)
            }
            Self::Operator => matches!(class, ActionClass::LiftFloor),
        }
    }
}

/// A required action-channel declaration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChannelDeclaration {
    /// Stable channel name.
    pub name: String,
    /// Principal authenticated by this channel.
    pub principal: PrincipalId,
    /// Mediation path available to the channel.
    pub gate_class: GateClass,
}

/// A complete, startup-validated channel registry.
#[derive(Clone, Debug)]
pub struct ChannelRegistry {
    declarations: BTreeMap<String, ChannelDeclaration>,
}

impl ChannelRegistry {
    /// Builds a registry and proves every required channel is declared exactly
    /// once, with no undeclared extras.
    /// # Errors
    /// Returns a channel-registry error on duplicate, missing, or unexpected
    /// declarations.
    pub fn new<I, S>(
        required_channels: I,
        declarations: impl IntoIterator<Item = ChannelDeclaration>,
    ) -> Result<Self, KernelError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let required = required_channels
            .into_iter()
            .map(Into::into)
            .collect::<std::collections::BTreeSet<_>>();
        let mut by_name = BTreeMap::new();
        for declaration in declarations {
            let name = declaration.name.clone();
            if by_name.insert(name.clone(), declaration).is_some() {
                return Err(KernelError::DuplicateChannel(name));
            }
        }

        if let Some(name) = required
            .difference(&by_name.keys().cloned().collect())
            .next()
        {
            return Err(KernelError::MissingChannel(name.clone()));
        }
        if let Some(name) = by_name
            .keys()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>()
            .difference(&required)
            .next()
        {
            return Err(KernelError::UnexpectedChannel(name.clone()));
        }

        Ok(Self {
            declarations: by_name,
        })
    }

    fn declaration(&self, channel: &str) -> Result<&ChannelDeclaration, KernelError> {
        self.declarations
            .get(channel)
            .ok_or_else(|| KernelError::UnknownChannel(channel.to_owned()))
    }
}

/// A concrete reason that an action cannot run automatically.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Violation {
    /// Stable rule identifier.
    pub rule: String,
    /// Human-readable detail suitable for the trusted gate.
    pub detail: String,
}

impl Violation {
    /// Creates a violation.
    #[must_use]
    pub fn new(rule: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            rule: rule.into(),
            detail: detail.into(),
        }
    }
}

/// A fail-closed policy evaluator. An action auto-allows only when this returns
/// an empty set.
pub trait Policy: Send {
    /// Returns every policy violation for an action.
    /// # Errors
    /// Returns an error when policy cannot produce a complete decision.
    fn violations(&self, action: &Action, facts: &SessionFacts) -> Result<Vec<Violation>, String>;
}

/// The exact action and reasons displayed by the trusted gate.
#[derive(Clone, Debug)]
pub struct GateRequest<'a> {
    /// Action awaiting a decision.
    pub action: &'a Action,
    /// All reasons the action requires approval.
    pub violations: &'a [Violation],
    /// Concrete provenance observations, most recent first.
    pub floor_history: &'a [FloorObservation],
    /// Caller-liveness signal for an action tied to an open relay connection.
    ///
    /// A set flag invalidates the prompt. Gates that cannot observe liveness
    /// receive `None`; a wrapper may still reject their answer after return.
    pub cancelled: Option<Arc<AtomicBool>>,
}

impl GateRequest<'_> {
    /// Copies the exact action and all escalation reasons into an owned
    /// trusted-screen payload.
    #[must_use]
    pub fn to_payload(&self) -> GatePayload {
        GatePayload {
            action_id: self.action.id(),
            action_class: self.action.asserted.class.as_str().to_owned(),
            exact_target: {
                let mut target = render_gate_target(&self.action.asserted.target);
                match self.action.stamped.integrity {
                    IntegrityVerdict::Lines { added, unaccounted } if unaccounted > 0 => {
                        let _ = fmt::Write::write_fmt(
                            &mut target,
                            format_args!(
                                "\nadded lines the model did not write: {unaccounted} of {added}"
                            ),
                        );
                    }
                    IntegrityVerdict::Uninspectable => {
                        target.push_str("\nthe protected diff could not be fully inspected");
                    }
                    _ => {}
                }
                if let Some(origin) = &self.action.stamped.origin {
                    target.push_str("\nissued by (guest-reported): ");
                    target.push_str(if origin.known {
                        &origin.summary
                    } else {
                        "unknown process"
                    });
                }
                target.into_bytes()
            },
            reasons: self
                .violations
                .iter()
                .map(|violation| GateReason {
                    rule: violation.rule.clone(),
                    detail: violation.detail.clone(),
                })
                .collect(),
            floor_history: self
                .floor_history
                .iter()
                .map(|entry| {
                    format!(
                        "rank {} at {}: {:?}",
                        entry.rank, entry.timestamp_ms, entry.source
                    )
                    .into_bytes()
                })
                .collect(),
            session_grant: grantable_egress(self.action, self.violations).map(|key| {
                format!(
                    "host {:?}, port {}, method {:?}; expires after 15 minutes, 64 total \
                     actions, or a lower floor",
                    key.host, key.port, key.method
                )
                .into_bytes()
            }),
        }
    }
}

fn render_gate_target(target: &Target) -> String {
    match target {
        Target::Workspace { path } => format!("path: {path:?}"),
        Target::Command { program, arguments } => {
            format!("program: {program:?}\narguments: {arguments:#?}")
        }
        Target::Network {
            host,
            port,
            method,
            path,
        } => format!("request: {method:?} {path:?}\nhost: {host:?}\nport: {port}"),
        Target::Git {
            remote,
            refs,
            is_force,
            is_default_branch,
            touches_manifest,
            manifest_diff,
        } => format!(
            "remote: {remote:?}\nrefs: {refs:#?}\nforce: {is_force}\ndefault branch: \
             {is_default_branch}\ntouches manifest or CI: {touches_manifest}\nprotected diff:\n{}",
            manifest_diff.as_deref().unwrap_or("(none)")
        ),
        Target::External {
            service,
            recipient,
            operation,
            detail,
        } => format!(
            "service: {service:?}\noperation: {operation:?}\nrecipient: {recipient:?}\ndetail:\n{detail}"
        ),
        Target::FloorLift {
            session_id,
            requested_floor,
        } => format!("session: {session_id:?}\nrequested floor: {requested_floor}"),
        Target::Protected(state) => format!("protected state: {state:?}"),
    }
}

/// Exact action data painted by the trusted terminal owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatePayload {
    /// Session-unique action identifier.
    pub action_id: u64,
    /// Action class.
    pub action_class: String,
    /// Exact command, diff, recipient, or other target bytes.
    pub exact_target: Vec<u8>,
    /// Complete policy and kernel reasons for escalation.
    pub reasons: Vec<GateReason>,
    /// Concrete provenance sources, most recent first.
    pub floor_history: Vec<Vec<u8>>,
    /// Scope and bounds of the session grant created by this approval, if any.
    pub session_grant: Option<Vec<u8>>,
}

/// One escalation reason painted on the trusted screen.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GateReason {
    /// Stable policy or kernel rule identifier.
    pub rule: String,
    /// Human-readable rule detail.
    pub detail: String,
}

/// Operator interaction required for one escalated action.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApprovalMethod {
    /// A fresh one-key confirmation after secure attention.
    Confirm,
    /// A fresh kernel-generated challenge must be typed in full.
    Challenge,
}

/// One pending action received from the kernel gate.
pub struct PendingApproval {
    payload: GatePayload,
    method: ApprovalMethod,
    challenge: Option<String>,
    decision: SyncSender<GateDecision>,
    active: Arc<AtomicBool>,
}

impl PendingApproval {
    /// Returns the complete trusted-screen payload.
    #[must_use]
    pub const fn payload(&self) -> &GatePayload {
        &self.payload
    }

    /// Returns the operator interaction required for this action.
    #[must_use]
    pub const fn method(&self) -> ApprovalMethod {
        self.method
    }

    /// Returns the fresh challenge for a high-impact action.
    #[must_use]
    pub fn challenge(&self) -> Option<&str> {
        self.challenge.as_deref()
    }

    /// Returns whether the kernel is still accepting a decision for this action.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::Acquire)
    }

    /// Delivers the operator's decision to the blocked kernel action.
    ///
    /// # Errors
    ///
    /// Returns an error if the kernel action has already ended.
    pub fn decide(self, decision: GateDecision) -> Result<(), String> {
        self.active
            .compare_exchange(true, false, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| "kernel gate is no longer waiting".to_owned())?;
        self.decision
            .send(decision)
            .map_err(|_| "kernel gate is no longer waiting".to_owned())
    }
}

/// Kernel-side endpoint for the trusted terminal approval channel.
pub struct TerminalGate {
    prompts: SyncSender<PendingApproval>,
    decision_timeout: Duration,
}

/// Terminal-side endpoint for the trusted terminal approval channel.
pub struct GateController {
    prompts: Receiver<PendingApproval>,
}

/// Creates a zero-buffered, in-process trusted approval channel.
#[must_use]
pub fn terminal_gate_channel() -> (TerminalGate, GateController) {
    let (prompts, controller) = sync_channel(0);
    (
        TerminalGate {
            prompts,
            decision_timeout: APPROVAL_DECISION_TIMEOUT,
        },
        GateController {
            prompts: controller,
        },
    )
}

impl GateController {
    /// Waits for the next escalated action.
    ///
    /// # Errors
    ///
    /// Returns an error when the kernel broker has stopped.
    pub fn receive(&self) -> Result<PendingApproval, String> {
        self.prompts
            .recv()
            .map_err(|_| "kernel gate channel is closed".to_owned())
    }

    /// Waits for a prompt for at most `timeout`, returning `None` on timeout.
    ///
    /// # Errors
    /// Returns an error when the kernel broker has stopped.
    pub fn receive_timeout(&self, timeout: Duration) -> Result<Option<PendingApproval>, String> {
        match self.prompts.recv_timeout(timeout) {
            Ok(prompt) => Ok(Some(prompt)),
            Err(RecvTimeoutError::Timeout) => Ok(None),
            Err(RecvTimeoutError::Disconnected) => Err("kernel gate channel is closed".to_owned()),
        }
    }
}

// Keep the trusted decision deadline shorter than the relay's five-minute
// pending deadline so the broker can always return an explicit denial before
// the guest gives up on the request.
const APPROVAL_DECISION_TIMEOUT: Duration = Duration::from_secs(4 * 60 + 45);

impl Gate for TerminalGate {
    fn decide(&mut self, request: GateRequest<'_>) -> GateDecision {
        if request
            .cancelled
            .as_ref()
            .is_some_and(|cancelled| cancelled.load(Ordering::Acquire))
        {
            return GateDecision::Unavailable;
        }
        let method = approval_method(request.action);
        let challenge = match method {
            ApprovalMethod::Confirm => None,
            ApprovalMethod::Challenge => {
                let Ok(challenge) = random_challenge() else {
                    return GateDecision::Unavailable;
                };
                Some(challenge)
            }
        };
        let (decision, response) = sync_channel(0);
        let active = Arc::new(AtomicBool::new(true));
        if self
            .prompts
            .send(PendingApproval {
                payload: request.to_payload(),
                method,
                challenge,
                decision,
                active: Arc::clone(&active),
            })
            .is_err()
        {
            return GateDecision::Unavailable;
        }
        let deadline = Instant::now() + self.decision_timeout;
        loop {
            if request
                .cancelled
                .as_ref()
                .is_some_and(|cancelled| cancelled.load(Ordering::Acquire))
            {
                active.store(false, Ordering::Release);
                return GateDecision::Unavailable;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                active.store(false, Ordering::Release);
                return GateDecision::Unavailable;
            }
            match response.recv_timeout(remaining.min(Duration::from_millis(50))) {
                Ok(decision)
                    if !request
                        .cancelled
                        .as_ref()
                        .is_some_and(|cancelled| cancelled.load(Ordering::Acquire)) =>
                {
                    return decision;
                }
                Ok(_) | Err(RecvTimeoutError::Disconnected) => {
                    active.store(false, Ordering::Release);
                    return GateDecision::Unavailable;
                }
                Err(RecvTimeoutError::Timeout) => {}
            }
        }
    }

    fn authority(&self) -> &'static str {
        "operator"
    }
}

fn random_challenge() -> Result<String, String> {
    use std::fmt::Write as _;

    let mut random = [0_u8; 4];
    SystemRandom::new()
        .fill(&mut random)
        .map_err(|_| "approval challenge randomness is unavailable".to_owned())?;
    let mut challenge = String::with_capacity(random.len() * 2);
    for byte in random {
        write!(challenge, "{byte:02X}").map_err(|error| error.to_string())?;
    }
    Ok(challenge)
}

/// A decision returned in-process by the trusted input path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GateDecision {
    /// Operator approved this exact borrowed action; this synchronous call
    /// consumes the decision.
    Approve,
    /// Approve this action and the reusable scope explicitly shown by the gate.
    ApproveGrant,
    /// Reject the action.
    Deny,
    /// No valid operator answer exists because the caller, channel, or bounded
    /// decision window ended. This is not an explicit operator denial.
    Unavailable,
}

/// Provenance behavior selected for one kernel run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProvenanceMode {
    /// Enforce the monotonically decreasing session floor.
    Floor,
    /// Show provenance at gates without applying a rank check.
    GateContext,
}

/// Trusted approval interface.
pub trait Gate: Send {
    /// Renders and decides one exact action.
    fn decide(&mut self, request: GateRequest<'_>) -> GateDecision;

    /// Names who can answer an escalation through this gate.
    ///
    /// A gate that no operator can reach still denies, which is safe, but it is
    /// a different run from one a human is watching and the record says which.
    fn authority(&self) -> &'static str {
        "deny-only"
    }
}

/// An action that has passed every check before the trusted gate.
///
/// A caller sharing the kernel may release its lock while a human decides;
/// [`Kernel::finish`] re-derives the action's reasons against the session as
/// it then stands, so state that changed during the wait cannot ride on the
/// operator's answer.
#[derive(Debug)]
pub struct PendingAction {
    action: Action,
    denial_scope: DenialScope,
    violations: Vec<Violation>,
    floor_history: Vec<FloorObservation>,
    needs_gate: bool,
}

impl PendingAction {
    /// Whether a trusted decision is required before [`Kernel::finish`].
    #[must_use]
    pub const fn needs_gate(&self) -> bool {
        self.needs_gate
    }

    /// Renders the exact request a gate decides.
    #[must_use]
    pub fn gate_request(&self) -> GateRequest<'_> {
        GateRequest {
            action: &self.action,
            violations: &self.violations,
            floor_history: &self.floor_history,
            cancelled: None,
        }
    }
}

/// One measured trusted decision about a pending action.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GateOutcome {
    /// Decision returned by the gate.
    pub decision: GateDecision,
    /// Authority that supplied the decision.
    pub authority: &'static str,
    /// Decision latency in milliseconds.
    pub time_to_decision_ms: u64,
}

impl GateOutcome {
    /// Asks `gate` to decide `request` and measures the decision.
    pub fn decide(gate: &mut (impl Gate + ?Sized), request: GateRequest<'_>) -> Self {
        let started = Instant::now();
        let decision = gate.decide(request);
        Self {
            decision,
            authority: gate.authority(),
            time_to_decision_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        }
    }
}

/// Converts an authorized action into an execution request containing any
/// required credentials.
pub trait CredentialInjector {
    /// Prepared request type visible to the executor.
    type Prepared;

    /// Injects credentials after authorization.
    /// # Errors
    /// Returns an error when credentials cannot be prepared.
    fn inject(&mut self, action: &Action) -> Result<Self::Prepared, String>;
}

/// Executes an authorized, credential-bearing request.
pub trait Executor<Prepared> {
    /// Successful execution result.
    type Output;

    /// Executes a prepared request.
    /// # Errors
    /// Returns an error when execution fails.
    fn execute(&mut self, request: Prepared) -> Result<Self::Output, String>;
}

/// Audit outcome recorded without target contents or credentials.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditOutcome {
    /// Authorization completed and external execution is about to begin.
    Attempted,
    /// Action completed successfully.
    Executed,
    /// Kernel rejected the action.
    Denied,
    /// Credential preparation failed.
    InjectionFailed,
    /// The executor returned an error.
    ExecutionFailed,
}

impl AuditOutcome {
    /// Returns the stable audit name for this outcome.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Attempted => "attempted",
            Self::Executed => "executed",
            Self::Denied => "denied",
            Self::InjectionFailed => "injection-failed",
            Self::ExecutionFailed => "execution-failed",
        }
    }
}

/// Measurements captured around one trusted gate decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GateTelemetry {
    /// Wall-clock-independent decision latency in milliseconds.
    pub time_to_decision_ms: u64,
    /// Operator decision returned by the trusted input path.
    pub decision: GateDecision,
    /// Kernel-owned provenance floor when the gate was rendered.
    pub floor_at_gate: u8,
    /// Provenance behavior active for this run.
    pub mode: ProvenanceMode,
    /// Authority that supplied the decision (`operator` or `deny-only`).
    pub authority: &'static str,
    /// Whether an operator prompt was actually reachable for this decision.
    pub prompt_presented: bool,
}

/// A secret-free event emitted by the kernel.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditEvent {
    /// Session-unique action identifier.
    pub action_id: u64,
    /// Verified principal.
    pub principal: PrincipalId,
    /// Action class.
    pub class: ActionClass,
    /// Coarse target kind; exact sensitive contents stay out of this event.
    pub target_kind: &'static str,
    /// SHA-256 commitment to the exact action class and target.
    pub target_hash: [u8; 32],
    /// Final outcome.
    pub outcome: AuditOutcome,
    /// Task-envelope verdict stamped by the kernel.
    pub intent: &'static str,
    /// Payload-flow verdict stamped by the kernel.
    pub flow: String,
    /// Guest-reported origin, rendered, when one accompanied the action.
    pub origin: Option<String>,
    /// Protected-content integrity verdict, when one was computed.
    pub integrity: Option<String>,
    /// Stable violation rule identifiers.
    pub rules: Vec<String>,
    /// Gate measurements, present exactly when this action escalated.
    pub gate: Option<GateTelemetry>,
    /// Typed, scoped denial state, present exactly for denied actions.
    pub denial: Option<DenialTelemetry>,
}

/// Trusted denial metadata attached to a denied action audit record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DenialTelemetry {
    /// Why the action was rejected.
    pub origin: DenialOrigin,
    /// Privacy-safe digest of the canonical action scope.
    pub scope: DenialScope,
    /// Whether this denial contributes to repeated-behavior review.
    pub counted_for_repeated_review: bool,
    /// Behavioral denials now active for this exact scope.
    pub recent_behavioral_denials_in_scope: u32,
}

/// A rejected request that could not safely be promoted into an [`Action`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StructuralRejectionEvent {
    /// Digest of the untrusted channel label.
    pub channel_hash: [u8; 32],
    /// Digest of the untrusted principal claim.
    pub principal_hash: [u8; 32],
    /// Asserted action class.
    pub class: ActionClass,
    /// Coarse target kind.
    pub target_kind: &'static str,
    /// Commitment to the asserted class and exact target.
    pub target_hash: [u8; 32],
    /// Stable rejection rule.
    pub rule: &'static str,
}

/// Receives kernel audit events.
pub trait AuditSink: Send {
    /// Records one event.
    /// # Errors
    /// Returns an error when durable recording fails.
    fn record(&mut self, event: AuditEvent) -> Result<(), String>;

    /// Records a structurally invalid request before returning its error.
    /// # Errors
    /// Returns an error when durable recording fails.
    fn record_structural_rejection(
        &mut self,
        _event: StructuralRejectionEvent,
    ) -> Result<(), String> {
        Ok(())
    }

    /// Records trusted model usage after an authorized response.
    /// # Errors
    /// Returns an error when durable recording fails.
    fn record_model_usage(&mut self, _event: ModelUsageEvent) -> Result<(), String> {
        Ok(())
    }

    /// Records a terminal model reservation transition before accounting state
    /// is changed. Production sinks override this just as they override the
    /// other optional lifecycle records; an error from that implementation
    /// prevents the accounting transition.
    /// # Errors
    /// Returns an error when durable recording fails.
    fn record_model_reservation(&mut self, _event: ModelReservationEvent) -> Result<(), String> {
        Ok(())
    }

    /// Records a classified result before it changes kernel state.
    /// # Errors
    /// Returns an error when durable recording fails.
    fn record_provenance(&mut self, _event: ProvenanceEvent) -> Result<(), String> {
        Ok(())
    }

    /// Records the context blocks of one model request or response.
    /// # Errors
    /// Returns an error when durable recording fails.
    fn record_context(&mut self, _event: ContextEvent) -> Result<(), String> {
        Ok(())
    }

    /// Records a run's admission manifest.
    /// # Errors
    /// Returns an error when durable recording fails.
    fn record_run_admitted(&mut self, _event: RunAdmittedEvent) -> Result<(), String> {
        Ok(())
    }

    /// Records an untrusted caller's claim about an authorized action's outcome.
    /// # Errors
    /// Returns an error when durable recording fails.
    fn record_reported_outcome(&mut self, _event: ReportedOutcomeEvent) -> Result<(), String> {
        Ok(())
    }

    /// Records which boundaries were standing at one point in the run.
    /// # Errors
    /// Returns an error when durable recording fails.
    fn record_enforcement_state(&mut self, _event: EnforcementStateEvent) -> Result<(), String> {
        Ok(())
    }

    /// Returns whether records written here survive the run.
    ///
    /// A sink that discards is not an audit boundary, and a report that claimed
    /// otherwise would be the exact failure this reporting exists to catch.
    fn is_durable(&self) -> bool {
        false
    }

    /// Flushes and closes the audit stream.
    /// # Errors
    /// Returns an error when durable shutdown fails.
    fn shutdown(&mut self) -> Result<(), String> {
        Ok(())
    }
}

/// Mutable facts and budgets owned by one kernel session.
#[derive(Clone, Debug)]
pub struct SessionState {
    facts: SessionFacts,
    committed_actions: u64,
    reserved_actions: u64,
    action_limit: u64,
    next_action_id: u64,
    repeat_limit: u32,
    repeats: HashMap<u64, (u64, u32)>,
}

/// A loop is a burst of identical actions, not a long session's total: the
/// harness sends the same model request shape for as long as it runs.
const LOOP_WINDOW_MS: u64 = 60_000;

impl SessionState {
    /// Starts a session at rank three with a hard action budget and loop limit.
    /// # Errors
    /// Returns an error for a zero action budget or zero repeat limit.
    pub fn new(action_limit: u64, repeat_limit: u32) -> Result<Self, KernelError> {
        if action_limit == 0 {
            return Err(KernelError::InvalidBudget);
        }
        if repeat_limit == 0 {
            return Err(KernelError::InvalidLoopLimit);
        }
        Ok(Self {
            facts: SessionFacts::default(),
            committed_actions: 0,
            reserved_actions: 0,
            action_limit,
            next_action_id: 1,
            repeat_limit,
            repeats: HashMap::new(),
        })
    }

    /// Restores validated trusted facts into a fresh action budget.
    /// # Errors
    /// Returns an error when either budget is zero.
    pub fn resume(
        action_limit: u64,
        repeat_limit: u32,
        facts: SessionFacts,
    ) -> Result<Self, KernelError> {
        let mut state = Self::new(action_limit, repeat_limit)?;
        state.facts = facts;
        Ok(state)
    }

    /// Returns the current provenance floor.
    #[must_use]
    pub const fn floor(&self) -> u8 {
        self.facts.floor
    }

    /// Returns the complete kernel-owned stateful policy facts.
    #[must_use]
    pub const fn facts(&self) -> &SessionFacts {
        &self.facts
    }

    /// Applies one result produced by the trusted provenance classifier.
    pub fn observe_result(&mut self, result: ClassifiedResult, timestamp_ms: u64) {
        result.apply(&mut self.facts, timestamp_ms);
    }

    /// Returns actions denied in this session.
    #[must_use]
    pub const fn denied_actions(&self) -> u32 {
        self.facts.denied_actions
    }

    /// Returns actions sent to the trusted gate.
    #[must_use]
    pub const fn escalated_actions(&self) -> u32 {
        self.facts.escalated_actions
    }

    /// Returns actions committed against the budget.
    #[must_use]
    pub const fn committed_actions(&self) -> u64 {
        self.committed_actions
    }

    const fn snapshot(&self) -> SessionSnapshot {
        SessionSnapshot {
            floor: self.facts.floor,
            denied_actions: self.facts.denied_actions as u64,
            committed_actions: self.committed_actions,
            action_limit: self.action_limit,
        }
    }

    fn observe_executed(&mut self, action: &Action) {
        match (&action.asserted.class, &action.asserted.target) {
            (ActionClass::WriteWorkspace, Target::Workspace { path }) => {
                let created = self.facts.files_created_by_this_vertex.contains(path);
                self.facts.record_write(path, created, unix_time_ms());
            }
            (ActionClass::Egress, Target::Network { host, .. }) => {
                self.facts.record_host(host, is_registry_host(host));
            }
            (
                ActionClass::LiftFloor,
                Target::FloorLift {
                    requested_floor, ..
                },
            ) => {
                self.facts.lift_floor(*requested_floor);
            }
            _ => {}
        }
    }

    fn allocate_action_id(&mut self) -> Result<u64, KernelError> {
        let id = self.next_action_id;
        self.next_action_id = self
            .next_action_id
            .checked_add(1)
            .ok_or(KernelError::ActionIdExhausted)?;
        Ok(id)
    }

    fn observe_action(&mut self, asserted: &Asserted, now_ms: u64) -> Result<(), KernelError> {
        let mut hasher = DefaultHasher::new();
        asserted.class.hash(&mut hasher);
        asserted.target.hash(&mut hasher);
        let live = |start: u64| now_ms.saturating_sub(start) < LOOP_WINDOW_MS;
        if self.repeats.len() >= 4_096 {
            self.repeats.retain(|_, (start, _)| live(*start));
        }
        let (start, count) = self.repeats.entry(hasher.finish()).or_insert((now_ms, 0));
        if !live(*start) {
            (*start, *count) = (now_ms, 0);
        }
        *count = count.saturating_add(1);
        if *count > self.repeat_limit {
            return Err(KernelError::LoopDetected);
        }
        Ok(())
    }

    fn reserve(&mut self) -> Result<(), KernelError> {
        let used = self
            .committed_actions
            .checked_add(self.reserved_actions)
            .ok_or(KernelError::BudgetExhausted)?;
        if used >= self.action_limit {
            return Err(KernelError::BudgetExhausted);
        }
        self.reserved_actions += 1;
        Ok(())
    }

    fn release(&mut self) {
        self.reserved_actions -= 1;
    }

    fn commit(&mut self) {
        self.reserved_actions -= 1;
        self.committed_actions += 1;
    }
}

/// Successful pipeline result.
#[derive(Debug, Eq, PartialEq)]
pub struct Processed<T> {
    /// Session-unique action identifier.
    pub action_id: u64,
    /// Executor result.
    pub output: T,
}

/// The trusted action-composition kernel.
pub struct Kernel<P> {
    registry: ChannelRegistry,
    session: SessionState,
    policy: P,
    egress_grants: HashMap<EgressGrantKey, SessionGrant>,
    provenance_mode: ProvenanceMode,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct EgressGrantKey {
    host: String,
    port: u16,
    method: String,
}

struct SessionGrant {
    issued_by_action_id: u64,
    expires_at_ms: u64,
    remaining_actions: u16,
    // A grant waives only the reasons the operator saw, at the floor they saw.
    // Influence read later is a new fact the approval never covered.
    waives: Vec<String>,
    floor_at_issue: u8,
}

const EGRESS_GRANT_TTL_MS: u64 = 15 * 60 * 1_000;
const EGRESS_GRANT_ACTIONS: u16 = 64;

impl<P: Policy> Kernel<P> {
    /// Creates a kernel from a complete registry, session, and policy.
    /// # Errors
    /// Returns an error when an ephemeral approval key cannot be generated.
    pub fn new(
        registry: ChannelRegistry,
        session: SessionState,
        policy: P,
        session_id: impl Into<String>,
    ) -> Result<Self, KernelError> {
        Self::with_provenance_mode(registry, session, policy, session_id, ProvenanceMode::Floor)
    }

    /// Audits and applies a classified result, failing before state mutation.
    /// # Errors
    /// Returns an audit error without changing the session if persistence fails.
    pub fn observe_result(
        &mut self,
        result: ClassifiedResult,
        timestamp_ms: u64,
        audit: &mut impl AuditSink,
    ) -> Result<(), KernelError> {
        if let (Some(rank), Some(source)) = (result.rank(), result.source()) {
            let floor_before = self.session.floor();
            audit
                .record_provenance(ProvenanceEvent {
                    rank: rank.as_u8(),
                    floor_before,
                    floor_after: floor_before.min(rank.as_u8()),
                    source: source.clone(),
                    timestamp_ms,
                })
                .map_err(KernelError::Audit)?;
        }
        self.session.observe_result(result, timestamp_ms);
        Ok(())
    }

    /// Creates a kernel with an explicit provenance behavior.
    /// # Errors
    /// Returns an error when the session identifier is malformed.
    pub fn with_provenance_mode(
        registry: ChannelRegistry,
        session: SessionState,
        policy: P,
        session_id: impl Into<String>,
        provenance_mode: ProvenanceMode,
    ) -> Result<Self, KernelError> {
        let session_id = session_id.into();
        if session_id.is_empty() || session_id.chars().any(char::is_control) {
            return Err(KernelError::InvalidSession);
        }
        Ok(Self {
            registry,
            session,
            policy,
            egress_grants: HashMap::new(),
            provenance_mode,
        })
    }

    /// Returns the kernel-owned session state.
    #[must_use]
    pub const fn session(&self) -> &SessionState {
        &self.session
    }

    fn conclude_gate(
        &mut self,
        action: &Action,
        denial_scope: DenialScope,
        violations: &[Violation],
        outcome: GateOutcome,
        audit: &mut impl AuditSink,
    ) -> Result<GateTelemetry, KernelError> {
        let GateOutcome {
            decision,
            authority,
            time_to_decision_ms,
        } = outcome;
        let telemetry = GateTelemetry {
            time_to_decision_ms,
            decision,
            floor_at_gate: action.stamped.session.floor,
            mode: self.provenance_mode,
            authority,
            prompt_presented: authority == "operator",
        };
        if matches!(decision, GateDecision::Deny | GateDecision::Unavailable) {
            self.session.release();
            let origin = if decision == GateDecision::Unavailable {
                DenialOrigin::Resource
            } else if authority == "operator" {
                DenialOrigin::Operator
            } else if violations
                .iter()
                .any(|violation| violation.rule == "kernel:model-budget")
            {
                DenialOrigin::Resource
            } else {
                DenialOrigin::Policy
            };
            let denial = observe_denial(&mut self.session.facts, origin, denial_scope);
            record(
                audit,
                action,
                AuditOutcome::Denied,
                &violation_rules(violations),
                Some(&telemetry),
                Some(&denial),
            )?;
            return Err(KernelError::GateDenied);
        }
        // The caller may have released its lock while the operator decided.
        // The approval covers the reasons that were displayed, so the action
        // is re-derived against the session as it stands now: a new reason,
        // such as a floor that dropped during the wait, was never shown.
        let mut current = action.clone();
        current.stamped.session = self.session.snapshot();
        let reasons = self.reasons(&current, denial_scope)?;
        if reasons.iter().any(|reason| {
            reason.rule.starts_with("deny:")
                || !violations.iter().any(|shown| shown.rule == reason.rule)
        }) {
            self.session.release();
            let denial = observe_denial(
                &mut self.session.facts,
                DenialOrigin::Resource,
                denial_scope,
            );
            record(
                audit,
                action,
                AuditOutcome::Denied,
                &["kernel:changed-during-approval".to_owned()],
                Some(&telemetry),
                Some(&denial),
            )?;
            return Err(KernelError::GateDenied);
        }
        Ok(telemetry)
    }

    /// Derives every reason the action needs approval from policy, rank, and
    /// action class, against the action's stamped session snapshot.
    fn reasons(
        &mut self,
        action: &Action,
        denial_scope: DenialScope,
    ) -> Result<Vec<Violation>, KernelError> {
        self.session
            .facts
            .select_denial_scope(denial_scope, unix_time_ms());
        let mut violations = self
            .policy
            .violations(action, &self.session.facts)
            .map_err(KernelError::Policy)?;
        let required = minimum_rank(action, &violations);
        let actual = action.stamped.session.floor;
        if self.provenance_mode == ProvenanceMode::Floor && actual < required {
            violations.push(Violation::new(
                MINIMUM_RANK_RULE,
                format!("action requires rank {required}, current floor is {actual}"),
            ));
        }
        if inherently_gated(action) {
            violations.push(Violation::new(
                "kernel:gate-required",
                "this action class always requires operator approval",
            ));
        }
        Ok(violations)
    }

    fn consume_egress_grant(&mut self, action: &Action, violations: &[Violation]) -> bool {
        let Some(key) = grantable_egress(action, violations) else {
            return false;
        };
        let now = unix_time_ms();
        let floor = action.stamped.session.floor;
        let valid = self.egress_grants.get_mut(&key).is_some_and(|grant| {
            if grant.expires_at_ms < now
                || grant.remaining_actions == 0
                || floor < grant.floor_at_issue
                || !violations
                    .iter()
                    .all(|violation| grant.waives.contains(&violation.rule))
            {
                return false;
            }
            grant.remaining_actions -= 1;
            true
        });
        if !valid {
            self.egress_grants.remove(&key);
        }
        valid
    }

    fn remember_egress_grant(&mut self, action: &Action, violations: &[Violation]) {
        let Some(key) = grantable_egress(action, violations) else {
            return;
        };
        self.egress_grants.insert(
            key,
            SessionGrant {
                issued_by_action_id: action.id,
                expires_at_ms: unix_time_ms().saturating_add(EGRESS_GRANT_TTL_MS),
                // The action just approved counts against the grant's budget.
                remaining_actions: EGRESS_GRANT_ACTIONS - 1,
                waives: violation_rules(violations),
                floor_at_issue: action.stamped.session.floor,
            },
        );
    }

    /// Revokes only the reusable grant minted by `action_id`, if it still
    /// exists. A later approval for the same host replaces the map entry and
    /// must not be removed by a delayed failure from the earlier action.
    fn revoke_egress_grant_issued_by(&mut self, action_id: u64) {
        self.egress_grants
            .retain(|_, grant| grant.issued_by_action_id != action_id);
    }

    fn deny_by_policy<A: AuditSink>(
        &mut self,
        action: &Action,
        denial_scope: DenialScope,
        violations: &[Violation],
        audit: &mut A,
    ) -> Result<bool, KernelError> {
        if !violations
            .iter()
            .any(|violation| violation.rule.starts_with("deny:"))
        {
            return Ok(false);
        }
        let denial = observe_denial(&mut self.session.facts, DenialOrigin::Policy, denial_scope);
        record(
            audit,
            action,
            AuditOutcome::Denied,
            &violation_rules(violations),
            None,
            Some(&denial),
        )?;
        Ok(true)
    }

    /// Runs the fixed action pipeline.
    /// Policy or rank violations require a trusted decision. Channel,
    /// structural, budget, and loop failures cannot be overridden. Credential
    /// injection occurs only after every authorization step passes.
    /// # Errors
    /// Returns an error when any fail-closed stage rejects or cannot complete.
    #[allow(clippy::too_many_arguments)]
    pub fn process<I, E, G, A>(
        &mut self,
        channel_name: &str,
        asserted_principal: &str,
        asserted: Asserted,
        gate: &mut G,
        injector: &mut I,
        executor: &mut E,
        audit: &mut A,
    ) -> Result<Processed<E::Output>, KernelError>
    where
        I: CredentialInjector,
        E: Executor<I::Prepared>,
        G: Gate + ?Sized,
        A: AuditSink,
    {
        let pending = self.begin(channel_name, asserted_principal, asserted, audit)?;
        let outcome = pending
            .needs_gate()
            .then(|| GateOutcome::decide(gate, pending.gate_request()));
        self.finish(pending, outcome, injector, executor, audit)
    }

    /// Runs every stage before the trusted gate: structural checks, loop
    /// detection, policy, provenance rank, budget reservation, and reusable
    /// grant consumption. A caller that shares this kernel may release its
    /// lock before asking the gate about the returned action.
    /// # Errors
    /// Returns an error when any fail-closed stage rejects.
    pub fn begin<A: AuditSink>(
        &mut self,
        channel_name: &str,
        asserted_principal: &str,
        asserted: Asserted,
        audit: &mut A,
    ) -> Result<PendingAction, KernelError> {
        self.begin_with_flow(
            channel_name,
            asserted_principal,
            asserted,
            FlowVerdict::NotChecked,
            audit,
        )
    }

    /// [`Self::begin`] for an action whose payload the trusted relay already
    /// judged. The verdict is stamped with the action and audited.
    /// # Errors
    /// Returns an error when any fail-closed stage rejects.
    pub fn begin_with_flow<A: AuditSink>(
        &mut self,
        channel_name: &str,
        asserted_principal: &str,
        asserted: Asserted,
        flow: FlowVerdict,
        audit: &mut A,
    ) -> Result<PendingAction, KernelError> {
        self.begin_reported(
            channel_name,
            asserted_principal,
            asserted,
            RelayFacts {
                flow,
                ..RelayFacts::default()
            },
            audit,
        )
    }

    /// [`Self::begin_with_flow`] that also stamps a guest-reported origin.
    /// # Errors
    /// Returns an error when any fail-closed stage rejects.
    #[allow(clippy::too_many_lines)]
    pub fn begin_reported<A: AuditSink>(
        &mut self,
        channel_name: &str,
        asserted_principal: &str,
        asserted: Asserted,
        facts: RelayFacts,
        audit: &mut A,
    ) -> Result<PendingAction, KernelError> {
        let RelayFacts {
            flow,
            origin,
            integrity,
        } = facts;
        let declaration = match self.registry.declaration(channel_name) {
            Ok(declaration) => declaration,
            Err(error) => {
                record_structural_rejection(
                    audit,
                    channel_name,
                    asserted_principal,
                    &asserted,
                    "kernel:unknown-channel",
                )?;
                return Err(error);
            }
        };
        if declaration.principal.as_str() != asserted_principal {
            record_structural_rejection(
                audit,
                channel_name,
                asserted_principal,
                &asserted,
                "kernel:principal-mismatch",
            )?;
            return Err(KernelError::PrincipalMismatch);
        }
        if !declaration.gate_class.accepts(asserted.class) {
            record_structural_rejection(
                audit,
                channel_name,
                asserted_principal,
                &asserted,
                "kernel:channel-class-mismatch",
            )?;
            return Err(KernelError::ChannelClassMismatch);
        }
        if let Err(error) = validate_asserted_target(&asserted) {
            record_structural_rejection(
                audit,
                channel_name,
                asserted_principal,
                &asserted,
                "kernel:target-shape",
            )?;
            return Err(error);
        }
        if matches!(asserted.target, Target::Protected(_)) {
            self.session.facts.record_scoped_denial(
                DenialOrigin::Structural,
                denial_scope_for_asserted(&asserted),
                unix_time_ms(),
            );
            record_structural_rejection(
                audit,
                channel_name,
                asserted_principal,
                &asserted,
                "kernel:protected-state",
            )?;
            return Err(KernelError::ProtectedStateMutation);
        }
        if let Err(error) = self.session.observe_action(&asserted, unix_time_ms()) {
            record_structural_rejection(
                audit,
                channel_name,
                asserted_principal,
                &asserted,
                "kernel:loop-detected",
            )?;
            return Err(error);
        }
        let intent = intent_verdict(&asserted, &self.session.facts.intent);
        let action = Action {
            id: self.session.allocate_action_id()?,
            asserted,
            stamped: Stamped {
                principal: declaration.principal.clone(),
                session: self.session.snapshot(),
                intent,
                flow,
                origin,
                integrity,
            },
        };

        let denial_scope = denial_scope_for_asserted(&action.asserted);
        let violations = self.reasons(&action, denial_scope)?;
        if self.deny_by_policy(&action, denial_scope, &violations, audit)? {
            return Err(KernelError::PolicyDenied);
        }

        if let Err(error) = self.session.reserve() {
            let denial = observe_denial(
                &mut self.session.facts,
                DenialOrigin::Resource,
                denial_scope,
            );
            record(
                audit,
                &action,
                AuditOutcome::Denied,
                &["kernel:budget".to_owned()],
                None,
                Some(&denial),
            )?;
            return Err(error);
        }

        // A one-action approval authorizes only this action. An explicit
        // `ApproveGrant` may additionally create the exact bounded egress grant
        // shown by the gate, but only after this action executes successfully.
        // Neither decision lifts the floor (§6.3): the floor describes what
        // untrusted content is in the agent's context, and approving an action
        // does not remove any of it.
        // Lifting it once for the session made approvals fungible across classes
        // — an operator who allowed one egress silently satisfied the rank
        // precondition of a later force-push to the default branch, and that push
        // gate never named the rank-0 source. `keel floor lift` is the only way
        // up, gated and counted, because it is the only one that shows the
        // read-set being vouched for.
        let needs_gate = !violations.is_empty() && !self.consume_egress_grant(&action, &violations);
        if needs_gate {
            self.session.facts.record_escalation();
        }
        Ok(PendingAction {
            floor_history: self.session.facts.floor_history.clone(),
            action,
            denial_scope,
            violations,
            needs_gate,
        })
    }

    /// Completes a begun action with the gate's answer, when one was needed.
    /// A missing answer for an action that needed one is treated as
    /// unavailable.
    /// # Errors
    /// Returns an error when the gate denied, the session changed in a way the
    /// operator did not see, or injection, audit, or execution fails.
    #[allow(clippy::too_many_lines)]
    pub fn finish<I, E, A>(
        &mut self,
        pending: PendingAction,
        outcome: Option<GateOutcome>,
        injector: &mut I,
        executor: &mut E,
        audit: &mut A,
    ) -> Result<Processed<E::Output>, KernelError>
    where
        I: CredentialInjector,
        E: Executor<I::Prepared>,
        A: AuditSink,
    {
        let PendingAction {
            action,
            denial_scope,
            violations,
            needs_gate,
            ..
        } = pending;
        let gate_telemetry = if needs_gate {
            let outcome = outcome.unwrap_or(GateOutcome {
                decision: GateDecision::Unavailable,
                authority: "unavailable",
                time_to_decision_ms: 0,
            });
            Some(self.conclude_gate(&action, denial_scope, &violations, outcome, audit)?)
        } else {
            None
        };

        let rules = violation_rules(&violations);
        let prepared = match injector.inject(&action) {
            Ok(prepared) => prepared,
            Err(error) => {
                self.session.release();
                record(
                    audit,
                    &action,
                    AuditOutcome::InjectionFailed,
                    &rules,
                    gate_telemetry.as_ref(),
                    None,
                )?;
                return Err(KernelError::Injection(error));
            }
        };

        if let Err(error) = record(
            audit,
            &action,
            AuditOutcome::Attempted,
            &rules,
            gate_telemetry.as_ref(),
            None,
        ) {
            self.session.release();
            return Err(error);
        }
        if gate_telemetry.is_some()
            && violations
                .iter()
                .any(|violation| violation.rule == REPEATED_DENIAL_RULE)
        {
            self.session
                .facts
                .clear_behavioral_denials_in_scope(denial_scope, unix_time_ms());
        }
        self.session.commit();
        match executor.execute(prepared) {
            Ok(output) => {
                self.session.observe_executed(&action);
                record(
                    audit,
                    &action,
                    AuditOutcome::Executed,
                    &rules,
                    gate_telemetry.as_ref(),
                    None,
                )?;
                if gate_telemetry
                    .as_ref()
                    .is_some_and(|telemetry| telemetry.decision == GateDecision::ApproveGrant)
                {
                    self.remember_egress_grant(&action, &violations);
                }
                Ok(Processed {
                    action_id: action.id,
                    output,
                })
            }
            Err(error) => {
                record(
                    audit,
                    &action,
                    AuditOutcome::ExecutionFailed,
                    &rules,
                    gate_telemetry.as_ref(),
                    None,
                )?;
                Err(KernelError::Execution(error))
            }
        }
    }

    fn reject_structural(
        &mut self,
        channel_name: &str,
        asserted_principal: &str,
        asserted: Asserted,
        rule: &str,
        audit: &mut impl AuditSink,
    ) -> Result<(), KernelError> {
        let declaration = self.registry.declaration(channel_name)?;
        if declaration.principal.as_str() != asserted_principal {
            return Err(KernelError::PrincipalMismatch);
        }
        if !declaration.gate_class.accepts(asserted.class) {
            return Err(KernelError::ChannelClassMismatch);
        }
        validate_asserted_target(&asserted)?;
        self.session.observe_action(&asserted, unix_time_ms())?;
        let flow = FlowVerdict::NotChecked;
        let intent = intent_verdict(&asserted, &self.session.facts.intent);
        let action = Action {
            id: self.session.allocate_action_id()?,
            asserted,
            stamped: Stamped {
                principal: declaration.principal.clone(),
                session: self.session.snapshot(),
                intent,
                flow,
                origin: None,
                integrity: IntegrityVerdict::NotChecked,
            },
        };
        let denial = observe_denial(
            &mut self.session.facts,
            DenialOrigin::Structural,
            denial_scope_for_asserted(&action.asserted),
        );
        record(
            audit,
            &action,
            AuditOutcome::Denied,
            &[rule.to_owned()],
            None,
            Some(&denial),
        )
    }
}

fn validate_asserted_target(asserted: &Asserted) -> Result<(), KernelError> {
    if !asserted.class.accepts_target(&asserted.target) {
        return Err(KernelError::TargetClassMismatch);
    }
    if let Target::FloorLift {
        requested_floor, ..
    } = &asserted.target
        && *requested_floor > 3
    {
        return Err(KernelError::InvalidFloor(*requested_floor));
    }
    Ok(())
}

/// Rank an action requires of the floor, per the capability table (§7.1).
///
/// Egress is rank-2 only when the host is off the run's egress intent. Requiring
/// it of every request read the table wrong and cost more than the misreading
/// suggests: §6.2 expects a session to reach floor 0 on its first test run, so an
/// unconditional rank 2 escalates every network call for the rest of that
/// session. The allowlist is the policy's to know, not the kernel's, so the
/// question is answered by the violation the policy has already raised for this
/// action rather than by a second copy of the allowlist here.
fn minimum_rank(action: &Action, violations: &[Violation]) -> u8 {
    match (&action.asserted.class, &action.asserted.target) {
        (
            ActionClass::GitPush,
            Target::Git {
                is_force,
                is_default_branch,
                touches_manifest,
                ..
            },
        ) if *is_force || *is_default_branch || *touches_manifest => 2,
        (ActionClass::PullRequest | ActionClass::Publish, _) => 2,
        (ActionClass::Egress, _) => {
            u8::from(
                violations
                    .iter()
                    .any(|violation| violation.rule == EGRESS_HOST_RULE),
            ) * 2
        }
        _ => 0,
    }
}

fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

/// Code the workload could have written does not push or open pull requests
/// on the operator's authority without the operator seeing it.
fn push_origin_violation(action: &Action, violations: &mut Vec<Violation>) {
    if let Some(origin) = action.stamped().reported_origin()
        && origin.workspace_code
    {
        violations.push(Violation::new(
            "origin:workspace-code",
            format!("issued by workspace code: {}", origin.summary),
        ));
    }
}

/// Matches an action against the operator-admitted task envelope.
/// Whether a triage run's admitted scope covers `host:port`.
fn in_scope(intent: &IntentFlags, host: &str, port: u16) -> bool {
    intent
        .scope
        .as_ref()
        .is_some_and(|scope| scope.contains(host, port))
}

fn intent_verdict(asserted: &Asserted, intent: &IntentFlags) -> IntentVerdict {
    match (&asserted.class, &asserted.target) {
        (
            ActionClass::GitPush,
            Target::Git {
                refs,
                is_force,
                is_default_branch,
                ..
            },
        ) => {
            if !intent.allow_push_branch {
                IntentVerdict::Outside("push-not-admitted")
            } else if *is_force {
                IntentVerdict::Outside("force-or-delete")
            } else if let Some(reason) = push_refs_outside(refs, *is_default_branch, intent) {
                IntentVerdict::Outside(reason)
            } else {
                IntentVerdict::Inside
            }
        }
        (ActionClass::PullRequest, Target::External { detail, .. }) => {
            if !intent.allow_pr_create {
                IntentVerdict::Outside("pr-not-admitted")
            } else if pr_target_outside(detail, intent) {
                IntentVerdict::Outside("pr-target")
            } else {
                IntentVerdict::Inside
            }
        }
        (
            ActionClass::Egress,
            Target::Network {
                host,
                port,
                method,
                path,
            },
        ) => {
            if path.is_empty() && matches!(method.as_str(), "TLS" | "CONNECT" | "HTTP") {
                // Connection setup terminates locally and sends nothing
                // upstream; the request inside it is judged separately.
                IntentVerdict::NotApplicable
            } else if !intent.allowed_egress_hosts.contains(host) && !in_scope(intent, host, *port)
            {
                IntentVerdict::Outside("egress-host")
            } else if is_registry_host(host)
                && !matches!(method.as_str(), "GET" | "HEAD" | "TLS" | "CONNECT" | "HTTP")
            {
                // Lockfile-derived registry hosts admit reads. Publishing is a
                // different effect the envelope has no way to admit yet.
                IntentVerdict::Outside("registry-write")
            } else {
                IntentVerdict::Inside
            }
        }
        (ActionClass::Publish | ActionClass::DeleteOutsideWorkspace, _) => {
            IntentVerdict::Outside("not-admissible")
        }
        _ => IntentVerdict::NotApplicable,
    }
}

/// Names why pushed refs fall outside the envelope, if they do. A default
/// branch is inside only when a `push:ref:` pattern names it exactly.
fn push_refs_outside(
    refs: &[String],
    is_default_branch: bool,
    intent: &IntentFlags,
) -> Option<&'static str> {
    if is_default_branch && !refs.iter().any(|name| intent.push_refs.contains(name)) {
        return Some("default-branch");
    }
    let matches = |name: &str| {
        intent.push_refs.iter().any(|pattern| {
            pattern
                .strip_suffix('*')
                .map_or(pattern == name, |prefix| name.starts_with(prefix))
        })
    };
    (!intent.push_refs.is_empty() && !refs.iter().all(|name| matches(name)))
        .then_some("ref-outside-envelope")
}

fn pr_target_outside(detail: &str, intent: &IntentFlags) -> bool {
    let base = serde_json::from_str::<serde_json::Value>(detail)
        .ok()
        .and_then(|detail| detail.get("base")?.as_str().map(str::to_owned));
    !intent.pr_targets.is_empty() && !base.is_some_and(|base| intent.pr_targets.contains(&base))
}

fn is_registry_host(host: &str) -> bool {
    matches!(
        host,
        "crates.io"
            | "index.crates.io"
            | "static.crates.io"
            | "registry.npmjs.org"
            | "pypi.org"
            | "files.pythonhosted.org"
            | "rubygems.org"
            | "proxy.golang.org"
    )
}

fn inherently_gated(action: &Action) -> bool {
    match (&action.asserted.class, &action.asserted.target) {
        (
            ActionClass::GitPush,
            Target::Git {
                is_force,
                is_default_branch,
                touches_manifest,
                ..
            },
        ) => *is_force || *is_default_branch || *touches_manifest,
        (
            ActionClass::PullRequest
            | ActionClass::Publish
            | ActionClass::WriteOutsideWorkspace
            | ActionClass::DeleteOutsideWorkspace
            | ActionClass::LiftFloor,
            _,
        ) => true,
        _ => false,
    }
}

fn approval_method(action: &Action) -> ApprovalMethod {
    match (&action.asserted.class, &action.asserted.target) {
        (
            ActionClass::GitPush,
            Target::Git {
                is_force,
                is_default_branch,
                ..
            },
        ) if *is_force || *is_default_branch => ApprovalMethod::Challenge,
        (ActionClass::PullRequest, Target::External { operation, .. })
            if matches!(operation.as_str(), "merge" | "merge-pull-request") =>
        {
            ApprovalMethod::Challenge
        }
        (
            ActionClass::Publish | ActionClass::DeleteOutsideWorkspace | ActionClass::LiftFloor,
            _,
        ) => ApprovalMethod::Challenge,
        _ => ApprovalMethod::Confirm,
    }
}

fn grantable_egress(action: &Action, violations: &[Violation]) -> Option<EgressGrantKey> {
    if approval_method(action) != ApprovalMethod::Confirm
        || violations.is_empty()
        || !violations.iter().all(|violation| {
            matches!(
                violation.rule.as_str(),
                EGRESS_HOST_RULE | ADMISSION_EGRESS_RULE | MINIMUM_RANK_RULE
            )
        })
    {
        return None;
    }
    match &action.asserted.target {
        // Hosts for which the trusted relay may hold an operator credential do
        // not receive a fungible same-host grant. Each request is evaluated and
        // effect-bound independently.
        Target::Network {
            host, port, method, ..
        } if host != "api.github.com" => Some(EgressGrantKey {
            host: host.clone(),
            port: *port,
            method: method.clone(),
        }),
        _ => None,
    }
}

fn violation_rules(violations: &[Violation]) -> Vec<String> {
    violations
        .iter()
        .map(|violation| violation.rule.clone())
        .collect()
}

fn record(
    audit: &mut impl AuditSink,
    action: &Action,
    outcome: AuditOutcome,
    rules: &[String],
    gate: Option<&GateTelemetry>,
    denial: Option<&DenialTelemetry>,
) -> Result<(), KernelError> {
    audit
        .record(AuditEvent {
            action_id: action.id,
            principal: action.stamped.principal.clone(),
            class: action.asserted.class,
            target_kind: action.asserted.target.kind(),
            target_hash: action_target_hash(action),
            outcome,
            intent: action.stamped.intent.as_str(),
            flow: action.stamped.flow.describe(),
            integrity: action.stamped.integrity.describe(),
            origin: action.stamped.origin.as_ref().map(|origin| {
                format!(
                    "{}{}",
                    if origin.workspace_code {
                        "workspace-code: "
                    } else if origin.known {
                        ""
                    } else {
                        "unknown"
                    },
                    origin.summary
                )
            }),
            rules: rules.to_vec(),
            gate: gate.cloned(),
            denial: denial.copied(),
        })
        .map_err(KernelError::Audit)
}

fn observe_denial(
    facts: &mut SessionFacts,
    origin: DenialOrigin,
    scope: DenialScope,
) -> DenialTelemetry {
    facts.record_scoped_denial(origin, scope, unix_time_ms());
    DenialTelemetry {
        origin,
        scope,
        counted_for_repeated_review: origin.counts_toward_behavioral_review(),
        recent_behavioral_denials_in_scope: facts.recent_behavioral_denials_in_scope,
    }
}

fn asserted_target_hash(asserted: &Asserted) -> [u8; 32] {
    let mut encoded = Vec::new();
    encoded.push(action_class_tag(asserted.class));
    encode_target(&mut encoded, &asserted.target);
    sha256_bytes(&encoded)
}

fn denial_scope_for_asserted(asserted: &Asserted) -> DenialScope {
    let target = match &asserted.target {
        Target::Network {
            host,
            port,
            method,
            path,
        } => Target::Network {
            host: host.clone(),
            port: *port,
            method: method.clone(),
            path: path.split('?').next().unwrap_or(path).to_owned(),
        },
        Target::Git {
            remote,
            refs,
            is_force,
            is_default_branch,
            touches_manifest,
            ..
        } => Target::Git {
            remote: remote.clone(),
            refs: refs.clone(),
            is_force: *is_force,
            is_default_branch: *is_default_branch,
            touches_manifest: *touches_manifest,
            manifest_diff: None,
        },
        Target::External {
            service,
            recipient,
            operation,
            ..
        } => Target::External {
            service: service.clone(),
            recipient: recipient.clone(),
            operation: operation.clone(),
            detail: String::new(),
        },
        target => target.clone(),
    };
    let normalized = Asserted {
        class: asserted.class,
        target,
        declared_cost: None,
    };
    let mut encoded = b"keel-denial-scope-v1\0".to_vec();
    encoded.extend_from_slice(&asserted_target_hash(&normalized));
    DenialScope::from_digest(sha256_bytes(&encoded))
}

fn sha256_bytes(value: &[u8]) -> [u8; 32] {
    let hash = digest(&SHA256, value);
    let mut output = [0_u8; 32];
    output.copy_from_slice(hash.as_ref());
    output
}

fn record_structural_rejection(
    audit: &mut impl AuditSink,
    channel: &str,
    principal: &str,
    asserted: &Asserted,
    rule: &'static str,
) -> Result<(), KernelError> {
    audit
        .record_structural_rejection(StructuralRejectionEvent {
            channel_hash: sha256_bytes(channel.as_bytes()),
            principal_hash: sha256_bytes(principal.as_bytes()),
            class: asserted.class,
            target_kind: asserted.target.kind(),
            target_hash: asserted_target_hash(asserted),
            rule,
        })
        .map_err(KernelError::Audit)
}

/// A fail-closed kernel error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KernelError {
    /// A principal identifier was empty or contained control characters.
    InvalidPrincipal,
    /// A session identifier was empty or contained control characters.
    InvalidSession,
    /// Session action limit was zero.
    InvalidBudget,
    /// Session repeat limit was zero.
    InvalidLoopLimit,
    /// A provenance floor was outside zero through three.
    InvalidFloor(u8),
    /// Required channel declaration was absent.
    MissingChannel(String),
    /// A channel was declared more than once.
    DuplicateChannel(String),
    /// An undeclared channel appeared in the registry.
    UnexpectedChannel(String),
    /// An action arrived through a channel unknown at startup.
    UnknownChannel(String),
    /// The untrusted principal claim did not match channel authentication.
    PrincipalMismatch,
    /// The channel cannot carry this action class.
    ChannelClassMismatch,
    /// The target shape does not match the asserted action class.
    TargetClassMismatch,
    /// Guest attempted to mutate kernel-owned state.
    ProtectedStateMutation,
    /// Session action identifier space was exhausted.
    ActionIdExhausted,
    /// The same action exceeded the configured loop limit.
    LoopDetected,
    /// The session's hard action budget was exhausted.
    BudgetExhausted,
    /// Policy evaluation failed.
    Policy(String),
    /// A non-overridable policy constraint denied the action.
    PolicyDenied,
    /// The trusted gate denied the action.
    GateDenied,
    /// Credential injection failed.
    Injection(String),
    /// Execution failed.
    Execution(String),
    /// Durable audit recording failed.
    Audit(String),
}

impl fmt::Display for KernelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPrincipal => formatter.write_str("invalid principal"),
            Self::InvalidSession => formatter.write_str("invalid session identifier"),
            Self::InvalidBudget => formatter.write_str("action budget must be positive"),
            Self::InvalidLoopLimit => formatter.write_str("loop limit must be positive"),
            Self::InvalidFloor(floor) => write!(formatter, "invalid provenance floor {floor}"),
            Self::MissingChannel(name) => write!(formatter, "missing channel declaration: {name}"),
            Self::DuplicateChannel(name) => {
                write!(formatter, "duplicate channel declaration: {name}")
            }
            Self::UnexpectedChannel(name) => {
                write!(formatter, "unexpected channel declaration: {name}")
            }
            Self::UnknownChannel(name) => write!(formatter, "unknown action channel: {name}"),
            Self::PrincipalMismatch => formatter.write_str("channel principal mismatch"),
            Self::ChannelClassMismatch => formatter.write_str("action class rejected by channel"),
            Self::TargetClassMismatch => formatter.write_str("target rejected for action class"),
            Self::ProtectedStateMutation => {
                formatter.write_str("guest cannot mutate kernel-owned state")
            }
            Self::ActionIdExhausted => formatter.write_str("action identifier space exhausted"),
            Self::LoopDetected => formatter.write_str("repeated-action loop detected"),
            Self::BudgetExhausted => formatter.write_str("session action budget exhausted"),
            Self::Policy(error) => write!(formatter, "policy evaluation failed: {error}"),
            Self::PolicyDenied => formatter.write_str("policy denied action without override"),
            Self::GateDenied => formatter.write_str("operator denied action"),
            Self::Injection(error) => write!(formatter, "credential injection failed: {error}"),
            Self::Execution(error) => write!(formatter, "execution failed: {error}"),
            Self::Audit(error) => write!(formatter, "audit recording failed: {error}"),
        }
    }
}

impl Error for KernelError {}

/// Private broker protocol marker for inspected egress connections.
pub const EGRESS_BROKER_MAGIC: &[u8] = b"KEEL-EGRESS-V2\0";
/// Private broker protocol marker for assessed Git pushes.
pub const GIT_BROKER_MAGIC: &[u8] = b"KEEL-GIT-V1\0";
/// Private broker protocol marker for a relay-reported Git push outcome.
///
/// Authorizing a push and completing one are different events: the relay still
/// has to reach the remote afterwards, and that leg can fail. The relay reports
/// what happened on this marker so the audit never asserts a push landed on the
/// strength of the authorization alone.
pub const GIT_REPORT_MAGIC: &[u8] = b"KEEL-GIT-REPORT-V1\0";
/// Relay report: the push reached the remote.
pub const GIT_REPORT_COMPLETED: u8 = b'C';
/// Relay report: the push was authorized but did not reach the remote.
pub const GIT_REPORT_FAILED: u8 = b'F';

/// Authorized pushes awaiting a relay report before the oldest is closed.
const MAX_UNREPORTED_PUSHES: usize = 64;
/// Exact credential-bearing effects awaiting their one permitted transport.
const MAX_PENDING_EFFECT_PERMITS: usize = 64;
/// An abandoned logical authorization must not become a reusable capability.
const EFFECT_PERMIT_TTL: Duration = Duration::from_mins(2);
const MAX_BROKER_CLIENTS: usize = 64;
const BROKER_HANDSHAKE_TIMEOUT: Duration = Duration::from_millis(500);
const MINIMUM_RANK_RULE: &str = "kernel:minimum-rank";
const REPEATED_DENIAL_RULE: &str = "repeated-denials-same-scope";
/// Policy rule naming a host the run's egress intent does not cover.
///
/// The rank check reads it, so the name is a contract between the two rather than
/// a label: a policy that renames it silently drops every egress to rank 0.
const EGRESS_HOST_RULE: &str = "intent:egress-host";
const ADMISSION_EGRESS_RULE: &str = "admission:egress";
/// Private broker protocol marker for external MCP actions.
pub const EXTERNAL_BROKER_MAGIC: &[u8] = b"KEEL-EXTERNAL-V1\0";

/// Kernel-broker response: policy or structural denial.
pub const EGRESS_DENIED: u8 = b'D';
/// Kernel-broker response: the complete request is awaiting adjudication.
/// This is only a liveness acknowledgement and grants no network authority.
pub const EGRESS_PENDING: u8 = b'P';
/// Kernel-broker response: policy allowed, but execution failed closed.
pub const EGRESS_EXECUTION_FAILED: u8 = b'E';
/// Kernel-broker response: the inspected local session is ready.
///
/// This does not imply DNS or an upstream connection. Production egress waits
/// for authorization of the decrypted request before doing either.
pub const EGRESS_ALLOWED: u8 = b'A';
/// Kernel-broker response: a Git action was denied.
pub const GIT_DENIED: u8 = b'D';
/// Kernel-broker response: a Git action was authorized and audited.
pub const GIT_ALLOWED: u8 = b'A';
/// Kernel-broker response: an external action was denied.
pub const EXTERNAL_DENIED: u8 = b'D';
/// Kernel-broker response: an external action was authorized and audited.
pub const EXTERNAL_ALLOWED: u8 = b'A';

/// Kernel-owned ceilings for cumulative model use in one run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ModelBudgetLimits {
    /// Maximum input plus output tokens.
    pub token_limit: u64,
    /// Maximum cost in millionths of one US dollar.
    pub cost_limit_microusd: u64,
}

impl Default for ModelBudgetLimits {
    fn default() -> Self {
        Self {
            token_limit: 1_000_000,
            cost_limit_microusd: 20_000_000,
        }
    }
}

impl ModelBudgetLimits {
    /// Rejects ceilings that cannot admit any model request.
    /// # Errors
    /// Returns an error when either ceiling is zero.
    pub fn validate(self) -> Result<Self, String> {
        if self.token_limit == 0 || self.cost_limit_microusd == 0 {
            Err("model token and cost budgets must be greater than zero".to_owned())
        } else {
            Ok(self)
        }
    }
}

/// Conservative model resource reservation derived inside trusted TLS custody.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelBudgetRequest {
    /// Upper bound on request input tokens.
    pub input_tokens_upper_bound: u64,
    /// API `max_tokens` output ceiling.
    pub max_output_tokens: u64,
    /// Pinned input price in micro-US-dollars per token.
    pub input_microusd_per_token: u64,
    /// Pinned output price in micro-US-dollars per token.
    pub output_microusd_per_token: u64,
}

/// Trusted token usage parsed from one model response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ModelUsage {
    /// Billed input tokens, including cache categories.
    pub input_tokens: u64,
    /// Billed output tokens.
    pub output_tokens: u64,
}

/// Secret-free model budget settlement sent to the audit sink.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ModelUsageEvent {
    /// Kernel action that authorized the model request.
    pub action_id: u64,
    /// Tokens reserved before sending.
    pub reserved_tokens: u64,
    /// Conservative cost reserved before sending.
    pub reserved_cost_microusd: u64,
    /// Tokens reported by the trusted response parser.
    pub actual_tokens: u64,
    /// Cost computed from trusted usage and the pinned tariff.
    pub actual_cost_microusd: u64,
}

/// The canonical admission manifest of one run, audited before its workload
/// starts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunAdmittedEvent {
    /// Canonical JSON: sorted keys, no whitespace.
    pub manifest: String,
    /// SHA-256 of `manifest`.
    pub digest: [u8; 32],
}

/// One content block of a model request or response, described without its
/// content, for the per-turn context provenance digest log.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContextBlock {
    /// Where the block sits: `system`, `tools`, `messages.N.ROLE`, or
    /// `response`.
    pub place: String,
    /// Block type from a fixed vocabulary; anything else is `other`.
    pub kind: &'static str,
    /// Length of the block's identity-bearing fields as canonical JSON.
    pub bytes: usize,
    /// Truncated SHA-256 of those fields, equal for a response block and the
    /// same block when a later request carries it back.
    pub digest: [u8; 8],
    /// The tool-use identifier a `tool_use` or `tool_result` block carries.
    pub tool_use: Option<String>,
}

/// One model request's or response's blocks, sent to the audit sink.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContextEvent {
    /// Kernel action that authorized the model request.
    pub action_id: u64,
    /// `request` or `response`.
    pub phase: &'static str,
    /// Every block's digest, in order.
    pub sequence: Vec<[u8; 8]>,
    /// Blocks whose digest this session has not logged before.
    pub described: Vec<ContextBlock>,
}

/// Stable identifier for one kernel-owned model budget reservation.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ModelReservationId(u64);

impl ModelReservationId {
    /// Reconstructs a run-local identifier for audit and accounting adapters.
    ///
    /// The identifier carries no authority; authorization remains bound to
    /// kernel-owned reservation state.
    #[must_use]
    pub const fn from_run_local(value: u64) -> Self {
        Self(value)
    }

    /// Returns the run-local integer written to the audit chain.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// A caller's evidence for closing one model budget reservation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModelReservationResolution {
    /// No upstream send was attempted, so the entire reservation may be returned.
    ReleasedUnsent,
    /// Trusted provider usage was recovered after an upstream send attempt.
    SettledActual(ModelUsage),
    /// The request may have been billed, but exact usage could not be recovered.
    CommittedConservative,
    /// The response ended early after the provider stated its usage so far.
    /// Carries a trusted upper bound: exact input, and output delivered plus a
    /// margin. The charge never exceeds the reservation.
    CommittedObserved(ModelUsage),
}

/// Durable terminal outcome of a model budget reservation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModelReservationOutcome {
    /// The upstream send was never attempted and the reservation was returned.
    ReleasedUnsent,
    /// Trusted usage fit inside the conservative reservation.
    SettledActual,
    /// Exact usage was unavailable after a possible upstream send.
    CommittedConservative,
    /// An interrupted response was charged a trusted upper bound on its usage.
    CommittedObserved,
    /// Trusted usage exceeded at least one conservative reservation ceiling.
    Overrun,
}

impl ModelReservationOutcome {
    /// Returns the stable audit spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReleasedUnsent => "released-unsent",
            Self::SettledActual => "settled-actual",
            Self::CommittedConservative => "committed-conservative",
            Self::CommittedObserved => "committed-observed",
            Self::Overrun => "overrun",
        }
    }
}

/// Secret-free terminal model reservation transition sent to the audit sink.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ModelReservationEvent {
    /// Run-local reservation identifier.
    pub reservation_id: ModelReservationId,
    /// Kernel action that authorized the model request.
    pub action_id: u64,
    /// Terminal accounting outcome.
    pub outcome: ModelReservationOutcome,
    /// Tokens reserved before any upstream send.
    pub reserved_tokens: u64,
    /// Conservative cost reserved before any upstream send.
    pub reserved_cost_microusd: u64,
    /// Trusted provider token usage when it was recovered.
    pub actual_tokens: Option<u64>,
    /// Trusted provider cost when it was recovered.
    pub actual_cost_microusd: Option<u64>,
}

/// An untrusted caller's claim about what became of an authorized action.
///
/// Recorded separately from the kernel's own `AuditEvent` because the kernel did
/// not observe it. An authorization is a kernel fact; completion is a report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReportedOutcomeEvent {
    /// Kernel action the report refers to.
    pub action_id: u64,
    /// Which channel made the claim.
    pub reporter: &'static str,
    /// The claimed outcome, or `unreported` when the caller never claimed one.
    pub outcome: String,
}

/// How far one named boundary is actually established for this run.
///
/// Deliberately without a `degraded` state. Every boundary Keel has is
/// fail-closed: one that cannot be established refuses the run rather than
/// weakening it, so a state meaning "up, but not really" would describe nothing
/// that can occur and would invite running with a boundary down.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnforcementState {
    /// Established and load-bearing.
    Active,
    /// Established, but defence in depth rather than the boundary itself.
    Advisory,
    /// Not applicable to this run. Not a failure.
    Absent,
    /// The platform cannot provide it.
    Unsupported,
}

impl EnforcementState {
    /// Returns the stable audit spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Advisory => "advisory",
            Self::Absent => "absent",
            Self::Unsupported => "unsupported",
        }
    }
}

/// One boundary, the state it is in, and the shape of what it covers.
///
/// `detail` carries shapes only — host names, scope prefixes, counts, ceilings —
/// and never a credential, a sentinel, or any value a secret is recoverable
/// from, because this is written into the audit chain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnforcementBoundary {
    /// Stable boundary name.
    pub name: &'static str,
    /// State derived from the object that enforces it.
    pub state: EnforcementState,
    /// Shape of what the boundary covers, for an operator reading the record.
    pub detail: String,
}

/// Every boundary's state at one point in a run.
///
/// Emitted after composition and before the first guest byte, and again at
/// shutdown. What the run intended is in its configuration; this is what was
/// actually standing when the guest met it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnforcementStateEvent {
    /// `start` or `shutdown`.
    pub phase: &'static str,
    /// Every boundary, in a deterministic order.
    pub boundaries: Vec<EnforcementBoundary>,
}

/// Authorizes one HTTP request observed after trusted protocol termination.
pub trait EgressRequestAuthorizer: Send {
    /// Runs the exact method and path through the kernel action pipeline.
    /// # Errors
    /// Returns an error when policy, budget, loop, or audit enforcement denies
    /// the request.
    fn authorize(
        &mut self,
        method: &str,
        path: &str,
        body_digest: [u8; 32],
        model_budget: Option<ModelBudgetRequest>,
    ) -> Result<(), String>;

    /// Shows the decrypted request target and body to the authorizer
    /// immediately before [`Self::authorize`], so it can judge payload flow.
    fn observe_payload(&mut self, _path: &str, _body: &[u8]) {}

    /// Shows the string arguments of tool calls in a complete, successful
    /// model response, so pushed content can be traced to the model.
    fn observe_model_output(&mut self, _arguments: &[String]) {}

    /// Shows the content blocks of a model request about to be authorized, or
    /// of its complete, successful response, for the shadow digest log.
    fn observe_model_context(&mut self, _response: bool, _blocks: Vec<ContextBlock>) {}

    /// Atomically commits the already-authorized request at the first external
    /// network operation. A peer disconnect that wins this handoff makes the
    /// request permanently unsendable, including requests admitted without a
    /// prompt or covered by a prior grant.
    /// # Errors
    /// Returns an error when the origin disconnected or this authorization was
    /// already committed.
    fn commit_request_send(&mut self) -> Result<(), String> {
        Ok(())
    }

    /// Records that upstream response bytes exist before their first delivery
    /// to the guest. An attempt that fails without response bytes must not
    /// lower provenance; partial bytes do, because they may influence the guest.
    /// # Errors
    /// Returns an error when provenance cannot be durably recorded.
    fn record_response(&mut self) -> Result<(), String>;

    /// Marks the current model reservation as possibly spent immediately
    /// before the first upstream write attempt.
    ///
    /// This transition must precede the write, rather than follow a successful
    /// flush: a partial or ambiguously failed write may already be billable.
    /// # Errors
    /// Returns an error when there is no current reservation or its lifecycle
    /// has already advanced.
    fn mark_model_request_send_attempted(&mut self) -> Result<(), String> {
        Ok(())
    }

    /// Closes the current model reservation using trusted lifecycle evidence.
    /// # Errors
    /// Returns an error for an invalid transition, duplicate resolution, bad
    /// accounting, or durable audit failure.
    fn resolve_model_reservation(
        &mut self,
        _resolution: ModelReservationResolution,
    ) -> Result<(), String> {
        Err("egress authorizer does not accept model reservation outcomes".to_owned())
    }

    /// Reconciles a model reservation with trusted upstream usage.
    /// # Errors
    /// Returns an error for missing reservations, malformed accounting, or
    /// durable audit failure.
    fn record_model_usage(&mut self, usage: ModelUsage) -> Result<(), String> {
        self.resolve_model_reservation(ModelReservationResolution::SettledActual(usage))
    }

    /// Returns a reservation the upstream never spent to the run budget.
    ///
    /// This is valid only before the first upstream write attempt. An HTTP
    /// refusal received after a send is not proof that the provider performed
    /// no billable work.
    ///
    /// # Errors
    /// Returns an error when the budget cannot be reached.
    fn release_model_reservation(&mut self) -> Result<(), String> {
        self.resolve_model_reservation(ModelReservationResolution::ReleasedUnsent)
    }

    /// Retains the full conservative charge because an attempted request may
    /// have been billed but exact usage could not be recovered.
    /// # Errors
    /// Returns an error for an invalid transition, duplicate resolution, or
    /// durable audit failure.
    fn commit_model_reservation_conservatively(&mut self) -> Result<(), String> {
        self.resolve_model_reservation(ModelReservationResolution::CommittedConservative)
    }

    /// Charges a trusted upper bound on the usage of a model response that
    /// ended after the provider stated its input, instead of the full
    /// reservation.
    /// # Errors
    /// Returns an error for an invalid transition, duplicate resolution, or
    /// durable audit failure.
    fn commit_model_reservation_observed(&mut self, usage: ModelUsage) -> Result<(), String> {
        self.resolve_model_reservation(ModelReservationResolution::CommittedObserved(usage))
    }
}

/// Trusted inspected egress session whose decrypted request metadata is
/// submitted back to the authorization kernel before external network I/O.
pub trait EgressSession: Send {
    /// Forwards one guest connection, authorizing every exact HTTP request.
    /// # Errors
    /// Returns an error when transport or trusted protocol handling fails.
    fn forward(
        self: Box<Self>,
        guest: UnixStream,
        authorizer: &mut dyn EgressRequestAuthorizer,
    ) -> Result<(), String>;
}

/// Trusted inspected-session boundary used by the kernel executor.
pub trait EgressConnector: Send {
    /// Returns whether hardcoded checks reject a target without network I/O.
    fn structurally_denied(&self, _host: &str, _port: u16, _method: &str) -> bool {
        false
    }

    /// Prepares a session for the claimed destination without releasing guest
    /// application bytes. Implementations may defer DNS and connection until
    /// [`EgressSession::forward`] has authorized the exact decrypted request.
    /// # Errors
    /// Returns an error when structural checks or local setup fail.
    fn connect(
        &mut self,
        host: &str,
        port: u16,
        method: &str,
    ) -> Result<Box<dyn EgressSession>, String>;

    /// Returns the public run CA certificate when this connector terminates
    /// guest TLS.
    fn ca_certificate_pem(&self) -> Option<String> {
        None
    }
}

/// Counts produced by one trusted kernel-broker run.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BrokerReport {
    /// Complete kernel audit events produced.
    pub audit_events: usize,
    /// Actions denied by policy or the trusted gate.
    pub denied_actions: u64,
    /// Actions allowed by policy but failed during trusted execution.
    pub execution_failures: usize,
    /// Final kernel-owned session facts for durable resume.
    pub session_facts: SessionFacts,
}

/// Private host action channel owned by the trusted runtime.
pub struct KernelBroker {
    socket_path: PathBuf,
    root: PathBuf,
    ca_certificate_pem: Option<String>,
    state: Arc<Mutex<BrokerState>>,
    stop: Arc<AtomicBool>,
    shutdown_boundaries: Arc<Mutex<Vec<EnforcementBoundary>>>,
    thread: Option<JoinHandle<Result<BrokerReport, String>>>,
}

impl KernelBroker {
    /// Starts one broker with an authenticated egress channel and bounded
    /// session state.
    /// # Errors
    /// Returns an error when the private socket or kernel cannot be created.
    pub fn spawn(
        session_id: String,
        allowed_hosts: BTreeSet<String>,
        connector: Box<dyn EgressConnector>,
    ) -> Result<Self, String> {
        Self::spawn_with_audit_and_gate(
            session_id,
            allowed_hosts,
            BTreeSet::new(),
            connector,
            Box::new(DiscardAudit),
            Box::new(DenyGate),
        )
    }

    /// Starts one broker with a caller-owned durable audit sink.
    /// The sink is closed only after every active egress bridge exits. Broker
    /// shutdown fails if the sink cannot flush its records.
    /// # Errors
    /// Returns an error when the private socket, kernel, or broker thread
    /// cannot be created.
    pub fn spawn_with_audit(
        session_id: String,
        allowed_hosts: BTreeSet<String>,
        connector: Box<dyn EgressConnector>,
        audit: Box<dyn AuditSink>,
    ) -> Result<Self, String> {
        Self::spawn_with_audit_and_capabilities(
            session_id,
            allowed_hosts,
            BTreeSet::new(),
            connector,
            audit,
        )
    }

    /// Starts one broker with explicit intent capabilities and durable audit.
    /// # Errors
    /// Returns an error when the private socket, kernel, or broker thread
    /// cannot be created.
    pub fn spawn_with_audit_and_capabilities(
        session_id: String,
        allowed_hosts: BTreeSet<String>,
        allowed_capabilities: BTreeSet<String>,
        connector: Box<dyn EgressConnector>,
        audit: Box<dyn AuditSink>,
    ) -> Result<Self, String> {
        Self::spawn_with_audit_and_gate(
            session_id,
            allowed_hosts,
            allowed_capabilities,
            connector,
            audit,
            Box::new(DenyGate),
        )
    }

    /// Starts one broker with caller-owned durable audit and trusted gate
    /// implementations.
    /// # Errors
    /// Returns an error when the private socket, kernel, or broker thread
    /// cannot be created.
    pub fn spawn_with_audit_and_gate(
        session_id: String,
        allowed_hosts: BTreeSet<String>,
        allowed_capabilities: BTreeSet<String>,
        connector: Box<dyn EgressConnector>,
        audit: Box<dyn AuditSink>,
        gate: Box<dyn Gate>,
    ) -> Result<Self, String> {
        Self::spawn_with_session_policy(
            session_id,
            allowed_hosts,
            allowed_capabilities,
            SessionFacts::default(),
            ProvenanceMode::Floor,
            Box::new(ConservativeSessionPolicy),
            connector,
            audit,
            Some(gate),
        )
    }

    /// Starts a broker with a caller-supplied stateful policy.
    /// # Errors
    /// Returns an error when the private socket or kernel cannot be created.
    #[allow(clippy::too_many_arguments)]
    pub fn spawn_with_session_policy(
        session_id: String,
        allowed_hosts: BTreeSet<String>,
        allowed_capabilities: BTreeSet<String>,
        session_facts: SessionFacts,
        provenance_mode: ProvenanceMode,
        session_policy: Box<dyn Policy>,
        connector: Box<dyn EgressConnector>,
        audit: Box<dyn AuditSink>,
        gate: Option<Box<dyn Gate>>,
    ) -> Result<Self, String> {
        Self::spawn_with_diagnostics(
            session_id,
            allowed_hosts,
            allowed_capabilities,
            // The provider a caller without model traffic would have named anyway.
            "api.anthropic.com".to_owned(),
            session_facts,
            provenance_mode,
            session_policy,
            connector,
            audit,
            gate,
            ModelBudgetLimits::default(),
            None,
        )
    }

    /// Starts a broker that also appends egress bridge failures to a log.
    ///
    /// A failed bridge is invisible to the guest beyond a dropped connection,
    /// so the operator needs the trusted reason recorded somewhere durable.
    /// # Errors
    /// Returns an error when the private socket or kernel cannot be created.
    #[allow(clippy::too_many_arguments)]
    pub fn spawn_with_diagnostics(
        session_id: String,
        allowed_hosts: BTreeSet<String>,
        allowed_capabilities: BTreeSet<String>,
        model_host: String,
        session_facts: SessionFacts,
        provenance_mode: ProvenanceMode,
        session_policy: Box<dyn Policy>,
        connector: Box<dyn EgressConnector>,
        audit: Box<dyn AuditSink>,
        gate: Option<Box<dyn Gate>>,
        model_budget_limits: ModelBudgetLimits,
        diagnostics: Option<PathBuf>,
    ) -> Result<Self, String> {
        let model_budget_limits = model_budget_limits.validate()?;
        let gate = gate.unwrap_or_else(|| Box::new(DenyGate));
        let ca_certificate_pem = connector.ca_certificate_pem();
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| error.to_string())?
            .as_nanos();
        let sequence = BROKER_PATH_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let root = broker_temporary_directory().join(format!(
            "keel-kernel-{}-{nonce:x}-{sequence:x}",
            std::process::id()
        ));
        let socket_path = root.join("actions.sock");
        let setup = (|| {
            fs::create_dir(&root).map_err(|error| error.to_string())?;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
                .map_err(|error| error.to_string())?;
            let listener = UnixListener::bind(&socket_path).map_err(|error| error.to_string())?;
            fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))
                .map_err(|error| error.to_string())?;
            listener
                .set_nonblocking(true)
                .map_err(|error| error.to_string())?;
            Ok::<_, String>(listener)
        })();
        let listener = match setup {
            Ok(listener) => listener,
            Err(error) => {
                let _ = fs::remove_file(&socket_path);
                let _ = fs::remove_dir(&root);
                return Err(error);
            }
        };
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let shutdown_boundaries = Arc::new(Mutex::new(Vec::new()));
        let thread_boundaries = Arc::clone(&shutdown_boundaries);
        let state = Arc::new(Mutex::new(BrokerState::new(
            session_id,
            allowed_hosts,
            allowed_capabilities,
            model_host,
            session_facts,
            provenance_mode,
            session_policy,
            connector,
            audit,
            gate,
            model_budget_limits,
        )?));
        // Record the enforcement boundary before exposing either the action
        // socket or the in-process operator control. This keeps the audit
        // chain ordered even when an operator action arrives immediately.
        if let Err(error) = state
            .lock()
            .map_err(|_| "kernel broker state is unavailable".to_owned())?
            .record_enforcement_state("start")
        {
            let _ = fs::remove_file(&socket_path);
            let _ = fs::remove_dir(&root);
            return Err(error);
        }
        let thread_state = Arc::clone(&state);
        let thread = match thread::Builder::new()
            .name("keel-kernel-broker".to_owned())
            .spawn(move || {
                broker_loop(
                    &listener,
                    &thread_state,
                    diagnostics.as_deref(),
                    &thread_boundaries,
                    &thread_stop,
                )
            }) {
            Ok(thread) => thread,
            Err(error) => {
                let _ = fs::remove_file(&socket_path);
                let _ = fs::remove_dir(&root);
                return Err(error.to_string());
            }
        };
        Ok(Self {
            socket_path,
            root,
            ca_certificate_pem,
            state,
            stop,
            shutdown_boundaries,
            thread: Some(thread),
        })
    }

    /// Returns the private socket path passed to the untrusted runtime.
    #[must_use]
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Returns the public run CA certificate installed into the guest trust
    /// store when TLS termination is enabled.
    #[must_use]
    pub fn ca_certificate_pem(&self) -> Option<&str> {
        self.ca_certificate_pem.as_deref()
    }

    /// Installs the admission-time payload policy. Requests judged before this
    /// call record `not-checked`.
    /// # Errors
    /// Returns an error when the broker state is unavailable.
    pub fn set_payload_policy(&self, policy: PayloadPolicy) -> Result<(), String> {
        self.state
            .lock()
            .map_err(|_| "kernel broker state is unavailable".to_owned())?
            .payload = Some(Arc::new(policy));
        Ok(())
    }

    /// Durably records this run's admission manifest. Call before any
    /// workload process exists; an error must refuse the run.
    /// # Errors
    /// Returns an error when the state or audit chain is unavailable.
    pub fn record_run_admitted(&self, event: RunAdmittedEvent) -> Result<(), String> {
        self.state
            .lock()
            .map_err(|_| "kernel broker state is unavailable".to_owned())?
            .audit
            .record_run_admitted(event)
    }

    /// Returns a cloneable in-process control path to this exact live kernel.
    #[must_use]
    pub fn control(&self) -> KernelBrokerControl {
        KernelBrokerControl {
            state: Arc::clone(&self.state),
        }
    }

    /// Stops the broker and returns its action counts.
    /// # Errors
    /// Returns an error when the broker thread or cleanup fails.
    pub fn shutdown(self) -> Result<BrokerReport, String> {
        self.shutdown_with_boundaries(Vec::new())
    }

    /// Stops the broker after attaching caller-derived teardown boundaries to
    /// the authenticated shutdown record.
    /// # Errors
    /// Returns an error when the boundary handoff, broker, audit, or cleanup
    /// fails.
    pub fn shutdown_with_boundaries(
        mut self,
        boundaries: Vec<EnforcementBoundary>,
    ) -> Result<BrokerReport, String> {
        *self
            .shutdown_boundaries
            .lock()
            .map_err(|_| "kernel shutdown boundaries are unavailable".to_owned())? = boundaries;
        self.stop.store(true, Ordering::Release);
        let report = self
            .thread
            .take()
            .ok_or_else(|| "kernel broker thread is unavailable".to_owned())?
            .join()
            .map_err(|_| "kernel broker thread panicked".to_owned())??;
        self.cleanup()?;
        Ok(report)
    }

    fn cleanup(&self) -> Result<(), String> {
        match fs::remove_file(&self.socket_path) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(error.to_string()),
        }
        match fs::remove_dir(&self.root) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.to_string()),
        }
    }
}

/// Trusted in-process control path for operator actions on a live broker.
#[derive(Clone)]
pub struct KernelBrokerControl {
    state: Arc<Mutex<BrokerState>>,
}

impl KernelBrokerControl {
    /// Requests a gated lift against the live session state and audit chain.
    ///
    /// # Errors
    ///
    /// Returns an error when the state is unavailable, the requested rank does
    /// not raise the floor, or policy, approval, execution, or audit fails.
    pub fn lift_floor(&self, requested_floor: u8) -> Result<u8, String> {
        run_unlocked(
            &self.state,
            &Arc::new(AtomicBool::new(false)),
            || Ok(()),
            |state| state.begin_lift_floor(requested_floor),
            BrokerState::finish_lift_floor,
        )?
    }
}

fn broker_temporary_directory() -> PathBuf {
    // macOS's per-user temporary directory is already long, and resolving its
    // `/var` symlink adds `/private`. A randomized broker socket below it can
    // then exceed sockaddr_un::sun_path even though binding the unresolved
    // spelling succeeded. `/tmp` is still protected by the private 0700 broker
    // directory, while leaving enough room for the canonical socket path.
    #[cfg(target_os = "macos")]
    {
        PathBuf::from("/tmp")
    }
    #[cfg(not(target_os = "macos"))]
    {
        std::env::temp_dir()
    }
}

impl Drop for KernelBroker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        let _ = self.cleanup();
    }
}

struct BrokerPolicy {
    allowed_hosts: BTreeSet<String>,
    allowed_capabilities: BTreeSet<String>,
    /// The one host whose requests are model egress for this run.
    ///
    /// Named by the caller rather than hardcoded here. The kernel decides whether
    /// a request is model egress, and that decision drives budget reservation, so
    /// a kernel that knows only one provider's hostname hard-denies every request
    /// to the other one — which is exactly what it did.
    model_host: String,
    model_budget_denied: bool,
    /// Set only while adjudicating an HTTP request that consumed an exact,
    /// one-use effect permit from its already approved logical action.
    effect_permit_consumed: bool,
    session_policy: Box<dyn Policy>,
}

impl Policy for BrokerPolicy {
    fn violations(&self, action: &Action, facts: &SessionFacts) -> Result<Vec<Violation>, String> {
        let mut violations = self.session_policy.violations(action, facts)?;
        match (&action.asserted().class, &action.asserted().target) {
            (ActionClass::GitPush, Target::Git { .. }) => {
                if !(facts.intent.task_admission == TaskAdmission::Trusted
                    && facts.intent.allow_push_branch)
                {
                    violations.push(Violation::new(
                        "admission:git-push",
                        "Git authority was not admitted at trusted task admission",
                    ));
                }
                push_origin_violation(action, &mut violations);
                // A declared ref scope only narrows: pushes outside it are
                // shown to the operator instead of riding `push:branch`.
                if action.stamped().intent() == IntentVerdict::Outside("ref-outside-envelope") {
                    violations.push(Violation::new(
                        "intent:push-ref",
                        "pushed refs are outside the admitted push:ref patterns",
                    ));
                }
                Ok(violations)
            }
            (
                ActionClass::PullRequest,
                Target::External {
                    service, operation, ..
                },
            ) if service == "github" && operation == "create-pull-request" => {
                violations.push(Violation::new(
                    "admission:pr-create",
                    "launcher-requested GitHub authority requires trusted operator approval",
                ));
                push_origin_violation(action, &mut violations);
                if action.stamped().intent() == IntentVerdict::Outside("pr-target") {
                    violations.push(Violation::new(
                        "intent:pr-target",
                        "the pull request base is outside the admitted pr:target branches",
                    ));
                }
                if self.allowed_capabilities.contains("pr:create") {
                    Ok(violations)
                } else {
                    violations.push(Violation::new(
                        "intent:pr-create",
                        "structured intent does not allow pull-request creation",
                    ));
                    Ok(violations)
                }
            }
            (
                ActionClass::Egress,
                Target::Network {
                    host,
                    port,
                    method,
                    path,
                },
            ) => {
                let allowed =
                    self.allowed_hosts.contains(host) || in_scope(&facts.intent, host, *port);
                let transport_assertion =
                    path.is_empty() && matches!(method.as_str(), "TLS" | "CONNECT" | "HTTP");
                // CONNECT and bare TLS are inspected setup, not the effect the
                // guest asked to perform. The trusted proxy releases no guest
                // application bytes on this leg; it terminates TLS and submits
                // the decrypted method/path below as the one policy action.
                // Gating both legs makes one HTTPS request require two answers,
                // with the useful second prompt appearing only after CONNECT.
                if !transport_assertion && !allowed {
                    violations.push(Violation::new(
                        EGRESS_HOST_RULE,
                        format!("structured intent does not allow egress to {host}"),
                    ));
                }
                let admitted = facts.intent.task_admission == TaskAdmission::Trusted && allowed;
                if *host != self.model_host
                    && !transport_assertion
                    && !self.effect_permit_consumed
                    && !admitted
                {
                    violations.push(Violation::new(
                        ADMISSION_EGRESS_RULE,
                        "launcher-requested non-model egress requires trusted operator approval",
                    ));
                }
                if *host == self.model_host
                    && !transport_assertion
                    && !model_path_allowed(&self.model_host, method, path)
                {
                    violations.push(Violation::new(
                        "egress:model-endpoint",
                        format!("model egress does not allow {method} {path}"),
                    ));
                }
                if self.model_budget_denied {
                    violations.push(Violation::new(
                        "kernel:model-budget",
                        "model budget metadata is missing or its token or cost ceiling is exhausted",
                    ));
                }
                Ok(violations)
            }
            (ActionClass::LiftFloor, Target::FloorLift { .. }) => Ok(violations),
            _ => Err("broker received an unsupported action target".to_owned()),
        }
    }
}

/// Reports whether one request to the run's model host is an authorized
/// invocation.
///
/// The kernel restates the endpoint shape rather than leaving it to the proxy's
/// sanitizer alone, and the shape is provider-specific: one provider names the
/// model in the body and the other names it in the path. A control-plane path on
/// a model host is not model egress, which is the case that matters — that is how
/// a harness reaches a permission classifier.
fn model_path_allowed(model_host: &str, method: &str, path: &str) -> bool {
    if method != "POST" {
        return false;
    }
    let path = path.split('?').next().unwrap_or(path);
    if model_host == "api.anthropic.com" {
        return path == "/v1/messages";
    }
    path.starts_with("/model/")
        && (path.ends_with("/invoke") || path.ends_with("/invoke-with-response-stream"))
}

struct ConservativeSessionPolicy;

impl Policy for ConservativeSessionPolicy {
    fn violations(&self, action: &Action, _facts: &SessionFacts) -> Result<Vec<Violation>, String> {
        if action.asserted().class == ActionClass::GitPush {
            Ok(vec![Violation::new(
                "kernel:stateful-policy-required",
                "branch pushes require an explicit stateful policy",
            )])
        } else {
            Ok(Vec::new())
        }
    }
}

struct DenyGate;

impl Gate for DenyGate {
    fn decide(&mut self, _request: GateRequest<'_>) -> GateDecision {
        GateDecision::Deny
    }
}

/// One begun broker action and what completing it needs.
struct Begun<C> {
    pending: PendingAction,
    /// A trusted resource failure already decided the answer.
    hard_deny: bool,
    context: C,
}

impl<C> Begun<C> {
    const fn new(pending: PendingAction, context: C) -> Self {
        Self {
            pending,
            hard_deny: false,
            context,
        }
    }
}

struct HttpContext {
    model_request: Result<Option<ModelBudgetRequest>, String>,
    consumed_effect_permit: bool,
}

impl Default for HttpContext {
    fn default() -> Self {
        Self {
            model_request: Ok(None),
            consumed_effect_permit: false,
        }
    }
}

struct GitContext {
    remote: Option<(String, String)>,
    body_digest: [u8; 32],
}

const UNAVAILABLE: GateOutcome = GateOutcome {
    decision: GateDecision::Unavailable,
    authority: "unavailable",
    time_to_decision_ms: 0,
};

/// Asks the trusted gate about a begun action. Only the adjudication slot is
/// held across the operator's decision, so traffic that needs no decision and
/// in-flight model and response bookkeeping keep using the broker state.
/// `on_slot` runs once this request owns the slot, or immediately when it
/// needs no operator.
fn adjudicate<C>(
    gate: &Mutex<Box<dyn Gate>>,
    begun: &Begun<C>,
    cancelled: &Arc<AtomicBool>,
    on_slot: impl FnOnce() -> Result<(), String>,
) -> Result<Option<GateOutcome>, String> {
    if !begun.pending.needs_gate() {
        on_slot()?;
        return Ok(None);
    }
    if begun.hard_deny {
        on_slot()?;
        return Ok(Some(GateOutcome::decide(
            &mut DenyGate,
            begun.pending.gate_request(),
        )));
    }
    let mut slot = gate
        .lock()
        .map_err(|_| "kernel gate is unavailable".to_owned())?;
    on_slot()?;
    let mut gate = CancellableGate {
        inner: slot.as_mut(),
        cancelled,
        called_inner: false,
    };
    Ok(Some(GateOutcome::decide(
        &mut gate,
        begun.pending.gate_request(),
    )))
}

/// Begins an action under the state lock, decides it with that lock
/// released, and finishes it under the lock again. A failure while deciding
/// still finishes the action as unavailable, so its reservation is released
/// and its denial audited.
fn run_unlocked<C, R>(
    state: &Mutex<BrokerState>,
    cancelled: &Arc<AtomicBool>,
    on_slot: impl FnOnce() -> Result<(), String>,
    start: impl FnOnce(&mut BrokerState) -> Result<Begun<C>, R>,
    complete: impl FnOnce(&mut BrokerState, Begun<C>, Option<GateOutcome>) -> R,
) -> Result<R, String> {
    let unavailable = || "kernel broker state is unavailable".to_owned();
    let (begun, gate) = {
        let mut state = state.lock().map_err(|_| unavailable())?;
        match start(&mut state) {
            Ok(begun) => (begun, Arc::clone(&state.gate)),
            Err(early) => return Ok(early),
        }
    };
    let outcome = adjudicate(&gate, &begun, cancelled, on_slot);
    let mut state = state.lock().map_err(|_| unavailable())?;
    match outcome {
        Ok(outcome) => Ok(complete(&mut state, begun, outcome)),
        Err(error) => {
            complete(&mut state, begun, Some(UNAVAILABLE));
            Err(error)
        }
    }
}

struct CancellableGate<'a> {
    inner: &'a mut dyn Gate,
    cancelled: &'a Arc<AtomicBool>,
    called_inner: bool,
}

impl Gate for CancellableGate<'_> {
    fn decide(&mut self, mut request: GateRequest<'_>) -> GateDecision {
        if self.cancelled.load(Ordering::Acquire) {
            return GateDecision::Unavailable;
        }
        self.called_inner = true;
        request.cancelled = Some(Arc::clone(self.cancelled));
        let decision = self.inner.decide(request);
        if self.cancelled.load(Ordering::Acquire) {
            GateDecision::Unavailable
        } else {
            decision
        }
    }

    fn authority(&self) -> &'static str {
        if self.called_inner {
            self.inner.authority()
        } else {
            "unavailable"
        }
    }
}

struct EgressTarget {
    host: String,
    port: u16,
    method: String,
}

struct EgressInjector;

impl CredentialInjector for EgressInjector {
    type Prepared = EgressTarget;

    fn inject(&mut self, action: &Action) -> Result<Self::Prepared, String> {
        let Target::Network {
            host, port, method, ..
        } = &action.asserted().target
        else {
            return Err("egress executor received a non-network target".to_owned());
        };
        Ok(EgressTarget {
            host: host.clone(),
            port: *port,
            method: method.clone(),
        })
    }
}

struct EgressExecutor {
    connector: Box<dyn EgressConnector>,
}

impl Executor<EgressTarget> for EgressExecutor {
    type Output = Box<dyn EgressSession>;

    fn execute(&mut self, target: EgressTarget) -> Result<Self::Output, String> {
        self.connector
            .connect(&target.host, target.port, &target.method)
    }
}

struct CancellableExecutor<'a, E> {
    inner: &'a mut E,
    cancelled: &'a AtomicBool,
}

impl<P, E: Executor<P>> Executor<P> for CancellableExecutor<'_, E> {
    type Output = E::Output;

    fn execute(&mut self, prepared: P) -> Result<Self::Output, String> {
        if self.cancelled.load(Ordering::Acquire) {
            return Err("relay disconnected before action execution".to_owned());
        }
        let output = self.inner.execute(prepared)?;
        if self.cancelled.load(Ordering::Acquire) {
            return Err("relay disconnected during action execution".to_owned());
        }
        Ok(output)
    }
}

struct EgressPermitInjector;

impl CredentialInjector for EgressPermitInjector {
    type Prepared = ();

    fn inject(&mut self, _action: &Action) -> Result<Self::Prepared, String> {
        Ok(())
    }
}

struct EgressPermitExecutor;

impl Executor<()> for EgressPermitExecutor {
    type Output = ();

    fn execute(&mut self, (): ()) -> Result<Self::Output, String> {
        Ok(())
    }
}

struct ModelBudget {
    limits: ModelBudgetLimits,
    charged_tokens: u64,
    charged_cost_microusd: u64,
    next_reservation_id: u64,
    reservations: BTreeMap<ModelReservationId, ModelReservation>,
}

struct ModelReservation {
    action_id: u64,
    request: ModelBudgetRequest,
    tokens: u64,
    cost_microusd: u64,
    state: ModelReservationState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ModelReservationState {
    AuthorizedUnsent,
    SendAttempted,
    Terminal(ModelReservationOutcome),
}

struct PlannedModelResolution {
    event: ModelReservationEvent,
    charged_tokens: u64,
    charged_cost_microusd: u64,
}

impl ModelBudget {
    fn new(limits: ModelBudgetLimits) -> Self {
        Self {
            limits,
            charged_tokens: 0,
            charged_cost_microusd: 0,
            next_reservation_id: 1,
            reservations: BTreeMap::new(),
        }
    }

    fn reservation_charge(request: &ModelBudgetRequest) -> Result<(u64, u64), String> {
        let tokens = request
            .input_tokens_upper_bound
            .checked_add(request.max_output_tokens)
            .ok_or_else(|| "model token reservation overflowed".to_owned())?;
        let cost_microusd = request
            .input_tokens_upper_bound
            .checked_mul(request.input_microusd_per_token)
            .and_then(|input| {
                request
                    .max_output_tokens
                    .checked_mul(request.output_microusd_per_token)
                    .and_then(|output| input.checked_add(output))
            })
            .ok_or_else(|| "model cost reservation overflowed".to_owned())?;
        Ok((tokens, cost_microusd))
    }

    fn can_reserve(&self, request: &ModelBudgetRequest) -> Result<(), String> {
        let (tokens, cost_microusd) = Self::reservation_charge(request)?;
        let charged_tokens = self
            .charged_tokens
            .checked_add(tokens)
            .ok_or_else(|| "model token budget overflowed".to_owned())?;
        let charged_cost = self
            .charged_cost_microusd
            .checked_add(cost_microusd)
            .ok_or_else(|| "model cost budget overflowed".to_owned())?;
        if charged_tokens > self.limits.token_limit
            || charged_cost > self.limits.cost_limit_microusd
        {
            return Err("model token or cost budget is exhausted".to_owned());
        }
        Ok(())
    }

    fn reserve(
        &mut self,
        action_id: u64,
        request: ModelBudgetRequest,
    ) -> Result<ModelReservationId, String> {
        self.can_reserve(&request)?;
        let (tokens, cost_microusd) = Self::reservation_charge(&request)?;
        let charged_tokens = self
            .charged_tokens
            .checked_add(tokens)
            .ok_or_else(|| "model token budget overflowed".to_owned())?;
        let charged_cost_microusd = self
            .charged_cost_microusd
            .checked_add(cost_microusd)
            .ok_or_else(|| "model cost budget overflowed".to_owned())?;
        let reservation_id = ModelReservationId(self.next_reservation_id);
        self.next_reservation_id = self
            .next_reservation_id
            .checked_add(1)
            .ok_or_else(|| "model reservation identifier overflowed".to_owned())?;
        self.charged_tokens = charged_tokens;
        self.charged_cost_microusd = charged_cost_microusd;
        self.reservations.insert(
            reservation_id,
            ModelReservation {
                action_id,
                request,
                tokens,
                cost_microusd,
                state: ModelReservationState::AuthorizedUnsent,
            },
        );
        Ok(reservation_id)
    }

    fn mark_send_attempted(&mut self, reservation_id: ModelReservationId) -> Result<(), String> {
        let reservation = self
            .reservations
            .get_mut(&reservation_id)
            .ok_or_else(|| "unknown model reservation".to_owned())?;
        match reservation.state {
            ModelReservationState::AuthorizedUnsent => {
                reservation.state = ModelReservationState::SendAttempted;
                Ok(())
            }
            ModelReservationState::SendAttempted => {
                Err("model reservation send was already attempted".to_owned())
            }
            ModelReservationState::Terminal(outcome) => Err(format!(
                "model reservation is already resolved as {}",
                outcome.as_str()
            )),
        }
    }

    fn resolve(
        &mut self,
        reservation_id: ModelReservationId,
        resolution: ModelReservationResolution,
        audit: &mut dyn AuditSink,
    ) -> Result<(), String> {
        let planned = self.plan_resolution(reservation_id, resolution)?;

        // The terminal fact must be durable before a refund or accounting
        // adjustment becomes visible to the next authorization decision.
        audit.record_model_reservation(planned.event)?;

        let reservation = self
            .reservations
            .get_mut(&reservation_id)
            .expect("planned model reservation must still exist");
        reservation.state = ModelReservationState::Terminal(planned.event.outcome);
        self.charged_tokens = planned.charged_tokens;
        self.charged_cost_microusd = planned.charged_cost_microusd;
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    fn plan_resolution(
        &self,
        reservation_id: ModelReservationId,
        resolution: ModelReservationResolution,
    ) -> Result<PlannedModelResolution, String> {
        let reservation = self
            .reservations
            .get(&reservation_id)
            .ok_or_else(|| "unknown model reservation".to_owned())?;
        if let ModelReservationState::Terminal(outcome) = reservation.state {
            return Err(format!(
                "model reservation is already resolved as {}",
                outcome.as_str()
            ));
        }

        let (outcome, actual_tokens, actual_cost_microusd, charged_tokens, charged_cost) =
            match resolution {
                ModelReservationResolution::ReleasedUnsent => {
                    if reservation.state != ModelReservationState::AuthorizedUnsent {
                        return Err(
                            "a model reservation cannot be released after a send attempt"
                                .to_owned(),
                        );
                    }
                    (
                        ModelReservationOutcome::ReleasedUnsent,
                        None,
                        None,
                        self.charged_tokens
                            .checked_sub(reservation.tokens)
                            .ok_or_else(|| "model token accounting underflowed".to_owned())?,
                        self.charged_cost_microusd
                            .checked_sub(reservation.cost_microusd)
                            .ok_or_else(|| "model cost accounting underflowed".to_owned())?,
                    )
                }
                ModelReservationResolution::CommittedConservative => (
                    ModelReservationOutcome::CommittedConservative,
                    None,
                    None,
                    self.charged_tokens,
                    self.charged_cost_microusd,
                ),
                ModelReservationResolution::SettledActual(usage)
                | ModelReservationResolution::CommittedObserved(usage) => {
                    let observed =
                        matches!(resolution, ModelReservationResolution::CommittedObserved(_));
                    if reservation.state != ModelReservationState::SendAttempted {
                        return Err(
                            "model usage cannot settle before an upstream send attempt".to_owned()
                        );
                    }
                    let actual_tokens = usage
                        .input_tokens
                        .checked_add(usage.output_tokens)
                        .ok_or_else(|| "model usage token count overflowed".to_owned())?;
                    let actual_cost = usage
                        .input_tokens
                        .checked_mul(reservation.request.input_microusd_per_token)
                        .and_then(|input| {
                            usage
                                .output_tokens
                                .checked_mul(reservation.request.output_microusd_per_token)
                                .and_then(|output| input.checked_add(output))
                        })
                        .ok_or_else(|| "model usage cost overflowed".to_owned())?;
                    // A bound for an interrupted response cannot exceed what
                    // was reserved for the complete one.
                    let (actual_tokens, actual_cost) = if observed {
                        (
                            actual_tokens.min(reservation.tokens),
                            actual_cost.min(reservation.cost_microusd),
                        )
                    } else {
                        (actual_tokens, actual_cost)
                    };
                    let charged_tokens = self
                        .charged_tokens
                        .checked_sub(reservation.tokens)
                        .and_then(|charged| charged.checked_add(actual_tokens))
                        .ok_or_else(|| "model token accounting overflowed".to_owned())?;
                    let charged_cost = self
                        .charged_cost_microusd
                        .checked_sub(reservation.cost_microusd)
                        .and_then(|charged| charged.checked_add(actual_cost))
                        .ok_or_else(|| "model cost accounting overflowed".to_owned())?;
                    let outcome = if observed {
                        ModelReservationOutcome::CommittedObserved
                    } else if actual_tokens > reservation.tokens
                        || actual_cost > reservation.cost_microusd
                    {
                        ModelReservationOutcome::Overrun
                    } else {
                        ModelReservationOutcome::SettledActual
                    };
                    (
                        outcome,
                        Some(actual_tokens),
                        Some(actual_cost),
                        charged_tokens,
                        charged_cost,
                    )
                }
            };

        Ok(PlannedModelResolution {
            event: ModelReservationEvent {
                reservation_id,
                action_id: reservation.action_id,
                outcome,
                reserved_tokens: reservation.tokens,
                reserved_cost_microusd: reservation.cost_microusd,
                actual_tokens,
                actual_cost_microusd,
            },
            charged_tokens,
            charged_cost_microusd: charged_cost,
        })
    }

    fn unresolved_ids(&self) -> Vec<ModelReservationId> {
        self.reservations
            .iter()
            .filter_map(|(reservation_id, reservation)| {
                (!matches!(reservation.state, ModelReservationState::Terminal(_)))
                    .then_some(*reservation_id)
            })
            .collect()
    }
}

struct CountingAudit {
    sink: Box<dyn AuditSink>,
    events: usize,
}

impl AuditSink for CountingAudit {
    fn record(&mut self, event: AuditEvent) -> Result<(), String> {
        self.sink.record(event)?;
        self.events += 1;
        Ok(())
    }

    fn shutdown(&mut self) -> Result<(), String> {
        self.sink.shutdown()
    }

    fn record_model_usage(&mut self, event: ModelUsageEvent) -> Result<(), String> {
        self.sink.record_model_usage(event)?;
        self.events += 1;
        Ok(())
    }

    fn record_model_reservation(&mut self, event: ModelReservationEvent) -> Result<(), String> {
        self.sink.record_model_reservation(event)?;
        self.events += 1;
        Ok(())
    }

    fn record_provenance(&mut self, event: ProvenanceEvent) -> Result<(), String> {
        self.sink.record_provenance(event)?;
        self.events += 1;
        Ok(())
    }

    fn record_context(&mut self, event: ContextEvent) -> Result<(), String> {
        self.sink.record_context(event)?;
        self.events += 1;
        Ok(())
    }

    fn record_run_admitted(&mut self, event: RunAdmittedEvent) -> Result<(), String> {
        self.sink.record_run_admitted(event)?;
        self.events += 1;
        Ok(())
    }

    fn record_reported_outcome(&mut self, event: ReportedOutcomeEvent) -> Result<(), String> {
        self.sink.record_reported_outcome(event)?;
        self.events += 1;
        Ok(())
    }

    // Not counted. `events` feeds the escalation metrics, which are per action;
    // enforcement state is a property of the run, not an action within it.
    fn record_enforcement_state(&mut self, event: EnforcementStateEvent) -> Result<(), String> {
        self.sink.record_enforcement_state(event)
    }

    fn is_durable(&self) -> bool {
        self.sink.is_durable()
    }
}

struct DiscardAudit;

impl AuditSink for DiscardAudit {
    fn record(&mut self, _event: AuditEvent) -> Result<(), String> {
        Ok(())
    }
}

struct BrokerState {
    session_id: String,
    kernel: Kernel<BrokerPolicy>,
    /// The serialized adjudication slot. Held, without the state lock, for the
    /// whole of one operator decision.
    gate: Arc<Mutex<Box<dyn Gate>>>,
    gate_authority: &'static str,
    injector: EgressInjector,
    executor: EgressExecutor,
    audit: CountingAudit,
    model_budget: ModelBudget,
    execution_failures: usize,
    /// Git actions authorized here whose outcome the relay has not reported.
    unreported_pushes: BTreeSet<u64>,
    /// Remotes this session's operator approved a push to, as host and
    /// repository path.
    pushed_remotes: BTreeSet<(String, String)>,
    /// Credential-bearing effects authorized by the action channel and waiting
    /// to be consumed by one exact HTTP request.
    pending_effects: Vec<PendingEffectPermit>,
    /// Admission-time confidential content, for shadow payload verdicts.
    payload: Option<Arc<PayloadPolicy>>,
    /// Lines the model emitted in tool calls, for push integrity verdicts.
    model_output: ModelOutputIndex,
    /// Context block digests already described in the digest log.
    context_described: HashSet<[u8; 8]>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PendingEffectPermit {
    action_id: u64,
    expires_at: Instant,
    effect: EffectPermit,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum EffectPermit {
    GitPush {
        host: String,
        path: String,
        body_digest: [u8; 32],
    },
    GithubPullRequest {
        path: String,
        body_digest: [u8; 32],
    },
}

impl EffectPermit {
    fn matches_http(
        &self,
        target: &EgressAuthorizationTarget,
        path: &str,
        body_digest: &[u8; 32],
    ) -> bool {
        match self {
            Self::GitPush {
                host,
                path: expected_path,
                body_digest: expected_digest,
            } => host == &target.host && expected_path == path && expected_digest == body_digest,
            Self::GithubPullRequest {
                path: expected_path,
                body_digest: expected_digest,
            } => {
                target.host == "api.github.com"
                    && expected_path == path
                    && expected_digest == body_digest
            }
        }
    }
}

impl BrokerState {
    fn prune_effect_permits(&mut self, now: Instant) {
        self.pending_effects
            .retain(|permit| permit.expires_at > now);
    }

    fn remember_effect_permit(&mut self, action_id: u64, effect: EffectPermit) {
        self.prune_effect_permits(Instant::now());
        while self.pending_effects.len() >= MAX_PENDING_EFFECT_PERMITS {
            self.pending_effects.remove(0);
        }
        self.pending_effects.push(PendingEffectPermit {
            action_id,
            expires_at: Instant::now() + EFFECT_PERMIT_TTL,
            effect,
        });
    }

    fn consume_effect_permit(
        &mut self,
        target: &EgressAuthorizationTarget,
        path: &str,
        body_digest: &[u8; 32],
    ) -> bool {
        self.prune_effect_permits(Instant::now());
        let Some(index) = self
            .pending_effects
            .iter()
            .position(|permit| permit.effect.matches_http(target, path, body_digest))
        else {
            return false;
        };
        self.pending_effects.remove(index);
        true
    }

    fn revoke_effect_permits(&mut self, action_id: u64) {
        self.pending_effects
            .retain(|permit| permit.action_id != action_id);
    }

    #[allow(clippy::too_many_arguments)]
    fn new(
        session_id: String,
        allowed_hosts: BTreeSet<String>,
        allowed_capabilities: BTreeSet<String>,
        model_host: String,
        session_facts: SessionFacts,
        provenance_mode: ProvenanceMode,
        session_policy: Box<dyn Policy>,
        connector: Box<dyn EgressConnector>,
        audit: Box<dyn AuditSink>,
        gate: Box<dyn Gate>,
        model_budget_limits: ModelBudgetLimits,
    ) -> Result<Self, String> {
        let principal =
            PrincipalId::new("vertex").map_err(|error| format!("broker principal: {error}"))?;
        let operator =
            PrincipalId::new("operator").map_err(|error| format!("broker principal: {error}"))?;
        let registry = ChannelRegistry::new(
            ["egress", "git", "external", "operator"],
            [
                ChannelDeclaration {
                    name: "egress".to_owned(),
                    principal: principal.clone(),
                    gate_class: GateClass::Egress,
                },
                ChannelDeclaration {
                    name: "git".to_owned(),
                    principal: principal.clone(),
                    gate_class: GateClass::Git,
                },
                ChannelDeclaration {
                    name: "external".to_owned(),
                    principal,
                    gate_class: GateClass::External,
                },
                ChannelDeclaration {
                    name: "operator".to_owned(),
                    principal: operator,
                    gate_class: GateClass::Operator,
                },
            ],
        )
        .map_err(|error| error.to_string())?;
        let mut session = SessionState::new(10_000, 1_000).map_err(|error| error.to_string())?;
        session.facts = session_facts;
        let policy = BrokerPolicy {
            allowed_hosts,
            allowed_capabilities,
            model_host,
            model_budget_denied: false,
            effect_permit_consumed: false,
            session_policy,
        };
        let kernel = Kernel::with_provenance_mode(
            registry,
            session,
            policy,
            session_id.clone(),
            provenance_mode,
        )
        .map_err(|error| error.to_string())?;
        Ok(Self {
            session_id,
            kernel,
            gate_authority: gate.authority(),
            gate: Arc::new(Mutex::new(gate)),
            injector: EgressInjector,
            executor: EgressExecutor { connector },
            audit: CountingAudit {
                sink: audit,
                events: 0,
            },
            model_budget: ModelBudget::new(model_budget_limits),
            execution_failures: 0,
            unreported_pushes: BTreeSet::new(),
            pushed_remotes: BTreeSet::new(),
            pending_effects: Vec::new(),
            payload: None,
            model_output: ModelOutputIndex::default(),
            context_described: HashSet::new(),
        })
    }

    /// Logs one model request's or response's blocks, describing each digest
    /// only the first time. The log is shadow data, so a recording failure
    /// changes no decision.
    fn record_context(&mut self, action_id: u64, response: bool, blocks: Vec<ContextBlock>) {
        let sequence = blocks.iter().map(|block| block.digest).collect();
        let described = blocks
            .into_iter()
            .filter(|block| self.context_described.insert(block.digest))
            .collect();
        let _ = self.audit.record_context(ContextEvent {
            action_id,
            phase: if response { "response" } else { "request" },
            sequence,
            described,
        });
    }

    fn begin_lift_floor(&mut self, requested_floor: u8) -> Result<Begun<()>, Result<u8, String>> {
        if requested_floor <= self.kernel.session().floor() {
            return Err(Err(
                "requested floor must be higher than the current floor".to_owned()
            ));
        }
        let asserted = Asserted {
            class: ActionClass::LiftFloor,
            target: Target::FloorLift {
                session_id: self.session_id.clone(),
                requested_floor,
            },
            declared_cost: None,
        };
        self.kernel
            .begin("operator", "operator", asserted, &mut self.audit)
            .map(|pending| Begun::new(pending, ()))
            .map_err(|error| Err(error.to_string()))
    }

    fn finish_lift_floor(
        &mut self,
        begun: Begun<()>,
        outcome: Option<GateOutcome>,
    ) -> Result<u8, String> {
        self.kernel
            .finish(
                begun.pending,
                outcome,
                &mut EgressPermitInjector,
                &mut EgressPermitExecutor,
                &mut self.audit,
            )
            .map_err(|error| error.to_string())?;
        Ok(self.kernel.session().floor())
    }

    /// Runs a begun action's decision while this caller owns the state.
    #[cfg(test)]
    fn run_locked<C, R>(
        &mut self,
        cancelled: &Arc<AtomicBool>,
        start: impl FnOnce(&mut Self) -> Result<Begun<C>, R>,
        complete: impl FnOnce(&mut Self, Begun<C>, Option<GateOutcome>) -> R,
    ) -> R {
        let begun = match start(self) {
            Ok(begun) => begun,
            Err(early) => return early,
        };
        let gate = Arc::clone(&self.gate);
        let outcome = adjudicate(&gate, &begun, cancelled, || Ok(())).unwrap_or(Some(UNAVAILABLE));
        complete(self, begun, outcome)
    }

    /// Derives every boundary's state from the objects that enforce it.
    ///
    /// Nothing here reads configuration, an argument, or a copy: each field is
    /// taken from the live registry, policy, connector, gate, budget, or sink
    /// that the request path itself uses. That is the whole point — a report
    /// assembled from what the run *intended* is the failure this record exists
    /// to catch, so there must be no second source for it to drift from.
    fn enforcement_boundaries(&self) -> Vec<EnforcementBoundary> {
        let mut boundaries = self.adjudication_boundaries();
        boundaries.extend(self.mediation_boundaries());
        boundaries
    }

    /// Boundaries the kernel adjudicates itself: what it will consider at all.
    fn adjudication_boundaries(&self) -> Vec<EnforcementBoundary> {
        let channels = self
            .kernel
            .registry
            .declarations
            .values()
            .map(|declaration| format!("{}={}", declaration.name, declaration.gate_class.as_str()))
            .collect::<Vec<_>>()
            .join(" ");
        let hosts = self
            .kernel
            .policy
            .allowed_hosts
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .join(",");
        let capabilities = self
            .kernel
            .policy
            .allowed_capabilities
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .join(",");
        let protected = PROTECTED_STATES.map(protected_state_name).join(",");
        let limits = &self.model_budget.limits;
        vec![
            EnforcementBoundary {
                name: "channel-registry",
                state: EnforcementState::Active,
                detail: channels,
            },
            EnforcementBoundary {
                name: "protected-state",
                state: EnforcementState::Active,
                detail: protected,
            },
            EnforcementBoundary {
                name: "egress-allowlist",
                // An empty allowlist denies every host, which is the most
                // confining state this boundary has. It is bracketed rather
                // than omitted so that reading it is unambiguous: `hosts=0 []`
                // is a fact, a missing line is a question.
                state: EnforcementState::Active,
                detail: format!("hosts={} [{hosts}]", self.kernel.policy.allowed_hosts.len()),
            },
            EnforcementBoundary {
                name: "capability-intent",
                state: EnforcementState::Active,
                detail: format!(
                    "capabilities={} [{capabilities}]",
                    self.kernel.policy.allowed_capabilities.len()
                ),
            },
            EnforcementBoundary {
                name: "task-admission",
                state: if self.kernel.session.facts.intent.task_admission == TaskAdmission::Absent {
                    EnforcementState::Absent
                } else {
                    EnforcementState::Active
                },
                detail: match self.kernel.session.facts.intent.task_admission {
                    TaskAdmission::Trusted => "trusted-terminal review of declared authority",
                    TaskAdmission::NotRequired => "no extra task authority requested",
                    TaskAdmission::Absent => "declared authority was not admitted",
                }
                .to_owned(),
            },
            EnforcementBoundary {
                name: "model-budget",
                state: EnforcementState::Active,
                detail: format!(
                    "tokens={} microusd={}",
                    limits.token_limit, limits.cost_limit_microusd
                ),
            },
        ]
    }

    /// Boundaries enforced by the objects the kernel delegates to: the
    /// connector that carries a request, the gate that decides it, and the sink
    /// that records it. Each is asked rather than assumed, because a run
    /// assembled with a weaker one is exactly what this record exists to show.
    fn mediation_boundaries(&self) -> Vec<EnforcementBoundary> {
        let network_floor =
            self.executor
                .connector
                .structurally_denied("169.254.169.254", 80, "GET");
        vec![
            EnforcementBoundary {
                name: "network-floor",
                state: if network_floor {
                    EnforcementState::Active
                } else {
                    EnforcementState::Absent
                },
                detail: "link-local, loopback, and private ranges before policy".to_owned(),
            },
            EnforcementBoundary {
                name: "tls-termination",
                state: if self.executor.connector.ca_certificate_pem().is_some() {
                    EnforcementState::Active
                } else {
                    EnforcementState::Absent
                },
                detail: "per-request method and path authorization".to_owned(),
            },
            EnforcementBoundary {
                name: "operator-gate",
                state: EnforcementState::Active,
                detail: format!("authority={}", self.gate_authority),
            },
            EnforcementBoundary {
                name: "provenance",
                // `gate-context` renders provenance at every gate but adds no
                // minimum-rank violation, so it informs a decision without
                // constraining one. Reporting that as active would overstate it.
                state: match self.kernel.provenance_mode {
                    ProvenanceMode::Floor => EnforcementState::Active,
                    ProvenanceMode::GateContext => EnforcementState::Advisory,
                },
                detail: match self.kernel.provenance_mode {
                    ProvenanceMode::Floor => "floor: rank shortfall escalates".to_owned(),
                    ProvenanceMode::GateContext => {
                        "gate-context: minimum rank not enforced".to_owned()
                    }
                },
            },
            EnforcementBoundary {
                name: "audit-chain",
                state: if self.audit.is_durable() {
                    EnforcementState::Active
                } else {
                    EnforcementState::Absent
                },
                detail: "signed hash chain with terminal seal".to_owned(),
            },
        ]
    }

    fn record_enforcement_state(&mut self, phase: &'static str) -> Result<(), String> {
        self.record_enforcement_state_with(phase, Vec::new())
    }

    fn record_enforcement_state_with(
        &mut self,
        phase: &'static str,
        mut extra: Vec<EnforcementBoundary>,
    ) -> Result<(), String> {
        let mut boundaries = self.enforcement_boundaries();
        boundaries.append(&mut extra);
        self.audit
            .record_enforcement_state(EnforcementStateEvent { phase, boundaries })
    }

    fn begin_egress(
        &mut self,
        request: EgressRequest,
        origin: Option<ReportedOrigin>,
        cancelled: &Arc<AtomicBool>,
    ) -> Result<Begun<EgressAuthorizationTarget>, BrokerDecision> {
        if cancelled.load(Ordering::Acquire) {
            return Err(BrokerDecision::denied());
        }
        let structurally_denied = self.executor.connector.structurally_denied(
            &request.host,
            request.port,
            &request.method,
        );
        let authorization_target = EgressAuthorizationTarget {
            host: request.host.clone(),
            port: request.port,
        };
        let asserted = Asserted {
            class: ActionClass::Egress,
            target: Target::Network {
                host: request.host,
                port: request.port,
                method: request.method,
                path: String::new(),
            },
            declared_cost: None,
        };
        // A triage run refuses everything its scope and admitted hosts do not
        // cover, without a prompt: a browser cannot wait on one per request.
        let out_of_scope = self.kernel.session.facts.intent.scope.is_some()
            && !self
                .kernel
                .policy
                .allowed_hosts
                .contains(&authorization_target.host)
            && !in_scope(
                &self.kernel.session.facts.intent,
                &authorization_target.host,
                authorization_target.port,
            );
        if structurally_denied || out_of_scope {
            let rule = if structurally_denied {
                "kernel:forbidden-network"
            } else {
                "kernel:out-of-scope"
            };
            let _ =
                self.kernel
                    .reject_structural("egress", "vertex", asserted, rule, &mut self.audit);
            return Err(BrokerDecision::denied());
        }
        self.kernel
            .begin_reported(
                "egress",
                "vertex",
                asserted,
                RelayFacts {
                    origin,
                    ..RelayFacts::default()
                },
                &mut self.audit,
            )
            .map(|pending| Begun::new(pending, authorization_target))
            .map_err(|_| BrokerDecision::denied())
    }

    fn finish_egress(
        &mut self,
        begun: Begun<EgressAuthorizationTarget>,
        outcome: Option<GateOutcome>,
        cancelled: &Arc<AtomicBool>,
    ) -> BrokerDecision {
        let mut executor = CancellableExecutor {
            inner: &mut self.executor,
            cancelled,
        };
        match self.kernel.finish(
            begun.pending,
            outcome,
            &mut self.injector,
            &mut executor,
            &mut self.audit,
        ) {
            Ok(processed) => BrokerDecision {
                response: EGRESS_ALLOWED,
                session: Some(processed.output),
                authorization_target: Some(begun.context),
                action_id: Some(processed.action_id),
            },
            Err(KernelError::Execution(_)) => {
                self.execution_failures += 1;
                BrokerDecision {
                    response: EGRESS_EXECUTION_FAILED,
                    session: None,
                    authorization_target: None,
                    action_id: None,
                }
            }
            Err(_) => BrokerDecision::denied(),
        }
    }

    #[cfg(test)]
    fn authorize_http(
        &mut self,
        target: &EgressAuthorizationTarget,
        method: &str,
        path: &str,
        body_digest: [u8; 32],
        model_request: Option<ModelBudgetRequest>,
    ) -> Result<Option<ModelReservationId>, String> {
        let cancelled = Arc::new(AtomicBool::new(false));
        self.run_locked(
            &cancelled,
            |state| {
                state.begin_http(
                    target,
                    method,
                    path,
                    body_digest,
                    model_request,
                    FlowVerdict::NotChecked,
                    None,
                )
            },
            Self::finish_http,
        )
        .map(|authorization| authorization.model_reservation)
    }

    #[allow(clippy::too_many_arguments)]
    fn begin_http(
        &mut self,
        target: &EgressAuthorizationTarget,
        method: &str,
        path: &str,
        body_digest: [u8; 32],
        model_request: Option<ModelBudgetRequest>,
        flow: FlowVerdict,
        origin: Option<ReportedOrigin>,
    ) -> Result<Begun<HttpContext>, Result<HttpAuthorization, String>> {
        let approved_push_transport = self.is_push_report(&target.host, method, path);
        let protected_effect = (target.host == "api.github.com"
            && method == "POST"
            && path.starts_with("/repos/")
            && path
                .split('?')
                .next()
                .is_some_and(|path| path.ends_with("/pulls")))
            || (method == "POST"
                && path
                    .split('?')
                    .next()
                    .is_some_and(|path| path.ends_with("/git-receive-pack")));
        let mut consumed_effect_permit = approved_push_transport;
        if protected_effect {
            let request_path = path.split('?').next().unwrap_or(path);
            if !self.consume_effect_permit(target, request_path, &body_digest) {
                return Err(Err(
                    "credential-bearing effect has no exact one-use action permit".to_owned(),
                ));
            }
            consumed_effect_permit = true;
        }
        let model_endpoint = target.host == self.kernel.policy.model_host;
        let model_request = match (model_endpoint, model_request) {
            (true, Some(request)) => self
                .model_budget
                .can_reserve(&request)
                .map(|()| Some(request)),
            (true, None) => Err("model endpoint is missing trusted budget metadata".to_owned()),
            (false, Some(_)) => Err("non-model endpoint supplied model budget metadata".to_owned()),
            (false, None) => Ok(None),
        };
        let context = HttpContext {
            model_request,
            consumed_effect_permit,
        };
        let asserted = Asserted {
            class: ActionClass::Egress,
            target: Target::Network {
                host: target.host.clone(),
                port: target.port,
                method: method.to_owned(),
                path: path.to_owned(),
            },
            declared_cost: None,
        };
        self.set_http_policy_facts(&context);
        let begun = self.kernel.begin_reported(
            "egress",
            "vertex",
            asserted,
            RelayFacts {
                flow,
                origin,
                ..RelayFacts::default()
            },
            &mut self.audit,
        );
        self.set_http_policy_facts(&HttpContext::default());
        let hard_deny = context.model_request.is_err();
        begun
            .map(|pending| Begun {
                hard_deny,
                ..Begun::new(pending, context)
            })
            .map_err(|error| Err(error.to_string()))
    }

    /// The broker policy reads per-request facts; `finish` re-derives the
    /// action's reasons, so it must see the same facts `begin` did.
    fn set_http_policy_facts(&mut self, context: &HttpContext) {
        self.kernel.policy.model_budget_denied = context.model_request.is_err();
        self.kernel.policy.effect_permit_consumed = context.consumed_effect_permit;
    }

    fn finish_http(
        &mut self,
        begun: Begun<HttpContext>,
        outcome: Option<GateOutcome>,
    ) -> Result<HttpAuthorization, String> {
        let Begun {
            pending, context, ..
        } = begun;
        self.set_http_policy_facts(&context);
        let processed = self.kernel.finish(
            pending,
            outcome,
            &mut EgressPermitInjector,
            &mut EgressPermitExecutor,
            &mut self.audit,
        );
        self.set_http_policy_facts(&HttpContext::default());
        let processed = processed.map_err(|error| error.to_string())?;
        let request = context.model_request?;
        let model_reservation = match request
            .map(|request| self.model_budget.reserve(processed.action_id, request))
            .transpose()
        {
            Ok(reservation) => reservation,
            Err(error) => {
                self.kernel
                    .revoke_egress_grant_issued_by(processed.action_id);
                return Err(error);
            }
        };
        Ok(HttpAuthorization {
            action_id: processed.action_id,
            model_reservation,
        })
    }

    /// Authorizes one Git action and returns the audit correlation id the relay
    /// reports its outcome against, or `None` when the action is refused.
    #[cfg(test)]
    fn authorize_git(&mut self, asserted: Asserted, body_digest: [u8; 32]) -> Option<u64> {
        let cancelled = Arc::new(AtomicBool::new(false));
        self.run_locked(
            &cancelled,
            |state| state.begin_git(asserted, body_digest, None, &cancelled),
            |state, begun, outcome| state.finish_git(begun, outcome, &cancelled),
        )
    }

    fn begin_git(
        &mut self,
        asserted: Asserted,
        body_digest: [u8; 32],
        origin: Option<ReportedOrigin>,
        cancelled: &Arc<AtomicBool>,
    ) -> Result<Begun<GitContext>, Option<u64>> {
        if cancelled.load(Ordering::Acquire) {
            return Err(None);
        }
        let remote = match &asserted.target {
            Target::Git { remote, .. } => git_remote_scope(remote),
            _ => None,
        };
        let integrity = match &asserted.target {
            Target::Git {
                manifest_diff: Some(diff),
                ..
            } => IntegrityVerdict::of_diff(diff, &self.model_output),
            _ => IntegrityVerdict::NotChecked,
        };
        self.kernel
            .begin_reported(
                "git",
                "vertex",
                asserted,
                RelayFacts {
                    origin,
                    integrity,
                    ..RelayFacts::default()
                },
                &mut self.audit,
            )
            .map(|pending| {
                Begun::new(
                    pending,
                    GitContext {
                        remote,
                        body_digest,
                    },
                )
            })
            .map_err(|_| None)
    }

    fn finish_git(
        &mut self,
        begun: Begun<GitContext>,
        outcome: Option<GateOutcome>,
        cancelled: &Arc<AtomicBool>,
    ) -> Option<u64> {
        let Begun {
            pending, context, ..
        } = begun;
        let mut executor = CancellableExecutor {
            inner: &mut EgressPermitExecutor,
            cancelled,
        };
        let processed = self
            .kernel
            .finish(
                pending,
                outcome,
                &mut EgressPermitInjector,
                &mut executor,
                &mut self.audit,
            )
            .ok()?;
        // Bounded: a relay that authorizes without ever reporting cannot grow this
        // set without bound, and the oldest unreported push is the one least likely
        // to still be in flight.
        while self.unreported_pushes.len() >= MAX_UNREPORTED_PUSHES {
            let Some(oldest) = self.unreported_pushes.iter().next().copied() else {
                break;
            };
            self.record_push_outcome(oldest, "unreported");
        }
        if cancelled.load(Ordering::Acquire) {
            return None;
        }
        self.unreported_pushes.insert(processed.action_id);
        if let Some(remote) = context.remote {
            self.pushed_remotes.insert(remote.clone());
            self.remember_effect_permit(
                processed.action_id,
                EffectPermit::GitPush {
                    host: remote.0,
                    path: format!("{}/git-receive-pack", remote.1.trim_end_matches('/')),
                    body_digest: context.body_digest,
                },
            );
        }
        Some(processed.action_id)
    }

    /// Records the relay's claim about an authorized push. Returns whether the
    /// report named an action this kernel authorized and has not yet closed.
    fn accept_git_report(&mut self, report: &GitOutcomeReport) -> bool {
        if !self.unreported_pushes.remove(&report.action_id) {
            return false;
        }
        self.record_push_outcome(
            report.action_id,
            if report.completed {
                "completed"
            } else {
                "failed"
            },
        );
        true
    }

    fn record_push_outcome(&mut self, action_id: u64, outcome: &str) {
        self.unreported_pushes.remove(&action_id);
        self.revoke_effect_permits(action_id);
        let _ = self.audit.record_reported_outcome(ReportedOutcomeEvent {
            action_id,
            reporter: "git-relay",
            outcome: outcome.to_owned(),
        });
    }

    /// Closes every push the relay authorized but never reported, so an
    /// authorization is never the last word on whether a push landed.
    fn close_unreported_pushes(&mut self) {
        for action_id in std::mem::take(&mut self.unreported_pushes) {
            self.record_push_outcome(action_id, "unreported");
        }
    }

    #[cfg(test)]
    fn authorize_external(&mut self, asserted: Asserted) -> u8 {
        let cancelled = Arc::new(AtomicBool::new(false));
        self.run_locked(
            &cancelled,
            |state| state.begin_external(asserted, None, &cancelled),
            |state, begun, outcome| state.finish_external(begun, outcome, &cancelled),
        )
        .0
    }

    fn begin_external(
        &mut self,
        asserted: Asserted,
        origin: Option<ReportedOrigin>,
        cancelled: &Arc<AtomicBool>,
    ) -> Result<Begun<Option<EffectPermit>>, (u8, Option<u64>)> {
        if cancelled.load(Ordering::Acquire) {
            return Err((EXTERNAL_DENIED, None));
        }
        let permit = github_pull_request_permit(&asserted);
        self.kernel
            .begin_reported(
                "external",
                "vertex",
                asserted,
                RelayFacts {
                    origin,
                    ..RelayFacts::default()
                },
                &mut self.audit,
            )
            .map(|pending| Begun::new(pending, permit))
            .map_err(|_| (EXTERNAL_DENIED, None))
    }

    fn finish_external(
        &mut self,
        begun: Begun<Option<EffectPermit>>,
        outcome: Option<GateOutcome>,
        cancelled: &Arc<AtomicBool>,
    ) -> (u8, Option<u64>) {
        let mut executor = CancellableExecutor {
            inner: &mut EgressPermitExecutor,
            cancelled,
        };
        match self.kernel.finish(
            begun.pending,
            outcome,
            &mut EgressPermitInjector,
            &mut executor,
            &mut self.audit,
        ) {
            Ok(processed) if !cancelled.load(Ordering::Acquire) => match begun.context {
                Some(permit) => {
                    self.remember_effect_permit(processed.action_id, permit);
                    (EXTERNAL_ALLOWED, Some(processed.action_id))
                }
                None => (EXTERNAL_DENIED, None),
            },
            Ok(_) | Err(_) => (EXTERNAL_DENIED, None),
        }
    }

    fn mark_model_send_attempted(
        &mut self,
        reservation_id: ModelReservationId,
    ) -> Result<(), String> {
        self.model_budget.mark_send_attempted(reservation_id)
    }

    fn resolve_model_reservation(
        &mut self,
        reservation_id: ModelReservationId,
        resolution: ModelReservationResolution,
    ) -> Result<(), String> {
        self.model_budget
            .resolve(reservation_id, resolution, &mut self.audit)
    }

    fn close_model_reservations(&mut self) -> Result<(), String> {
        for reservation_id in self.model_budget.unresolved_ids() {
            self.resolve_model_reservation(
                reservation_id,
                ModelReservationResolution::CommittedConservative,
            )?;
        }
        Ok(())
    }

    fn observe_egress_response(
        &mut self,
        host: String,
        method: &str,
        path: String,
    ) -> Result<(), String> {
        // A model response is the harness's own turn, not content the harness went
        // and fetched, so it does not move the floor. Which host that is depends on
        // the run's provider, and the test has to be the same one authorization
        // used: an approved control-plane call on a model host does ingest content.
        if host == self.kernel.policy.model_host && model_path_allowed(&host, method, &path) {
            return Ok(());
        }
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| error.to_string())?
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX);
        // A push's report-status is the remote answering a push the operator
        // approved, not a page the harness went and fetched. It is still the
        // remote's own text, so it ranks as operator data rather than not
        // counting at all: the floor records that the remote spoke, and every
        // action that needs rank 2 still proceeds without a second approval.
        let rank = if self.is_push_report(&host, method, &path) {
            Rank::OperatorData
        } else {
            Rank::UntrustedContent
        };
        let result = ClassifiedResult::new(rank, SourceRef::Host { host, path });
        self.kernel
            .observe_result(result, timestamp_ms, &mut self.audit)
            .map_err(|error| error.to_string())
    }

    /// Whether this response is a smart-HTTP push exchange with a remote this
    /// session already authorized a push to.
    fn is_push_report(&self, host: &str, method: &str, path: &str) -> bool {
        let path = path.split('?').next().unwrap_or(path);
        let Some((repository, endpoint)) = ["/git-receive-pack", "/info/refs"]
            .into_iter()
            .find_map(|endpoint| path.strip_suffix(endpoint).map(|left| (left, endpoint)))
        else {
            return false;
        };
        matches!(
            (method, endpoint),
            ("POST", "/git-receive-pack") | ("GET", "/info/refs")
        ) && self
            .pushed_remotes
            .contains(&(host.to_owned(), repository.to_owned()))
    }
}

/// Splits an HTTPS Git remote into the host and repository path that a
/// smart-HTTP request for it carries.
fn git_remote_scope(remote: &str) -> Option<(String, String)> {
    let (host, path) = remote.strip_prefix("https://")?.split_once('/')?;
    let path = path.trim_end_matches('/');
    (!host.is_empty() && !path.is_empty()).then(|| (host.to_owned(), format!("/{path}")))
}

fn github_pull_request_permit(asserted: &Asserted) -> Option<EffectPermit> {
    let Target::External {
        service,
        recipient,
        operation,
        detail,
    } = &asserted.target
    else {
        return None;
    };
    if asserted.class != ActionClass::PullRequest
        || service != "github"
        || operation != "create-pull-request"
        || !valid_github_repository(recipient)
    {
        return None;
    }
    let detail: serde_json::Value = serde_json::from_str(detail).ok()?;
    let text = |name: &str| detail.get(name)?.as_str().map(str::to_owned);
    let body = serde_json::to_vec(&serde_json::json!({
        "title": text("title")?,
        "head": text("head")?,
        "base": text("base")?,
        "body": text("body")?,
    }))
    .ok()?;
    Some(EffectPermit::GithubPullRequest {
        path: format!("/repos/{recipient}/pulls"),
        body_digest: sha256(&body),
    })
}

fn valid_github_repository(recipient: &str) -> bool {
    let Some((owner, repository)) = recipient.split_once('/') else {
        return false;
    };
    !owner.is_empty()
        && !repository.is_empty()
        && !repository.contains('/')
        && [owner, repository].into_iter().all(|component| {
            component.len() <= 100
                && component != "."
                && component != ".."
                && component
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        })
}

fn sha256(value: &[u8]) -> [u8; 32] {
    let hash = digest(&SHA256, value);
    let mut bytes = [0_u8; 32];
    bytes.copy_from_slice(hash.as_ref());
    bytes
}

#[derive(Clone)]
struct EgressAuthorizationTarget {
    host: String,
    port: u16,
}

struct HttpAuthorization {
    action_id: u64,
    model_reservation: Option<ModelReservationId>,
}

struct BrokerDecision {
    response: u8,
    session: Option<Box<dyn EgressSession>>,
    authorization_target: Option<EgressAuthorizationTarget>,
    action_id: Option<u64>,
}

impl BrokerDecision {
    const fn denied() -> Self {
        Self {
            response: EGRESS_DENIED,
            session: None,
            authorization_target: None,
            action_id: None,
        }
    }
}

const SEND_HANDOFF_PENDING: u8 = 0;
const SEND_HANDOFF_CANCELLED: u8 = 1;
const SEND_HANDOFF_COMMITTED: u8 = 2;

/// One atomic winner between origin loss and the first external operation for
/// an exact HTTP request.
struct NetworkSendHandoff {
    state: AtomicU8,
}

impl NetworkSendHandoff {
    const fn new() -> Self {
        Self {
            state: AtomicU8::new(SEND_HANDOFF_PENDING),
        }
    }

    fn cancel(&self) {
        let _ = self.state.compare_exchange(
            SEND_HANDOFF_PENDING,
            SEND_HANDOFF_CANCELLED,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }

    fn commit(&self) -> Result<(), String> {
        match self.state.compare_exchange(
            SEND_HANDOFF_PENDING,
            SEND_HANDOFF_COMMITTED,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => Ok(()),
            Err(SEND_HANDOFF_CANCELLED) => {
                Err("origin disconnected before the external request".to_owned())
            }
            Err(SEND_HANDOFF_COMMITTED) => {
                Err("external request authorization was already committed".to_owned())
            }
            Err(_) => Err("external request handoff is invalid".to_owned()),
        }
    }

    fn response_recorded(&self, cancelled: &AtomicBool) -> Result<(), String> {
        self.state
            .compare_exchange(
                SEND_HANDOFF_COMMITTED,
                SEND_HANDOFF_PENDING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map_err(|_| "external response has no committed request".to_owned())?;
        if cancelled.load(Ordering::Acquire) {
            self.cancel();
            Err("origin disconnected before response delivery".to_owned())
        } else {
            Ok(())
        }
    }

    fn is_pending(&self) -> bool {
        self.state.load(Ordering::Acquire) == SEND_HANDOFF_PENDING
    }
}

struct BrokerRequestAuthorizer {
    state: Arc<Mutex<BrokerState>>,
    target: EgressAuthorizationTarget,
    cancelled: Arc<AtomicBool>,
    send_handoff: Arc<NetworkSendHandoff>,
    authorized_request: Option<(String, String)>,
    /// The action whose reusable grant must be withdrawn unless its exact
    /// request produces a response that is ready for delivery to the origin.
    uncommitted_grant_action: Option<u64>,
    model_reservation: Option<ModelReservationId>,
    last_model_reservation: Option<ModelReservationId>,
    /// Verdict on the payload of the request about to be authorized.
    flow: FlowVerdict,
    /// Guest-reported origin of the connection carrying these requests.
    origin: Option<ReportedOrigin>,
    /// Blocks of the model request about to be authorized.
    context: Vec<ContextBlock>,
    /// The action that authorized the latest model request.
    model_action: Option<u64>,
}

/// How long a model request waits for in-flight reservations to settle.
const MODEL_BUDGET_WAIT: Duration = Duration::from_secs(30);

impl BrokerRequestAuthorizer {
    /// Waits, outside the state lock, while this request would fit once the
    /// reservations already in flight settle. A harness sends small helper
    /// requests beside its main one; refusing the main request only because a
    /// helper had not settled yet surfaced as a spurious API error. A request
    /// that cannot fit even after every reservation settles is not delayed,
    /// and the authorization that follows still enforces the ceiling.
    fn await_model_budget(&self, request: &ModelBudgetRequest) {
        let deadline = Instant::now() + MODEL_BUDGET_WAIT;
        while Instant::now() < deadline && !self.cancelled.load(Ordering::Acquire) {
            let Ok(state) = self.state.lock() else {
                return;
            };
            if state.model_budget.can_reserve(request).is_ok()
                || state.model_budget.unresolved_ids().is_empty()
            {
                return;
            }
            drop(state);
            thread::sleep(Duration::from_millis(50));
        }
    }

    fn close_open_model_reservation(&mut self) -> Result<(), String> {
        if self.model_reservation.is_none() {
            return Ok(());
        }
        self.resolve_model_reservation(ModelReservationResolution::CommittedConservative)
    }

    fn revoke_uncommitted_grant(&mut self) {
        let Some(action_id) = self.uncommitted_grant_action.take() else {
            return;
        };
        if let Ok(mut state) = self.state.lock() {
            state.kernel.revoke_egress_grant_issued_by(action_id);
        }
    }
}

impl Drop for BrokerRequestAuthorizer {
    fn drop(&mut self) {
        self.revoke_uncommitted_grant();
    }
}

impl EgressRequestAuthorizer for BrokerRequestAuthorizer {
    fn observe_model_context(&mut self, response: bool, blocks: Vec<ContextBlock>) {
        if !response {
            self.context = blocks;
        } else if let (Some(action_id), Ok(mut state)) = (self.model_action, self.state.lock()) {
            state.record_context(action_id, true, blocks);
        }
    }

    fn observe_model_output(&mut self, arguments: &[String]) {
        if let Ok(mut state) = self.state.lock() {
            for argument in arguments {
                state.model_output.add(argument);
            }
        }
    }

    fn observe_payload(&mut self, path: &str, body: &[u8]) {
        // Clone the immutable policy out of the lock; scanning a large body
        // must not stall other traffic.
        let policy = self.state.lock().ok().and_then(|state| {
            state
                .payload
                .clone()
                .map(|policy| (policy, state.kernel.policy.model_host.clone()))
        });
        self.flow = policy.map_or(FlowVerdict::NotChecked, |(policy, model_host)| {
            policy.judge(&self.target.host, path, body, &model_host)
        });
    }

    fn authorize(
        &mut self,
        method: &str,
        path: &str,
        body_digest: [u8; 32],
        model_budget: Option<ModelBudgetRequest>,
    ) -> Result<(), String> {
        if self.cancelled.load(Ordering::Acquire) || !self.send_handoff.is_pending() {
            return Err("origin is unavailable for a new external request".to_owned());
        }
        if self.authorized_request.is_some() {
            return Err("egress session already authorized a request".to_owned());
        }
        if self.model_reservation.is_some() {
            return Err("previous model reservation has no terminal outcome".to_owned());
        }
        if let Some(request) = &model_budget {
            self.await_model_budget(request);
        }
        let target = &self.target;
        let flow = std::mem::replace(&mut self.flow, FlowVerdict::NotChecked);
        let origin = self.origin.clone();
        let authorization = run_unlocked(
            &self.state,
            &self.cancelled,
            || Ok(()),
            |state| {
                state.begin_http(
                    target,
                    method,
                    path,
                    body_digest,
                    model_budget,
                    flow,
                    origin,
                )
            },
            BrokerState::finish_http,
        )??;
        self.model_reservation = authorization.model_reservation;
        self.uncommitted_grant_action = Some(authorization.action_id);
        let context = std::mem::take(&mut self.context);
        if self.model_reservation.is_some() {
            self.model_action = Some(authorization.action_id);
            if let Ok(mut state) = self.state.lock() {
                state.record_context(authorization.action_id, false, context);
            }
        }
        self.authorized_request = Some((method.to_owned(), path.to_owned()));
        Ok(())
    }

    fn commit_request_send(&mut self) -> Result<(), String> {
        if self.authorized_request.is_none() {
            return Err("external send has no authorized request".to_owned());
        }
        self.send_handoff.commit()
    }

    fn record_response(&mut self) -> Result<(), String> {
        if self.cancelled.load(Ordering::Acquire) {
            return Err("origin disconnected before response delivery".to_owned());
        }
        let (method, path) = self
            .authorized_request
            .take()
            .ok_or_else(|| "egress response has no authorized request".to_owned())?;
        self.state
            .lock()
            .map_err(|_| "kernel broker state is unavailable".to_owned())?
            .observe_egress_response(self.target.host.clone(), &method, path)?;
        self.send_handoff.response_recorded(&self.cancelled)?;
        // Authorization and the cancellation handoff precede DNS/TCP/TLS and
        // request forwarding. Keep a newly minted reusable grant provisional
        // until trusted transport has an upstream response ready for the live
        // origin. Any setup or forwarding failure then drops this authorizer
        // and revokes only the grant created by this exact action.
        self.uncommitted_grant_action = None;
        Ok(())
    }

    fn mark_model_request_send_attempted(&mut self) -> Result<(), String> {
        let reservation_id = self
            .model_reservation
            .ok_or_else(|| "model request has no budget reservation".to_owned())?;
        self.state
            .lock()
            .map_err(|_| "kernel broker state is unavailable".to_owned())?
            .mark_model_send_attempted(reservation_id)
    }

    fn resolve_model_reservation(
        &mut self,
        resolution: ModelReservationResolution,
    ) -> Result<(), String> {
        let reservation_id = self
            .model_reservation
            .or(self.last_model_reservation)
            .ok_or_else(|| "model response has no budget reservation".to_owned())?;
        let result = self
            .state
            .lock()
            .map_err(|_| "kernel broker state is unavailable".to_owned())?
            .resolve_model_reservation(reservation_id, resolution);
        if result.is_ok() {
            self.model_reservation = None;
            self.last_model_reservation = Some(reservation_id);
        }
        result
    }
}

struct EgressRequest {
    host: String,
    port: u16,
    method: String,
}

/// Polls an accepted relay descriptor without consuming application bytes.
///
/// A clone refers to the same connected Unix socket, so `POLLHUP` and
/// `POLLERR` provide caller liveness while the authorization thread is blocked
/// in trusted policy or operator input. A relay write-side close means no more
/// complete requests can originate on this connection and cancels authority
/// that has not crossed the external-send handoff. The stop flag bounds
/// teardown by one short poll interval.
struct PeerMonitor {
    cancelled: Arc<AtomicBool>,
    send_handoff: Arc<NetworkSendHandoff>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

/// Returns whether the peer's write side reached EOF without consuming any
/// application data. On Unix, FIN can be reported as readable EOF without a
/// simultaneous `POLLHUP`; relying on HUP alone leaves a cancelled approval
/// live. `MSG_PEEK` distinguishes that EOF from real bytes waiting for the
/// trusted bridge, and `MSG_DONTWAIT` keeps the monitor from racing the bridge
/// into a blocking read.
fn peer_write_side_ended(peer: &UnixStream) -> Result<bool, Errno> {
    let mut byte = [0_u8; 1];
    match recv(
        peer.as_raw_fd(),
        &mut byte,
        MsgFlags::MSG_PEEK | MsgFlags::MSG_DONTWAIT,
    ) {
        Ok(0) => Ok(true),
        Ok(_) | Err(Errno::EAGAIN | Errno::EINTR) => Ok(false),
        Err(error) => Err(error),
    }
}

impl PeerMonitor {
    fn start(stream: &UnixStream, shutdown: &Arc<AtomicBool>) -> Result<Self, String> {
        let peer = stream.try_clone().map_err(|error| error.to_string())?;
        let cancelled = Arc::new(AtomicBool::new(false));
        let send_handoff = Arc::new(NetworkSendHandoff::new());
        let stop = Arc::new(AtomicBool::new(false));
        let worker_cancelled = Arc::clone(&cancelled);
        let worker_handoff = Arc::clone(&send_handoff);
        let worker_stop = Arc::clone(&stop);
        let worker_shutdown = Arc::clone(shutdown);
        let worker = thread::Builder::new()
            .name("keel-broker-peer-monitor".to_owned())
            .spawn(move || {
                while !worker_stop.load(Ordering::Acquire) {
                    if worker_shutdown.load(Ordering::Acquire) {
                        worker_cancelled.store(true, Ordering::Release);
                        worker_handoff.cancel();
                        let _ = peer.shutdown(std::net::Shutdown::Both);
                        break;
                    }
                    let mut descriptors = [PollFd::new(peer.as_fd(), PollFlags::POLLIN)];
                    match poll(&mut descriptors, 50_u16) {
                        Ok(_) => {
                            let events = descriptors[0].revents().unwrap_or_else(PollFlags::empty);
                            let ended = events.intersects(
                                PollFlags::POLLHUP | PollFlags::POLLERR | PollFlags::POLLNVAL,
                            ) || (events.contains(PollFlags::POLLIN)
                                && peer_write_side_ended(&peer).unwrap_or(true));
                            if ended {
                                worker_cancelled.store(true, Ordering::Release);
                                worker_handoff.cancel();
                                break;
                            }
                            // Readable application bytes belong to the bridge;
                            // the EOF probe above peeks and never consumes them.
                            if events.contains(PollFlags::POLLIN) {
                                thread::sleep(Duration::from_millis(50));
                            }
                        }
                        Err(Errno::EINTR) => {}
                        Err(_) => {
                            worker_cancelled.store(true, Ordering::Release);
                            worker_handoff.cancel();
                            break;
                        }
                    }
                }
            })
            .map_err(|error| error.to_string())?;
        Ok(Self {
            cancelled,
            send_handoff,
            stop,
            worker: Some(worker),
        })
    }

    /// Refreshes cancellation at a protocol handoff, closing the small window
    /// between the monitor's bounded poll iterations.
    fn refresh_origin_state(&self, stream: &UnixStream) -> bool {
        if self.cancelled.load(Ordering::Acquire) {
            return false;
        }
        if peer_write_side_ended(stream).unwrap_or(true) {
            self.cancelled.store(true, Ordering::Release);
            self.send_handoff.cancel();
            return false;
        }
        true
    }
}

impl Drop for PeerMonitor {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

enum BrokerRequest {
    Egress(EgressRequest),
    Git(Asserted, [u8; 32]),
    GitReport(GitOutcomeReport),
    External(Asserted),
}

/// One relay claim about an authorized push. Untrusted: the kernel checks only
/// that the action was authorized here and has not been reported yet.
struct GitOutcomeReport {
    action_id: u64,
    completed: bool,
}

#[allow(clippy::too_many_arguments)]
fn broker_loop(
    listener: &UnixListener,
    state: &Arc<Mutex<BrokerState>>,
    diagnostics: Option<&Path>,
    shutdown_boundaries: &Mutex<Vec<EnforcementBoundary>>,
    stop: &Arc<AtomicBool>,
) -> Result<BrokerReport, String> {
    let mut bridges = Vec::new();
    while !stop.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((stream, _)) => {
                if bridges.len() >= MAX_BROKER_CLIENTS {
                    let mut stream = stream;
                    let _ = stream.write_all(&[EGRESS_DENIED]);
                    let _ = stream.flush();
                } else {
                    let state = Arc::clone(state);
                    let diagnostics = diagnostics.map(Path::to_path_buf);
                    let shutdown = Arc::clone(stop);
                    let client = thread::Builder::new()
                        .name("keel-broker-client".to_owned())
                        .spawn(move || {
                            if let Ok(Some(bridge)) = handle_broker_connection(
                                stream,
                                &state,
                                diagnostics.as_deref(),
                                &shutdown,
                            ) {
                                let _ = bridge.join();
                            }
                        })
                        .map_err(|error| error.to_string())?;
                    bridges.push(client);
                }
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(20));
            }
            Err(error) => return Err(error.to_string()),
        }
        let mut index = 0;
        while index < bridges.len() {
            if bridges[index].is_finished() {
                let bridge = bridges.swap_remove(index);
                let _ = bridge.join();
            } else {
                index += 1;
            }
        }
    }
    for bridge in bridges {
        let _ = bridge.join();
    }
    let mut state = state
        .lock()
        .map_err(|_| "kernel broker state is unavailable".to_owned())?;
    state.close_unreported_pushes();
    state.close_model_reservations()?;
    let extra = shutdown_boundaries
        .lock()
        .map_err(|_| "kernel shutdown boundaries are unavailable".to_owned())?
        .clone();
    state.record_enforcement_state_with("shutdown", extra)?;
    let report = BrokerReport {
        audit_events: state.audit.events,
        denied_actions: u64::from(state.kernel.session().denied_actions()),
        execution_failures: state.execution_failures,
        session_facts: state.kernel.session().facts().clone(),
    };
    state.audit.shutdown()?;
    Ok(report)
}

#[allow(clippy::too_many_lines)]
fn handle_broker_connection(
    mut stream: UnixStream,
    state: &Arc<Mutex<BrokerState>>,
    diagnostics: Option<&Path>,
    shutdown: &Arc<AtomicBool>,
) -> Result<Option<JoinHandle<()>>, String> {
    // Sockets accepted from a non-blocking listener inherit O_NONBLOCK, and a
    // read timeout does not clear it. The broker protocol and the trusted proxy
    // both read this stream expecting to block, so the flag is cleared first.
    stream
        .set_nonblocking(false)
        .map_err(|error| error.to_string())?;
    stream
        .set_read_timeout(Some(BROKER_HANDSHAKE_TIMEOUT))
        .map_err(|error| error.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|error| error.to_string())?;
    let Ok((origin, request)) = read_broker_request(&mut stream) else {
        stream
            .write_all(&[EGRESS_DENIED])
            .map_err(|error| error.to_string())?;
        stream.flush().map_err(|error| error.to_string())?;
        return Ok(None);
    };
    if let BrokerRequest::Git(asserted, body_digest) = request {
        let monitor = PeerMonitor::start(&stream, shutdown)?;
        let cancelled = &monitor.cancelled;
        let authorized = run_unlocked(
            state,
            cancelled,
            || Ok(()),
            |state| state.begin_git(asserted, body_digest, origin, cancelled),
            |state, begun, outcome| state.finish_git(begun, outcome, cancelled),
        )
        .unwrap_or(None);
        // The correlation id follows an allow so the relay can report back what
        // became of the push it was just authorized to forward.
        let mut response = vec![GIT_DENIED];
        if let Some(action_id) = authorized {
            response = vec![GIT_ALLOWED];
            response.extend_from_slice(&action_id.to_be_bytes());
        }
        if let Err(error) = stream.write_all(&response).and_then(|()| stream.flush()) {
            if let Some(action_id) = authorized
                && let Ok(mut state) = state.lock()
            {
                state.record_push_outcome(action_id, "unreported");
            }
            return Err(error.to_string());
        }
        return Ok(None);
    }
    if let BrokerRequest::GitReport(report) = request {
        let accepted = state
            .lock()
            .is_ok_and(|mut state| state.accept_git_report(&report));
        stream
            .write_all(&[if accepted { GIT_ALLOWED } else { GIT_DENIED }])
            .map_err(|error| error.to_string())?;
        stream.flush().map_err(|error| error.to_string())?;
        return Ok(None);
    }
    if let BrokerRequest::External(asserted) = request {
        let monitor = PeerMonitor::start(&stream, shutdown)?;
        let cancelled = &monitor.cancelled;
        let (response, permit_action) = run_unlocked(
            state,
            cancelled,
            || Ok(()),
            |state| state.begin_external(asserted, origin, cancelled),
            |state, begun, outcome| state.finish_external(begun, outcome, cancelled),
        )
        .unwrap_or((EXTERNAL_DENIED, None));
        if let Err(error) = stream.write_all(&[response]).and_then(|()| stream.flush()) {
            if let Some(action_id) = permit_action
                && let Ok(mut state) = state.lock()
            {
                state.revoke_effect_permits(action_id);
            }
            return Err(error.to_string());
        }
        return Ok(None);
    }
    let BrokerRequest::Egress(request) = request else {
        unreachable!("Git and external requests return above");
    };
    let monitor = PeerMonitor::start(&stream, shutdown)?;
    if monitor.cancelled.load(Ordering::Acquire) {
        return Ok(None);
    }
    // `P` means this request owns the serialized adjudication slot, or needs
    // no operator at all. Sending it earlier would start the client's
    // five-minute decision clock while another human prompt could still be
    // ahead of it.
    let pending_sent = std::cell::Cell::new(false);
    let send_pending = || -> Result<(), String> {
        (&stream)
            .write_all(&[EGRESS_PENDING])
            .and_then(|()| (&stream).flush())
            .map_err(|error| error.to_string())?;
        pending_sent.set(true);
        Ok(())
    };
    let cancelled = &monitor.cancelled;
    let decision = run_unlocked(
        state,
        cancelled,
        send_pending,
        |state| state.begin_egress(request, origin.clone(), cancelled),
        |state, begun, outcome| state.finish_egress(begun, outcome, cancelled),
    )?;
    if !pending_sent.get() {
        // Refused before adjudication: the protocol still acknowledges first.
        stream
            .write_all(&[EGRESS_PENDING])
            .map_err(|error| error.to_string())?;
    }
    let BrokerDecision {
        response,
        session,
        authorization_target,
        action_id,
    } = decision;
    let delivery = stream.write_all(&[response]).and_then(|()| stream.flush());
    if delivery.is_err() || !monitor.refresh_origin_state(&stream) {
        if let Some(action_id) = action_id
            && let Ok(mut state) = state.lock()
        {
            state.kernel.revoke_egress_grant_issued_by(action_id);
        }
        return delivery.map(|()| None).map_err(|error| error.to_string());
    }
    if let (Some(session), Some(target)) = (session, authorization_target) {
        stream
            .set_read_timeout(None)
            .and_then(|()| stream.set_write_timeout(None))
            .map_err(|error| error.to_string())?;
        let state = Arc::clone(state);
        let diagnostics = diagnostics.map(Path::to_path_buf);
        let endpoint = format!("{}:{}", target.host, target.port);
        let cancelled = Arc::clone(&monitor.cancelled);
        let send_handoff = Arc::clone(&monitor.send_handoff);
        let bridge = thread::Builder::new()
            .name("keel-egress-bridge".to_owned())
            .spawn(move || {
                let _monitor = monitor;
                let mut authorizer = BrokerRequestAuthorizer {
                    state,
                    target,
                    cancelled,
                    send_handoff,
                    authorized_request: None,
                    uncommitted_grant_action: None,
                    model_reservation: None,
                    last_model_reservation: None,
                    flow: FlowVerdict::NotChecked,
                    origin,
                    context: Vec::new(),
                    model_action: None,
                };
                let forward = session.forward(stream, &mut authorizer);
                let close = authorizer.close_open_model_reservation();
                if let Err(error) = forward.and(close) {
                    // The guest only ever sees a dropped connection, so the
                    // trusted reason is recorded for the operator instead.
                    record_egress_failure(diagnostics.as_deref(), &endpoint, &error);
                }
            })
            .map_err(|error| error.to_string())?;
        return Ok(Some(bridge));
    }
    Ok(None)
}

/// Appends one bounded, control-character-free bridge failure line.
fn record_egress_failure(diagnostics: Option<&Path>, endpoint: &str, error: &str) {
    let Some(diagnostics) = diagnostics else {
        return;
    };
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_millis());
    let reason = error
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .take(512)
        .collect::<String>();
    if let Ok(mut file) = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(diagnostics)
    {
        let _ = writeln!(file, "{timestamp} egress {endpoint} failed: {reason}");
    }
}

fn read_broker_request(
    stream: &mut UnixStream,
) -> Result<(Option<ReportedOrigin>, BrokerRequest), String> {
    let mut marker = read_broker_marker(stream)?;
    let mut origin = None;
    if marker == ORIGIN_MAGIC {
        let length = usize::from(read_u16(stream)?);
        if length > MAX_ORIGIN_BYTES {
            return Err("origin frame exceeds its bound".to_owned());
        }
        let mut bytes = vec![0_u8; length];
        stream
            .read_exact(&mut bytes)
            .map_err(|error| error.to_string())?;
        origin = Some(ReportedOrigin::parse(&bytes));
        marker = read_broker_marker(stream)?;
    }
    read_typed_request(stream, &marker).map(|request| (origin, request))
}

fn read_typed_request(stream: &mut UnixStream, marker: &[u8]) -> Result<BrokerRequest, String> {
    if marker == EGRESS_BROKER_MAGIC {
        return read_egress_request(stream).map(BrokerRequest::Egress);
    }
    if marker == GIT_BROKER_MAGIC {
        return read_git_request(stream)
            .map(|(asserted, digest)| BrokerRequest::Git(asserted, digest));
    }
    if marker == GIT_REPORT_MAGIC {
        return read_git_report(stream).map(BrokerRequest::GitReport);
    }
    if marker == EXTERNAL_BROKER_MAGIC {
        return read_external_request(stream).map(BrokerRequest::External);
    }
    Err("invalid broker request marker".to_owned())
}

fn read_broker_marker(stream: &mut UnixStream) -> Result<Vec<u8>, String> {
    let mut marker = Vec::with_capacity(32);
    for _ in 0..32 {
        let mut byte = [0_u8; 1];
        stream
            .read_exact(&mut byte)
            .map_err(|error| error.to_string())?;
        marker.push(byte[0]);
        if byte[0] == 0 {
            return Ok(marker);
        }
    }
    Err("broker request marker exceeds its bound".to_owned())
}

fn read_egress_request(stream: &mut UnixStream) -> Result<EgressRequest, String> {
    let mut length = [0_u8; 2];
    stream
        .read_exact(&mut length)
        .map_err(|error| error.to_string())?;
    let length = usize::from(u16::from_be_bytes(length));
    if !(1..=253).contains(&length) {
        return Err("invalid egress host length".to_owned());
    }
    let mut host = vec![0_u8; length];
    stream
        .read_exact(&mut host)
        .map_err(|error| error.to_string())?;
    let host = String::from_utf8(host).map_err(|error| error.to_string())?;
    validate_dns_name(&host)?;
    let mut port = [0_u8; 2];
    stream
        .read_exact(&mut port)
        .map_err(|error| error.to_string())?;
    let port = u16::from_be_bytes(port);
    if port == 0 {
        return Err("egress port cannot be zero".to_owned());
    }
    let mut method = [0_u8; 1];
    stream
        .read_exact(&mut method)
        .map_err(|error| error.to_string())?;
    let method = match method[0] {
        1 => "TLS",
        2 => "CONNECT",
        3 => "HTTP",
        _ => return Err("invalid egress method".to_owned()),
    };
    Ok(EgressRequest {
        host,
        port,
        method: method.to_owned(),
    })
}

fn read_git_request(stream: &mut UnixStream) -> Result<(Asserted, [u8; 32]), String> {
    const MAX_REMOTE_LENGTH: usize = 4_096;
    const MAX_REFS: usize = 256;
    const MAX_REF_LENGTH: usize = 1_024;
    const MAX_MANIFEST_DIFF: usize = 1024 * 1024;

    let remote = read_bounded_string(stream, MAX_REMOTE_LENGTH, "Git remote")?;
    if remote.chars().any(char::is_control) {
        return Err("Git remote contains control characters".to_owned());
    }
    let ref_count = usize::from(read_u16(stream)?);
    if !(1..=MAX_REFS).contains(&ref_count) {
        return Err("Git ref count is outside its bound".to_owned());
    }
    let mut refs = Vec::with_capacity(ref_count);
    for _ in 0..ref_count {
        let reference = read_bounded_string(stream, MAX_REF_LENGTH, "Git ref")?;
        if !valid_git_ref(&reference) {
            return Err("Git request contains an invalid ref name".to_owned());
        }
        refs.push(reference);
    }
    let mut flags = [0_u8; 3];
    stream
        .read_exact(&mut flags)
        .map_err(|error| error.to_string())?;
    if flags.iter().any(|flag| !matches!(flag, 0 | 1)) {
        return Err("Git request contains a non-boolean flag".to_owned());
    }
    let mut presence = [0_u8; 1];
    stream
        .read_exact(&mut presence)
        .map_err(|error| error.to_string())?;
    let manifest_diff = match presence[0] {
        0 => None,
        1 => {
            let mut length = [0_u8; 4];
            stream
                .read_exact(&mut length)
                .map_err(|error| error.to_string())?;
            let length =
                usize::try_from(u32::from_be_bytes(length)).map_err(|error| error.to_string())?;
            if !(1..=MAX_MANIFEST_DIFF).contains(&length) {
                return Err("Git manifest diff length is outside its bound".to_owned());
            }
            let mut bytes = vec![0_u8; length];
            stream
                .read_exact(&mut bytes)
                .map_err(|error| error.to_string())?;
            Some(String::from_utf8(bytes).map_err(|error| error.to_string())?)
        }
        _ => return Err("Git manifest diff presence marker is invalid".to_owned()),
    };
    let touches_manifest = flags[2] == 1;
    // A protected-path change must carry its diff; a default-branch update
    // carries one for every file, so it may have a diff without one.
    if (touches_manifest && manifest_diff.is_none())
        || (manifest_diff.is_some() && !touches_manifest && flags[1] == 0)
    {
        return Err("Git manifest flag and exact diff disagree".to_owned());
    }
    let mut body_digest = [0_u8; 32];
    stream
        .read_exact(&mut body_digest)
        .map_err(|error| error.to_string())?;
    Ok((
        Asserted {
            class: ActionClass::GitPush,
            target: Target::Git {
                remote,
                refs,
                is_force: flags[0] == 1,
                is_default_branch: flags[1] == 1,
                touches_manifest,
                manifest_diff,
            },
            declared_cost: None,
        },
        body_digest,
    ))
}

fn read_git_report(stream: &mut UnixStream) -> Result<GitOutcomeReport, String> {
    let mut bytes = [0_u8; 9];
    stream
        .read_exact(&mut bytes)
        .map_err(|error| error.to_string())?;
    let (id, outcome) = bytes.split_at(8);
    let action_id = u64::from_be_bytes(id.try_into().map_err(|_| "Git report action id")?);
    Ok(GitOutcomeReport {
        action_id,
        completed: match outcome[0] {
            GIT_REPORT_COMPLETED => true,
            GIT_REPORT_FAILED => false,
            _ => return Err("Git outcome report is invalid".to_owned()),
        },
    })
}

fn read_external_request(stream: &mut UnixStream) -> Result<Asserted, String> {
    const MAX_EXTERNAL_FIELD: usize = 4_096;
    const MAX_EXTERNAL_DETAIL: usize = 65_535;

    let mut class = [0_u8; 1];
    stream
        .read_exact(&mut class)
        .map_err(|error| error.to_string())?;
    let class = match class[0] {
        1 => ActionClass::PullRequest,
        2 => ActionClass::Publish,
        _ => return Err("external action class is invalid".to_owned()),
    };
    let service = read_bounded_string(stream, MAX_EXTERNAL_FIELD, "external service")?;
    let recipient = read_bounded_string(stream, MAX_EXTERNAL_FIELD, "external recipient")?;
    let operation = read_bounded_string(stream, MAX_EXTERNAL_FIELD, "external operation")?;
    let detail = read_bounded_string(stream, MAX_EXTERNAL_DETAIL, "external detail")?;
    if [&service, &recipient, &operation]
        .into_iter()
        .any(|value| value.chars().any(char::is_control))
    {
        return Err("external action contains control characters".to_owned());
    }
    Ok(Asserted {
        class,
        target: Target::External {
            service,
            recipient,
            operation,
            detail,
        },
        declared_cost: None,
    })
}

fn read_u16(stream: &mut UnixStream) -> Result<u16, String> {
    let mut bytes = [0_u8; 2];
    stream
        .read_exact(&mut bytes)
        .map_err(|error| error.to_string())?;
    Ok(u16::from_be_bytes(bytes))
}

fn read_bounded_string(
    stream: &mut UnixStream,
    maximum: usize,
    name: &str,
) -> Result<String, String> {
    let length = usize::from(read_u16(stream)?);
    if !(1..=maximum).contains(&length) {
        return Err(format!("{name} length is outside its bound"));
    }
    let mut bytes = vec![0_u8; length];
    stream
        .read_exact(&mut bytes)
        .map_err(|error| error.to_string())?;
    String::from_utf8(bytes).map_err(|error| error.to_string())
}

fn valid_git_ref(name: &str) -> bool {
    name.starts_with("refs/")
        && !name.contains("..")
        && !name.contains("@{")
        && !name.ends_with('.')
        && !name.ends_with('/')
        && !name.contains("//")
        && !name
            .bytes()
            .any(|byte| byte.is_ascii_control() || b" ~^:?*[\\".contains(&byte))
}

fn validate_dns_name(host: &str) -> Result<(), String> {
    let valid = !host.is_empty()
        && host.len() <= 253
        && host == host.to_ascii_lowercase()
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        });
    if valid {
        Ok(())
    } else {
        Err("egress target is not a normalized DNS name".to_owned())
    }
}

#[cfg(test)]
#[path = "../tests/support/broker_hardening.rs"]
mod broker_hardening_tests;
#[cfg(test)]
#[path = "../tests/support/unit.rs"]
mod tests;
