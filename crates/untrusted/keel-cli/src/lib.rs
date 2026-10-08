#![doc = "Untrusted command-line launcher for Keel."]

mod setup;

mod openrouter;
use keel_audit::{AuditRecord, RunKey, read_verified_file, read_verified_prefix};
use keel_compile::{PolicyArtifact, SessionPolicyArtifact};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    env,
    error::Error,
    ffi::{OsStr, OsString},
    fmt, fs,
    fs::OpenOptions,
    io::Write as _,
    path::{Path, PathBuf},
    process::{Command as ProcessCommand, ExitStatus},
    time::{SystemTime, UNIX_EPOCH},
};

pub use setup::{DoctorReport, apply_runtime_config, configured_input_runtime, doctor, install};

/// Identifies this crate as outside the trusted computing base.
pub const TRUST_CLASS: &str = "untrusted";

/// Default virtual CPU count for a Keel guest.
pub const DEFAULT_VM_CPUS: usize = 2;

/// Highest virtual CPU count accepted by the Keel CLI.
pub const MAX_VM_CPUS: usize = 64;

/// Default guest memory for a workspace VM, in GiB.
pub const DEFAULT_VM_MEMORY_GIB: usize = 2;

/// Most guest memory the Keel CLI accepts, in GiB. The VZ backend also
/// refuses anything above what Virtualization.framework allows on the host.
pub const MAX_VM_MEMORY_GIB: usize = 64;

/// Default per-run ceiling for model input and output tokens.
pub const DEFAULT_MODEL_TOKEN_BUDGET: u64 = 1_000_000;

/// Default per-run model cost ceiling, measured in millionths of a US dollar.
pub const DEFAULT_MODEL_COST_BUDGET_MICROUSD: u64 = 20_000_000;

const fn default_vm_cpus() -> usize {
    DEFAULT_VM_CPUS
}

const fn default_vm_memory_gib() -> usize {
    DEFAULT_VM_MEMORY_GIB
}

const fn default_model_token_budget() -> u64 {
    DEFAULT_MODEL_TOKEN_BUDGET
}

const fn default_model_cost_budget_microusd() -> u64 {
    DEFAULT_MODEL_COST_BUDGET_MICROUSD
}

/// Top-level parsed CLI operation.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum Command {
    /// Download, build, and install the local Keel runtime.
    Setup,
    /// Check the local Keel runtime and current workspace.
    Doctor,
    /// Launch a harness through the configured runtime.
    Run(RunRequest),
    /// Compile a natural-language policy into a verified draft.
    PolicyCompile {
        /// File or inline source text.
        source: PolicySource,
        /// Draft artifact destination.
        output: PathBuf,
        /// Optional pre-generated closed-IR translation.
        translation: Option<PathBuf>,
    },
    /// Accept a reviewed, blocker-free draft.
    PolicyAccept {
        /// Draft artifact path.
        draft: PathBuf,
        /// Accepted artifact destination.
        output: PathBuf,
    },
    /// Display and verify one policy artifact.
    PolicyShow {
        /// Policy artifact path.
        artifact: PathBuf,
    },
    /// Show semantic review changes between two policies.
    PolicyDiff {
        /// Earlier policy artifact.
        old: PathBuf,
        /// Newer policy artifact.
        new: PathBuf,
    },
    /// Attach to a persistent session.
    Attach {
        /// Session identifier.
        session_id: String,
    },
    /// Stop a persistent session.
    Stop {
        /// Session identifier.
        session_id: String,
    },
    /// Verify an authenticated audit chain.
    AuditVerify {
        /// NDJSON audit path.
        audit: PathBuf,
        /// File containing the hexadecimal run key.
        key: PathBuf,
    },
    /// Compare today's prompts with the action-centric rules, per session.
    ReportAxes {
        /// Session identifiers; empty means every session with an audit chain.
        sessions: Vec<String>,
    },
    /// Summarize the per-turn context digest log, per session.
    ReportContext {
        /// Session identifiers; empty means every session with an audit chain.
        sessions: Vec<String>,
    },
    /// Report escalation-fatigue metrics from authenticated audit chains.
    Report {
        /// One or more audit and run-key pairs, each representing one task.
        inputs: Vec<ReportInput>,
    },
    /// Display a persisted provenance floor.
    FloorShow {
        /// Session identifier.
        session_id: String,
        /// Optional explicit snapshot path.
        state: Option<PathBuf>,
    },
    /// Show the boundaries a session's audit chain says were enforced.
    Status {
        /// Session identifier.
        session_id: String,
        /// Optional explicit audit path; the run key is its `.key` sibling.
        audit: Option<PathBuf>,
    },
    /// Request a gated operator attestation from a live session.
    FloorLift {
        /// Session identifier.
        session_id: String,
        /// Requested higher floor.
        requested_floor: u8,
    },
    /// Show command help.
    Help,
}

/// Source accepted by `keel policy compile`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolicySource {
    /// A UTF-8 policy document.
    File(PathBuf),
    /// A short policy supplied directly on the command line.
    Text(String),
}

/// A triage run's profile and analyst-declared scope.
///
/// Trusted admission parses the rules, shows them, and refuses everything
/// outside them; this side only collects them.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct TriageRequest {
    /// `triage`, or absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    /// Host rules: `host`, `*.host`, optionally `:port`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scope: Vec<String>,
    /// Rules that override any scope match.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude: Vec<String>,
}

#[derive(Default)]
struct TriageArguments {
    request: TriageRequest,
    report: Option<PathBuf>,
}

impl TriageArguments {
    /// Consumes one triage option, returning whether `option` was one.
    fn parse(
        &mut self,
        option: &str,
        arguments: &[OsString],
        index: &mut usize,
    ) -> Result<bool, CliError> {
        match option {
            "--profile" => {
                let profile = next_utf8(arguments, index, "--profile")?;
                if profile != "triage" {
                    return Err(CliError::new(format!("unknown --profile `{profile}`")));
                }
                self.request.profile = Some(profile);
            }
            "--scope" => self
                .request
                .scope
                .push(next_utf8(arguments, index, "--scope")?),
            "--exclude" => self
                .request
                .exclude
                .push(next_utf8(arguments, index, "--exclude")?),
            "--scope-file" => {
                let path = next_utf8(arguments, index, "--scope-file")?;
                let text = fs::read_to_string(&path)
                    .map_err(|error| CliError::new(format!("cannot read {path}: {error}")))?;
                for line in text.lines().map(str::trim) {
                    match line.strip_prefix('!') {
                        _ if line.is_empty() || line.starts_with('#') => {}
                        Some(rule) => self.request.exclude.push(rule.trim().to_owned()),
                        None => self.request.scope.push(line.to_owned()),
                    }
                }
            }
            "--report" => {
                self.report = Some(PathBuf::from(next_utf8(arguments, index, "--report")?));
            }
            _ => return Ok(false),
        }
        Ok(true)
    }

    /// Validates the combination and, when no scope was declared, proposes
    /// the report's URL hosts for the analyst to admit or refuse.
    fn finish(mut self) -> Result<TriageRequest, CliError> {
        let declared = !self.request.scope.is_empty() || !self.request.exclude.is_empty();
        if self.request.profile.is_none() {
            if declared || self.report.is_some() {
                return Err(CliError::new(
                    "--scope, --exclude, --scope-file, and --report need --profile triage",
                ));
            }
            return Ok(self.request);
        }
        if self.request.scope.is_empty()
            && let Some(report) = &self.report
        {
            let text = fs::read_to_string(report).map_err(|error| {
                CliError::new(format!("cannot read {}: {error}", report.display()))
            })?;
            self.request.scope = report_hosts(&text);
        }
        if self.request.scope.is_empty() {
            return Err(CliError::new(
                "--profile triage needs --scope, --scope-file, or a --report naming target URLs",
            ));
        }
        Ok(self.request)
    }
}

/// Hosts of the `http(s)://` URLs a report names, sorted and deduplicated.
fn report_hosts(text: &str) -> Vec<String> {
    let mut hosts = text
        .split(|character: char| character.is_whitespace() || "<>()[]\"'`".contains(character))
        .filter_map(|word| {
            let rest = word
                .strip_prefix("https://")
                .or_else(|| word.strip_prefix("http://"))?;
            let authority = rest.split(['/', '?', '#']).next()?;
            let host = authority.rsplit('@').next()?.to_ascii_lowercase();
            (host.contains('.')
                && host
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b".-:".contains(&byte)))
            .then_some(host)
        })
        .collect::<Vec<_>>();
    hosts.sort();
    hosts.dedup();
    hosts
}

/// One authenticated task supplied to `keel report`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReportInput {
    /// NDJSON audit path.
    pub audit: PathBuf,
    /// File containing the hexadecimal run key.
    pub key: PathBuf,
}

/// Provenance behavior selected for one run.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProvenanceMode {
    /// Enforce the session's monotonically decreasing floor.
    Floor,
    /// Render provenance at every gate without a rank check.
    GateContext,
}

impl ProvenanceMode {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Floor => "floor",
            Self::GateContext => "gate-context",
        }
    }
}

/// Execution isolation selected for one run.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum IsolationMode {
    /// Run the requested harness inside Keel's microVM.
    #[default]
    Vm,
    /// Run a V8 harness inside Keel's microVM.
    VmV8,
    /// Run a V8 harness directly on the host with Deno permissions.
    V8Sandboxed,
}

impl IsolationMode {
    /// Returns the stable request spelling for this isolation mode.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Vm => "vm",
            Self::VmV8 => "vm-v8",
            Self::V8Sandboxed => "v8-sandboxed",
        }
    }
}

/// Structured request handed from the untrusted CLI to the runtime.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RunRequest {
    /// Stable session identifier.
    pub session_id: String,
    /// Selected provenance behavior.
    pub provenance: ProvenanceMode,
    /// Reuse bounded same-host HTTP connections inside the trusted proxy.
    #[serde(default)]
    pub reuse_connections: bool,
    /// Number of virtual CPUs assigned to VM profiles.
    #[serde(default = "default_vm_cpus")]
    pub cpus: usize,
    /// Guest memory for VM profiles, in GiB.
    #[serde(default = "default_vm_memory_gib")]
    pub memory_gib: usize,
    /// Selected execution boundary. Old requests default to the microVM.
    #[serde(default)]
    pub isolation: IsolationMode,
    /// Render the guest through Keel's fixed-viewport terminal multiplexer.
    #[serde(default)]
    pub mux: bool,
    /// Keep the host runtime and VM alive across terminal attachments.
    #[serde(skip)]
    pub keep_alive: bool,
    /// Reviewed intent capabilities.
    pub allow: Vec<String>,
    /// Accepted natural-language policy selected for this run.
    #[serde(skip)]
    pub policy: Option<PathBuf>,
    /// Independently pinned digest for a materialized policy bundle.
    #[serde(default)]
    pub policy_bundle_hash: Option<String>,
    /// Explicit workspace selected for mux startup; omitted to show the picker.
    #[serde(skip)]
    pub workspace: Option<PathBuf>,
    /// Harness executable name.
    pub harness: String,
    /// Arguments passed to the harness inside the guest.
    pub harness_args: Vec<String>,
    /// Model the guest's harness is pinned to.
    ///
    /// The guest holds no account session, so nothing in there knows the
    /// operator's usual model: it is named here or the harness picks its own
    /// default.
    #[serde(default)]
    pub model: Option<String>,
    /// Credential shape this run authenticates the model host with.
    ///
    /// `api-key` or `bedrock`. Unset leaves the choice to the trusted process,
    /// which infers it from which credentials are configured.
    #[serde(default)]
    pub auth: Option<String>,
    /// The triage profile and its declared scope, when requested.
    #[serde(flatten)]
    pub triage: TriageRequest,
    /// Maximum model input and output tokens charged to this run.
    #[serde(default = "default_model_token_budget")]
    pub model_token_budget: u64,
    /// Maximum model cost charged to this run, in millionths of a US dollar.
    #[serde(default = "default_model_cost_budget_microusd")]
    pub model_cost_budget_microusd: u64,
}

/// One concrete source that lowered the persisted floor.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FloorObservation {
    /// Resulting floor, zero through three.
    pub rank: u8,
    /// Concrete source rendered to the operator.
    pub source: serde_json::Value,
    /// Observation time in Unix milliseconds.
    pub timestamp_ms: u64,
}

/// Read-only session snapshot displayed by `keel floor show`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FloorStatus {
    /// Harness session identifier.
    pub session_id: String,
    /// Current floor, zero through three.
    pub floor: u8,
    /// Runtime provenance behavior.
    pub provenance: ProvenanceMode,
    /// Most-recent-first floor history.
    pub floor_history: Vec<FloorObservation>,
}

/// CLI argument or persisted-state error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CliError(String);

impl CliError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for CliError {}

/// Parses top-level CLI arguments, excluding the executable name.
///
/// # Errors
///
/// Returns a usage error for an unknown command, missing value, malformed
/// provenance mode, or malformed run request.
pub fn parse_args(arguments: impl IntoIterator<Item = OsString>) -> Result<Command, CliError> {
    let arguments = arguments.into_iter().collect::<Vec<_>>();
    let Some(command) = arguments.first().and_then(|value| value.to_str()) else {
        return Ok(Command::Help);
    };
    match command {
        "setup" if arguments.len() == 1 => Ok(Command::Setup),
        "doctor" if arguments.len() == 1 => Ok(Command::Doctor),
        "run" | "mux" if requests_help(&arguments[1..]) => Ok(Command::Help),
        "run" => parse_run(&arguments[1..]).map(Command::Run),
        "mux" => parse_mux(&arguments[1..]).map(Command::Run),
        "policy" | "constitution" => parse_policy(&arguments[1..]),
        "attach" => parse_session_command("attach", &arguments[1..])
            .map(|session_id| Command::Attach { session_id }),
        "stop" => parse_session_command("stop", &arguments[1..])
            .map(|session_id| Command::Stop { session_id }),
        "status" => parse_status(&arguments[1..]),
        "audit" => parse_audit(&arguments[1..]),
        "report" => parse_report(&arguments[1..]),
        "floor" => parse_floor(&arguments[1..]),
        "help" | "-h" | "--help" => Ok(Command::Help),
        unknown => Err(CliError::new(format!("unknown command: {unknown}"))),
    }
}

fn requests_help(arguments: &[OsString]) -> bool {
    arguments
        .iter()
        .take_while(|argument| argument.as_os_str() != OsStr::new("--"))
        .any(|argument| matches!(argument.to_str(), Some("-h" | "--help")))
}

fn parse_mux(arguments: &[OsString]) -> Result<RunRequest, CliError> {
    let mut workspace = None;
    let mut mux_arguments = Vec::with_capacity(arguments.len() + 1);
    mux_arguments.push(OsString::from("claude"));
    let mut index = 0;
    let mut passthrough = false;
    while index < arguments.len() {
        if !passthrough && arguments[index] == "--" {
            passthrough = true;
        }
        if !passthrough && arguments[index] == "--workspace" {
            if workspace.is_some() {
                return Err(CliError::new("--workspace may be supplied only once"));
            }
            index += 1;
            let value = arguments
                .get(index)
                .ok_or_else(|| CliError::new("--workspace requires a value"))?;
            workspace = Some(PathBuf::from(value));
        } else {
            mux_arguments.push(arguments[index].clone());
        }
        index += 1;
    }
    let mut request = parse_run(&mux_arguments)?;
    request.mux = true;
    request.keep_alive = true;
    request.workspace = workspace;
    Ok(request)
}

fn parse_report(arguments: &[OsString]) -> Result<Command, CliError> {
    let flag = arguments.first().and_then(|argument| argument.to_str());
    if matches!(flag, Some("--axes" | "--context")) {
        let sessions = arguments[1..]
            .iter()
            .map(|session| {
                let session = session
                    .to_str()
                    .ok_or_else(|| CliError::new("session id is not UTF-8"))?;
                validate_session_id(session)?;
                Ok(session.to_owned())
            })
            .collect::<Result<_, CliError>>()?;
        return Ok(if flag == Some("--axes") {
            Command::ReportAxes { sessions }
        } else {
            Command::ReportContext { sessions }
        });
    }
    if arguments.len() < 2 || !arguments.len().is_multiple_of(2) {
        return Err(CliError::new(
            "usage: keel report AUDIT.ndjson RUN_KEY_FILE [AUDIT.ndjson RUN_KEY_FILE ...]",
        ));
    }
    Ok(Command::Report {
        inputs: arguments
            .chunks_exact(2)
            .map(|pair| ReportInput {
                audit: PathBuf::from(&pair[0]),
                key: PathBuf::from(&pair[1]),
            })
            .collect(),
    })
}

#[allow(clippy::too_many_lines)]
fn parse_run(arguments: &[OsString]) -> Result<RunRequest, CliError> {
    let mut provenance = ProvenanceMode::Floor;
    let mut isolation = IsolationMode::Vm;
    let mut reuse_connections = false;
    let mut cpus = DEFAULT_VM_CPUS;
    let mut memory_gib = DEFAULT_VM_MEMORY_GIB;
    let mux = false;
    let mut keep_alive = false;
    let mut allow = Vec::new();
    let mut policy = None;
    let mut session_id = None;
    let mut harness = None;
    let mut harness_args = Vec::new();
    let mut model = None;
    let mut triage = TriageArguments::default();
    let mut auth = None;
    let mut model_budget = ModelBudgetArguments::default();
    let mut index = 0;
    let mut passthrough = false;

    while index < arguments.len() {
        let value = arguments[index]
            .to_str()
            .ok_or_else(|| CliError::new("run arguments must be UTF-8"))?;
        if passthrough {
            harness_args.push(value.to_owned());
        } else {
            match value {
                "--" => passthrough = true,
                "--allow" => {
                    let capability = next_utf8(arguments, &mut index, "--allow")?;
                    validate_label(&capability, "capability")?;
                    allow.push(capability);
                }
                "--policy" => {
                    if policy.is_some() {
                        return Err(CliError::new("--policy may be supplied only once"));
                    }
                    policy = Some(PathBuf::from(next_utf8(arguments, &mut index, "--policy")?));
                }
                "--provenance" => {
                    provenance = parse_provenance(arguments, &mut index)?;
                }
                "--isolation" => {
                    isolation = parse_isolation(&next_utf8(arguments, &mut index, "--isolation")?)?;
                }
                "--reuse-connections" => reuse_connections = true,
                "--keep-alive" => keep_alive = true,
                "--cpus" => {
                    let value = next_utf8(arguments, &mut index, "--cpus")?;
                    cpus = parse_cpus(&value)?;
                }
                "--memory" => {
                    let value = next_utf8(arguments, &mut index, "--memory")?;
                    memory_gib = parse_memory(&value)?;
                }
                "--continue" => {
                    let value = next_utf8(arguments, &mut index, "--continue")?;
                    validate_label(&value, "session id")?;
                    session_id = Some(value);
                }
                "--model" => {
                    let value = next_utf8(arguments, &mut index, "--model")?;
                    validate_model(&value)?;
                    model = Some(value);
                }
                "--auth" => {
                    auth = Some(parse_auth(&next_utf8(arguments, &mut index, "--auth")?)?);
                }
                option @ ("--model-token-budget" | "--model-cost-budget") => {
                    parse_model_budget_option(option, arguments, &mut index, &mut model_budget)?;
                }
                option if harness.is_none() && triage.parse(option, arguments, &mut index)? => {}
                option if option.starts_with('-') && harness.is_none() => {
                    return Err(CliError::new(format!("unknown run option: {option}")));
                }
                executable if harness.is_none() => harness = Some(executable.to_owned()),
                argument => harness_args.push(argument.to_owned()),
            }
        }
        index += 1;
    }

    let harness = harness.ok_or_else(|| CliError::new("keel run requires a harness"))?;
    validate_label(&harness, "harness")?;
    allow.sort();
    allow.dedup();
    let request = RunRequest {
        session_id: session_id.unwrap_or_else(new_session_id),
        provenance,
        reuse_connections,
        cpus,
        memory_gib,
        isolation,
        mux,
        keep_alive,
        allow,
        policy,
        policy_bundle_hash: None,
        workspace: None,
        harness,
        harness_args,
        model,
        auth,
        triage: triage.finish()?,
        model_token_budget: model_budget.tokens.unwrap_or(DEFAULT_MODEL_TOKEN_BUDGET),
        model_cost_budget_microusd: model_budget
            .cost_microusd
            .unwrap_or(DEFAULT_MODEL_COST_BUDGET_MICROUSD),
    };
    validate_parsed_isolation(&request)?;
    Ok(request)
}

fn parse_isolation(value: &str) -> Result<IsolationMode, CliError> {
    match value {
        "vm" => Ok(IsolationMode::Vm),
        "vm-v8" => Ok(IsolationMode::VmV8),
        "v8-sandboxed" => Ok(IsolationMode::V8Sandboxed),
        mode => Err(CliError::new(format!(
            "invalid isolation mode: {mode}; expected vm, vm-v8, or v8-sandboxed"
        ))),
    }
}

fn parse_provenance(arguments: &[OsString], index: &mut usize) -> Result<ProvenanceMode, CliError> {
    match next_utf8(arguments, index, "--provenance")?.as_str() {
        "floor" => Ok(ProvenanceMode::Floor),
        "gate-context" => Ok(ProvenanceMode::GateContext),
        mode => Err(CliError::new(format!("invalid provenance mode: {mode}"))),
    }
}

fn parse_auth(value: &str) -> Result<String, CliError> {
    if matches!(value, "api-key" | "bedrock" | "openrouter") {
        Ok(value.to_owned())
    } else {
        Err(CliError::new(format!(
            "invalid --auth value: {value}; expected api-key, bedrock, or openrouter"
        )))
    }
}

#[derive(Default)]
struct ModelBudgetArguments {
    tokens: Option<u64>,
    cost_microusd: Option<u64>,
}

fn parse_model_budget_option(
    option: &str,
    arguments: &[OsString],
    index: &mut usize,
    budget: &mut ModelBudgetArguments,
) -> Result<(), CliError> {
    match option {
        "--model-token-budget" => {
            if budget.tokens.is_some() {
                return Err(CliError::new(
                    "--model-token-budget may be supplied only once",
                ));
            }
            budget.tokens = Some(parse_model_token_budget(&next_utf8(
                arguments, index, option,
            )?)?);
        }
        "--model-cost-budget" => {
            if budget.cost_microusd.is_some() {
                return Err(CliError::new(
                    "--model-cost-budget may be supplied only once",
                ));
            }
            budget.cost_microusd = Some(parse_model_cost_budget(&next_utf8(
                arguments, index, option,
            )?)?);
        }
        _ => unreachable!("caller restricts model budget options"),
    }
    Ok(())
}

fn parse_model_token_budget(value: &str) -> Result<u64, CliError> {
    let budget = value
        .parse::<u64>()
        .map_err(|_| CliError::new("--model-token-budget must be a positive integer"))?;
    if budget == 0 {
        return Err(CliError::new(
            "--model-token-budget must be greater than zero",
        ));
    }
    Ok(budget)
}

fn parse_model_cost_budget(value: &str) -> Result<u64, CliError> {
    const MICROUSD_PER_USD: u64 = 1_000_000;
    let invalid = || {
        CliError::new(
            "--model-cost-budget must be a positive USD amount with at most six decimal places",
        )
    };
    let (dollars, fractional) = match value.split_once('.') {
        Some((dollars, fractional))
            if !dollars.is_empty() && !fractional.is_empty() && !fractional.contains('.') =>
        {
            (dollars, fractional)
        }
        Some(_) => return Err(invalid()),
        None => (value, ""),
    };
    if dollars.is_empty()
        || !dollars.bytes().all(|byte| byte.is_ascii_digit())
        || !fractional.bytes().all(|byte| byte.is_ascii_digit())
        || fractional.len() > 6
    {
        return Err(invalid());
    }
    let dollars = dollars.parse::<u64>().map_err(|_| invalid())?;
    let fractional = if fractional.is_empty() {
        0
    } else {
        let digits = u32::try_from(fractional.len()).map_err(|_| invalid())?;
        fractional.parse::<u64>().map_err(|_| invalid())? * 10_u64.pow(6 - digits)
    };
    let budget = dollars
        .checked_mul(MICROUSD_PER_USD)
        .and_then(|whole| whole.checked_add(fractional))
        .ok_or_else(invalid)?;
    if budget == 0 {
        return Err(CliError::new(
            "--model-cost-budget must be greater than zero",
        ));
    }
    Ok(budget)
}

fn validate_parsed_isolation(request: &RunRequest) -> Result<(), CliError> {
    match request.isolation {
        IsolationMode::V8Sandboxed
            if request.policy.is_some()
                && !request
                    .allow
                    .iter()
                    .any(|capability| capability == "isolation:v8-sandboxed") =>
        {
            if request.harness == "v8" {
                Ok(())
            } else {
                Err(CliError::new(
                    "v8-sandboxed isolation requires the v8 harness",
                ))
            }
        }
        _ => validate_run_isolation(request),
    }
}

fn parse_cpus(value: &str) -> Result<usize, CliError> {
    let cpus = value.parse::<usize>().map_err(|_| {
        CliError::new(format!(
            "--cpus must be an integer between 1 and {MAX_VM_CPUS}"
        ))
    })?;
    if !(1..=MAX_VM_CPUS).contains(&cpus) {
        return Err(CliError::new(format!(
            "--cpus must be between 1 and {MAX_VM_CPUS}"
        )));
    }
    Ok(cpus)
}

/// Guest memory in GiB, written `8` or `8G`.
fn parse_memory(value: &str) -> Result<usize, CliError> {
    let invalid = || {
        CliError::new(format!(
            "--memory must be between 1 and {MAX_VM_MEMORY_GIB} (GiB)"
        ))
    };
    let gib = value
        .strip_suffix(['G', 'g'])
        .unwrap_or(value)
        .parse::<usize>()
        .map_err(|_| invalid())?;
    (1..=MAX_VM_MEMORY_GIB)
        .contains(&gib)
        .then_some(gib)
        .ok_or_else(invalid)
}

fn parse_policy(arguments: &[OsString]) -> Result<Command, CliError> {
    let Some(operation) = arguments.first().and_then(|value| value.to_str()) else {
        return Err(CliError::new(
            "usage: keel policy compile POLICY.md --output DRAFT.json [--translation RESULT.json]\n       keel policy compile --text TEXT --output DRAFT.json [--translation RESULT.json]\n       keel policy accept DRAFT.json --output POLICY.json\n       keel policy show POLICY.json\n       keel policy diff OLD.json NEW.json",
        ));
    };
    match operation {
        "compile" => {
            let mut source = None;
            let mut inline_text = None;
            let mut output = None;
            let mut translation = None;
            let mut index = 1;
            while index < arguments.len() {
                let value = utf8(&arguments[index], "policy argument")?;
                match value.as_str() {
                    "--text" => {
                        if inline_text.is_some() {
                            return Err(CliError::new("--text may be supplied only once"));
                        }
                        inline_text = Some(next_utf8(arguments, &mut index, "--text")?);
                    }
                    "--output" => {
                        if output.is_some() {
                            return Err(CliError::new("--output may be supplied only once"));
                        }
                        output = Some(PathBuf::from(next_utf8(arguments, &mut index, "--output")?));
                    }
                    "--translation" => {
                        if translation.is_some() {
                            return Err(CliError::new("--translation may be supplied only once"));
                        }
                        translation = Some(PathBuf::from(next_utf8(
                            arguments,
                            &mut index,
                            "--translation",
                        )?));
                    }
                    option if option.starts_with('-') => {
                        return Err(CliError::new(format!(
                            "unknown policy compile option: {option}"
                        )));
                    }
                    _ if source.is_none() => source = Some(PathBuf::from(value)),
                    _ => {
                        return Err(CliError::new(
                            "policy compile accepts one source file or one --text value",
                        ));
                    }
                }
                index += 1;
            }
            let output = output.ok_or_else(|| CliError::new("policy compile requires --output"))?;
            let source = match (source, inline_text) {
                (Some(path), None) => PolicySource::File(path),
                (None, Some(text)) if !text.trim().is_empty() => PolicySource::Text(text),
                (None, Some(_)) => return Err(CliError::new("--text must not be empty")),
                (Some(_), Some(_)) => {
                    return Err(CliError::new(
                        "policy compile accepts either a source file or --text, not both",
                    ));
                }
                (None, None) => {
                    return Err(CliError::new(
                        "policy compile requires a source file or --text",
                    ));
                }
            };
            Ok(Command::PolicyCompile {
                source,
                output,
                translation,
            })
        }
        "accept" => match &arguments[1..] {
            [draft, flag, output] if flag == "--output" => Ok(Command::PolicyAccept {
                draft: PathBuf::from(draft),
                output: PathBuf::from(output),
            }),
            _ => Err(CliError::new(
                "usage: keel policy accept DRAFT.json --output POLICY.json",
            )),
        },
        "show" => match &arguments[1..] {
            [artifact] => Ok(Command::PolicyShow {
                artifact: PathBuf::from(artifact),
            }),
            _ => Err(CliError::new("usage: keel policy show POLICY.json")),
        },
        "diff" => match &arguments[1..] {
            [old, new] => Ok(Command::PolicyDiff {
                old: PathBuf::from(old),
                new: PathBuf::from(new),
            }),
            _ => Err(CliError::new("usage: keel policy diff OLD.json NEW.json")),
        },
        _ => Err(CliError::new(format!(
            "unknown policy operation: {operation}"
        ))),
    }
}

/// Loads an accepted natural-language policy, verifies its repository scope,
/// and merges its closed set of capabilities into a run request.
///
/// # Errors
///
/// Returns an error for invalid, draft, blocked, or wrong-repository policy
/// artifacts.
pub fn apply_session_policy(
    request: &mut RunRequest,
    workspace: &Path,
) -> Result<String, CliError> {
    apply_session_policy_with_ledger(request, workspace, &accepted_policy_ledger()?)
}

/// Returns the host-only directory recording which policy hashes the operator
/// accepted. It lives under the state root, which neither guest nor host V8
/// workload can write, unlike the workspace that usually holds the artifact.
///
/// # Errors
///
/// Returns an error when neither `KEEL_STATE_DIR` nor `HOME` is set.
pub fn accepted_policy_ledger() -> Result<PathBuf, CliError> {
    Ok(state_root()?.join("accepted-policies"))
}

/// Records that the operator accepted the artifact with this content hash.
///
/// # Errors
///
/// Returns an error for a malformed hash or when the ledger cannot be written.
pub fn record_accepted_policy(ledger: &Path, hash: &str) -> Result<(), CliError> {
    use std::os::unix::fs::PermissionsExt as _;
    validate_policy_hash(hash)?;
    fs::create_dir_all(ledger).map_err(|error| CliError::new(error.to_string()))?;
    fs::set_permissions(ledger, fs::Permissions::from_mode(0o700))
        .map_err(|error| CliError::new(error.to_string()))?;
    fs::write(ledger.join(hash), b"").map_err(|error| CliError::new(error.to_string()))
}

fn require_accepted_policy(ledger: &Path, hash: &str) -> Result<(), CliError> {
    validate_policy_hash(hash)?;
    if ledger.join(hash).is_file() {
        return Ok(());
    }
    // The artifact's own hash and status fields are self-asserted: anything
    // that can write the file can recompute them. Only a ledger entry written
    // by `keel policy accept` on this host shows the operator accepted it.
    Err(CliError::new(format!(
        "policy {hash} was not accepted on this host; review it and run `keel policy accept`"
    )))
}

fn validate_policy_hash(hash: &str) -> Result<(), CliError> {
    if hash.len() == 64
        && hash
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        Ok(())
    } else {
        Err(CliError::new("policy artifact hash is malformed"))
    }
}

fn apply_session_policy_with_ledger(
    request: &mut RunRequest,
    workspace: &Path,
    ledger: &Path,
) -> Result<String, CliError> {
    let path = request
        .policy
        .as_deref()
        .ok_or_else(|| CliError::new("run request has no session policy"))?;
    let format = serde_json::from_slice::<serde_json::Value>(
        &fs::read(path).map_err(|error| CliError::new(error.to_string()))?,
    )
    .map_err(|error| CliError::new(format!("invalid policy artifact: {error}")))?
    .get("format")
    .and_then(serde_json::Value::as_str)
    .unwrap_or_default()
    .to_owned();
    if format == "keel-policy-v2" {
        let artifact =
            PolicyArtifact::load(path).map_err(|error| CliError::new(error.to_string()))?;
        if !artifact
            .is_accepted()
            .map_err(|error| CliError::new(error.to_string()))?
        {
            return Err(CliError::new(
                "policy is still a draft; run `keel policy accept` first",
            ));
        }
        require_accepted_policy(ledger, artifact.hash())?;
        if let Some(expected) = artifact.repository() {
            let actual = github_origin(workspace)?;
            if actual != expected {
                return Err(CliError::new(format!(
                    "policy is scoped to GitHub repository {expected}, but this workspace origin is {actual}"
                )));
            }
        }
        request
            .allow
            .extend(artifact.capabilities().iter().cloned());
        request.allow.sort();
        request.allow.dedup();
        let bundle = session_directory(&request.session_id)?.join("policy");
        if bundle.exists() {
            fs::remove_dir_all(&bundle).map_err(|error| CliError::new(error.to_string()))?;
        }
        artifact
            .materialize_bundle(&bundle)
            .map_err(|error| CliError::new(error.to_string()))?;
        request.policy_bundle_hash = Some(artifact.bundle_hash().to_owned());
        request.policy = None;
        return Ok(artifact.review());
    }
    let artifact =
        SessionPolicyArtifact::load(path).map_err(|error| CliError::new(error.to_string()))?;
    let capabilities = artifact
        .accepted_capabilities()
        .map_err(|error| CliError::new(error.to_string()))?;
    require_accepted_policy(ledger, &artifact.hash)?;
    if let Some(expected) = artifact.repository() {
        let actual = github_origin(workspace)?;
        if actual != expected {
            return Err(CliError::new(format!(
                "policy is scoped to GitHub repository {expected}, but this workspace origin is {actual}"
            )));
        }
    }
    request.allow.extend(capabilities.iter().cloned());
    request.allow.sort();
    request.allow.dedup();
    let bundle = session_directory(&request.session_id)?.join("policy");
    if bundle.exists() {
        fs::remove_dir_all(bundle).map_err(|error| CliError::new(error.to_string()))?;
    }
    request.policy_bundle_hash = None;
    request.policy = None;
    Ok(artifact.review())
}

/// Validates the isolation and harness combination after policy grants have
/// been merged into a run request.
///
/// # Errors
///
/// Returns an error when a V8 mode has the wrong harness or when the
/// lower-assurance host mode lacks its explicit grant.
pub fn validate_run_isolation(request: &RunRequest) -> Result<(), CliError> {
    match request.isolation {
        IsolationMode::Vm if request.harness == "v8" => Err(CliError::new(
            "the v8 harness requires --isolation vm-v8 or --isolation v8-sandboxed",
        )),
        IsolationMode::Vm => Ok(()),
        IsolationMode::VmV8 if request.harness == "v8" => Ok(()),
        IsolationMode::VmV8 => Err(CliError::new("vm-v8 isolation requires the v8 harness")),
        IsolationMode::V8Sandboxed if request.harness != "v8" => Err(CliError::new(
            "v8-sandboxed isolation requires the v8 harness",
        )),
        IsolationMode::V8Sandboxed
            if request
                .allow
                .iter()
                .any(|capability| capability == "isolation:v8-sandboxed") =>
        {
            Ok(())
        }
        IsolationMode::V8Sandboxed => Err(CliError::new(
            "v8-sandboxed isolation requires --allow isolation:v8-sandboxed or an accepted policy with that grant",
        )),
    }
}

/// Validates and normalizes the entry point for a V8 run.
///
/// The returned path is relative to the canonical workspace root. Absolute
/// paths, parent traversal, missing or non-regular files, symlink escapes, and
/// unsupported source extensions are rejected.
///
/// # Errors
///
/// Returns an error unless `entry` names an existing JavaScript file contained
/// by `workspace`.
pub fn validate_v8_entry(workspace: &Path, entry: &str) -> Result<String, CliError> {
    let entry_path = Path::new(entry);
    if entry.len() > 256
        || entry_path.is_absolute()
        || entry_path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(CliError::new(
            "V8 entry point must be a relative workspace path without parent traversal",
        ));
    }
    let workspace = workspace
        .canonicalize()
        .map_err(|error| CliError::new(format!("cannot open V8 workspace: {error}")))?;
    let candidate = workspace
        .join(entry_path)
        .canonicalize()
        .map_err(|error| CliError::new(format!("cannot open V8 entry point: {error}")))?;
    if !candidate.is_file() || !candidate.starts_with(&workspace) {
        return Err(CliError::new(
            "V8 entry point must be a file inside the selected worktree",
        ));
    }
    if !matches!(
        candidate.extension().and_then(OsStr::to_str),
        Some("js" | "mjs" | "cjs")
    ) {
        return Err(CliError::new(
            "V8 entry point must end in .js, .mjs, or .cjs",
        ));
    }
    candidate
        .strip_prefix(&workspace)
        .ok()
        .and_then(Path::to_str)
        .map(str::to_owned)
        .ok_or_else(|| CliError::new("V8 entry point must have a UTF-8 workspace-relative path"))
}

/// Revalidates and normalizes the entry point carried by a V8 run request.
///
/// Non-V8 requests are unchanged.
///
/// # Errors
///
/// Returns an error when a V8 request has no entry point or its entry point is
/// not accepted by [`validate_v8_entry`].
pub fn validate_v8_request_entry(
    request: &mut RunRequest,
    workspace: &Path,
) -> Result<(), CliError> {
    if request.harness != "v8" {
        return Ok(());
    }
    let entry = request
        .harness_args
        .first_mut()
        .ok_or_else(|| CliError::new("v8 harness requires a script path"))?;
    *entry = validate_v8_entry(workspace, entry)?;
    Ok(())
}

/// Adds registry hosts implied by dependency lockfiles to the task manifest.
///
/// These are suggestions only: the trusted runtime renders the resulting
/// manifest and requires operator admission before granting them.
pub fn derive_workspace_egress(request: &mut RunRequest, workspace: &Path) {
    let groups: &[(&[&str], &[&str])] = &[
        (
            &["Cargo.lock"],
            &["crates.io", "index.crates.io", "static.crates.io"],
        ),
        (
            &["package-lock.json", "pnpm-lock.yaml", "yarn.lock"],
            &["registry.npmjs.org"],
        ),
        (
            &["uv.lock", "poetry.lock", "Pipfile.lock"],
            &["pypi.org", "files.pythonhosted.org"],
        ),
        (&["go.sum"], &["proxy.golang.org"]),
        (&["Gemfile.lock"], &["rubygems.org"]),
    ];
    for (files, hosts) in groups {
        if files.iter().any(|file| workspace.join(file).is_file()) {
            request
                .allow
                .extend(hosts.iter().map(|host| format!("egress:{host}")));
        }
    }
    request.allow.sort();
    request.allow.dedup();
}

#[derive(Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "kebab-case")]
enum LauncherWorkspace {
    NewWorkspace(String),
    ExistingDirectory(PathBuf),
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum LauncherProfile {
    ClaudeVm,
    VmV8,
    V8Sandboxed,
}

#[derive(Deserialize)]
struct LauncherSelection {
    profile: LauncherProfile,
    workspace: LauncherWorkspace,
    entry: Option<String>,
}

/// Runs Keel's trusted-terminal start screen, applies its selected runtime
/// profile to `request`, and returns the independently validated worktree.
///
/// A missing result means the operator pressed Escape. The untrusted renderer's
/// result is revalidated here before it can change the launch directory or
/// runtime profile.
///
/// # Errors
///
/// Returns an error if the launcher fails, its result is malformed, a requested
/// path is not a Git worktree, a managed workspace cannot be initialized, or a
/// V8 entry point is not a JavaScript file inside the selected worktree.
pub fn select_mux_launch(
    runtime: &Path,
    start: &Path,
    request: &mut RunRequest,
) -> Result<Option<PathBuf>, CliError> {
    let home = setup::home_directory()?;
    let workspace_root = home.join(".local/share/keel/workspaces");
    let state_root = home.join(".local/share/keel/launcher");
    fs::create_dir_all(&workspace_root).map_err(|error| CliError::new(error.to_string()))?;
    fs::create_dir_all(&state_root).map_err(|error| CliError::new(error.to_string()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&state_root, fs::Permissions::from_mode(0o700))
            .map_err(|error| CliError::new(error.to_string()))?;
    }
    let result = state_root.join(format!("selection-{}.json", new_session_id()));
    let mut command = ProcessCommand::new(runtime);
    apply_runtime_config(&mut command)?;
    let status = command
        .arg("launcher")
        .arg(start)
        .arg(&workspace_root)
        .arg(&result)
        .status()
        .map_err(|error| CliError::new(format!("cannot start Keel's start screen: {error}")))?;
    if !status.success() {
        let _ = fs::remove_file(&result);
        return Err(CliError::new(format!(
            "Keel's start screen exited with {status}"
        )));
    }
    let metadata = match fs::metadata(&result) {
        Ok(metadata) if metadata.len() <= 4_096 => metadata,
        Ok(_) => {
            let _ = fs::remove_file(&result);
            return Err(CliError::new("start-screen result exceeds 4096 bytes"));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(CliError::new(error.to_string())),
    };
    let bytes = match fs::read(&result) {
        Ok(bytes) => bytes,
        Err(error) => return Err(CliError::new(error.to_string())),
    };
    debug_assert!(metadata.len() <= 4_096);
    let _ = fs::remove_file(&result);
    let selection = serde_json::from_slice::<LauncherSelection>(&bytes)
        .map_err(|error| CliError::new(format!("invalid start-screen result: {error}")))?;
    if matches!(
        selection.profile,
        LauncherProfile::VmV8 | LauncherProfile::V8Sandboxed
    ) && matches!(&selection.workspace, LauncherWorkspace::NewWorkspace(_))
    {
        return Err(CliError::new(
            "V8 launcher profiles require an existing workspace with an entry file",
        ));
    }
    let workspace = match selection.workspace {
        LauncherWorkspace::NewWorkspace(name) => create_managed_workspace(&workspace_root, &name)?,
        LauncherWorkspace::ExistingDirectory(path) => resolve_git_workspace(&path)?,
    };
    apply_launcher_profile(request, selection.profile, selection.entry, &workspace)?;
    Ok(Some(workspace))
}

fn apply_launcher_profile(
    request: &mut RunRequest,
    profile: LauncherProfile,
    entry: Option<String>,
    workspace: &Path,
) -> Result<(), CliError> {
    match profile {
        LauncherProfile::ClaudeVm => {
            if entry.is_some() {
                return Err(CliError::new(
                    "Claude launcher profile cannot carry a V8 entry point",
                ));
            }
            "claude".clone_into(&mut request.harness);
            request.isolation = IsolationMode::Vm;
        }
        LauncherProfile::VmV8 | LauncherProfile::V8Sandboxed => {
            let entry = entry
                .ok_or_else(|| CliError::new("V8 launcher profile requires an entry point"))?;
            let entry = validate_v8_entry(workspace, &entry)?;
            "v8".clone_into(&mut request.harness);
            request.harness_args = vec![entry];
            request.isolation = match profile {
                LauncherProfile::VmV8 => IsolationMode::VmV8,
                LauncherProfile::V8Sandboxed => IsolationMode::V8Sandboxed,
                LauncherProfile::ClaudeVm => unreachable!(),
            };
        }
    }
    Ok(())
}

/// Resolves an explicit mux workspace without showing the start screen.
///
/// # Errors
///
/// Returns an error unless `path` belongs to a Git worktree.
pub fn explicit_mux_workspace(path: &Path) -> Result<PathBuf, CliError> {
    resolve_git_workspace(path)
}

fn create_managed_workspace(root: &Path, name: &str) -> Result<PathBuf, CliError> {
    if name.is_empty()
        || name.len() > 64
        || matches!(name, "." | "..")
        || name.starts_with('.')
        || !name.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
        })
    {
        return Err(CliError::new("the workspace name is not path-safe"));
    }
    let destination = root.join(name);
    fs::create_dir(&destination).map_err(|error| {
        CliError::new(format!(
            "cannot create workspace {}: {error}",
            destination.display()
        ))
    })?;
    let output = keel_provenance::trusted_git_command()
        .args(["init", "--quiet", "--initial-branch", "main"])
        .arg(&destination)
        .output()
        .map_err(|error| CliError::new(format!("cannot initialize Git: {error}")))?;
    if !output.status.success() {
        let _ = fs::remove_dir(&destination);
        return Err(CliError::new(format!(
            "cannot initialize {} as a Git workspace: {}",
            destination.display(),
            visible(String::from_utf8_lossy(&output.stderr).trim())
        )));
    }
    resolve_git_workspace(&destination)
}

fn resolve_git_workspace(path: &Path) -> Result<PathBuf, CliError> {
    let path = path.canonicalize().map_err(|error| {
        CliError::new(format!("cannot open workspace {}: {error}", path.display()))
    })?;
    if !path.is_dir() {
        return Err(CliError::new(format!(
            "workspace is not a directory: {}",
            path.display()
        )));
    }
    let output = keel_provenance::trusted_git_command()
        .arg("-C")
        .arg(&path)
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .map_err(|error| CliError::new(format!("cannot inspect Git workspace: {error}")))?;
    if !output.status.success() {
        return Err(CliError::new(format!(
            "{} is not a Git worktree",
            path.display()
        )));
    }
    let root = String::from_utf8(output.stdout)
        .map_err(|_| CliError::new("Git returned a non-UTF-8 worktree path"))?;
    Path::new(root.trim())
        .canonicalize()
        .map_err(|error| CliError::new(error.to_string()))
}

fn github_origin(workspace: &Path) -> Result<String, CliError> {
    let output = keel_provenance::trusted_git_command()
        .arg("-C")
        .arg(workspace)
        .args(["remote", "get-url", "origin"])
        .output()
        .map_err(|error| CliError::new(format!("cannot inspect Git origin: {error}")))?;
    if !output.status.success() {
        return Err(CliError::new(
            "policy has repository scope but this workspace has no Git origin",
        ));
    }
    let origin =
        String::from_utf8(output.stdout).map_err(|_| CliError::new("Git origin is not UTF-8"))?;
    let origin = origin
        .trim()
        .strip_prefix("https://github.com/")
        .ok_or_else(|| CliError::new("repository-scoped policies require an HTTPS GitHub origin"))?
        .trim_end_matches(".git")
        .trim_matches('/')
        .to_ascii_lowercase();
    let mut parts = origin.split('/');
    if !matches!(
        (parts.next(), parts.next(), parts.next()),
        (Some(_), Some(_), None)
    ) {
        return Err(CliError::new(
            "GitHub origin is not an owner/repository URL",
        ));
    }
    Ok(origin)
}

/// Tells the trusted process which credential shape this run chose.
///
/// Only the name of the choice travels here. The credential itself is resolved
/// on the other side, which is the side that can tell whether it resolves at
/// all, and the choice is what an operator holding two of them has to make.
fn apply_model_auth(command: &mut ProcessCommand, request: &RunRequest) -> Result<(), CliError> {
    if let Some(auth) = &request.auth {
        command.env("KEEL_MODEL_AUTH", auth);
    }
    if request.auth.as_deref() == Some("openrouter") {
        if request.harness != "claude" {
            return Err(CliError::new(
                "--auth openrouter supports the claude harness only",
            ));
        }
        let model = request
            .model
            .as_deref()
            .filter(|model| model.contains('/'))
            .ok_or_else(|| {
                CliError::new(
                    "--auth openrouter needs --model PROVIDER/MODEL, for example \
anthropic/claude-sonnet-4.6",
                )
            })?;
        let (input, output) = openrouter::price_snapshot(model)?;
        command.env(
            "KEEL_OPENROUTER_TARIFF",
            format!("{model}={input},{output}"),
        );
    }
    Ok(())
}

/// Accepts a model name the guest's harness will be pinned to.
///
/// The value is written into the guest's environment and appears in the request
/// path the kernel authorizes, so it is held to what a model identifier can be:
/// printable, bounded, and free of anything a shell or a header would read as
/// structure.
fn validate_model(value: &str) -> Result<(), CliError> {
    const MAX_MODEL_LENGTH: usize = 200;

    if value.is_empty() || value.len() > MAX_MODEL_LENGTH {
        return Err(CliError::new(format!(
            "--model must be between 1 and {MAX_MODEL_LENGTH} characters"
        )));
    }
    if value.chars().any(|character| {
        !character.is_ascii_alphanumeric() && !matches!(character, '.' | '-' | '_' | ':' | '/')
    }) {
        return Err(CliError::new(format!(
            "invalid --model value: {value}; expected letters, digits, and `.-_:/`"
        )));
    }
    Ok(())
}

/// The model an operator already told this host to use, when `--model` did not
/// name one.
///
/// A run inside the VM cannot see the operator's Claude configuration — there is
/// no account session in there and nothing from the host is mounted — so the
/// choice is read here, where it is only configuration, and passed down as the
/// one value the guest is pinned to.
#[must_use]
pub fn host_default_model() -> Option<String> {
    if let Some(model) = env::var("ANTHROPIC_MODEL")
        .ok()
        .filter(|model| validate_model(model).is_ok())
    {
        return Some(model);
    }
    let settings = setup::home_directory()
        .ok()
        .map(|home| home.join(".claude/settings.json"))?;
    let settings: serde_json::Value = serde_json::from_str(&fs::read_to_string(settings).ok()?)
        .ok()
        .unwrap_or_default();
    settings
        .get("model")?
        .as_str()
        .map(str::to_owned)
        .filter(|model| validate_model(model).is_ok())
}

fn parse_session_command(operation: &str, arguments: &[OsString]) -> Result<String, CliError> {
    let [session_id] = arguments else {
        return Err(CliError::new(format!("usage: keel {operation} SESSION")));
    };
    let session_id = session_id
        .to_str()
        .ok_or_else(|| CliError::new("session id must be UTF-8"))?
        .to_owned();
    validate_session_id(&session_id)?;
    Ok(session_id)
}

fn parse_status(arguments: &[OsString]) -> Result<Command, CliError> {
    match arguments {
        [session] => {
            let session_id = utf8(session, "session id")?;
            validate_session_id(&session_id)?;
            Ok(Command::Status {
                session_id,
                audit: None,
            })
        }
        [session, flag, audit] if flag == "--audit" => {
            let session_id = utf8(session, "session id")?;
            validate_session_id(&session_id)?;
            Ok(Command::Status {
                session_id,
                audit: Some(PathBuf::from(audit)),
            })
        }
        _ => Err(CliError::new(
            "usage: keel status SESSION [--audit AUDIT.ndjson]",
        )),
    }
}

fn parse_audit(arguments: &[OsString]) -> Result<Command, CliError> {
    match arguments {
        [operation, audit, key] if operation == "verify" => Ok(Command::AuditVerify {
            audit: PathBuf::from(audit),
            key: PathBuf::from(key),
        }),
        _ => Err(CliError::new(
            "usage: keel audit verify AUDIT.ndjson RUN_KEY_FILE",
        )),
    }
}

fn parse_floor(arguments: &[OsString]) -> Result<Command, CliError> {
    match arguments {
        [operation, session] if operation == "show" => {
            let session_id = utf8(session, "session id")?;
            validate_session_id(&session_id)?;
            Ok(Command::FloorShow {
                session_id,
                state: None,
            })
        }
        [operation, session, flag, state] if operation == "show" && flag == "--state" => {
            let session_id = utf8(session, "session id")?;
            validate_session_id(&session_id)?;
            Ok(Command::FloorShow {
                session_id,
                state: Some(PathBuf::from(state)),
            })
        }
        [operation, session] if operation == "lift" => floor_lift_command(session, OsStr::new("3")),
        [operation, session, rank] if operation == "lift" => floor_lift_command(session, rank),
        _ => Err(CliError::new(
            "usage: keel floor show SESSION [--state FLOOR.json]\n       keel floor lift SESSION [RANK]",
        )),
    }
}

fn floor_lift_command(session: &OsStr, rank: &OsStr) -> Result<Command, CliError> {
    let session_id = utf8(session, "session id")?;
    validate_session_id(&session_id)?;
    let requested_floor = utf8(rank, "floor")?
        .parse::<u8>()
        .map_err(|_| CliError::new("floor lift rank must be one through three"))?;
    if !(1..=3).contains(&requested_floor) {
        return Err(CliError::new("floor lift rank must be one through three"));
    }
    Ok(Command::FloorLift {
        session_id,
        requested_floor,
    })
}

fn next_utf8(arguments: &[OsString], index: &mut usize, option: &str) -> Result<String, CliError> {
    *index += 1;
    arguments
        .get(*index)
        .ok_or_else(|| CliError::new(format!("{option} requires a value")))
        .and_then(|value| utf8(value, option))
}

fn utf8(value: &OsStr, name: &str) -> Result<String, CliError> {
    value
        .to_str()
        .map(str::to_owned)
        .ok_or_else(|| CliError::new(format!("{name} must be UTF-8")))
}

fn validate_label(value: &str, name: &str) -> Result<(), CliError> {
    if value.is_empty() || value.chars().any(char::is_control) {
        return Err(CliError::new(format!("invalid {name}")));
    }
    Ok(())
}

fn validate_session_id(session_id: &str) -> Result<(), CliError> {
    validate_label(session_id, "session id")?;
    if session_id.contains('/')
        || session_id.contains('\\')
        || session_id == "."
        || session_id == ".."
    {
        return Err(CliError::new("invalid session id"));
    }
    Ok(())
}

/// Creates a process-unique session identifier for a new mux tab.
#[must_use]
pub fn new_session_id() -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis());
    format!("run-{millis}-{}", std::process::id())
}

/// Returns the default state directory for a session.
///
/// # Errors
///
/// Returns an error when neither `KEEL_STATE_DIR` nor the user's home
/// directory is available.
pub fn session_directory(session_id: &str) -> Result<PathBuf, CliError> {
    validate_session_id(session_id)?;
    Ok(state_root()?.join("sessions").join(session_id))
}

fn state_root() -> Result<PathBuf, CliError> {
    if let Some(root) = env::var_os("KEEL_STATE_DIR") {
        return Ok(PathBuf::from(root));
    }
    env::var_os("HOME")
        .map(|home| PathBuf::from(home).join(".keel"))
        .ok_or_else(|| CliError::new("HOME and KEEL_STATE_DIR are unset"))
}

/// Loads and validates a display-only floor snapshot.
///
/// # Errors
///
/// Returns an error if the file cannot be read, is malformed, names another
/// session, or contains ranks outside zero through three.
pub fn load_floor_status(path: &Path, session_id: &str) -> Result<FloorStatus, CliError> {
    validate_session_id(session_id)?;
    let bytes = fs::read(path).map_err(|error| CliError::new(error.to_string()))?;
    let status: FloorStatus =
        serde_json::from_slice(&bytes).map_err(|error| CliError::new(error.to_string()))?;
    if status.session_id != session_id {
        return Err(CliError::new("floor snapshot belongs to another session"));
    }
    if status.floor > 3 || status.floor_history.iter().any(|entry| entry.rank > 3) {
        return Err(CliError::new("floor snapshot contains an invalid rank"));
    }
    Ok(status)
}

/// Formats a floor snapshot without interpreting source strings as terminal
/// control sequences.
#[must_use]
pub fn format_floor_status(status: &FloorStatus) -> String {
    use std::fmt::Write as _;

    let mut output = format!(
        "session: {}\nmode: {}\nfloor: {}\n",
        visible(&status.session_id),
        status.provenance.as_str(),
        status.floor
    );
    if status.floor_history.is_empty() {
        output.push_str("history: none\n");
    } else {
        output.push_str("history:\n");
        for entry in &status.floor_history {
            let source = serde_json::to_string(&entry.source)
                .unwrap_or_else(|_| "\"invalid source\"".to_owned());
            let _ = writeln!(
                output,
                "  rank {} at {}: {}",
                entry.rank,
                entry.timestamp_ms,
                visible(&source)
            );
        }
    }
    output
}

/// The boundaries a run's audit chain says were standing.
///
/// This is a log read, not a query: the kernel writes what it derived from the
/// objects that enforce each boundary, and this reads it back. Nothing here can
/// ask a live run how it is configured, so nothing here can be answered by a
/// component that is itself the thing in question.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnforcementReport {
    /// Session the chain belongs to.
    pub session_id: String,
    /// Audit chain the record was read from.
    pub audit: PathBuf,
    /// Phase of the most recent record: `start` or `shutdown`.
    pub phase: String,
    /// Record time in Unix milliseconds.
    pub timestamp_ms: u64,
    /// Boundary name and its reported `state: detail`, sorted by name.
    pub boundaries: Vec<(String, String)>,
    /// `active`, `closed`, or `interrupted`.
    pub state: &'static str,
    /// One-line admission manifest summary, when the chain records one.
    pub admitted: Option<String>,
}

/// Whether a chain is sealed (`closed`), still written by a live trusted
/// runtime (`active`), or left unsealed by one that is gone (`interrupted`).
/// The writer's process id is part of the chain's file name.
fn session_state(audit: &Path, sealed: bool) -> &'static str {
    if sealed {
        return "closed";
    }
    let pid = audit.file_name().and_then(OsStr::to_str).and_then(|name| {
        name.strip_prefix("audit-")?
            .split('-')
            .next()?
            .parse::<u32>()
            .ok()
    });
    let alive = pid.is_some_and(|pid| {
        ProcessCommand::new("/bin/ps")
            .args(["-p", &pid.to_string(), "-o", "comm="])
            .output()
            .is_ok_and(|output| {
                String::from_utf8_lossy(&output.stdout).contains("keel-input-runtime")
            })
    });
    if alive { "active" } else { "interrupted" }
}

/// The run configuration a session's results should not be pooled across:
/// harness, model, provider, and guest kernel, from its admission manifest.
fn manifest_group(records: &[AuditRecord]) -> String {
    let manifest = records
        .iter()
        .find(|record| record.payload.event == "kernel.run-admitted")
        .and_then(|record| record.payload.fields.get("manifest"))
        .and_then(|manifest| serde_json::from_str::<serde_json::Value>(manifest).ok());
    let Some(manifest) = manifest else {
        return "no admission manifest".to_owned();
    };
    let text = |value: &serde_json::Value| value.as_str().unwrap_or("-").to_owned();
    format!(
        "{} on {} via {}, kernel {}",
        text(&manifest["run"]["harness"]),
        text(&manifest["model"]["model"]),
        text(&manifest["model"]["provider"]),
        text(&manifest["kernel_release"]),
    )
}

/// One line describing a chain's admission manifest, if it records one.
fn manifest_summary(records: &[AuditRecord]) -> Option<String> {
    let record = records
        .iter()
        .find(|record| record.payload.event == "kernel.run-admitted")?;
    let manifest =
        serde_json::from_str::<serde_json::Value>(record.payload.fields.get("manifest")?).ok()?;
    let text = |value: &serde_json::Value| value.as_str().unwrap_or("-").to_owned();
    let short = |value: Option<&str>| {
        value.map_or("none".to_owned(), |hash| hash.chars().take(12).collect())
    };
    Some(format!(
        "{} on {} via {}, kernel {}, policy {}, manifest {}",
        text(&manifest["run"]["harness"]),
        text(&manifest["model"]["model"]),
        text(&manifest["model"]["provider"]),
        text(&manifest["kernel_release"]),
        short(manifest["policy_bundle"].as_str()),
        short(
            record
                .payload
                .fields
                .get("manifest_sha256")
                .map(String::as_str)
        ),
    ))
}

/// Reads the most recent enforcement state from a session's audit chain.
///
/// The chain is authenticated before anything is read out of it, so an
/// unverifiable log yields an error rather than a reassuring report.
///
/// # Errors
///
/// Returns an error when the session directory holds no audit chain, the run
/// key is missing or malformed, authentication fails, or the chain records no
/// enforcement state.
pub fn session_enforcement_state(
    session_id: &str,
    audit: Option<&Path>,
) -> Result<EnforcementReport, CliError> {
    validate_session_id(session_id)?;
    let audit = match audit {
        Some(path) => path.to_path_buf(),
        None => latest_audit_chain(&session_directory(session_id)?)?,
    };
    let key_path = audit.with_extension("key");
    let key = fs::read_to_string(&key_path)
        .map_err(|error| CliError::new(format!("cannot read {}: {error}", key_path.display())))?;
    let key = RunKey::from_hex(&key).map_err(|error| CliError::new(error.to_string()))?;
    // An unsealed chain is exactly what an active or interrupted session
    // has, so status reads the authenticated prefix rather than requiring the
    // seal.
    let (records, status) = read_verified_prefix(&audit, &key)
        .map_err(|error| CliError::new(format!("{}: {error}", audit.display())))?;
    let state = session_state(&audit, status.sealed);
    let admitted = manifest_summary(&records);
    let record = records
        .iter()
        .rev()
        .find(|record| record.payload.event == "kernel.enforcement-state")
        .ok_or_else(|| {
            CliError::new(format!("{} records no enforcement state", audit.display()))
        })?;
    Ok(EnforcementReport {
        session_id: session_id.to_owned(),
        audit,
        phase: record
            .payload
            .fields
            .get("phase")
            .cloned()
            .unwrap_or_else(|| "unknown".to_owned()),
        timestamp_ms: record.payload.timestamp_ms,
        boundaries: record
            .payload
            .fields
            .iter()
            .filter_map(|(key, value)| {
                key.strip_prefix("boundary.")
                    .map(|name| (name.to_owned(), value.clone()))
            })
            .collect(),
        state,
        admitted,
    })
}

fn latest_audit_chain(directory: &Path) -> Result<PathBuf, CliError> {
    let entries = fs::read_dir(directory)
        .map_err(|error| CliError::new(format!("cannot read {}: {error}", directory.display())))?;
    let mut candidates = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| CliError::new(error.to_string()))?;
        let path = entry.path();
        let Some(name) = path.file_name().and_then(OsStr::to_str) else {
            continue;
        };
        // A chain without its key cannot be authenticated, so it is not a
        // candidate — reporting from an unauthenticated log would defeat the
        // purpose of reading the log at all.
        if !name.starts_with("audit-")
            || !name.ends_with(".ndjson")
            || !path.with_extension("key").exists()
        {
            continue;
        }
        let modified = entry
            .metadata()
            .and_then(|metadata| metadata.modified())
            .ok();
        candidates.push((modified, path));
    }
    candidates.sort();
    candidates.pop().map(|(_, path)| path).ok_or_else(|| {
        CliError::new(format!(
            "{} holds no authenticated audit chain",
            directory.display()
        ))
    })
}

/// Formats an enforcement report, leading with whatever is not fully enforced.
#[must_use]
pub fn format_enforcement_report(report: &EnforcementReport) -> String {
    use std::fmt::Write as _;

    let mut output = format!(
        "session: {}\nstate: {}\naudit: {}\nadmitted: {}\nphase: {} at {}\n",
        visible(&report.session_id),
        report.state,
        visible(&report.audit.display().to_string()),
        visible(
            report
                .admitted
                .as_deref()
                .unwrap_or("no manifest (run predates admission records)")
        ),
        visible(&report.phase),
        report.timestamp_ms
    );
    let weak = report
        .boundaries
        .iter()
        .filter(|(_, value)| !value.starts_with("active:"))
        .map(|(name, value)| {
            format!(
                "{} ({})",
                visible(name),
                visible(value.split(':').next().unwrap_or(value))
            )
        })
        .collect::<Vec<_>>();
    if weak.is_empty() {
        output.push_str("not fully enforced: none\n");
    } else {
        let _ = writeln!(output, "not fully enforced: {}", weak.join(", "));
    }
    output.push_str("boundaries:\n");
    for (name, value) in &report.boundaries {
        let _ = writeln!(output, "  {}: {}", visible(name), visible(value));
    }
    output
}

#[derive(Default)]
struct RuleMetrics {
    gate_events: u64,
    prompts: u64,
    approvals: u64,
}

#[derive(Default)]
struct FatigueMetrics {
    tasks: u64,
    gate_events: u64,
    prompts: u64,
    automatic_decisions: u64,
    legacy_prompt_inferences: u64,
    approvals: u64,
    fast_approvals: u64,
    approved_floor_lifts: u64,
    decision_times: Vec<u64>,
    rules: BTreeMap<String, RuleMetrics>,
}

struct Escalation {
    approved: bool,
    prompt: PromptClassification,
    time_ms: u64,
    floor_lift: bool,
    mode: String,
    rules: BTreeSet<String>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum PromptClassification {
    Presented,
    Inferred,
    Automatic,
}

impl FatigueMetrics {
    fn record(&mut self, escalation: &Escalation) {
        self.gate_events += 1;
        let presented = escalation.prompt != PromptClassification::Automatic;
        self.prompts += u64::from(presented);
        self.automatic_decisions += u64::from(!presented);
        self.legacy_prompt_inferences +=
            u64::from(escalation.prompt == PromptClassification::Inferred);
        if presented {
            self.decision_times.push(escalation.time_ms);
        }
        if escalation.approved && presented {
            self.approvals += 1;
            self.fast_approvals += u64::from(escalation.time_ms < 2_000);
            self.approved_floor_lifts += u64::from(escalation.floor_lift);
        }
        for rule in &escalation.rules {
            let metrics = self.rules.entry(rule.clone()).or_default();
            metrics.gate_events += 1;
            metrics.prompts += u64::from(presented);
            metrics.approvals += u64::from(escalation.approved && presented);
        }
    }
}

/// Rules the action-centric model replaces. Any other violation, such as an
/// accepted-policy escalation or an inherently gated action, still prompts.
const REPLACED_RULES: &[&str] = &[
    "intent:egress-host",
    "intent:pr-create",
    "admission:egress",
    "admission:git-push",
    "admission:pr-create",
    "kernel:minimum-rank",
];

/// What the action-centric rules would do with one recorded action.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AxesDecision {
    Allow,
    Prompt,
    Deny,
}

/// Decides one action from its recorded intent, flow, and rules, as the
/// action-centric design's decision table would.
fn axes_decision(intent: &str, flow: &str, rules: &[String]) -> AxesDecision {
    if flow.starts_with("secret-to-") {
        AxesDecision::Deny
    } else if flow.contains("-to-")
        || flow.starts_with("unaccounted")
        || flow == "uninspectable"
        || !matches!(intent, "inside" | "not-applicable")
        || rules
            .iter()
            .any(|rule| !REPLACED_RULES.contains(&rule.as_str()))
    {
        AxesDecision::Prompt
    } else {
        AxesDecision::Allow
    }
}

#[derive(Clone, Default)]
struct AxesSummary {
    effects: usize,
    prompted_today: usize,
    would_prompt: usize,
    would_deny: usize,
    unrecorded: usize,
    outside: BTreeMap<String, usize>,
    flows: BTreeMap<String, usize>,
    avoided: Vec<String>,
    added: Vec<String>,
}

impl AxesSummary {
    fn observe(&mut self, action_id: u64, fields: &BTreeMap<String, String>) {
        let Some(intent) = fields.get("intent") else {
            self.unrecorded += 1;
            return;
        };
        // Unaccounted content entering a protected place is judged like a
        // flow violation: both are what the action carries.
        let flow = match fields.get("integrity").map(String::as_str) {
            Some(integrity)
                if integrity.starts_with("unaccounted") || integrity == "uninspectable" =>
            {
                integrity
            }
            _ => fields.get("flow").map_or("not-checked", String::as_str),
        };
        let rules = fields
            .get("rules")
            .and_then(|rules| serde_json::from_str::<Vec<String>>(rules).ok())
            .unwrap_or_default();
        // Budget and model-budget refusals are resource limits in both models,
        // even when the kernel recorded them through its deny-only gate.
        if fields
            .get("denial_origin")
            .is_some_and(|origin| origin == "resource")
            || rules
                .iter()
                .any(|rule| matches!(rule.as_str(), "kernel:budget" | "kernel:model-budget"))
        {
            return;
        }
        let prompted = fields
            .get("prompt_presented")
            .is_some_and(|value| value == "true");
        // A real request outside intent always carries a violation. One with
        // none is a connection-setup leg, recorded before such legs were
        // marked not-applicable.
        let setup_leg = intent != "inside" && rules.is_empty() && flow == "not-checked";
        if (intent == "not-applicable" || setup_leg) && !prompted && !flow.contains("-to-") {
            return;
        }
        self.effects += 1;
        if !matches!(intent.as_str(), "inside" | "not-applicable") {
            *self.outside.entry(intent.clone()).or_default() += 1;
        }
        let flow_kind = flow.split(':').next().unwrap_or(flow);
        if flow_kind != "not-checked" {
            *self.flows.entry(flow_kind.to_owned()).or_default() += 1;
        }
        let decision = axes_decision(intent, flow, &rules);
        let class = fields.get("action_class").map_or("action", String::as_str);
        let detail = format!("#{action_id} {class} (intent {intent}, flow {flow})");
        self.prompted_today += usize::from(prompted);
        match decision {
            AxesDecision::Allow if prompted => self.avoided.push(detail),
            AxesDecision::Allow => {}
            AxesDecision::Prompt | AxesDecision::Deny => {
                if decision == AxesDecision::Deny {
                    self.would_deny += 1;
                } else {
                    self.would_prompt += 1;
                }
                if !prompted {
                    self.added.push(detail);
                }
            }
        }
    }

    fn render(&self, output: &mut String) {
        use std::fmt::Write as _;
        let count = |map: &BTreeMap<String, usize>| {
            map.iter()
                .map(|(name, count)| format!("{} {count}", visible(name)))
                .collect::<Vec<_>>()
                .join(", ")
        };
        let _ = writeln!(output, "  effects judged:          {}", self.effects);
        let _ = writeln!(output, "  prompts today:           {}", self.prompted_today);
        let _ = writeln!(
            output,
            "  action-centric prompts:  {}  ({} avoided, {} added)",
            self.would_prompt,
            self.avoided.len(),
            self.added.len()
        );
        let _ = writeln!(output, "  action-centric denials:  {}", self.would_deny);
        if !self.outside.is_empty() {
            let _ = writeln!(
                output,
                "  outside intent:          {}",
                count(&self.outside)
            );
        }
        if !self.flows.is_empty() {
            let _ = writeln!(output, "  payload flow:            {}", count(&self.flows));
        }
        for detail in &self.avoided {
            let _ = writeln!(output, "  avoided: {}", visible(detail));
        }
        for detail in &self.added {
            let _ = writeln!(output, "  added:   {}", visible(detail));
        }
        if self.unrecorded > 0 {
            let _ = writeln!(
                output,
                "  {} actions predate intent and flow verdicts and are not judged",
                self.unrecorded
            );
        }
    }

    fn absorb(&mut self, other: Self) {
        self.effects += other.effects;
        self.prompted_today += other.prompted_today;
        self.would_prompt += other.would_prompt;
        self.would_deny += other.would_deny;
        self.unrecorded += other.unrecorded;
        for (name, count) in other.outside {
            *self.outside.entry(name).or_default() += count;
        }
        for (name, count) in other.flows {
            *self.flows.entry(name).or_default() += count;
        }
        self.avoided.extend(other.avoided);
        self.added.extend(other.added);
    }
}

/// Compares, per session, the prompts Keel presented with what the
/// action-centric rules would have done, using only sealed, authenticated
/// audit chains. Shadow verdicts make no decision; this is how to judge
/// whether they should.
///
/// # Errors
///
/// Returns an error when the session directory cannot be read or a named
/// session has no audit chain.
pub fn axes_report(sessions: &[String]) -> Result<String, CliError> {
    use std::fmt::Write as _;
    let (sessions, skipped) = sealed_sessions(sessions)?;
    let mut output = String::from(
        "Action-centric comparison (shadow verdicts; sealed, authenticated audit only)\n",
    );
    let mut total = AxesSummary::default();
    let mut groups = BTreeMap::<String, (usize, AxesSummary)>::new();
    let mut judged = 0_usize;
    for (session, records) in sessions {
        let admitted = manifest_summary(&records);
        let group = manifest_group(&records);
        let mut actions = BTreeMap::<u64, BTreeMap<String, String>>::new();
        for record in records {
            if record.payload.event == "kernel.action"
                && let Some(action_id) = record.payload.action_id
            {
                actions.insert(action_id, record.payload.fields);
            }
        }
        let mut summary = AxesSummary::default();
        for (action_id, fields) in &actions {
            summary.observe(*action_id, fields);
        }
        if summary.effects == 0 && summary.unrecorded == 0 {
            continue;
        }
        judged += 1;
        let _ = writeln!(output, "\n{}", visible(&session));
        if let Some(admitted) = admitted {
            let _ = writeln!(output, "  admitted: {}", visible(&admitted));
        }
        summary.render(&mut output);
        let entry = groups.entry(group).or_default();
        entry.0 += 1;
        entry.1.absorb(summary.clone());
        total.absorb(summary);
    }
    if groups.len() > 1 {
        for (group, (count, summary)) in &groups {
            let _ = writeln!(output, "\nGroup: {} ({count} sessions)", visible(group));
            summary.render(&mut output);
        }
    }
    let _ = writeln!(output, "\nAll {judged} sessions");
    total.render(&mut output);
    if skipped > 0 {
        let _ = writeln!(
            output,
            "\n{skipped} sessions skipped: still running, unsealed, or without an authenticated chain"
        );
    }
    Ok(output)
}

/// A session's identifier and its verified audit records.
type SealedSession = (String, Vec<AuditRecord>);

/// Reads the latest sealed, authenticated audit chain of each named session,
/// or of every session when none is named, and counts the sessions skipped
/// because they are running, unsealed, or unauthenticated.
fn sealed_sessions(sessions: &[String]) -> Result<(Vec<SealedSession>, usize), CliError> {
    let sessions = if sessions.is_empty() {
        let root = state_root()?.join("sessions");
        let mut names = fs::read_dir(&root)
            .map_err(|error| CliError::new(format!("cannot read {}: {error}", root.display())))?
            .filter_map(|entry| entry.ok()?.file_name().into_string().ok())
            .collect::<Vec<_>>();
        names.sort();
        names
    } else {
        sessions.to_vec()
    };
    let mut sealed = Vec::new();
    let mut skipped = 0_usize;
    for session in sessions {
        let records = session_directory(&session)
            .and_then(|directory| latest_audit_chain(&directory))
            .and_then(|audit| {
                let key = fs::read_to_string(audit.with_extension("key"))
                    .map_err(|error| CliError::new(error.to_string()))?;
                let key =
                    RunKey::from_hex(&key).map_err(|error| CliError::new(error.to_string()))?;
                read_verified_file(&audit, &key).map_err(|error| CliError::new(error.to_string()))
            });
        match records {
            Ok(records) => sealed.push((session, records)),
            Err(_) => skipped += 1,
        }
    }
    Ok((sealed, skipped))
}

/// One described block from the context digest log.
struct LoggedBlock {
    place: String,
    kind: String,
    tool_use: Option<String>,
}

/// Per-session measurements of what model requests carried, from the
/// shadow context digest log.
#[derive(Default)]
struct ContextSummary {
    requests: usize,
    responses: usize,
    blocks: BTreeMap<&'static str, usize>,
    /// Requests whose context holds no tool output and no assistant block
    /// the model did not emit: those a per-turn rank could place above 0.
    untainted: usize,
    system_variants: BTreeSet<String>,
    tool_variants: BTreeSet<String>,
}

impl ContextSummary {
    fn observe(records: &[AuditRecord]) -> Self {
        let mut summary = Self::default();
        let mut described = HashMap::<String, LoggedBlock>::new();
        let mut emitted = HashSet::<String>::new();
        let mut emitted_tools = HashSet::<String>::new();
        for record in records {
            let fields = &record.payload.fields;
            if record.payload.event != "kernel.model-context" {
                continue;
            }
            for block in fields
                .get("blocks")
                .and_then(|blocks| serde_json::from_str::<Vec<serde_json::Value>>(blocks).ok())
                .unwrap_or_default()
            {
                let text = |name: &str| {
                    block
                        .get(name)
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned)
                };
                if let (Some(digest), Some(place), Some(kind)) =
                    (text("digest"), text("place"), text("kind"))
                {
                    described.insert(
                        digest,
                        LoggedBlock {
                            place,
                            kind,
                            tool_use: text("tool_use"),
                        },
                    );
                }
            }
            let sequence = fields
                .get("sequence")
                .map(|sequence| sequence.split_whitespace().collect::<Vec<_>>())
                .unwrap_or_default();
            if fields.get("phase").is_some_and(|phase| phase == "response") {
                summary.responses += 1;
                for digest in sequence {
                    emitted.insert(digest.to_owned());
                    if let Some(tool) = described
                        .get(digest)
                        .and_then(|block| block.tool_use.clone())
                    {
                        emitted_tools.insert(tool);
                    }
                }
                continue;
            }
            summary.requests += 1;
            let (mut system, mut tools, mut tainted) = (String::new(), String::new(), false);
            for digest in sequence {
                let Some(block) = described.get(digest) else {
                    *summary.blocks.entry("undescribed").or_default() += 1;
                    tainted = true;
                    continue;
                };
                // A block is described once, where it first appeared, so a
                // model block carried back is recognized by digest.
                let category = if emitted.contains(digest) {
                    "assistant, emitted by the model"
                } else if block.place == "system" {
                    system.push_str(digest);
                    "system"
                } else if block.place == "tools" {
                    tools.push_str(digest);
                    "tool definition"
                } else if block.place.ends_with(".assistant") {
                    tainted = true;
                    "assistant, not emitted by the model"
                } else if block.kind == "tool_result" {
                    tainted = true;
                    if block
                        .tool_use
                        .as_ref()
                        .is_some_and(|tool| emitted_tools.contains(tool))
                    {
                        "tool result, bound to a model tool call"
                    } else {
                        "tool result, unbound"
                    }
                } else {
                    "user content (operator match not yet recorded)"
                };
                *summary.blocks.entry(category).or_default() += 1;
            }
            summary.untainted += usize::from(!tainted);
            summary.system_variants.insert(system);
            summary.tool_variants.insert(tools);
        }
        summary
    }

    /// Adds another session's counts; variant sets are unioned.
    fn absorb(&mut self, other: &Self) {
        self.requests += other.requests;
        self.responses += other.responses;
        self.untainted += other.untainted;
        for (category, count) in &other.blocks {
            *self.blocks.entry(category).or_default() += count;
        }
        self.system_variants
            .extend(other.system_variants.iter().cloned());
        self.tool_variants
            .extend(other.tool_variants.iter().cloned());
    }

    fn render(&self, output: &mut String) {
        use std::fmt::Write as _;
        let _ = writeln!(output, "  model requests:          {}", self.requests);
        let _ = writeln!(output, "  model responses logged:  {}", self.responses);
        let _ = writeln!(
            output,
            "  without tool output:     {}  (could rank above 0 per turn)",
            self.untainted
        );
        let _ = writeln!(
            output,
            "  system prompt variants:  {}; tool set variants: {}",
            self.system_variants.len(),
            self.tool_variants.len()
        );
        for (category, count) in &self.blocks {
            let _ = writeln!(output, "  blocks, {category}: {count}");
        }
    }
}

/// Summarizes, per session, the shadow per-turn context digest log: how much
/// of each model request's context the model itself emitted, how much is tool
/// output, and how stable the harness's system prompt and tools are.
///
/// # Errors
///
/// Returns an error when the session directory cannot be read.
pub fn context_report(sessions: &[String]) -> Result<String, CliError> {
    use std::fmt::Write as _;
    let (sessions, skipped) = sealed_sessions(sessions)?;
    let mut output =
        String::from("Per-turn context digest log (shadow; sealed, authenticated audit only)\n");
    let mut logged = 0_usize;
    let mut groups = BTreeMap::<String, (usize, ContextSummary)>::new();
    for (session, records) in sessions {
        let summary = ContextSummary::observe(&records);
        if summary.requests == 0 {
            continue;
        }
        logged += 1;
        let entry = groups.entry(manifest_group(&records)).or_default();
        entry.0 += 1;
        entry.1.absorb(&summary);
        let _ = writeln!(output, "\n{}", visible(&session));
        if let Some(admitted) = manifest_summary(&records) {
            let _ = writeln!(output, "  admitted: {}", visible(&admitted));
        }
        summary.render(&mut output);
    }
    if logged == 0 {
        let _ = writeln!(output, "\nNo session has logged model context yet.");
    }
    for (group, (count, summary)) in &groups {
        let _ = writeln!(output, "\nGroup: {} ({count} sessions)", visible(group));
        summary.render(&mut output);
    }
    if skipped > 0 {
        let _ = writeln!(
            output,
            "\n{skipped} sessions skipped: still running, unsealed, or without an authenticated chain"
        );
    }
    Ok(output)
}

/// Verifies task audit chains and formats escalation-fatigue measurements.
///
/// # Errors
///
/// Returns an error if an audit or key cannot be read, authentication fails,
/// or a gate event is missing a required measurement.
pub fn fatigue_report(inputs: &[ReportInput]) -> Result<String, CliError> {
    if inputs.is_empty() {
        return Err(CliError::new("keel report requires at least one task"));
    }
    let mut overall = FatigueMetrics::default();
    let mut by_mode = BTreeMap::<String, FatigueMetrics>::new();
    for input in inputs {
        let key = fs::read_to_string(&input.key).map_err(|error| {
            CliError::new(format!("cannot read {}: {error}", input.key.display()))
        })?;
        let key = RunKey::from_hex(&key).map_err(|error| CliError::new(error.to_string()))?;
        let records = read_verified_file(&input.audit, &key)
            .map_err(|error| CliError::new(format!("{}: {error}", input.audit.display())))?;
        let escalations = records
            .iter()
            .filter_map(parse_escalation)
            .collect::<Result<Vec<_>, _>>()?;
        let modes = escalations
            .iter()
            .map(|event| event.mode.as_str())
            .collect::<BTreeSet<_>>();
        if modes.len() > 1 {
            return Err(CliError::new(format!(
                "{} contains inconsistent provenance modes",
                input.audit.display()
            )));
        }
        let mode = modes.first().copied().unwrap_or("no-gates").to_owned();
        overall.tasks += 1;
        let mode_metrics = by_mode.entry(mode).or_default();
        mode_metrics.tasks += 1;
        for escalation in escalations {
            overall.record(&escalation);
            mode_metrics.record(&escalation);
        }
    }
    let mut output = String::new();
    format_metrics(&mut output, "overall", &mut overall);
    for (mode, mut metrics) in by_mode {
        output.push('\n');
        format_metrics(&mut output, &format!("mode {mode}"), &mut metrics);
    }
    Ok(output)
}

fn parse_escalation(record: &AuditRecord) -> Option<Result<Escalation, CliError>> {
    if record.payload.event != "kernel.action"
        || !record.payload.fields.contains_key("gate_decision")
        || record
            .payload
            .fields
            .get("outcome")
            .is_some_and(|outcome| outcome == "attempted")
    {
        return None;
    }
    Some((|| {
        let field = |name: &str| {
            record
                .payload
                .fields
                .get(name)
                .ok_or_else(|| CliError::new(format!("gate event is missing {name}")))
        };
        let approved = match field("gate_decision")?.as_str() {
            "approve" | "approve-grant" => true,
            "deny" | "unavailable" => false,
            value => return Err(CliError::new(format!("invalid gate decision: {value}"))),
        };
        let time_ms = field("gate_time_ms")?
            .parse()
            .map_err(|_| CliError::new("invalid gate decision time"))?;
        let floor = field("gate_floor")?
            .parse::<u8>()
            .map_err(|_| CliError::new("invalid gate floor"))?;
        if floor > 3 {
            return Err(CliError::new("invalid gate floor"));
        }
        let mode = field("provenance_mode")?.clone();
        if !matches!(mode.as_str(), "floor" | "gate-context") {
            return Err(CliError::new(format!("invalid provenance mode: {mode}")));
        }
        let rules = serde_json::from_str::<Vec<String>>(field("rules")?)
            .map_err(|_| CliError::new("invalid gate rule list"))?
            .into_iter()
            .collect();
        let prompt = match record.payload.fields.get("prompt_presented") {
            Some(value) => {
                if value
                    .parse::<bool>()
                    .map_err(|_| CliError::new("invalid prompt_presented value"))?
                {
                    PromptClassification::Presented
                } else {
                    PromptClassification::Automatic
                }
            }
            None => PromptClassification::Inferred,
        };
        if let Some(authority) = record.payload.fields.get("gate_authority")
            && !matches!(authority.as_str(), "operator" | "deny-only")
        {
            return Err(CliError::new(format!(
                "invalid gate authority: {authority}"
            )));
        }
        Ok(Escalation {
            approved,
            prompt,
            time_ms,
            floor_lift: field("action_class")? == "lift-floor",
            mode,
            rules,
        })
    })())
}

fn format_metrics(output: &mut String, label: &str, metrics: &mut FatigueMetrics) {
    use std::fmt::Write as _;

    metrics.decision_times.sort_unstable();
    let _ = writeln!(output, "{label}:");
    let _ = writeln!(output, "  tasks: {}", metrics.tasks);
    let _ = writeln!(
        output,
        "  gate decisions/task: {} ({})",
        ratio(metrics.gate_events, metrics.tasks),
        metrics.gate_events
    );
    let _ = writeln!(
        output,
        "  visible prompts/task: {} ({})",
        ratio(metrics.prompts, metrics.tasks),
        metrics.prompts
    );
    let _ = writeln!(
        output,
        "  automatic decisions: {}",
        metrics.automatic_decisions
    );
    if metrics.legacy_prompt_inferences > 0 {
        let _ = writeln!(
            output,
            "  legacy prompt classifications (inferred): {}",
            metrics.legacy_prompt_inferences
        );
    }
    let _ = writeln!(
        output,
        "  approved floor lifts/task: {} ({})",
        ratio(metrics.approved_floor_lifts, metrics.tasks),
        metrics.approved_floor_lifts
    );
    if metrics.decision_times.is_empty() {
        output.push_str("  decision time ms: n/a\n");
    } else {
        let _ = writeln!(
            output,
            "  decision time ms: p50={} p95={} max={}",
            percentile(&metrics.decision_times, 50),
            percentile(&metrics.decision_times, 95),
            metrics
                .decision_times
                .last()
                .expect("decision times are nonempty")
        );
    }
    let _ = writeln!(
        output,
        "  approved <2s: {}",
        fraction(metrics.fast_approvals, metrics.approvals)
    );
    if metrics.rules.is_empty() {
        output.push_str("  rules: none\n");
    } else {
        output.push_str("  rules:\n");
        for (rule, values) in &metrics.rules {
            let _ = writeln!(
                output,
                "    {}: prompts/task {} ({}), prompt share {}, approval rate {}; gate decisions {}",
                visible(rule),
                ratio(values.prompts, metrics.tasks),
                values.prompts,
                fraction(values.prompts, metrics.prompts),
                fraction(values.approvals, values.prompts),
                values.gate_events
            );
        }
    }
}

fn ratio(numerator: u64, denominator: u64) -> String {
    if denominator == 0 {
        "0.00".to_owned()
    } else {
        let scaled =
            (u128::from(numerator) * 100 + u128::from(denominator) / 2) / u128::from(denominator);
        format!("{}.{:02}", scaled / 100, scaled % 100)
    }
}

fn fraction(numerator: u64, denominator: u64) -> String {
    if denominator == 0 {
        "n/a (0/0)".to_owned()
    } else {
        let scaled =
            (u128::from(numerator) * 1_000 + u128::from(denominator) / 2) / u128::from(denominator);
        format!(
            "{}.{}% ({numerator}/{denominator})",
            scaled / 10,
            scaled % 10
        )
    }
}

fn percentile(sorted: &[u64], percent: usize) -> u64 {
    let index = sorted.len().saturating_mul(percent).div_ceil(100) - 1;
    sorted[index]
}

fn visible(value: &str) -> String {
    value
        .chars()
        .flat_map(|character| {
            if character.is_control() {
                format!("\\u{{{:x}}}", u32::from(character))
                    .chars()
                    .collect()
            } else {
                vec![character]
            }
        })
        .collect()
}

/// Serializes and hands a run request to a runtime executable.
///
/// The request is sent over stdin. Harness execution never falls back to the
/// host if the runtime is missing.
///
/// # Errors
///
/// Returns an error if serialization, process creation, or IPC fails.
pub fn launch_runtime(runtime: &Path, request: &RunRequest) -> Result<ExitStatus, CliError> {
    let mut command = ProcessCommand::new(runtime);
    // This process owns the operator's terminal for the lifetime of the child.
    // Persistent attachment uses a distinct, explicitly untrusted value in the
    // trusted supervisor. Absence of this marker is fail-closed.
    command.env("KEEL_INPUT_SOURCE", "trusted-terminal");
    apply_runtime_config(&mut command)?;
    apply_model_auth(&mut command, request)?;
    if let Some((rows, columns)) = host_terminal_dimensions() {
        command
            .env("KEEL_TERMINAL_ROWS", rows)
            .env("KEEL_TERMINAL_COLUMNS", columns);
    }
    let request_path = write_runtime_request(request)?;
    let child = command
        .arg("run")
        .arg("--request")
        .arg(&request_path)
        .spawn()
        .map_err(|error| CliError::new(format!("cannot start Keel runtime: {error}")));
    let result = match child {
        Ok(mut child) => child
            .wait()
            .map_err(|error| CliError::new(format!("Keel runtime failed: {error}"))),
        Err(error) => Err(error),
    };
    let cleanup = fs::remove_file(&request_path)
        .map_err(|error| CliError::new(format!("cannot remove runtime request: {error}")));
    match (result, cleanup) {
        (Ok(status), Ok(())) => Ok(status),
        (Err(error), _) | (Ok(_), Err(error)) => Err(error),
    }
}

fn host_terminal_dimensions() -> Option<(String, String)> {
    let output = ProcessCommand::new("stty")
        .arg("size")
        .stdin(std::process::Stdio::inherit())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let size = String::from_utf8(output.stdout).ok()?;
    let mut dimensions = size.split_whitespace();
    let rows = dimensions.next()?.parse::<u16>().ok()?;
    let columns = dimensions.next()?.parse::<u16>().ok()?;
    if rows == 0 || columns == 0 || dimensions.next().is_some() {
        return None;
    }
    Some((rows.to_string(), columns.to_string()))
}

/// Starts a persistent runtime supervisor and returns its attachment socket.
///
/// # Errors
///
/// Returns an error if the request cannot be written, the supervisor cannot
/// start, or it does not create its socket within five seconds.
pub fn start_persistent_runtime(runtime: &Path, request: &RunRequest) -> Result<PathBuf, CliError> {
    use std::os::unix::{
        fs::{FileTypeExt as _, OpenOptionsExt as _},
        process::CommandExt as _,
    };
    use std::{process::Stdio, thread, time::Duration};

    let request_path = write_runtime_request(request)?;
    let directory = session_directory(&request.session_id)?;
    let socket = directory.join("attach.sock");
    if socket.exists() {
        if std::os::unix::net::UnixStream::connect(&socket).is_ok() {
            let _ = fs::remove_file(&request_path);
            return Err(CliError::new(format!(
                "persistent session {} is already running",
                request.session_id
            )));
        }
        fs::remove_file(&socket).map_err(|error| {
            CliError::new(format!("cannot remove stale attach socket: {error}"))
        })?;
    }
    let log_path = directory.join("session.log");
    let log = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(&log_path)
        .map_err(|error| CliError::new(format!("cannot open persistent session log: {error}")))?;
    let mut command = ProcessCommand::new(runtime);
    apply_runtime_config(&mut command)?;
    apply_model_auth(&mut command, request)?;
    if let Some((rows, columns)) = host_terminal_dimensions() {
        command
            .env("KEEL_TERMINAL_ROWS", rows)
            .env("KEEL_TERMINAL_COLUMNS", columns);
    }
    let child = command
        .arg("serve")
        .arg("--request")
        .arg(&request_path)
        .arg("--socket")
        .arg(&socket)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(log))
        .process_group(0)
        .spawn();
    let mut child = match child {
        Ok(child) => child,
        Err(error) => {
            let _ = fs::remove_file(&request_path);
            return Err(CliError::new(format!(
                "cannot start persistent Keel runtime: {error}"
            )));
        }
    };
    for _ in 0..250 {
        if socket
            .metadata()
            .is_ok_and(|metadata| metadata.file_type().is_socket())
        {
            return Ok(socket);
        }
        if let Some(status) = child
            .try_wait()
            .map_err(|error| CliError::new(format!("persistent runtime failed: {error}")))?
        {
            let _ = fs::remove_file(&request_path);
            return Err(CliError::new(format!(
                "persistent runtime exited with {status}; see {}",
                log_path.display()
            )));
        }
        thread::sleep(Duration::from_millis(20));
    }
    let _ = child.kill();
    let _ = child.wait();
    let _ = fs::remove_file(&request_path);
    Err(CliError::new(format!(
        "persistent runtime did not become ready; see {}",
        log_path.display()
    )))
}

/// Runs one trusted attachment operation for a persistent session.
///
/// # Errors
///
/// Returns an error if the trusted runtime cannot be started or waited on.
pub fn persistent_runtime_operation(
    runtime: &Path,
    operation: &str,
    session_id: &str,
) -> Result<ExitStatus, CliError> {
    validate_session_id(session_id)?;
    let socket = session_directory(session_id)?.join("attach.sock");
    ProcessCommand::new(runtime)
        .arg(operation)
        .arg("--socket")
        .arg(socket)
        .env("KEEL_SESSION_ID", session_id)
        .status()
        .map_err(|error| CliError::new(format!("cannot {operation} Keel session: {error}")))
}

fn write_runtime_request(request: &RunRequest) -> Result<PathBuf, CliError> {
    let directory = session_directory(&request.session_id)?;
    write_runtime_request_in(request, &directory)
}

/// Serializes a runtime request in an explicit session directory.
///
/// # Errors
///
/// Returns an error if the directory or request file cannot be written.
pub fn write_runtime_request_in(
    request: &RunRequest,
    directory: &Path,
) -> Result<PathBuf, CliError> {
    fs::create_dir_all(directory).map_err(|error| CliError::new(error.to_string()))?;
    let path = directory.join(format!("run-request-{}.json", std::process::id()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(&path)
        .map_err(|error| CliError::new(format!("cannot create runtime request: {error}")))?;
    if let Err(error) = serde_json::to_writer(&mut file, request)
        .and_then(|()| file.write_all(b"\n").map_err(serde_json::Error::io))
        .and_then(|()| file.sync_all().map_err(serde_json::Error::io))
    {
        let _ = fs::remove_file(&path);
        return Err(CliError::new(error.to_string()));
    }
    Ok(path)
}

/// Returns concise command help.
#[must_use]
pub const fn help() -> &'static str {
    "usage:\n  keel setup\n  keel doctor\n  keel mux [--workspace PATH] [RUN_OPTIONS] [-- CLAUDE_ARGS...]\n  keel run [--isolation vm|vm-v8|v8-sandboxed] [--provenance floor|gate-context] [--cpus N] [--memory GIB] [--reuse-connections] [--keep-alive] [--allow CAPABILITY] [--policy POLICY.json] [--continue SESSION] [--model MODEL] [--auth api-key|bedrock|openrouter] [--profile triage --scope RULE|--scope-file FILE|--report REPORT [--exclude RULE]] [--model-token-budget N] [--model-cost-budget USD] HARNESS [ARGS...]\n  keel policy compile POLICY.md --output DRAFT.json [--translation RESULT.json]\n  keel policy compile --text TEXT --output DRAFT.json [--translation RESULT.json]\n  keel policy accept DRAFT.json --output POLICY.json\n  keel policy show POLICY.json\n  keel policy diff OLD.json NEW.json\n  keel attach SESSION\n  keel stop SESSION\n  keel status SESSION [--audit AUDIT.ndjson]\n  keel audit verify AUDIT.ndjson RUN_KEY_FILE\n  keel report AUDIT.ndjson RUN_KEY_FILE [AUDIT.ndjson RUN_KEY_FILE ...]\n  keel report --axes [SESSION ...]\n  keel report --context [SESSION ...]\n  keel floor show SESSION [--state FLOOR.json]\n  keel floor lift SESSION [RANK]\n\ncapabilities:\n  egress:HOST\n  push:branch\n  push:ref:refs/heads/PATTERN\n  pr:create\n  pr:target:BRANCH\n  github:read-private-issues\n  deny:force-push\n  isolation:v8-sandboxed\n  workspace:public\n"
}

#[cfg(test)]
mod tests {
    use super::{
        Command, FloorObservation, FloorStatus, IsolationMode, LauncherProfile, PolicySource,
        ProvenanceMode, ReportInput, apply_launcher_profile, apply_session_policy_with_ledger,
        create_managed_workspace, fatigue_report, format_enforcement_report, format_floor_status,
        help, load_floor_status, parse_args, record_accepted_policy, resolve_git_workspace,
        validate_run_isolation, validate_v8_request_entry,
    };
    use keel_audit::{AuditPayload, AuditWriter, Redactor, RunKey};
    use keel_compile::{SessionPolicyArtifact, SessionPolicyTranslation};
    use std::{
        collections::BTreeMap,
        ffi::OsString,
        fs,
        os::unix::fs::symlink,
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    };

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn parses_setup_and_doctor_without_arguments() {
        assert_eq!(parse_args(args(&["setup"])).unwrap(), Command::Setup);
        assert_eq!(parse_args(args(&["doctor"])).unwrap(), Command::Doctor);
        assert!(parse_args(args(&["setup", "--unknown"])).is_err());
        assert!(parse_args(args(&["doctor", "--unknown"])).is_err());
    }

    #[test]
    fn parses_policy_lifecycle_and_run_selection() {
        assert_eq!(
            parse_args(args(&[
                "policy",
                "compile",
                "POLICY.md",
                "--output",
                "draft.json",
                "--translation",
                "translation.json",
            ]))
            .unwrap(),
            Command::PolicyCompile {
                source: PolicySource::File(PathBuf::from("POLICY.md")),
                output: PathBuf::from("draft.json"),
                translation: Some(PathBuf::from("translation.json")),
            }
        );
        assert_eq!(
            parse_args(args(&[
                "policy",
                "compile",
                "--text",
                "Allow docs.rs",
                "--output",
                "draft.json",
            ]))
            .unwrap(),
            Command::PolicyCompile {
                source: PolicySource::Text("Allow docs.rs".to_owned()),
                output: PathBuf::from("draft.json"),
                translation: None,
            }
        );
        assert_eq!(
            parse_args(args(&[
                "policy",
                "accept",
                "draft.json",
                "--output",
                "policy.json",
            ]))
            .unwrap(),
            Command::PolicyAccept {
                draft: PathBuf::from("draft.json"),
                output: PathBuf::from("policy.json"),
            }
        );
        assert_eq!(
            parse_args(args(&["policy", "show", "policy.json"])).unwrap(),
            Command::PolicyShow {
                artifact: PathBuf::from("policy.json"),
            }
        );
        assert_eq!(
            parse_args(args(&["policy", "diff", "old.json", "new.json"])).unwrap(),
            Command::PolicyDiff {
                old: PathBuf::from("old.json"),
                new: PathBuf::from("new.json"),
            }
        );
        let Command::Run(request) =
            parse_args(args(&["run", "--policy", "policy.json", "claude"])).unwrap()
        else {
            panic!("run");
        };
        assert_eq!(request.policy, Some(PathBuf::from("policy.json")));
        assert!(parse_args(args(&["policy", "compile", "POLICY.md"])).is_err());
        assert!(
            parse_args(args(&[
                "policy",
                "compile",
                "POLICY.md",
                "--text",
                "duplicate",
                "--output",
                "draft.json",
            ]))
            .is_err()
        );
        assert!(parse_args(args(&["policy", "accept", "draft.json"])).is_err());
    }

    #[test]
    fn constitution_is_a_compatibility_alias_for_policy() {
        assert_eq!(
            parse_args(args(&[
                "constitution",
                "compile",
                "POLICY.md",
                "--output",
                "draft.json",
                "--translation",
                "translation.json",
            ]))
            .unwrap(),
            Command::PolicyCompile {
                source: PolicySource::File(PathBuf::from("POLICY.md")),
                output: PathBuf::from("draft.json"),
                translation: Some(PathBuf::from("translation.json")),
            }
        );
        assert_eq!(
            parse_args(args(&[
                "constitution",
                "accept",
                "draft.json",
                "--output",
                "policy.json",
            ]))
            .unwrap(),
            Command::PolicyAccept {
                draft: PathBuf::from("draft.json"),
                output: PathBuf::from("policy.json"),
            }
        );
        assert_eq!(
            parse_args(args(&["constitution", "diff", "old.json", "new.json"])).unwrap(),
            Command::PolicyDiff {
                old: PathBuf::from("old.json"),
                new: PathBuf::from("new.json"),
            }
        );
        assert!(parse_args(args(&["constitution", "compile", "POLICY.md"])).is_err());
    }

    #[test]
    fn accepted_policy_is_scoped_to_the_current_github_origin() {
        let root = std::env::temp_dir().join(format!(
            "keel-policy-workspace-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        let git = |arguments: &[&str]| {
            std::process::Command::new("git")
                .arg("-C")
                .arg(&root)
                .args(arguments)
                .status()
                .unwrap()
        };
        assert!(git(&["init", "--quiet"]).success());
        assert!(
            git(&[
                "remote",
                "add",
                "origin",
                "https://github.com/example-org/keel-live-test.git",
            ])
            .success()
        );
        let mut artifact = SessionPolicyArtifact::draft(
            "Allow ordinary branch pushes in example-org/keel-live-test.",
            SessionPolicyTranslation {
                repository: Some("example-org/keel-live-test".to_owned()),
                grants: vec!["push:branch".to_owned()],
                constraints: Vec::new(),
                blockers: Vec::new(),
                notes: Vec::new(),
            },
            1,
        )
        .unwrap();
        artifact.accept(2).unwrap();
        let policy = root.join("policy.json");
        artifact.save(&policy).unwrap();
        let Command::Run(mut request) = parse_args(args(&[
            "run",
            "--policy",
            policy.to_str().unwrap(),
            "claude",
        ]))
        .unwrap() else {
            panic!("run");
        };
        let ledger = root.join("ledger");
        let error = apply_session_policy_with_ledger(&mut request, &root, &ledger).unwrap_err();
        assert!(error.to_string().contains("not accepted on this host"));
        record_accepted_policy(&ledger, &artifact.hash).unwrap();
        apply_session_policy_with_ledger(&mut request, &root, &ledger).unwrap();
        assert_eq!(request.allow, ["push:branch"]);
        assert!(request.policy.is_none());

        // Draft and accept need no secret, so a workload that can write the
        // artifact can mint a self-consistent "accepted" one. Without the
        // host ledger entry it still does not authorize a run.
        let mut forged = SessionPolicyArtifact::draft(
            "Allow ordinary branch pushes in example-org/keel-live-test.",
            SessionPolicyTranslation {
                repository: Some("example-org/keel-live-test".to_owned()),
                grants: vec!["push:branch".to_owned(), "pr:create".to_owned()],
                constraints: Vec::new(),
                blockers: Vec::new(),
                notes: Vec::new(),
            },
            1,
        )
        .unwrap();
        forged.accept(2).unwrap();
        forged.save(&policy).unwrap();
        request.policy = Some(policy.clone());
        let error = apply_session_policy_with_ledger(&mut request, &root, &ledger).unwrap_err();
        assert!(error.to_string().contains("not accepted on this host"));
        artifact.save(&policy).unwrap();

        assert!(
            git(&[
                "remote",
                "set-url",
                "origin",
                "https://github.com/other/repo.git"
            ])
            .success()
        );
        request.policy = Some(policy);
        assert!(apply_session_policy_with_ledger(&mut request, &root, &ledger).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn parses_structured_intent_and_harness_arguments() {
        let command = parse_args(args(&[
            "run",
            "claude",
            "--allow",
            "push:branch",
            "--allow",
            "pr:create",
            "--allow",
            "github:read-private-issues",
            "--provenance",
            "gate-context",
            "--cpus",
            "4",
            "--keep-alive",
            "--reuse-connections",
            "--",
            "--model",
            "sonnet",
        ]))
        .unwrap();
        let Command::Run(request) = command else {
            panic!("expected run request");
        };
        assert_eq!(request.harness, "claude");
        assert_eq!(
            request.allow,
            ["github:read-private-issues", "pr:create", "push:branch"]
        );
        assert_eq!(request.provenance, ProvenanceMode::GateContext);
        assert_eq!(request.cpus, 4);
        assert!(request.keep_alive);
        assert!(request.reuse_connections);
        assert!(!request.mux);
        assert_eq!(request.harness_args, ["--model", "sonnet"]);
    }

    #[test]
    fn mux_is_a_persistent_claude_session_with_run_options() {
        let Command::Run(request) = parse_args(args(&[
            "mux",
            "--workspace",
            "/tmp/project",
            "--cpus",
            "6",
            "--allow",
            "pr:create",
            "--",
            "--verbose",
        ]))
        .unwrap() else {
            panic!("expected mux run request");
        };

        assert_eq!(request.harness, "claude");
        assert_eq!(request.cpus, 6);
        assert_eq!(request.allow, ["pr:create"]);
        assert_eq!(request.harness_args, ["--verbose"]);
        assert!(request.mux);
        assert!(request.keep_alive);
        assert_eq!(request.workspace, Some(PathBuf::from("/tmp/project")));
        assert!(parse_args(args(&["mux", "--workspace", "one", "--workspace", "two"])).is_err());
    }

    #[test]
    fn managed_workspace_is_initialized_and_existing_paths_resolve_to_the_worktree() {
        let root = std::env::temp_dir().join(format!(
            "keel-managed-workspace-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        let workspace = create_managed_workspace(&root, "demo").unwrap();
        fs::create_dir(workspace.join("nested")).unwrap();
        assert_eq!(
            resolve_git_workspace(&workspace.join("nested")).unwrap(),
            workspace
        );
        assert!(workspace.join(".git").is_dir());
        assert!(create_managed_workspace(&root, "../escape").is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn launcher_profile_is_revalidated_before_it_changes_the_run() {
        let root = std::env::temp_dir().join(format!(
            "keel-launch-profile-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(root.join("scripts")).unwrap();
        fs::write(root.join("scripts/agent.mjs"), "console.log('ok');\n").unwrap();
        let workspace = root.canonicalize().unwrap();
        let Command::Run(mut request) = parse_args(args(&["mux"])).unwrap() else {
            panic!("expected mux request");
        };

        apply_launcher_profile(
            &mut request,
            LauncherProfile::VmV8,
            Some("scripts/agent.mjs".to_owned()),
            &workspace,
        )
        .unwrap();
        assert_eq!(request.harness, "v8");
        assert_eq!(request.isolation, IsolationMode::VmV8);
        assert_eq!(request.harness_args, ["scripts/agent.mjs"]);
        assert!(validate_run_isolation(&request).is_ok());

        apply_launcher_profile(
            &mut request,
            LauncherProfile::V8Sandboxed,
            Some("scripts/agent.mjs".to_owned()),
            &workspace,
        )
        .unwrap();
        assert_eq!(request.isolation, IsolationMode::V8Sandboxed);
        assert!(validate_run_isolation(&request).is_err());
        request.allow.push("isolation:v8-sandboxed".to_owned());
        assert!(validate_run_isolation(&request).is_ok());

        assert!(
            apply_launcher_profile(
                &mut request,
                LauncherProfile::VmV8,
                Some("../escape.mjs".to_owned()),
                &workspace,
            )
            .is_err()
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn run_help_does_not_start_a_harness_but_passthrough_help_does() {
        assert_eq!(parse_args(args(&["mux", "--help"])).unwrap(), Command::Help);
        assert!(help().contains("github:read-private-issues"));
        let Command::Run(request) = parse_args(args(&["mux", "--", "--help"])).unwrap() else {
            panic!("expected mux run request");
        };
        assert_eq!(request.harness_args, ["--help"]);
    }

    #[test]
    fn triage_runs_declare_scope_or_propose_it_from_the_report() {
        let Command::Run(request) = parse_args(args(&[
            "run",
            "--profile",
            "triage",
            "--scope",
            "*.target.example",
            "--exclude",
            "admin.target.example",
            "claude",
        ]))
        .unwrap() else {
            panic!("expected run request");
        };
        assert_eq!(request.triage.profile.as_deref(), Some("triage"));
        assert_eq!(request.triage.scope, ["*.target.example"]);
        assert_eq!(request.triage.exclude, ["admin.target.example"]);
        let wire = serde_json::to_value(&request).unwrap();
        assert_eq!(wire["profile"], "triage");
        assert_eq!(wire["scope"][0], "*.target.example");

        let directory =
            std::env::temp_dir().join(format!("keel-triage-cli-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let report = directory.join("report.md");
        std::fs::write(
            &report,
            "Repro: open <https://App.Target.example/login?next=/> then POST to \
             https://api.target.example:8443/v1/users (see https://docs.vendor.example).",
        )
        .unwrap();
        let rules = directory.join("scope.txt");
        std::fs::write(
            &rules,
            "# program\n*.target.example\n!admin.target.example\n\n",
        )
        .unwrap();
        let parse = |extra: &[&str]| {
            let mut arguments = vec!["run", "--profile", "triage"];
            arguments.extend_from_slice(extra);
            arguments.push("claude");
            parse_args(args(&arguments))
        };
        let Command::Run(proposed) = parse(&["--report", report.to_str().unwrap()]).unwrap() else {
            panic!("expected run request");
        };
        assert_eq!(
            proposed.triage.scope,
            [
                "api.target.example:8443",
                "app.target.example",
                "docs.vendor.example"
            ]
        );
        let Command::Run(filed) = parse(&["--scope-file", rules.to_str().unwrap()]).unwrap() else {
            panic!("expected run request");
        };
        assert_eq!(filed.triage.scope, ["*.target.example"]);
        assert_eq!(filed.triage.exclude, ["admin.target.example"]);
        assert!(parse(&[]).is_err(), "triage needs a scope");
        assert!(parse_args(args(&["run", "--scope", "a.example", "claude"])).is_err());
        assert!(parse_args(args(&["run", "--profile", "recon", "claude"])).is_err());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn openrouter_runs_name_a_provider_qualified_model() {
        let Command::Run(request) = parse_args(args(&[
            "run",
            "--auth",
            "openrouter",
            "--model",
            "anthropic/claude-sonnet-4.6",
            "claude",
        ]))
        .unwrap() else {
            panic!("expected run request");
        };
        assert_eq!(request.auth.as_deref(), Some("openrouter"));
        assert_eq!(
            request.model.as_deref(),
            Some("anthropic/claude-sonnet-4.6")
        );
        let mut unqualified = request.clone();
        unqualified.model = Some("claude-sonnet-4-6".to_owned());
        let mut command = std::process::Command::new("true");
        let error = super::apply_model_auth(&mut command, &unqualified).unwrap_err();
        assert!(error.to_string().contains("PROVIDER/MODEL"), "{error}");
        let mut v8 = request;
        v8.harness = "v8".to_owned();
        assert!(super::apply_model_auth(&mut command, &v8).is_err());
    }

    #[test]
    fn pins_the_guest_model_and_names_the_credential_shape() {
        let Command::Run(request) = parse_args(args(&[
            "run",
            "--model",
            "us.anthropic.claude-opus-5",
            "--auth",
            "bedrock",
            "claude",
        ]))
        .unwrap() else {
            panic!("expected run request");
        };
        assert_eq!(request.model.as_deref(), Some("us.anthropic.claude-opus-5"));
        assert_eq!(request.auth.as_deref(), Some("bedrock"));
        let Command::Run(unpinned) = parse_args(args(&["run", "claude"])).unwrap() else {
            panic!("expected run request");
        };
        assert_eq!(
            unpinned.model, None,
            "a run was pinned to a model nobody named"
        );
        assert_eq!(unpinned.auth, None);
    }

    #[test]
    fn parses_exact_per_run_model_budgets_for_run_and_mux() {
        let Command::Run(request) = parse_args(args(&[
            "run",
            "--model-token-budget",
            "250000",
            "--model-cost-budget",
            "12.345678",
            "claude",
        ]))
        .unwrap() else {
            panic!("expected run request");
        };
        assert_eq!(request.model_token_budget, 250_000);
        assert_eq!(request.model_cost_budget_microusd, 12_345_678);

        let Command::Run(mux) = parse_args(args(&[
            "mux",
            "--model-token-budget",
            "42",
            "--model-cost-budget",
            "0.000001",
        ]))
        .unwrap() else {
            panic!("expected mux run request");
        };
        assert_eq!(mux.model_token_budget, 42);
        assert_eq!(mux.model_cost_budget_microusd, 1);
    }

    #[test]
    fn rejects_ambiguous_invalid_or_repeated_model_budgets() {
        for value in ["", "0", "-1", "1.5", "lots", "18446744073709551616"] {
            assert!(
                parse_args(args(&["run", "--model-token-budget", value, "claude"])).is_err(),
                "accepted token budget {value:?}"
            );
        }
        for value in [
            "",
            "0",
            "0.000000",
            ".5",
            "1.",
            "-1",
            "$10",
            "1e2",
            "1.0000001",
            "18446744073710",
        ] {
            assert!(
                parse_args(args(&["run", "--model-cost-budget", value, "claude"])).is_err(),
                "accepted cost budget {value:?}"
            );
        }
        assert!(
            parse_args(args(&[
                "run",
                "--model-token-budget",
                "1",
                "--model-token-budget",
                "2",
                "claude",
            ]))
            .is_err()
        );
        assert!(
            parse_args(args(&[
                "run",
                "--model-cost-budget",
                "1",
                "--model-cost-budget",
                "2",
                "claude",
            ]))
            .is_err()
        );
    }

    #[test]
    fn refuses_a_model_or_credential_shape_it_cannot_pass_on() {
        // Both values cross process boundaries as environment and as a request
        // path: one reaches a shell that writes the guest's environment, the
        // other decides which credential this run holds. Neither is a place to
        // forward something unvalidated.
        for model in ["", "opus 5", "opus;rm -rf /", "opus\n", "$(whoami)"] {
            assert!(
                parse_args(args(&["run", "--model", model, "claude"])).is_err(),
                "accepted model {model:?}"
            );
        }
        assert!(parse_args(args(&["run", "--auth", "sso", "claude"])).is_err());
        assert!(parse_args(args(&["run", "--auth", "claude"])).is_err());
    }

    #[test]
    fn never_treats_a_missing_harness_as_a_host_command() {
        assert!(parse_args(args(&["run", "--allow", "push:branch"])).is_err());
        assert!(parse_args(args(&["run", "--unknown", "claude"])).is_err());
        let Command::Run(request) = parse_args(args(&["run", "claude"])).unwrap() else {
            panic!("expected run request");
        };
        assert!(!request.reuse_connections);
        assert!(!request.mux);
        assert!(!request.keep_alive);
        assert_eq!(request.cpus, 2);
        assert!(parse_args(args(&["run", "--cpus", "0", "claude"])).is_err());
        assert!(parse_args(args(&["run", "--cpus", "65", "claude"])).is_err());
        assert!(parse_args(args(&["run", "--cpus", "many", "claude"])).is_err());
        let Command::Run(sized) = parse_args(args(&["run", "--memory", "8G", "claude"])).unwrap()
        else {
            panic!("expected run request");
        };
        assert_eq!(sized.memory_gib, 8);
        let Command::Run(default) = parse_args(args(&["run", "claude"])).unwrap() else {
            panic!("expected run request");
        };
        assert_eq!(default.memory_gib, 2);
        for invalid in ["0", "65", "8M", "lots"] {
            assert!(parse_args(args(&["run", "--memory", invalid, "claude"])).is_err());
        }
    }

    #[test]
    fn v8_modes_are_explicit_and_the_host_mode_requires_a_grant() {
        let Command::Run(vm) =
            parse_args(args(&["run", "--isolation", "vm-v8", "v8", "agent.ts"])).unwrap()
        else {
            panic!("expected VM V8 request");
        };
        assert_eq!(vm.isolation, super::IsolationMode::VmV8);
        assert_eq!(vm.harness_args, ["agent.ts"]);

        assert!(
            parse_args(args(&[
                "run",
                "--isolation",
                "v8-sandboxed",
                "v8",
                "agent.ts",
            ]))
            .is_err()
        );
        let Command::Run(host) = parse_args(args(&[
            "run",
            "--isolation",
            "v8-sandboxed",
            "--allow",
            "isolation:v8-sandboxed",
            "v8",
            "agent.ts",
        ]))
        .unwrap() else {
            panic!("expected host V8 request");
        };
        assert_eq!(host.isolation, super::IsolationMode::V8Sandboxed);
        assert!(host.allow.contains(&"isolation:v8-sandboxed".to_owned()));

        assert!(parse_args(args(&["run", "v8", "agent.ts"])).is_err());
        assert!(parse_args(args(&["run", "--isolation", "vm-v8", "claude"])).is_err());
        assert!(parse_args(args(&["run", "--isolation", "unknown", "claude"])).is_err());
    }

    #[test]
    fn direct_v8_runs_require_a_contained_javascript_entry() {
        let root = scratch_dir("direct-v8-entry");
        let workspace = root.join("workspace");
        let outside = root.join("outside");
        fs::create_dir_all(workspace.join("scripts")).unwrap();
        fs::create_dir(&outside).unwrap();
        for entry in ["agent.js", "scripts/agent.mjs", "agent.cjs"] {
            fs::write(workspace.join(entry), "console.log('ok');\n").unwrap();
            let Command::Run(mut request) =
                parse_args(args(&["run", "--isolation", "vm-v8", "v8", entry])).unwrap()
            else {
                panic!("expected direct V8 request");
            };
            validate_v8_request_entry(&mut request, &workspace).unwrap();
            assert_eq!(request.harness_args[0], entry);
        }

        fs::write(workspace.join("notes.txt"), "not JavaScript\n").unwrap();
        fs::write(outside.join("escape.js"), "console.log('escape');\n").unwrap();
        symlink(outside.join("escape.js"), workspace.join("linked.js")).unwrap();
        let invalid = [
            workspace.join("agent.js").to_string_lossy().into_owned(),
            "../outside/escape.js".to_owned(),
            "linked.js".to_owned(),
            "missing.js".to_owned(),
            "notes.txt".to_owned(),
        ];
        for entry in invalid {
            let Command::Run(mut request) =
                parse_args(args(&["run", "--isolation", "vm-v8", "v8", &entry])).unwrap()
            else {
                panic!("expected direct V8 request");
            };
            assert!(
                validate_v8_request_entry(&mut request, &workspace).is_err(),
                "direct V8 accepted invalid entry {entry:?}"
            );
        }

        let Command::Run(mut missing) =
            parse_args(args(&["run", "--isolation", "vm-v8", "v8"])).unwrap()
        else {
            panic!("expected direct V8 request");
        };
        assert!(validate_v8_request_entry(&mut missing, &workspace).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn lockfiles_derive_reviewable_registry_egress() {
        let root = scratch_dir("derived-egress");
        fs::write(root.join("Cargo.lock"), "").unwrap();
        fs::write(root.join("package-lock.json"), "{}").unwrap();
        let Command::Run(mut request) = parse_args(args(&["run", "claude"])).unwrap() else {
            panic!("run request");
        };
        super::derive_workspace_egress(&mut request, &root);
        assert!(request.allow.contains(&"egress:crates.io".to_owned()));
        assert!(request.allow.contains(&"egress:index.crates.io".to_owned()));
        assert!(
            request
                .allow
                .contains(&"egress:registry.npmjs.org".to_owned())
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn parses_persistent_session_commands() {
        assert_eq!(
            parse_args(args(&["attach", "session-1"])).unwrap(),
            Command::Attach {
                session_id: "session-1".to_owned()
            }
        );
        assert_eq!(
            parse_args(args(&["stop", "session-1"])).unwrap(),
            Command::Stop {
                session_id: "session-1".to_owned()
            }
        );
        assert!(parse_args(args(&["attach", "../escape"])).is_err());
        assert!(parse_args(args(&["stop"])).is_err());
    }

    #[test]
    fn old_run_requests_default_to_two_cpus() {
        let request: super::RunRequest = serde_json::from_str(
            r#"{"session_id":"old","provenance":"floor","allow":[],"harness":"claude","harness_args":[]}"#,
        )
        .unwrap();
        assert_eq!(request.cpus, 2);
        assert_eq!(request.isolation, super::IsolationMode::Vm);
        assert_eq!(
            request.model_token_budget,
            super::DEFAULT_MODEL_TOKEN_BUDGET
        );
        assert_eq!(
            request.model_cost_budget_microusd,
            super::DEFAULT_MODEL_COST_BUDGET_MICROUSD
        );
    }

    #[test]
    fn parses_only_valid_floor_lifts() {
        assert_eq!(
            parse_args(args(&["floor", "lift", "session-1"])).unwrap(),
            Command::FloorLift {
                session_id: "session-1".to_owned(),
                requested_floor: 3,
            }
        );
        assert_eq!(
            parse_args(args(&["floor", "lift", "session-1", "2"])).unwrap(),
            Command::FloorLift {
                session_id: "session-1".to_owned(),
                requested_floor: 2,
            }
        );
        assert!(parse_args(args(&["floor", "lift", "session-1", "0"])).is_err());
        assert!(parse_args(args(&["floor", "lift", "session-1", "4"])).is_err());
        assert!(parse_args(args(&["floor", "lift", "../other", "2"])).is_err());
    }

    #[test]
    fn parses_one_or_more_report_tasks() {
        assert_eq!(
            parse_args(args(&[
                "report",
                "one.ndjson",
                "one.key",
                "two.ndjson",
                "two.key"
            ]))
            .unwrap(),
            Command::Report {
                inputs: vec![
                    ReportInput {
                        audit: PathBuf::from("one.ndjson"),
                        key: PathBuf::from("one.key"),
                    },
                    ReportInput {
                        audit: PathBuf::from("two.ndjson"),
                        key: PathBuf::from("two.key"),
                    },
                ],
            }
        );
        assert!(parse_args(args(&["report", "audit-without-key"])).is_err());
    }

    #[test]
    fn reports_authenticated_escalation_fatigue_by_rule_and_mode() {
        let root = std::env::temp_dir().join(super::new_session_id());
        fs::create_dir(&root).unwrap();
        let first = write_report_task(
            &root,
            "first",
            "floor",
            &[
                ("approve", 1_000, "write-workspace", &["rule-a"]),
                ("deny", 3_000, "git-push", &["rule-a", "rule-b"]),
                ("approve", 2_500, "lift-floor", &["kernel:gate-required"]),
            ],
        );
        let second = write_report_task(
            &root,
            "second",
            "gate-context",
            &[("approve", 1_999, "git-push", &["rule-a"])],
        );

        let report = fatigue_report(&[first.clone(), second]).unwrap();
        assert!(report.contains(
            "overall:\n  tasks: 2\n  gate decisions/task: 2.00 (4)\n  visible prompts/task: 2.00 (4)"
        ));
        assert!(report.contains("approved floor lifts/task: 0.50 (1)"));
        assert!(report.contains("decision time ms: p50=1999 p95=3000 max=3000"));
        assert!(report.contains("approved <2s: 66.7% (2/3)"));
        assert!(report.contains(
            "rule-a: prompts/task 1.50 (3), prompt share 75.0% (3/4), approval rate 66.7% (2/3); gate decisions 3"
        ));
        assert!(report.contains("mode floor:\n  tasks: 1"));
        assert!(report.contains("mode gate-context:\n  tasks: 1"));

        let contents = fs::read_to_string(&first.audit).unwrap();
        fs::write(&first.audit, contents.replace("\"approve\"", "\"deny\"")).unwrap();
        assert!(fatigue_report(&[first]).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn floor_display_escapes_guest_control_sequences() {
        let status = FloorStatus {
            session_id: "session-1".to_owned(),
            floor: 1,
            provenance: ProvenanceMode::Floor,
            floor_history: vec![FloorObservation {
                rank: 1,
                source: serde_json::json!("Host(evil.example,\u{1b}[2J)"),
                timestamp_ms: 42,
            }],
        };
        let output = format_floor_status(&status);
        assert!(output.contains(r"Host(evil.example,\u001b[2J)"));
        assert!(!output.contains('\u{1b}'));
    }

    #[test]
    fn rejects_mismatched_and_invalid_floor_snapshots() {
        let path = std::env::temp_dir().join(format!(
            "keel-cli-floor-{}-{}.json",
            std::process::id(),
            super::new_session_id()
        ));
        fs::write(
            &path,
            br#"{"session_id":"other","floor":4,"provenance":"floor","floor_history":[]}"#,
        )
        .unwrap();
        assert!(load_floor_status(&path, "expected").is_err());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn parses_only_valid_status_requests() {
        assert_eq!(
            parse_args(args(&["status", "session-1"])).unwrap(),
            Command::Status {
                session_id: "session-1".to_owned(),
                audit: None,
            }
        );
        assert_eq!(
            parse_args(args(&["status", "session-1", "--audit", "a.ndjson"])).unwrap(),
            Command::Status {
                session_id: "session-1".to_owned(),
                audit: Some(PathBuf::from("a.ndjson")),
            }
        );
        assert!(parse_args(args(&["status", "../other"])).is_err());
        assert!(parse_args(args(&["status"])).is_err());
    }

    /// `keel status` reads the chain rather than asking the running system, so
    /// it must report the *last* state the kernel recorded, and must refuse
    /// outright when the chain no longer authenticates — a status line derived
    /// from an edited log is worse than no status line.
    #[test]
    fn status_reports_the_last_recorded_state_from_an_authenticated_chain() {
        let root = scratch_dir("status");
        let audit = write_enforcement_chain(&root, "audit-1-a-1");
        assert_eq!(super::latest_audit_chain(&root).unwrap(), audit);

        let report = super::session_enforcement_state("session-1", Some(&audit)).unwrap();
        assert_eq!(report.phase, "shutdown");
        assert_eq!(report.timestamp_ms, 2);
        let output = format_enforcement_report(&report);
        assert!(output.contains("phase: shutdown at 2"));
        assert!(
            output.contains("not fully enforced: network-floor (absent), provenance (advisory)")
        );
        assert!(output.contains("  egress-allowlist: active: hosts=0 []"));
        assert!(!output.contains('\u{1b}'));
        assert!(output.contains(r"\u{1b}[2J"));

        let contents = fs::read_to_string(&audit).unwrap();
        fs::write(&audit, contents.replace("absent", "active")).unwrap();
        assert!(super::session_enforcement_state("session-1", Some(&audit)).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_chain_without_its_run_key_is_not_a_status_candidate() {
        let root = scratch_dir("keyless");
        fs::write(root.join("audit-1-a-1.ndjson"), "{}\n").unwrap();
        assert!(super::latest_audit_chain(&root).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    fn scratch_dir(label: &str) -> PathBuf {
        let root =
            std::env::temp_dir().join(format!("keel-cli-{label}-{}", super::new_session_id()));
        fs::create_dir(&root).unwrap();
        root
    }

    fn write_enforcement_chain(root: &Path, name: &str) -> PathBuf {
        let audit = root.join(format!("{name}.ndjson"));
        let key = root.join(format!("{name}.key"));
        let run_key = RunKey::new([4; 32]);
        run_key.write_new(&key).unwrap();
        let writer = AuditWriter::spawn(
            &audit,
            "session-1",
            run_key,
            Redactor::new(Vec::<String>::new()).unwrap(),
        )
        .unwrap();
        for (index, phase) in ["start", "shutdown"].into_iter().enumerate() {
            writer
                .record(AuditPayload {
                    timestamp_ms: u64::try_from(index).unwrap() + 1,
                    event: "kernel.enforcement-state".to_owned(),
                    action_id: None,
                    fields: BTreeMap::from([
                        ("phase".to_owned(), phase.to_owned()),
                        (
                            "boundary.egress-allowlist".to_owned(),
                            "active: hosts=0 []".to_owned(),
                        ),
                        (
                            "boundary.network-floor".to_owned(),
                            "absent: link-local\u{1b}[2J".to_owned(),
                        ),
                        (
                            "boundary.provenance".to_owned(),
                            "advisory: gate-context: minimum rank not enforced".to_owned(),
                        ),
                    ]),
                })
                .unwrap();
        }
        writer.shutdown().unwrap();
        audit
    }

    fn write_report_task(
        root: &Path,
        name: &str,
        mode: &str,
        gates: &[(&str, u64, &str, &[&str])],
    ) -> ReportInput {
        let audit = root.join(format!("{name}.ndjson"));
        let key = root.join(format!("{name}.key"));
        let run_key = RunKey::new([u8::try_from(name.len()).unwrap(); 32]);
        run_key.write_new(&key).unwrap();
        let writer = AuditWriter::spawn(
            &audit,
            name,
            run_key,
            Redactor::new(Vec::<String>::new()).unwrap(),
        )
        .unwrap();
        for (index, (decision, time, class, rules)) in gates.iter().enumerate() {
            writer
                .record(AuditPayload {
                    timestamp_ms: u64::try_from(index).unwrap(),
                    event: "kernel.action".to_owned(),
                    action_id: Some(u64::try_from(index).unwrap()),
                    fields: BTreeMap::from([
                        ("action_class".to_owned(), (*class).to_owned()),
                        ("gate_decision".to_owned(), (*decision).to_owned()),
                        ("gate_floor".to_owned(), "1".to_owned()),
                        ("gate_authority".to_owned(), "operator".to_owned()),
                        ("gate_time_ms".to_owned(), time.to_string()),
                        ("prompt_presented".to_owned(), "true".to_owned()),
                        ("provenance_mode".to_owned(), mode.to_owned()),
                        ("rules".to_owned(), serde_json::to_string(rules).unwrap()),
                    ]),
                })
                .unwrap();
        }
        writer.shutdown().unwrap();
        ReportInput { audit, key }
    }
}

#[cfg(test)]
mod axes_tests {
    use super::{
        AuditRecord, AxesDecision, AxesSummary, Command, ContextSummary, axes_decision, parse_args,
    };
    use std::{collections::BTreeMap, ffi::OsString};

    fn fields(entries: &[(&str, &str)]) -> BTreeMap<String, String> {
        entries
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect()
    }

    #[test]
    fn decisions_follow_the_action_centric_table() {
        let none = Vec::new();
        assert_eq!(axes_decision("inside", "clean", &none), AxesDecision::Allow);
        assert_eq!(
            axes_decision("inside", "unaccounted:3/40", &none),
            AxesDecision::Prompt,
            "unaccounted content entering a protected place prompts"
        );
        assert_eq!(
            axes_decision("inside", "not-checked", &["kernel:minimum-rank".to_owned()]),
            AxesDecision::Allow,
            "the floor alone no longer prompts inside intent"
        );
        assert_eq!(
            axes_decision("egress-host", "clean", &none),
            AxesDecision::Prompt
        );
        assert_eq!(
            axes_decision("inside", "private-to-public:3", &none),
            AxesDecision::Prompt
        );
        assert_eq!(
            axes_decision("inside", "secret-to-private:1", &none),
            AxesDecision::Deny
        );
        assert_eq!(
            axes_decision("inside", "clean", &["policy:escalate-writes".to_owned()]),
            AxesDecision::Prompt,
            "rules the model does not replace still prompt"
        );
    }

    #[test]
    fn summary_counts_avoided_and_added_prompts_and_skips_resource_and_setup() {
        let mut summary = AxesSummary::default();
        // Prompted today only because of the floor: avoided.
        summary.observe(
            1,
            &fields(&[
                ("intent", "inside"),
                ("flow", "clean"),
                ("rules", r#"["kernel:minimum-rank"]"#),
                ("prompt_presented", "true"),
            ]),
        );
        // Silently allowed today, but carries private content outward: added.
        summary.observe(
            2,
            &fields(&[
                ("intent", "inside"),
                ("flow", "private-to-public:9"),
                ("rules", "[]"),
            ]),
        );
        // A model-budget refusal, a setup leg, and an action from before the
        // verdicts existed are not judged as prompts.
        summary.observe(
            3,
            &fields(&[
                ("intent", "inside"),
                ("rules", r#"["kernel:model-budget"]"#),
                ("gate_decision", "deny"),
            ]),
        );
        summary.observe(
            4,
            &fields(&[
                ("intent", "egress-host"),
                ("flow", "not-checked"),
                ("rules", "[]"),
            ]),
        );
        summary.observe(5, &fields(&[("outcome", "executed")]));

        assert_eq!(summary.effects, 2);
        assert_eq!(summary.prompted_today, 1);
        assert_eq!(summary.avoided.len(), 1);
        assert_eq!(summary.added.len(), 1);
        assert_eq!(summary.unrecorded, 1);
    }

    fn context_record(phase: &str, sequence: &str, blocks: &str) -> AuditRecord {
        AuditRecord {
            seq: 0,
            run_id: "run".to_owned(),
            previous_hash: String::new(),
            payload: keel_audit::AuditPayload {
                timestamp_ms: 0,
                event: "kernel.model-context".to_owned(),
                action_id: Some(1),
                fields: fields(&[("phase", phase), ("sequence", sequence), ("blocks", blocks)]),
            },
            record_hash: String::new(),
            mac: String::new(),
        }
    }

    #[test]
    fn context_summary_separates_model_output_from_tool_output() {
        let records = [
            context_record(
                "request",
                "s1 u1",
                r#"[{"place":"system","kind":"text","digest":"s1"},
                    {"place":"messages.0.user","kind":"text","digest":"u1"}]"#,
            ),
            context_record(
                "response",
                "a1",
                r#"[{"place":"response","kind":"tool_use","digest":"a1","tool_use":"t1"}]"#,
            ),
            context_record(
                "request",
                "s1 u1 a1 r1 f1",
                r#"[{"place":"messages.2.user","kind":"tool_result","digest":"r1","tool_use":"t1"},
                    {"place":"messages.3.assistant","kind":"text","digest":"f1"}]"#,
            ),
        ];
        let summary = ContextSummary::observe(&records);
        assert_eq!((summary.requests, summary.responses), (2, 1));
        assert_eq!(
            summary.untainted, 1,
            "only the first request has no tool output"
        );
        assert_eq!(summary.system_variants.len(), 1);
        assert_eq!(summary.blocks["assistant, emitted by the model"], 1);
        assert_eq!(summary.blocks["assistant, not emitted by the model"], 1);
        assert_eq!(summary.blocks["tool result, bound to a model tool call"], 1);
        assert_eq!(summary.blocks["system"], 2);
    }

    #[test]
    fn sessions_are_classified_and_manifests_summarized() {
        let chain = std::path::Path::new("/nonexistent/audit-4194303-abc-0.ndjson");
        assert_eq!(super::session_state(chain, true), "closed");
        assert_eq!(super::session_state(chain, false), "interrupted");
        let own = format!("/nonexistent/audit-{}-abc-0.ndjson", std::process::id());
        assert_eq!(
            super::session_state(std::path::Path::new(&own), false),
            "interrupted",
            "a live process that is not the trusted runtime does not count"
        );
        let mut record = context_record("request", "", "[]");
        record.payload.event = "kernel.run-admitted".to_owned();
        record.payload.fields = fields(&[
            (
                "manifest",
                r#"{"kernel_release":"6.12.111-0-virt","model":{"model":"anthropic/claude-sonnet-4.6","provider":"openrouter"},"policy_bundle":null,"run":{"harness":"claude"}}"#,
            ),
            ("manifest_sha256", "0123456789abcdef0123"),
        ]);
        assert_eq!(
            super::manifest_summary(&[record]).as_deref(),
            Some(
                "claude on anthropic/claude-sonnet-4.6 via openrouter, kernel 6.12.111-0-virt, policy none, manifest 0123456789ab"
            )
        );
        let mut grouped = context_record("request", "", "[]");
        grouped.payload.event = "kernel.run-admitted".to_owned();
        grouped.payload.fields = fields(&[(
            "manifest",
            r#"{"kernel_release":"6.12.111-0-virt","model":{"model":"m","provider":"bedrock"},"run":{"harness":"claude"}}"#,
        )]);
        assert_eq!(
            super::manifest_group(&[grouped]),
            "claude on m via bedrock, kernel 6.12.111-0-virt"
        );
        assert_eq!(super::manifest_summary(&[]), None);
        assert_eq!(super::manifest_group(&[]), "no admission manifest");
    }

    #[test]
    fn report_context_parses_sessions() {
        assert!(matches!(
            parse_args(["report", "--context"].map(OsString::from).to_vec()).unwrap(),
            Command::ReportContext { sessions } if sessions.is_empty()
        ));
    }

    #[test]
    fn report_axes_parses_sessions() {
        let Command::ReportAxes { sessions } =
            parse_args(["report", "--axes", "run-1"].map(OsString::from).to_vec()).unwrap()
        else {
            panic!("axes report");
        };
        assert_eq!(sessions, ["run-1"]);
        assert!(parse_args(["report", "--axes", "../x"].map(OsString::from).to_vec()).is_err());
    }
}
