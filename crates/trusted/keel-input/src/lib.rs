#![forbid(unsafe_code)]
#![doc = "Trusted operator-input path for Keel."]

use keel_audit::{AuditWriter, KernelAudit, Redactor, RunKey};
pub use keel_kernel::{
    ApprovalMethod, GateController, GatePayload, GateReason, PendingApproval, TerminalGate,
    terminal_gate_channel,
};
use keel_kernel::{
    BrokerReport, EnforcementBoundary, EnforcementState, Gate, KernelBroker, KernelBrokerControl,
    ModelBudgetLimits, PayloadPolicy, ProvenanceMode,
};
use keel_policy::{ArtifactHash, StatefulPolicy};
use keel_provenance::{
    FloorState, IntentFlags, PayloadIndex, PersistedMode, Scope, SessionFacts, SourceRef,
    TaskAdmission, trusted_git_command,
};
use keel_secrets::{GitCredentialScope, GitHubAuthorities, SystemEgressConnector};
use ring::digest::{Context as DigestContext, SHA256};
use serde::Deserialize;
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};
mod manifest;

static AUDIT_PATH_SEQUENCE: AtomicU64 = AtomicU64::new(0);
/// The secure-attention byte reserved by the Phase 0 terminal spike.
pub const SECURE_ATTENTION: u8 = 0x1d;
const MAX_CHALLENGE: usize = 16;
const MAX_REQUEST_FILE: usize = 1024 * 1024;

#[derive(Deserialize)]
struct RunRequestView {
    session_id: String,
    provenance: String,
    #[serde(default = "default_isolation")]
    isolation: String,
    #[serde(default)]
    reuse_connections: bool,
    #[serde(default)]
    mux: bool,
    #[serde(default)]
    policy_bundle_hash: Option<String>,
    model_token_budget: Option<u64>,
    model_cost_budget_microusd: Option<u64>,
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    cpus: Option<u64>,
    #[serde(default)]
    memory_gib: Option<u64>,
    #[serde(default)]
    profile: Option<String>,
    #[serde(default)]
    scope: Vec<String>,
    #[serde(default)]
    exclude: Vec<String>,
    allow: Vec<String>,
    harness: String,
}

fn default_isolation() -> String {
    "vm".to_owned()
}

/// A triage run's declared scope. The operator admits it, and the run's
/// provider, on the trusted terminal before anything starts.
fn triage_scope(request: &RunRequestView) -> Result<Option<Scope>, String> {
    match request.profile.as_deref() {
        None => Ok(None),
        Some("triage") => Scope::parse(&request.scope, &request.exclude).map(Some),
        Some(other) => Err(format!("unknown run profile `{other}`")),
    }
}

/// Refuses a triage run whose model provider is not on the approved list,
/// because the model endpoint receives the report and everything the run sees.
fn approved_for_triage(
    provider: &keel_secrets::ModelProvider,
    scope: Option<&Scope>,
) -> Result<(), String> {
    if scope.is_none() {
        return Ok(());
    }
    let approved =
        std::env::var("KEEL_TRIAGE_PROVIDERS").unwrap_or_else(|_| "anthropic,bedrock".to_owned());
    if approved
        .split(',')
        .any(|name| name.trim() == provider.name())
    {
        Ok(())
    } else {
        Err(format!(
            "triage runs use only approved model providers ({approved}), not {}",
            provider.name()
        ))
    }
}

fn parse_model_budget(request: &RunRequestView) -> Result<(ModelBudgetLimits, bool), String> {
    let default = ModelBudgetLimits::default();
    let limits = ModelBudgetLimits {
        token_limit: request.model_token_budget.unwrap_or(default.token_limit),
        cost_limit_microusd: request
            .model_cost_budget_microusd
            .unwrap_or(default.cost_limit_microusd),
    }
    .validate()?;
    let elevated = limits.token_limit > default.token_limit
        || limits.cost_limit_microusd > default.cost_limit_microusd;
    Ok((limits, elevated))
}

/// Trusted subset of one runtime request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeIntent {
    session_id: String,
    egress_hosts: BTreeSet<String>,
    /// The model host for this run, or empty for a harness with no model egress.
    model_host: String,
    capabilities: BTreeSet<String>,
    state_directory: PathBuf,
    provenance: ProvenanceMode,
    reuse_connections: bool,
    mux: bool,
    isolation: String,
    policy_bundle_hash: Option<String>,
    model_budget_limits: ModelBudgetLimits,
    /// The `OpenRouter` price snapshot this run's budget is charged at, which
    /// the operator must admit because the untrusted launcher fetched it.
    model_tariff: Option<String>,
    task_admission: TaskAdmission,
    harness: String,
    model: Option<String>,
    cpus: Option<u64>,
    memory_gib: Option<u64>,
    /// A triage run's operator-declared scope.
    scope: Option<Scope>,
}

impl RuntimeIntent {
    /// Reads the trusted session and structured egress intent from runtime
    /// arguments of the form `run --request REQUEST.json`.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed arguments, oversized or invalid JSON,
    /// invalid session identifiers, or malformed egress host capabilities.
    #[allow(clippy::too_many_lines)]
    pub fn from_runtime_arguments(arguments: &[std::ffi::OsString]) -> Result<Self, String> {
        let [run, request_flag, request_path] = arguments else {
            return Err("expected runtime arguments: run --request REQUEST.json".to_owned());
        };
        if run != "run" || request_flag != "--request" {
            return Err("expected runtime arguments: run --request REQUEST.json".to_owned());
        }
        let request_path = Path::new(request_path);
        let bytes = fs::read(request_path).map_err(|error| error.to_string())?;
        if bytes.len() > MAX_REQUEST_FILE {
            return Err("runtime request exceeds 1 MiB".to_owned());
        }
        let request: RunRequestView =
            serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
        if request.session_id.is_empty() || request.session_id.chars().any(char::is_control) {
            return Err("runtime request contains an invalid session id".to_owned());
        }
        let (model_budget_limits, mut task_authority) = parse_model_budget(&request)?;
        let scope = triage_scope(&request)?;
        let (mut egress_hosts, capabilities) =
            parse_capabilities(request.allow, &mut task_authority)?;
        let mut model_host = String::new();
        let mut model_tariff = None;
        task_authority |= scope.is_some();
        match request.isolation.as_str() {
            "vm" if request.harness == "v8" => {
                return Err("the v8 harness cannot run in plain vm mode".to_owned());
            }
            "vm" => {}
            "vm-v8" if request.harness == "v8" => {}
            "v8-sandboxed"
                if request.harness == "v8" && capabilities.contains("isolation:v8-sandboxed") => {}
            "v8-sandboxed" if request.harness != "v8" => {
                return Err("v8-sandboxed isolation requires the v8 harness".to_owned());
            }
            "v8-sandboxed" => {
                return Err(
                    "v8-sandboxed isolation requires the isolation:v8-sandboxed capability"
                        .to_owned(),
                );
            }
            "vm-v8" => return Err("vm-v8 isolation requires the v8 harness".to_owned()),
            _ => return Err("runtime request contains an invalid isolation mode".to_owned()),
        }
        if matches!(request.harness.as_str(), "claude" | "v8") {
            // Which model host a run may reach is configuration, never something
            // the guest or its capability flags name: the provider selection and
            // its region both come from the trusted environment.
            let provider = keel_secrets::runtime_model_provider()?;
            if let Some(model) = request.model.as_deref() {
                keel_secrets::validate_model_tariff(&provider, model)?;
            }
            if provider.host == keel_secrets::OPENROUTER_HOST {
                let (model, input, output) = keel_secrets::openrouter_snapshot()
                    .filter(|(model, _, _)| request.model.as_deref() == Some(model.as_str()))
                    .ok_or("an OpenRouter run needs a price snapshot for its pinned model")?;
                model_tariff = Some(format!(
                    "model-tariff: {model} input={input} output={output} micro-USD per token (OpenRouter snapshot)"
                ));
                task_authority = true;
            }
            approved_for_triage(&provider, scope.as_ref())?;
            model_host = provider.host;
            egress_hosts.insert(model_host.clone());
            if let Some(region) = provider.region {
                // Recent Claude Code releases probe Bedrock's control endpoint
                // before using Bedrock Runtime. The TLS proxy admits the
                // connection so it can return a clean refusal, but deliberately
                // refuses every control-plane HTTP operation before forwarding
                // application bytes upstream.
                egress_hosts.insert(format!("bedrock.{region}.amazonaws.com"));
            }
        }
        if capabilities.contains("pr:create") || capabilities.contains("github:read-private-issues")
        {
            egress_hosts.insert("api.github.com".to_owned());
        }
        let state_directory = request_path
            .parent()
            .ok_or_else(|| "runtime request has no state directory".to_owned())?
            .canonicalize()
            .map_err(|error| error.to_string())?;
        Ok(Self {
            session_id: request.session_id,
            egress_hosts,
            model_host,
            capabilities,
            state_directory,
            reuse_connections: request.reuse_connections,
            mux: request.mux,
            isolation: request.isolation,
            policy_bundle_hash: request.policy_bundle_hash,
            model_budget_limits,
            model_tariff,
            harness: request.harness,
            model: request.model,
            cpus: request.cpus,
            memory_gib: request.memory_gib,
            scope,
            task_admission: if task_authority {
                TaskAdmission::Absent
            } else {
                TaskAdmission::NotRequired
            },
            provenance: match request.provenance.as_str() {
                "floor" => ProvenanceMode::Floor,
                "gate-context" => ProvenanceMode::GateContext,
                _ => return Err("runtime request contains an invalid provenance mode".to_owned()),
            },
        })
    }

    /// Returns the validated session identifier used in terminal chrome.
    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Returns whether this run requested the stateful mux display.
    #[must_use]
    pub const fn mux(&self) -> bool {
        self.mux
    }

    /// Returns the isolation profile admitted by the trusted parser.
    #[must_use]
    pub fn isolation(&self) -> &str {
        &self.isolation
    }

    /// Returns the declared authority that still needs trusted admission.
    #[must_use]
    pub fn task_admission(&self) -> Option<String> {
        (self.task_admission == TaskAdmission::Absent).then(|| self.admission_summary())
    }

    /// The exact authority summary trusted input shows for admission.
    fn admission_summary(&self) -> String {
        let mut items = self
            .capabilities
            .iter()
            .filter(|capability| capability.as_str() != "isolation:v8-sandboxed")
            .cloned()
            .collect::<Vec<_>>();
        items.extend(
            self.egress_hosts
                .iter()
                .map(|host| format!("egress:{host}")),
        );
        let cost = self.model_budget_limits.cost_limit_microusd;
        items.push(format!(
            "model-budget: token ceiling={} cost ceiling={cost} micro-USD (USD {}.{:06})",
            self.model_budget_limits.token_limit,
            cost / 1_000_000,
            cost % 1_000_000,
        ));
        items.extend(self.model_tariff.clone());
        items.extend(self.scope.as_ref().map(|scope| {
            format!(
                "triage scope (all else refused): {}",
                scope.describe().join(" ")
            )
        }));
        items.join("\r\n  ")
    }

    /// Marks this exact parsed task manifest as admitted by trusted input.
    pub fn admit_task(&mut self) {
        self.task_admission = TaskAdmission::Trusted;
    }

    /// Starts the trusted kernel broker for this parsed intent.
    ///
    /// # Errors
    ///
    /// Returns an error when the private action channel cannot be created.
    pub fn start_kernel_broker(self) -> Result<RuntimeBroker, String> {
        self.start_kernel_broker_inner(None)
    }
    /// Starts the trusted kernel broker with an interactive terminal gate.
    ///
    /// # Errors
    ///
    /// Returns an error when audit storage or the private action channel
    /// cannot be created.
    pub fn start_kernel_broker_with_gate(
        self,
        gate: TerminalGate,
    ) -> Result<RuntimeBroker, String> {
        self.start_kernel_broker_inner(Some(Box::new(gate)))
    }
    /// Whether the model ceiling exceeds the defaults or the run is charged at
    /// a launcher-fetched price snapshot.
    fn model_terms_need_admission(&self) -> bool {
        let default = ModelBudgetLimits::default();
        self.model_tariff.is_some()
            || self.model_budget_limits.token_limit > default.token_limit
            || self.model_budget_limits.cost_limit_microusd > default.cost_limit_microusd
    }

    #[allow(clippy::too_many_lines)]
    fn start_kernel_broker_inner(
        self,
        gate: Option<Box<dyn Gate>>,
    ) -> Result<RuntimeBroker, String> {
        if self.model_terms_need_admission() && self.task_admission != TaskAdmission::Trusted {
            return Err("elevated model budget requires trusted task admission".to_owned());
        }
        let workspace = std::env::current_dir()
            .and_then(|path| path.canonicalize())
            .map_err(|error| error.to_string())?;
        let git_control_digest = git_control_digest(&workspace)?;
        let (push_refs, pr_targets) = (
            scoped(&self.capabilities, "push:ref:"),
            scoped(&self.capabilities, "pr:target:"),
        );
        let allow_git_push = self.capabilities.contains("push:branch") || !push_refs.is_empty();
        let public_workspace = self.capabilities.contains("workspace:public");
        let allow_pr_create = self.capabilities.contains("pr:create");
        let allow_private_issue_reads = self.capabilities.contains("github:read-private-issues");
        let (connector, git_scope, github_private_repository, redactor) =
            SystemEgressConnector::from_runtime_environment(
                allow_git_push,
                GitHubAuthorities::new(allow_pr_create, allow_private_issue_reads),
                !self.model_host.is_empty(),
            )?;
        let connector = Box::new(connector.with_connection_reuse(self.reuse_connections));
        // Mediating a Git operation means the trusted relay itself connects to the
        // remote, so the credential's own host has to be in the run's egress intent.
        // Without this, `--allow push:branch` authorizes the push and then gates the
        // transport leg it requires, which no Git client waits out.
        let mut egress_hosts = self.egress_hosts.clone();
        if let Some(scope) = &git_scope {
            egress_hosts.insert(scope.host.clone());
        }
        let admission = self.admission_core(
            &workspace,
            git_control_digest,
            &egress_hosts,
            &connector.credential_scopes(),
        );
        let (audit, audit_path, key_path) =
            start_audit(&self.state_directory, &self.session_id, redactor)?;
        let state_path = self.state_directory.join("floor.json");
        // The session directory is prepared by the untrusted CLI. Persisted
        // floor state therefore cannot authorize a new trusted run. Begin from
        // a conservative observation of the directly exposed workspace; the
        // file remains useful as non-authoritative continuity metadata only.
        let mut session_facts = SessionFacts::default();
        session_facts.target_created_by_vertex = false;
        session_facts.record_floor_observation(
            0,
            SourceRef::File {
                path: "workspace://direct-exposure".to_owned(),
                author: None,
            },
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|error| error.to_string())?
                .as_millis()
                .try_into()
                .unwrap_or(u64::MAX),
        );
        session_facts.intent = IntentFlags {
            task_admission: self.task_admission,
            allow_push_branch: allow_git_push,
            allow_pr_create,
            deny_force_push: self.capabilities.contains("deny:force-push"),
            allowed_egress_hosts: egress_hosts.clone(),
            push_refs,
            pr_targets,
            scope: self.scope.clone(),
        };
        let policy_directory = self.state_directory.join("policy");
        let policy = if let Some(hash) = &self.policy_bundle_hash {
            StatefulPolicy::load(
                &policy_directory,
                ArtifactHash::parse(hash).map_err(|error| error.to_string())?,
            )
        } else if policy_directory.exists() {
            return Err("session policy exists without a pinned run-request hash".to_owned());
        } else {
            StatefulPolicy::new()
        }
        .map_err(|error| error.to_string())?;
        let broker = KernelBroker::spawn_with_diagnostics(
            self.session_id.clone(),
            egress_hosts,
            self.capabilities,
            self.model_host,
            session_facts,
            self.provenance,
            Box::new(policy),
            connector,
            Box::new(audit),
            gate,
            self.model_budget_limits,
            // Do not follow an attacker-prepared diagnostic path in the
            // untrusted session directory. Broker failures remain in the
            // authenticated audit stream and terminal diagnostics.
            None,
        )?;
        broker.set_payload_policy(payload_policy(&workspace, public_workspace)?)?;
        Ok(RuntimeBroker {
            broker,
            audit_path,
            key_path,
            git_scope,
            github_private_repository,
            session_id: self.session_id,
            state_path,
            persisted_mode: match self.provenance {
                ProvenanceMode::Floor => PersistedMode::Floor,
                ProvenanceMode::GateContext => PersistedMode::GateContext,
            },
            workspace,
            git_control_digest,
            admission,
        })
    }

    /// Everything this run was admitted with, before boot-artifact digests.
    fn admission_core(
        &self,
        workspace: &Path,
        git_control: Option<[u8; 32]>,
        egress_hosts: &BTreeSet<String>,
        credential_scopes: &[String],
    ) -> serde_json::Value {
        let provider = keel_secrets::runtime_model_provider()
            .ok()
            .filter(|_| !self.model_host.is_empty());
        let tariff = provider
            .as_ref()
            .zip(self.model.as_deref())
            .and_then(|(provider, model)| keel_secrets::model_tariff(provider, model))
            .map(|(input, output, source)| {
                serde_json::json!({ "input": input, "output": output, "source": source })
            });
        let name = provider.as_ref().map(keel_secrets::ModelProvider::name);
        let (head, dirty, origin) = manifest::workspace_state(workspace);
        let admitted = self.task_admission == TaskAdmission::Trusted;
        serde_json::json!({
            "version": 1,
            "run_id": self.session_id,
            "keel_build": env!("CARGO_PKG_VERSION"),
            "policy_bundle": self.policy_bundle_hash,
            "workspace": {
                "root": workspace.display().to_string(),
                "head": head,
                "dirty": dirty,
                "origin": origin,
                "git_control": git_control.map(|digest| manifest::hex(&digest)),
            },
            "authority": {
                "capabilities": self.capabilities,
                "egress_hosts": egress_hosts,
                "credential_scopes": credential_scopes,
            },
            "model": {
                "provider": name,
                "host": provider.as_ref().map(|provider| provider.host.clone()),
                "region": provider.and_then(|provider| provider.region),
                "model": self.model,
                "tariff": tariff,
                "token_ceiling": self.model_budget_limits.token_limit,
                "microusd_ceiling": self.model_budget_limits.cost_limit_microusd,
            },
            "run": {
                "harness": self.harness,
                "isolation": self.isolation,
                "cpus": self.cpus,
                "memory_gib": self.memory_gib,
                "provenance_mode": match self.provenance {
                    ProvenanceMode::Floor => "floor",
                    ProvenanceMode::GateContext => "gate-context",
                },
                "starting_floor": 0,
                "connection_reuse": self.reuse_connections,
                "mux": self.mux,
                "profile": self.scope.as_ref().map(|_| "triage"),
                "scope": self.scope.as_ref().map(Scope::describe),
            },
            "admission": {
                "admitted_by": if admitted { "trusted-terminal" } else { "not-required" },
                "summary_sha256": admitted.then(|| {
                    manifest::hex(ring::digest::digest(&SHA256, self.admission_summary().as_bytes()).as_ref())
                }),
            },
        })
    }
}
/// Trusted runtime broker and its durable audit artifacts.
pub struct RuntimeBroker {
    broker: KernelBroker,
    audit_path: PathBuf,
    key_path: PathBuf,
    git_scope: Option<GitCredentialScope>,
    github_private_repository: Option<String>,
    session_id: String,
    state_path: PathBuf,
    persisted_mode: PersistedMode,
    workspace: PathBuf,
    git_control_digest: Option<[u8; 32]>,
    /// The admission manifest, completed with artifact digests at boot.
    admission: serde_json::Value,
}
impl RuntimeBroker {
    /// Records the admission manifest, completed with these boot-artifact
    /// digests, in the audit chain. Call before any workload process exists.
    ///
    /// # Errors
    ///
    /// Returns an error when an artifact cannot be hashed or the record cannot
    /// be written; the run must then refuse to start.
    pub fn record_admission(
        &self,
        artifacts: &[(&str, &Path)],
        kernel_release: Option<&str>,
    ) -> Result<(), String> {
        let event = manifest::finish(self.admission.clone(), artifacts, kernel_release)?;
        self.broker.record_run_admitted(event)
    }
    /// Returns the private kernel action socket.
    #[must_use]
    pub fn socket_path(&self) -> &Path {
        self.broker.socket_path()
    }
    /// Returns the public run CA certificate.
    #[must_use]
    pub fn ca_certificate_pem(&self) -> Option<&str> {
        self.broker.ca_certificate_pem()
    }
    /// Returns the non-secret Git credential sentinel exposed to the relay.
    #[must_use]
    pub fn git_sentinel(&self) -> Option<&str> {
        self.git_scope.as_ref().map(|scope| scope.sentinel.as_str())
    }
    /// Returns the exact GitHub repository whose issue reads may use the
    /// host-held GitHub credential.
    ///
    /// The value is derived from admitted repository metadata, never from
    /// an MCP argument. Other issue reads remain anonymous.
    #[must_use]
    pub fn github_private_repository(&self) -> Option<&str> {
        self.github_private_repository.as_deref()
    }
    /// Returns the authenticated audit stream path.
    #[must_use]
    pub fn audit_path(&self) -> &Path {
        &self.audit_path
    }
    /// Returns the mode-0600 audit verification key path.
    #[must_use]
    pub fn audit_key_path(&self) -> &Path {
        &self.key_path
    }
    /// Returns a trusted control path to this live broker.
    #[must_use]
    pub fn control(&self) -> KernelBrokerControl {
        self.broker.control()
    }
    /// Stops the kernel and durably closes the audit chain.
    ///
    /// # Errors
    ///
    /// Returns an error when broker or audit shutdown fails.
    pub fn shutdown(self) -> Result<BrokerReport, String> {
        let current = git_control_digest(&self.workspace);
        let changed = current.as_ref().ok() != Some(&self.git_control_digest);
        let detail = match &current {
            Ok(_) if changed => "changed during run",
            Ok(_) => "unchanged since admission",
            Err(_) => "could not be read at shutdown",
        };
        if changed {
            eprintln!("KEEL SECURITY WARNING: .git/config or .git/hooks changed during this run");
        }
        let report = self
            .broker
            .shutdown_with_boundaries(vec![EnforcementBoundary {
                name: "workspace-git-control-files",
                state: if changed {
                    EnforcementState::Advisory
                } else {
                    EnforcementState::Active
                },
                detail: detail.to_owned(),
            }])?;
        FloorState::capture(&self.session_id, self.persisted_mode, &report.session_facts)
            .save(&self.state_path)
            .map_err(|error| error.to_string())?;
        Ok(report)
    }
}

fn git_control_digest(workspace: &Path) -> Result<Option<[u8; 32]>, String> {
    const MAX_FILES: usize = 256;
    const MAX_FILE_BYTES: u64 = 1024 * 1024;

    let git = workspace.join(".git");
    let metadata = match fs::symlink_metadata(&git) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.to_string()),
    };
    let mut paths = if metadata.is_dir() {
        let mut paths = vec![git.join("config")];
        let hooks = git.join("hooks");
        match fs::symlink_metadata(&hooks) {
            Ok(hooks_metadata) if hooks_metadata.is_dir() => {
                let entries = fs::read_dir(&hooks).map_err(|error| error.to_string())?;
                for entry in entries.take(MAX_FILES + 1) {
                    paths.push(entry.map_err(|error| error.to_string())?.path());
                }
            }
            Ok(_) => paths.push(hooks),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.to_string()),
        }
        paths
    } else {
        vec![git]
    };
    paths.sort();
    if paths.len() > MAX_FILES + 1 {
        return Err("too many Git control files".to_owned());
    }
    let mut digest = DigestContext::new(&SHA256);
    for path in paths {
        let path_bytes = path.as_os_str().as_encoded_bytes();
        digest.update(&(path_bytes.len() as u64).to_be_bytes());
        digest.update(path_bytes);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                digest.update(&[0]);
                continue;
            }
            Err(error) => return Err(error.to_string()),
        };
        if metadata.file_type().is_symlink() {
            digest.update(&[1]);
            let target = fs::read_link(&path).map_err(|error| error.to_string())?;
            digest.update(target.as_os_str().as_encoded_bytes());
        } else if metadata.is_file() {
            if metadata.len() > MAX_FILE_BYTES {
                return Err("Git control file exceeds 1 MiB".to_owned());
            }
            digest.update(&[2]);
            digest.update(&fs::read(&path).map_err(|error| error.to_string())?);
        } else {
            digest.update(&[3]);
        }
    }
    let mut output = [0_u8; 32];
    output.copy_from_slice(digest.finish().as_ref());
    Ok(Some(output))
}
fn start_audit(
    directory: &Path,
    session_id: &str,
    redactor: Redactor,
) -> Result<(KernelAudit, PathBuf, PathBuf), String> {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_nanos();
    let sequence = AUDIT_PATH_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let artifact = format!("audit-{}-{nonce:x}-{sequence:x}", std::process::id());
    let audit_path = directory.join(format!("{artifact}.ndjson"));
    let key_path = directory.join(format!("{artifact}.key"));
    let run_key = RunKey::generate().map_err(|error| error.to_string())?;
    run_key
        .write_new(&key_path)
        .map_err(|error| error.to_string())?;
    let writer = match AuditWriter::spawn(&audit_path, session_id, run_key, redactor) {
        Ok(writer) => writer,
        Err(error) => {
            let _ = fs::remove_file(&key_path);
            return Err(error.to_string());
        }
    };
    Ok((KernelAudit::new(writer), audit_path, key_path))
}

/// Validates requested capabilities into admitted egress hosts and the closed
/// capability set, noting whether any of them needs trusted task admission.
fn parse_capabilities(
    allow: Vec<String>,
    task_authority: &mut bool,
) -> Result<(BTreeSet<String>, BTreeSet<String>), String> {
    let mut egress_hosts = BTreeSet::new();
    let mut capabilities = BTreeSet::new();
    for capability in allow {
        if let Some(host) = capability.strip_prefix("egress:") {
            egress_hosts.insert(normalize_dns_name(host)?);
            *task_authority = true;
        } else if capability
            .strip_prefix("push:ref:refs/heads/")
            .or_else(|| capability.strip_prefix("pr:target:"))
            .is_some_and(valid_ref_scope)
        {
            *task_authority = true;
            capabilities.insert(capability);
        } else if matches!(
            capability.as_str(),
            "push:branch"
                | "pr:create"
                | "github:read-private-issues"
                | "deny:force-push"
                | "isolation:v8-sandboxed"
                | "workspace:public"
        ) {
            *task_authority |= capability != "isolation:v8-sandboxed";
            capabilities.insert(capability);
        } else {
            return Err(format!("unsupported runtime capability: {capability}"));
        }
    }
    if capabilities
        .iter()
        .any(|capability| capability.starts_with("pr:target:"))
        && !capabilities.contains("pr:create")
    {
        return Err("pr:target narrows pr:create and requires it".to_owned());
    }
    Ok((egress_hosts, capabilities))
}

/// Indexes the committed tree as private content, unless the operator
/// declared the repository public, and clears the workspace's own GitHub
/// origin to receive it.
fn payload_policy(workspace: &Path, public: bool) -> Result<PayloadPolicy, String> {
    let index = if public {
        PayloadIndex::default()
    } else {
        PayloadIndex::from_git_head(workspace)?
    };
    let origin = trusted_git_command()
        .arg("-C")
        .arg(workspace)
        .args(["config", "--get", "remote.origin.url"])
        .output()
        .map_err(|error| error.to_string())?;
    let origin = String::from_utf8_lossy(&origin.stdout);
    let repository = origin
        .trim()
        .strip_prefix("https://github.com/")
        .map(|path| path.trim_end_matches('/').trim_end_matches(".git"))
        .filter(|path| path.split('/').count() == 2 && !path.contains(".."));
    let sinks = repository.map_or_else(Vec::new, |repository| {
        vec![
            ("github.com".to_owned(), format!("/{repository}")),
            ("api.github.com".to_owned(), format!("/repos/{repository}/")),
        ]
    });
    Ok(PayloadPolicy::new(index, sinks))
}

fn scoped(capabilities: &BTreeSet<String>, prefix: &str) -> BTreeSet<String> {
    capabilities
        .iter()
        .filter_map(|capability| capability.strip_prefix(prefix))
        .map(str::to_owned)
        .collect()
}

/// A branch scope: Git-safe characters, an optional trailing `*`, no `..`.
fn valid_ref_scope(scope: &str) -> bool {
    let body = scope.strip_suffix('*').unwrap_or(scope);
    !body.is_empty()
        && scope.len() <= 200
        && !body.contains("..")
        && !body.starts_with('/')
        && body
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'_' | b'.'))
}

fn normalize_dns_name(host: &str) -> Result<String, String> {
    let host = host.strip_suffix('.').unwrap_or(host);
    let valid = !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        });
    if !valid {
        return Err("egress capability is not a DNS name".to_owned());
    }
    Ok(host.to_ascii_lowercase())
}
/// Result of routing one byte read from the operator's tty.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InputEvent {
    /// Forward this byte to the guest.
    Forward(u8),
    /// Trusted approval mode began.
    EnterTrusted,
    /// The byte was consumed while collecting the challenge.
    Consumed,
    /// The supplied challenge did not match; trusted mode remains active.
    ChallengeMismatch,
    /// The pending action was approved.
    Approved,
    /// The pending action and displayed reusable scope were approved.
    ApprovedGrant,
    /// The pending action was denied.
    Denied,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Mode {
    Normal,
    Trusted { typed: Vec<u8>, invalid: bool },
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum PendingInput {
    Confirm { grantable: bool },
    Challenge(Vec<u8>),
}
/// Pure state machine for the terminal's secure-attention path.
///
/// The platform adapter owns the tty and feeds bytes and renderer frames into
/// this type. Approval state never enters the untrusted renderer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InputGate {
    mode: Mode,
    pending: Option<PendingInput>,
}

impl InputGate {
    /// Creates a gate in normal passthrough mode with no pending action.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            mode: Mode::Normal,
            pending: None,
        }
    }

    /// Registers one pending action and its required operator interaction.
    ///
    /// # Panics
    ///
    /// Panics if a challenge action has no valid challenge, or a confirmation
    /// action unexpectedly has one.
    pub fn set_pending(&mut self, method: ApprovalMethod, challenge: Option<&str>) {
        self.set_pending_with_grant(method, challenge, false);
    }

    /// Registers a pending action and whether its displayed reusable grant can be chosen.
    ///
    /// # Panics
    /// Panics when the method and challenge shape disagree.
    pub fn set_pending_with_grant(
        &mut self,
        method: ApprovalMethod,
        challenge: Option<&str>,
        grantable: bool,
    ) {
        self.pending = Some(match method {
            ApprovalMethod::Confirm => {
                assert!(challenge.is_none(), "confirmations do not carry challenges");
                PendingInput::Confirm { grantable }
            }
            ApprovalMethod::Challenge => {
                let challenge = challenge.expect("challenge approval requires a challenge");
                assert!(
                    !challenge.is_empty()
                        && challenge.len() <= MAX_CHALLENGE
                        && challenge.bytes().all(|byte| byte.is_ascii_alphanumeric()),
                    "approval challenges must be 1-16 ASCII alphanumeric bytes"
                );
                PendingInput::Challenge(challenge.as_bytes().to_vec())
            }
        });
        self.mode = Mode::Normal;
    }

    /// Returns whether an action is waiting for an operator decision.
    #[must_use]
    pub const fn has_pending(&self) -> bool {
        self.pending.is_some()
    }

    /// Returns whether guest I/O must remain suspended.
    #[must_use]
    pub const fn in_trusted_mode(&self) -> bool {
        matches!(self.mode, Mode::Trusted { .. })
    }

    /// Routes one raw byte read from the operator tty.
    pub fn accept(&mut self, byte: u8) -> InputEvent {
        match &mut self.mode {
            Mode::Normal if byte == SECURE_ATTENTION && self.pending.is_some() => {
                self.mode = Mode::Trusted {
                    typed: Vec::new(),
                    invalid: false,
                };
                InputEvent::EnterTrusted
            }
            Mode::Normal if byte == SECURE_ATTENTION => InputEvent::Consumed,
            Mode::Normal => InputEvent::Forward(byte),
            Mode::Trusted { .. } if byte == 0x1b => {
                self.pending = None;
                self.mode = Mode::Normal;
                InputEvent::Denied
            }
            Mode::Trusted { .. }
                if matches!(self.pending, Some(PendingInput::Confirm { .. }))
                    && matches!(byte, b'a' | b'A') =>
            {
                self.pending = None;
                self.mode = Mode::Normal;
                InputEvent::Approved
            }
            Mode::Trusted { .. }
                if matches!(
                    self.pending,
                    Some(PendingInput::Confirm { grantable: true })
                ) && matches!(byte, b'g' | b'G') =>
            {
                self.pending = None;
                self.mode = Mode::Normal;
                InputEvent::ApprovedGrant
            }
            Mode::Trusted { .. } if matches!(self.pending, Some(PendingInput::Confirm { .. })) => {
                InputEvent::Consumed
            }
            Mode::Trusted { typed, invalid } if byte == b'\n' || byte == b'\r' => {
                let matches = matches!(
                    self.pending.as_ref(),
                    Some(PendingInput::Challenge(challenge))
                        if !*invalid && challenge.as_slice() == typed.as_slice()
                );
                if matches {
                    self.pending = None;
                    self.mode = Mode::Normal;
                    InputEvent::Approved
                } else {
                    typed.clear();
                    *invalid = false;
                    InputEvent::ChallengeMismatch
                }
            }
            Mode::Trusted { typed, invalid } => {
                if byte.is_ascii_alphanumeric() && !*invalid {
                    if typed.len() < MAX_CHALLENGE {
                        typed.push(byte);
                    } else {
                        *invalid = true;
                    }
                } else {
                    *invalid = true;
                }
                InputEvent::Consumed
            }
        }
    }
}

/// Paints a terminal-safe trusted approval screen from the exact action.
///
/// Every untrusted field is escaped before rendering.
#[must_use]
pub fn render_gate(
    payload: &GatePayload,
    method: ApprovalMethod,
    challenge: Option<&str>,
) -> String {
    let mut screen = format!(
        "KEEL TRUSTED SCREEN\napproval\naction id: {}\nclass: {}\ntarget:\n{}\nreasons:\n",
        payload.action_id,
        safe_text(payload.action_class.as_bytes()),
        safe_text(&payload.exact_target)
    );
    if payload.reasons.is_empty() {
        screen.push_str("  (none)\n");
    } else {
        for reason in &payload.reasons {
            screen.push_str("  - ");
            screen.push_str(&safe_text(reason.rule.as_bytes()));
            screen.push_str(": ");
            screen.push_str(&safe_text(reason.detail.as_bytes()));
            screen.push('\n');
        }
    }
    screen.push_str("provenance:\n");
    if payload.floor_history.is_empty() {
        screen.push_str("  (none)\n");
    } else {
        for source in &payload.floor_history {
            screen.push_str("  - ");
            screen.push_str(&safe_text(source));
            screen.push('\n');
        }
    }
    if let Some(grant) = &payload.session_grant {
        screen.push_str("available reusable grant:\n  ");
        screen.push_str(&safe_text(grant));
        screen.push('\n');
    }
    match method {
        ApprovalMethod::Confirm => {
            if payload.session_grant.is_some() {
                screen.push_str("press A once; G for displayed grant; Escape to deny\n");
            } else {
                screen.push_str("press A to approve; press Escape to deny\n");
            }
        }
        ApprovalMethod::Challenge => {
            let Some(challenge) = challenge else {
                screen.push_str("challenge unavailable; press Escape to deny\n");
                return screen;
            };
            screen.push_str("challenge: ");
            screen.push_str(&safe_text(challenge.as_bytes()));
            screen.push_str(
                "\ntype the challenge and press Enter to approve; press Escape to deny\n",
            );
        }
    }
    screen
}

/// Introduces a control message on a Keel terminal input stream.
///
/// The operator's keystrokes and Keel's own control messages share one pipe on
/// every hop from the attached terminal to the guest pty, so a message needs a
/// prefix, and a literal prefix byte the operator typed needs an escape. The
/// guest half of this codec lives in `keel-mcp-guest` and must agree with it.
pub const TERMINAL_CONTROL: u8 = 0x07;
/// Asks the session to make the guest repaint.
pub const TERMINAL_CONTROL_REDRAW: u8 = b'r';
/// Announces a new terminal size, as rows then columns, big-endian.
pub const TERMINAL_CONTROL_RESIZE: u8 = b's';
/// Requests a gated lift on the live kernel, followed by one rank byte.
pub const TERMINAL_CONTROL_FLOOR_LIFT: u8 = b'f';
/// Requests an orderly shutdown from the trusted runtime owner.
pub const TERMINAL_CONTROL_SHUTDOWN: u8 = b'q';
/// The key the guest harness already treats as "repaint the screen".
pub const REDRAW_KEY: u8 = 0x0c;
/// Trusted mux command-mode toggle.
pub const MUX_COMMAND_KEY: u8 = 0x01;

/// Returns whether bounded detached output contains an approval notice.
#[must_use]
pub fn detached_output_has_pending_approval(output: &[u8]) -> bool {
    output
        .windows(b"KEEL APPROVAL PENDING".len())
        .any(|window| window == b"KEEL APPROVAL PENDING")
}

/// Result of routing one operator byte through mux command mode.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MuxCommandEvent {
    /// Forward the byte to the guest PTY.
    Forward(u8),
    /// Repaint the command line.
    Render,
    /// Return to PTY mode and request a complete repaint.
    Redraw,
    /// Send trusted operator text to the guest followed by Enter.
    Submit(Vec<u8>),
    /// Detach with a supervisor action code.
    Detach(u8),
    /// Request a gated floor lift on the live kernel.
    LiftFloor(u8),
}

/// Small trusted input state machine for the persistent mux command line.
#[derive(Default)]
pub struct MuxCommandInput {
    command: Option<Vec<u8>>,
}

impl MuxCommandInput {
    /// Routes one terminal byte.
    #[must_use]
    pub fn accept(&mut self, byte: u8) -> MuxCommandEvent {
        let Some(command) = self.command.as_mut() else {
            if byte == MUX_COMMAND_KEY {
                self.command = Some(Vec::new());
                return MuxCommandEvent::Render;
            }
            return MuxCommandEvent::Forward(byte);
        };
        match byte {
            MUX_COMMAND_KEY | 0x1b => {
                self.command = None;
                MuxCommandEvent::Redraw
            }
            0x08 | 0x7f => {
                command.pop();
                MuxCommandEvent::Render
            }
            b'\r' | b'\n' => {
                let command = self.command.take().unwrap_or_default();
                if let Some(rank) = parse_floor_lift(&command) {
                    return MuxCommandEvent::LiftFloor(rank);
                }
                if command.starts_with(b"/floor-lift") {
                    return MuxCommandEvent::Redraw;
                }
                match command.as_slice() {
                    b"/approve" => MuxCommandEvent::Forward(SECURE_ATTENTION),
                    b"/detach" => MuxCommandEvent::Detach(24),
                    b"/new" => MuxCommandEvent::Detach(20),
                    b"/tab" => MuxCommandEvent::Detach(21),
                    b"/close" => MuxCommandEvent::Detach(22),
                    b"/resume" => MuxCommandEvent::Detach(23),
                    b"/redraw" | b"" => MuxCommandEvent::Redraw,
                    _ => MuxCommandEvent::Submit(command),
                }
            }
            byte if (byte.is_ascii_graphic() || byte == b' ') && command.len() < 4096 => {
                command.push(byte);
                MuxCommandEvent::Render
            }
            _ => MuxCommandEvent::Render,
        }
    }

    /// Current command text when command mode is active.
    #[must_use]
    pub fn command(&self) -> Option<&[u8]> {
        self.command.as_deref()
    }
}

fn parse_floor_lift(command: &[u8]) -> Option<u8> {
    match command {
        b"/floor-lift" => Some(3),
        [
            b'/',
            b'f',
            b'l',
            b'o',
            b'o',
            b'r',
            b'-',
            b'l',
            b'i',
            b'f',
            b't',
            b' ',
            rank @ b'1'..=b'3',
        ] => Some(*rank - b'0'),
        _ => None,
    }
}

/// One control message decoded from a terminal input stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminalControl {
    /// Repaint the guest's screen.
    Redraw,
    /// Adopt this terminal size.
    Resize {
        /// Rows the operator's terminal now has.
        rows: u16,
        /// Columns the operator's terminal now has.
        columns: u16,
    },
    /// Request a gated lift against the live kernel state.
    FloorLift(u8),
    /// Shut the runtime down after sealing its audit stream.
    Shutdown,
}

/// Encodes one resize control message for a terminal input stream.
#[must_use]
pub fn encode_resize(rows: u16, columns: u16) -> [u8; 6] {
    let [row_high, row_low] = rows.to_be_bytes();
    let [column_high, column_low] = columns.to_be_bytes();
    [
        TERMINAL_CONTROL,
        TERMINAL_CONTROL_RESIZE,
        row_high,
        row_low,
        column_high,
        column_low,
    ]
}

/// Encodes a live floor-lift request for the trusted runtime.
#[must_use]
pub const fn encode_floor_lift(rank: u8) -> [u8; 3] {
    [TERMINAL_CONTROL, TERMINAL_CONTROL_FLOOR_LIFT, rank]
}

/// Encodes an orderly runtime-shutdown request.
#[must_use]
pub const fn encode_shutdown() -> [u8; 2] {
    [TERMINAL_CONTROL, TERMINAL_CONTROL_SHUTDOWN]
}

/// Appends one operator keystroke, escaping a literal control byte.
///
/// A doubled control byte is how an operator pressing Ctrl-G stays
/// distinguishable from the start of a control message.
pub fn push_keystroke(forward: &mut Vec<u8>, byte: u8) {
    if byte == TERMINAL_CONTROL {
        forward.push(TERMINAL_CONTROL);
    }
    forward.push(byte);
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum ControlState {
    #[default]
    Text,
    Prefix,
    Resize {
        payload: [u8; 4],
        filled: usize,
    },
    FloorLift,
}

/// Splits a terminal input stream into guest keystrokes and control messages.
///
/// A message is only acted on once every byte of it has arrived, which can take
/// several reads, so the reader is kept across reads of one stream.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TerminalControlReader {
    state: ControlState,
}

impl TerminalControlReader {
    /// Creates a reader positioned at the start of a stream.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: ControlState::Text,
        }
    }

    /// Appends the keystrokes in `bytes` and returns the messages they carried.
    pub fn split(&mut self, bytes: &[u8], keystrokes: &mut Vec<u8>) -> Vec<TerminalControl> {
        let mut controls = Vec::new();
        for byte in bytes {
            match &mut self.state {
                ControlState::Text if *byte == TERMINAL_CONTROL => {
                    self.state = ControlState::Prefix;
                }
                ControlState::Text => keystrokes.push(*byte),
                ControlState::Prefix => {
                    self.state = ControlState::Text;
                    match *byte {
                        TERMINAL_CONTROL => keystrokes.push(TERMINAL_CONTROL),
                        TERMINAL_CONTROL_REDRAW => controls.push(TerminalControl::Redraw),
                        TERMINAL_CONTROL_RESIZE => {
                            self.state = ControlState::Resize {
                                payload: [0; 4],
                                filled: 0,
                            };
                        }
                        TERMINAL_CONTROL_FLOOR_LIFT => self.state = ControlState::FloorLift,
                        TERMINAL_CONTROL_SHUTDOWN => controls.push(TerminalControl::Shutdown),
                        // An unrecognized message is dropped rather than typed
                        // into the guest, so a newer peer on one hop cannot
                        // corrupt the harness's input line on an older one.
                        _ => {}
                    }
                }
                ControlState::Resize { payload, filled } => {
                    payload[*filled] = *byte;
                    *filled += 1;
                    if *filled == payload.len() {
                        controls.push(TerminalControl::Resize {
                            rows: u16::from_be_bytes([payload[0], payload[1]]),
                            columns: u16::from_be_bytes([payload[2], payload[3]]),
                        });
                        self.state = ControlState::Text;
                    }
                }
                ControlState::FloorLift => {
                    if (1..=3).contains(byte) {
                        controls.push(TerminalControl::FloorLift(*byte));
                    }
                    self.state = ControlState::Text;
                }
            }
        }
        controls
    }
}

impl Default for InputGate {
    fn default() -> Self {
        Self::new()
    }
}

/// Converts untrusted bytes into terminal-safe text.
///
/// Newlines and tabs are preserved for readable diffs. Every other control
/// character is rendered as a visible hexadecimal escape.
#[must_use]
pub fn safe_text(input: &[u8]) -> String {
    let mut output = String::new();
    for character in String::from_utf8_lossy(input).chars() {
        match character {
            '\n' | '\t' => output.push(character),
            value if value.is_control() => {
                use std::fmt::Write as _;
                write!(output, "\\x{:02x}", u32::from(value))
                    .expect("writing to a String cannot fail");
            }
            value => output.push(value),
        }
    }
    output
}
