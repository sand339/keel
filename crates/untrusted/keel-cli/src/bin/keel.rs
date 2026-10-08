#![doc = "Keel command-line interface."]

use keel_audit::{RunKey, inspect_file};
use keel_cli::{
    Command, PolicySource, accepted_policy_ledger, apply_session_policy, axes_report,
    configured_input_runtime, context_report, derive_workspace_egress, doctor,
    explicit_mux_workspace, fatigue_report, format_enforcement_report, format_floor_status, help,
    host_default_model, install, launch_runtime, load_floor_status, new_session_id, parse_args,
    persistent_runtime_operation, record_accepted_policy, select_mux_launch, session_directory,
    session_enforcement_state, start_persistent_runtime, validate_run_isolation,
    validate_v8_request_entry,
};
use keel_compile::{PolicyArtifact, load_policy_translation, translate_policy_with_claude};
use serde::{Deserialize, Serialize};
use std::{
    env, fs,
    io::{self, IsTerminal as _, Write as _},
    os::unix::{fs::OpenOptionsExt as _, net::UnixStream},
    path::Path,
    process::{Command as ProcessCommand, ExitCode, ExitStatus},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
    time::{SystemTime, UNIX_EPOCH},
};

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(error) => {
            eprintln!("keel: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<ExitCode, Box<dyn std::error::Error>> {
    match parse_args(env::args_os().skip(1))? {
        Command::Setup => {
            println!("{}", install()?);
            Ok(ExitCode::SUCCESS)
        }
        Command::Doctor => {
            let report = doctor();
            print!("{}", report.output);
            Ok(if report.healthy {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            })
        }
        Command::Help => {
            print!("{}", help());
            Ok(ExitCode::SUCCESS)
        }
        command @ (Command::PolicyCompile { .. }
        | Command::PolicyAccept { .. }
        | Command::PolicyShow { .. }
        | Command::PolicyDiff { .. }) => run_policy_command(command),
        Command::AuditVerify { audit, key } => {
            let run_key = RunKey::from_hex(&fs::read_to_string(key)?)?;
            let status = inspect_file(&audit, &run_key)?;
            if status.sealed {
                println!("VERIFIED AND SEALED — {} audit records", status.records);
                Ok(ExitCode::SUCCESS)
            } else {
                println!(
                    "VERIFIED PREFIX — SESSION UNSEALED — {} audit records",
                    status.records
                );
                Ok(ExitCode::FAILURE)
            }
        }
        Command::ReportAxes { sessions } => {
            print!("{}", axes_report(&sessions)?);
            Ok(ExitCode::SUCCESS)
        }
        Command::ReportContext { sessions } => {
            print!("{}", context_report(&sessions)?);
            Ok(ExitCode::SUCCESS)
        }
        Command::Report { inputs } => {
            print!("{}", fatigue_report(&inputs)?);
            Ok(ExitCode::SUCCESS)
        }
        Command::FloorShow { session_id, state } => {
            let path = state.unwrap_or(session_directory(&session_id)?.join("floor.json"));
            let status = load_floor_status(&path, &session_id)?;
            print!("{}", format_floor_status(&status));
            Ok(ExitCode::SUCCESS)
        }
        Command::Status { session_id, audit } => {
            let report = session_enforcement_state(&session_id, audit.as_deref())?;
            print!("{}", format_enforcement_report(&report));
            Ok(ExitCode::SUCCESS)
        }
        Command::FloorLift {
            session_id,
            requested_floor,
        } => {
            let runtime = configured_input_runtime()?;
            let status = ProcessCommand::new(runtime)
                .env("KEEL_INPUT_SOURCE", "trusted-terminal")
                .args(["lift", &requested_floor.to_string(), "--socket"])
                .arg(session_directory(&session_id)?.join("attach.sock"))
                .status()?;
            Ok(match status.code() {
                Some(code) => ExitCode::from(u8::try_from(code).unwrap_or(1)),
                None => ExitCode::FAILURE,
            })
        }
        Command::Attach { session_id } => {
            let runtime = configured_input_runtime()?;
            if let Some(manager) = load_mux_manager(&session_id)? {
                return run_restored_mux_manager(&runtime, &session_id, manager);
            }
            let status = persistent_runtime_operation(&runtime, "attach", &session_id)?;
            if status.code() == Some(MUX_DETACH) {
                println!("Detached from {session_id}. Reattach with `keel attach {session_id}`.");
                Ok(ExitCode::SUCCESS)
            } else {
                Ok(exit_status(status))
            }
        }
        Command::Stop { session_id } => {
            let runtime = configured_input_runtime()?;
            let status = persistent_runtime_operation(&runtime, "stop", &session_id)?;
            Ok(exit_status(status))
        }
        Command::Run(request) => run_harness(request),
    }
}

fn run_harness(mut request: keel_cli::RunRequest) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let runtime = configured_input_runtime()?;
    if request.mux {
        return run_mux_manager(&runtime, request);
    }
    if request.policy.is_some() {
        let workspace = env::current_dir()?;
        print!("{}", apply_session_policy(&mut request, &workspace)?);
    }
    derive_workspace_egress(&mut request, &env::current_dir()?);
    validate_run_isolation(&request)?;
    if request.harness == "v8" {
        let workspace = explicit_mux_workspace(&env::current_dir()?)?;
        validate_v8_request_entry(&mut request, &workspace)?;
    }
    if matches!(request.harness.as_str(), "claude" | "v8") {
        if request.auth.is_none() {
            request.auth = choose_model_auth()?;
        }
        require_model_credential(request.auth.as_deref())?;
        if request.model.is_none() {
            request.model = host_default_model();
        }
    }
    if request.keep_alive {
        if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
            return Err("keel run --keep-alive requires a real terminal".into());
        }
        start_persistent_runtime(&runtime, &request)?;
        println!(
            "Persistent Keel session: {}\nPress Ctrl-A for mux commands.",
            request.session_id
        );
        let status = persistent_runtime_operation(&runtime, "attach", &request.session_id)?;
        Ok(exit_status(status))
    } else {
        let status = launch_runtime(&runtime, &request)?;
        Ok(exit_status(status))
    }
}

const MUX_NEW: i32 = 20;
const MUX_TAB: i32 = 21;
const MUX_CLOSE: i32 = 22;
const MUX_RESUME: i32 = 23;
const MUX_DETACH: i32 = 24;

#[derive(Clone, Deserialize, Serialize)]
struct MuxTab {
    session_id: String,
    label: String,
    workspace: Option<std::path::PathBuf>,
    #[serde(default)]
    pending: bool,
}

#[derive(Serialize)]
struct MuxTabsView<'a> {
    active: &'a str,
    tabs: &'a [MuxTab],
}

#[derive(Deserialize, Serialize)]
struct MuxManagerState {
    version: u8,
    template: keel_cli::RunRequest,
    policy: Option<std::path::PathBuf>,
    active: String,
    tabs: Vec<MuxTab>,
}

fn run_mux_manager(
    runtime: &Path,
    mut template: keel_cli::RunRequest,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err("keel mux requires a real terminal".into());
    }
    let start = env::current_dir()?;
    if let Some(policy) = &template.policy
        && policy.is_relative()
    {
        template.policy = Some(start.join(policy));
    }
    let mut selected = template.clone();
    let workspace = if let Some(path) = selected.workspace.take() {
        Some(explicit_mux_workspace(&path)?)
    } else {
        select_mux_launch(runtime, &start, &mut selected)?
    };
    let Some(workspace) = workspace else {
        return Ok(ExitCode::SUCCESS);
    };
    if template.auth.is_none() {
        template.auth = choose_model_auth()?;
    }
    selected.auth.clone_from(&template.auth);
    require_model_credential(template.auth.as_deref())?;
    if template.model.is_none() {
        template.model = host_default_model();
    }
    selected.model.clone_from(&template.model);
    let first = start_mux_tab(runtime, &selected, &workspace, Some(&template.session_id))?;
    drive_mux_manager(runtime, &template, vec![first], 0)
}

fn run_restored_mux_manager(
    runtime: &Path,
    requested: &str,
    mut state: MuxManagerState,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    state
        .tabs
        .retain(|tab| session_status(&tab.session_id).is_some());
    if state.tabs.is_empty() {
        return Err("none of the saved mux tabs is still running".into());
    }
    let active = state
        .tabs
        .iter()
        .position(|tab| tab.session_id == requested)
        .or_else(|| {
            state
                .tabs
                .iter()
                .position(|tab| tab.session_id == state.active)
        })
        .unwrap_or(0);
    state.template.policy = state.policy;
    drive_mux_manager(runtime, &state.template, state.tabs, active)
}

fn drive_mux_manager(
    runtime: &Path,
    template: &keel_cli::RunRequest,
    mut tabs: Vec<MuxTab>,
    mut active: usize,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    loop {
        refresh_pending(&mut tabs);
        write_tab_views(&tabs, active)?;
        write_mux_manager(template, &tabs, active)?;
        let status = attach_managed(runtime, &tabs, active)?;
        match status.code() {
            Some(0) => {
                tabs.remove(active);
                if tabs.is_empty() {
                    return Ok(ExitCode::SUCCESS);
                }
                active %= tabs.len();
            }
            Some(MUX_NEW) => {
                let start = tabs[active].workspace.as_deref().unwrap_or(Path::new("."));
                let mut selected = template.clone();
                if let Some(workspace) = select_mux_launch(runtime, start, &mut selected)? {
                    let tab = start_mux_tab(runtime, &selected, &workspace, None)?;
                    tabs.push(tab);
                    active = tabs.len() - 1;
                }
            }
            Some(MUX_TAB) => active = (active + 1) % tabs.len(),
            Some(MUX_CLOSE) => {
                let closing = tabs.remove(active);
                let _ = persistent_runtime_operation(runtime, "stop", &closing.session_id);
                if tabs.is_empty() {
                    return Ok(ExitCode::SUCCESS);
                }
                active %= tabs.len();
            }
            Some(MUX_RESUME) => {
                if let Some(tab) = resumable_tab(&tabs)? {
                    tabs.push(tab);
                    active = tabs.len() - 1;
                } else {
                    println!("No detached Keel session is available to resume.");
                }
            }
            Some(MUX_DETACH) => {
                println!(
                    "Detached with {} tab(s) running. Reattach with `keel attach {}`.",
                    tabs.len(),
                    tabs[active].session_id
                );
                return Ok(ExitCode::SUCCESS);
            }
            Some(code) => return Ok(ExitCode::from(u8::try_from(code).unwrap_or(1))),
            None => return Ok(ExitCode::FAILURE),
        }
    }
}

fn start_mux_tab(
    runtime: &Path,
    template: &keel_cli::RunRequest,
    workspace: &Path,
    session_id: Option<&str>,
) -> Result<MuxTab, Box<dyn std::error::Error>> {
    let workspace = explicit_mux_workspace(workspace)?;
    env::set_current_dir(&workspace)?;
    let mut request = template.clone();
    request.session_id = session_id.map_or_else(new_session_id, str::to_owned);
    if request.policy.is_some() {
        print!("{}", apply_session_policy(&mut request, &workspace)?);
    }
    derive_workspace_egress(&mut request, &workspace);
    validate_run_isolation(&request)?;
    validate_v8_request_entry(&mut request, &workspace)?;
    println!(
        "Starting {} tab in {}",
        request.isolation.as_str(),
        workspace.display()
    );
    start_persistent_runtime(runtime, &request)?;
    let tab = MuxTab {
        session_id: request.session_id,
        label: format!(
            "{}{}",
            workspace
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("workspace"),
            match request.isolation {
                keel_cli::IsolationMode::Vm => "",
                keel_cli::IsolationMode::VmV8 => " · V8/VM",
                keel_cli::IsolationMode::V8Sandboxed => " · V8/host",
            }
        ),
        workspace: Some(workspace),
        pending: false,
    };
    write_tab_metadata(&tab)?;
    Ok(tab)
}

fn attach_managed(
    runtime: &Path,
    tabs: &[MuxTab],
    active: usize,
) -> Result<ExitStatus, Box<dyn std::error::Error>> {
    let done = Arc::new(AtomicBool::new(false));
    let update_done = Arc::clone(&done);
    let update_tabs = tabs.to_vec();
    let updater = thread::spawn(move || {
        while !update_done.load(Ordering::Relaxed) {
            let mut tabs = update_tabs.clone();
            refresh_pending(&mut tabs);
            let _ = write_tab_views(&tabs, active);
            thread::sleep(Duration::from_millis(400));
        }
    });
    let socket = session_directory(&tabs[active].session_id)?.join("attach.sock");
    let status = ProcessCommand::new(runtime)
        .arg("attach")
        .arg("--socket")
        .arg(socket)
        .env("KEEL_SESSION_ID", &tabs[active].session_id)
        .status()?;
    done.store(true, Ordering::Relaxed);
    let _ = updater.join();
    Ok(status)
}

fn refresh_pending(tabs: &mut [MuxTab]) {
    for tab in tabs {
        tab.pending = matches!(
            session_status(&tab.session_id),
            Some(SessionStatus::Pending)
        );
    }
}

enum SessionStatus {
    Active,
    Pending,
    Idle,
}

fn session_status(session_id: &str) -> Option<SessionStatus> {
    use std::io::{Read as _, Write as _};
    let socket = session_directory(session_id).ok()?.join("attach.sock");
    let mut stream = UnixStream::connect(socket).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_millis(200)))
        .ok()?;
    stream.write_all(b"STATUS\n").ok()?;
    let mut response = [0_u8; 16];
    let count = stream.read(&mut response).ok()?;
    match &response[..count] {
        b"ACTIVE\n" => Some(SessionStatus::Active),
        b"PENDING\n" => Some(SessionStatus::Pending),
        b"IDLE\n" => Some(SessionStatus::Idle),
        _ => None,
    }
}

fn write_tab_metadata(tab: &MuxTab) -> Result<(), Box<dyn std::error::Error>> {
    write_private_json(
        &session_directory(&tab.session_id)?.join("mux-tab.json"),
        tab,
    )
}

fn write_tab_views(tabs: &[MuxTab], active: usize) -> Result<(), Box<dyn std::error::Error>> {
    let view = MuxTabsView {
        active: &tabs[active].session_id,
        tabs,
    };
    for tab in tabs {
        write_private_json(
            &session_directory(&tab.session_id)?.join("mux-tabs.json"),
            &view,
        )?;
    }
    Ok(())
}

fn write_mux_manager(
    template: &keel_cli::RunRequest,
    tabs: &[MuxTab],
    active: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let state = MuxManagerState {
        version: 1,
        template: template.clone(),
        policy: template.policy.clone(),
        active: tabs[active].session_id.clone(),
        tabs: tabs.to_vec(),
    };
    for tab in tabs {
        write_private_json(
            &session_directory(&tab.session_id)?.join("mux-manager.json"),
            &state,
        )?;
    }
    Ok(())
}

fn load_mux_manager(
    session_id: &str,
) -> Result<Option<MuxManagerState>, Box<dyn std::error::Error>> {
    let path = session_directory(session_id)?.join("mux-manager.json");
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if bytes.len() > 1024 * 1024 {
        return Err(format!("mux manager state at {} exceeds 1 MiB", path.display()).into());
    }
    let state = serde_json::from_slice::<MuxManagerState>(&bytes)?;
    if state.version != 1 {
        return Err(format!("unsupported mux manager state version {}", state.version).into());
    }
    Ok(Some(state))
}

fn write_private_json(
    path: &Path,
    value: &impl Serialize,
) -> Result<(), Box<dyn std::error::Error>> {
    let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&temporary)?;
    serde_json::to_writer(&mut file, value)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    fs::rename(temporary, path)?;
    Ok(())
}

fn resumable_tab(current: &[MuxTab]) -> Result<Option<MuxTab>, Box<dyn std::error::Error>> {
    let probe = session_directory("probe")?;
    let Some(root) = probe.parent() else {
        return Ok(None);
    };
    let mut entries = fs::read_dir(root)?
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
        .collect::<Vec<_>>();
    entries.sort_by_key(|entry| {
        std::cmp::Reverse(
            entry
                .metadata()
                .and_then(|metadata| metadata.modified())
                .unwrap_or(SystemTime::UNIX_EPOCH),
        )
    });
    for entry in entries {
        let Some(session_id) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if current.iter().any(|tab| tab.session_id == session_id)
            || !matches!(
                session_status(&session_id),
                Some(SessionStatus::Idle | SessionStatus::Pending)
            )
        {
            continue;
        }
        let metadata = fs::read(entry.path().join("mux-tab.json"))
            .ok()
            .and_then(|bytes| serde_json::from_slice::<MuxTab>(&bytes).ok());
        return Ok(Some(metadata.unwrap_or(MuxTab {
            label: session_id.clone(),
            session_id,
            workspace: None,
            pending: false,
        })));
    }
    Ok(None)
}

fn run_policy_command(command: Command) -> Result<ExitCode, Box<dyn std::error::Error>> {
    match command {
        Command::PolicyCompile {
            source,
            output,
            translation,
        } => {
            let text = match source {
                PolicySource::File(path) => fs::read_to_string(path)?,
                PolicySource::Text(text) => text,
            };
            let translation = translation.as_deref().map_or_else(
                || translate_policy_with_claude(&text),
                load_policy_translation,
            )?;
            let artifact = PolicyArtifact::draft(&text, translation, unix_time_ms()?)?;
            artifact.save(&output)?;
            print!("{}", artifact.review());
            if artifact.has_blockers() {
                println!(
                    "Verified draft written to {}\nResolve the blockers before accepting it.",
                    output.display()
                );
                Ok(ExitCode::from(2))
            } else {
                println!(
                    "Verified draft written to {}\nReview it, then run:\n  keel policy accept {} --output .keel/policy.json",
                    output.display(),
                    shell_path(&output)
                );
                Ok(ExitCode::SUCCESS)
            }
        }
        Command::PolicyAccept { draft, output } => {
            let mut artifact = PolicyArtifact::load(&draft)?;
            print!("{}", artifact.review());
            // An artifact accepted elsewhere, or before the host ledger
            // existed, is recorded as-is once reviewed here.
            if !artifact.is_accepted()? {
                artifact.accept(unix_time_ms()?)?;
            }
            artifact.save(&output)?;
            record_accepted_policy(&accepted_policy_ledger()?, artifact.hash())?;
            println!(
                "Accepted policy written to {}\nUse it with:\n  keel mux --policy {}",
                output.display(),
                shell_path(&output)
            );
            Ok(ExitCode::SUCCESS)
        }
        Command::PolicyShow { artifact } => {
            print!("{}", PolicyArtifact::load(&artifact)?.review());
            Ok(ExitCode::SUCCESS)
        }
        Command::PolicyDiff { old, new } => {
            let old = PolicyArtifact::load(&old)?;
            let new = PolicyArtifact::load(&new)?;
            print!("{}", old.diff(&new));
            Ok(ExitCode::SUCCESS)
        }
        _ => unreachable!("only policy commands reach this function"),
    }
}

fn unix_time_ms() -> Result<u64, Box<dyn std::error::Error>> {
    Ok(
        u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())
            .unwrap_or(u64::MAX),
    )
}

fn shell_path(path: &Path) -> String {
    let value = path.display().to_string();
    format!("'{}'", value.replace('\'', "'\\''"))
}

/// Refuses a run that nothing could answer the guest's model requests with.
///
/// The guest presents a sentinel key that the trusted proxy answers with a real
/// credential — swapped in for Anthropic, computed as a signature for a regional
/// provider. With neither configured, every model request is refused inside the
/// proxy and reaches the harness only as a dropped connection, so refuse before
/// booting a VM. This check is deliberately coarse: it asks whether a provider
/// was named at all, and leaves a half-configured one to the trusted process,
/// which is the only side that can tell whether a credential resolves.
fn require_model_credential(auth: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    let configured = match auth {
        // A named choice is checked against what it needs, not against whatever
        // else this host happens to hold: choosing one provider and booting on
        // the other's credential is the confusion this option exists to end.
        Some("api-key") => env::var_os("ANTHROPIC_API_KEY").is_some(),
        Some("openrouter") => env::var_os("OPENROUTER_API_KEY").is_some(),
        Some("bedrock") => {
            env::var_os("AWS_BEARER_TOKEN_BEDROCK").is_some()
                || env::var_os("KEEL_AWS_CREDENTIAL_PROCESS").is_some()
                || env::var_os("AWS_ACCESS_KEY_ID").is_some()
        }
        _ => {
            env::var_os("ANTHROPIC_API_KEY").is_some()
                || env::var_os("AWS_BEARER_TOKEN_BEDROCK").is_some()
                || env::var("KEEL_MODEL_PROVIDER").as_deref() == Ok("bedrock")
        }
    };
    if configured {
        return Ok(());
    }
    Err(format!(
        "no model credential is configured for {}, so Keel cannot answer the guest's model \
requests; export ANTHROPIC_API_KEY, or OPENROUTER_API_KEY with --auth openrouter, or for Bedrock set KEEL_MODEL_PROVIDER=bedrock and \
AWS_REGION, with AWS SSO supplying the credential through \
KEEL_AWS_CREDENTIAL_PROCESS='aws configure export-credentials --profile PROFILE'",
        auth.unwrap_or("this run")
    )
    .into())
}

/// Asks which credential shape to use when this host has both.
///
/// Holding an API key and a Bedrock login is not a choice, and the old rule —
/// whichever variable happens to be set wins — spends the wrong budget against
/// the wrong account without saying so. The question is asked only when the
/// answer is genuinely unknown: `--auth` skips it, one configured provider skips
/// it, and so does a run with no terminal to ask through.
fn choose_model_auth() -> Result<Option<String>, Box<dyn std::error::Error>> {
    let api_key = env::var_os("ANTHROPIC_API_KEY").is_some();
    let bedrock = env::var_os("AWS_BEARER_TOKEN_BEDROCK").is_some()
        || env::var("KEEL_MODEL_PROVIDER").as_deref() == Ok("bedrock")
        || env::var_os("KEEL_AWS_CREDENTIAL_PROCESS").is_some();
    if !(api_key && bedrock && io::stdin().is_terminal()) {
        return Ok(None);
    }
    let region = env::var("AWS_REGION").unwrap_or_else(|_| "an unset AWS_REGION".to_owned());
    print!(
        "Two model credentials are configured for this host.\n  \
         1) Anthropic API key\n  \
         2) Bedrock in {region}\nWhich should this run use? [1/2]: "
    );
    io::stdout().flush()?;
    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    match answer.trim() {
        "1" => Ok(Some("api-key".to_owned())),
        "2" => Ok(Some("bedrock".to_owned())),
        other => Err(format!(
            "`{other}` is not 1 or 2; pass --auth api-key or --auth bedrock to choose without \
being asked"
        )
        .into()),
    }
}

fn exit_status(status: std::process::ExitStatus) -> ExitCode {
    match status.code() {
        Some(code) => ExitCode::from(u8::try_from(code).unwrap_or(1)),
        None => ExitCode::FAILURE,
    }
}

#[cfg(test)]
mod tests {
    use super::{MuxManagerState, MuxTab};
    use keel_cli::{Command, parse_args};
    use std::{ffi::OsString, path::PathBuf};

    #[test]
    fn mux_manager_state_preserves_tabs_policy_and_active_session() {
        let Command::Run(template) =
            parse_args(["mux", "--workspace", "/tmp/project"].map(OsString::from)).unwrap()
        else {
            panic!("mux must parse as a run");
        };
        let state = MuxManagerState {
            version: 1,
            template,
            policy: Some(PathBuf::from("/tmp/policy.json")),
            active: "run-2".to_owned(),
            tabs: vec![
                MuxTab {
                    session_id: "run-1".to_owned(),
                    label: "api".to_owned(),
                    workspace: Some(PathBuf::from("/tmp/api")),
                    pending: true,
                },
                MuxTab {
                    session_id: "run-2".to_owned(),
                    label: "web".to_owned(),
                    workspace: Some(PathBuf::from("/tmp/web")),
                    pending: false,
                },
            ],
        };

        let restored: MuxManagerState =
            serde_json::from_slice(&serde_json::to_vec(&state).unwrap()).unwrap();
        assert_eq!(restored.version, 1);
        assert_eq!(restored.active, "run-2");
        assert_eq!(restored.policy, Some(PathBuf::from("/tmp/policy.json")));
        assert_eq!(restored.tabs.len(), 2);
        assert!(restored.tabs[0].pending);
    }
}
