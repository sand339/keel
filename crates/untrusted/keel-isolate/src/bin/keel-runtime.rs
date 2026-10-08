#![doc = "Keel microVM runtime entry point."]

use keel_cli::{IsolationMode, MAX_VM_CPUS, RunRequest, validate_v8_request_entry};
use keel_isolate::{RuntimePlan, host_v8::HostEgressProxy, resolve_workspace};
use std::{
    env, fs,
    io::Write as _,
    net::{Ipv4Addr, SocketAddr, TcpListener},
    os::{
        fd::{FromRawFd as _, RawFd},
        unix::fs::{OpenOptionsExt as _, PermissionsExt as _},
    },
    path::{Path, PathBuf},
    process::{Command, ExitCode},
};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("keel-runtime: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = env::args_os().skip(1);
    if arguments.next().as_deref() != Some(std::ffi::OsStr::new("run"))
        || arguments.next().as_deref() != Some(std::ffi::OsStr::new("--request"))
    {
        return Err("usage: keel-runtime run --request REQUEST.json".into());
    }
    let request_path = PathBuf::from(
        arguments
            .next()
            .ok_or("usage: keel-runtime run --request REQUEST.json")?,
    );
    if arguments.next().is_some() {
        return Err("usage: keel-runtime run --request REQUEST.json".into());
    }
    let request: RunRequest = serde_json::from_slice(&fs::read(request_path)?)?;
    if !(1..=MAX_VM_CPUS).contains(&request.cpus) {
        return Err(format!("requested CPU count must be between 1 and {MAX_VM_CPUS}").into());
    }
    match request.isolation {
        IsolationMode::Vm | IsolationMode::VmV8 => run_vm(&request),
        IsolationMode::V8Sandboxed => run_host_v8(&request),
    }
}

fn run_vm(request: &RunRequest) -> Result<(), Box<dyn std::error::Error>> {
    let plan = RuntimePlan::from_environment(&env::current_dir()?)
        .map_err(|error| format!("runtime preflight failed: {error}"))?;
    let mut request = request.clone();
    validate_v8_request_entry(&mut request, &plan.workspace)
        .map_err(|error| format!("invalid V8 entry point: {error}"))?;
    eprintln!(
        "runtime preflight passed for session {}: {} ({}) in {} with {} vCPUs",
        request.session_id,
        request.harness,
        request.isolation.as_str(),
        plan.workspace.display(),
        request.cpus
    );
    let ca_certificate = env::var_os("KEEL_RUN_CA_PEM");
    let control = create_control(&request, ca_certificate.as_deref())
        .map_err(|error| format!("create VM control directory: {error}"))?;
    let preflight = env::var_os("KEEL_VZ_BACKEND")
        .map(PathBuf::from)
        .unwrap_or(env::current_exe()?.with_file_name("keel-vz-spike"));
    let mut backend = Command::new(preflight);
    backend
        .arg(&plan.kernel)
        .arg(&plan.initramfs)
        .arg(&plan.workspace)
        .arg(&control)
        .arg("--cpus")
        .arg(request.cpus.to_string())
        .arg("--memory")
        .arg(request.memory_gib.to_string());
    if let Some(rootfs) = &plan.rootfs {
        backend.arg("--rootfs").arg(rootfs);
    }
    let status = backend.status();
    let cleanup = fs::remove_dir_all(&control);
    let status = status.map_err(|error| format!("start VZ backend: {error}"))?;
    cleanup.map_err(|error| format!("remove VM control directory: {error}"))?;
    if !status.success() {
        return Err(format!("VZ preflight exited with {status}").into());
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn run_host_v8(request: &RunRequest) -> Result<(), Box<dyn std::error::Error>> {
    validate_host_v8_request(request)?;
    let workspace = resolve_workspace(&env::current_dir()?)
        .map_err(|error| format!("runtime preflight failed: {error}"))?;
    let mut request = request.clone();
    validate_v8_request_entry(&mut request, &workspace)
        .map_err(|error| format!("invalid V8 entry point: {error}"))?;
    let (script, script_arguments) = request
        .harness_args
        .split_first()
        .ok_or("v8 harness requires a script path")?;
    let script = workspace.join(script);
    let executable = env::var_os("KEEL_DENO")
        .map(PathBuf::from)
        .unwrap_or(env::current_exe()?.with_file_name("deno"));
    if !executable.is_file() {
        return Err(format!(
            "pinned Deno runtime is missing: {}; rerun `keel setup` or set KEEL_DENO",
            executable.display()
        )
        .into());
    }
    let sdk = env::var_os("KEEL_V8_SDK")
        .map(PathBuf::from)
        .unwrap_or(env::current_exe()?.with_file_name("keel-v8-sdk.ts"));
    if !sdk.is_file() {
        return Err(format!(
            "Keel V8 SDK is missing: {}; rerun `keel setup` or set KEEL_V8_SDK",
            sdk.display()
        )
        .into());
    }
    let control = create_host_v8_control(&request, &sdk, &script)
        .map_err(|error| format!("create host V8 control directory: {error}"))?;
    let proxy_port = env::var("KEEL_V8_PROXY_PORT")
        .map_err(|_| "trusted launcher did not assign the V8 proxy port")?
        .parse::<u16>()
        .map_err(|_| "trusted launcher assigned an invalid V8 proxy port")?;
    let proxy_listener = inherited_v8_proxy_listener(proxy_port)?;
    let proxy = HostEgressProxy::start_with_listener(
        env::var_os("KEEL_KERNEL_SOCKET").map(PathBuf::from),
        proxy_listener,
    )
    .map_err(|error| format!("start host V8 egress proxy: {error}"))?;
    let proxy_url = proxy.url();
    let import_map = control.join("import-map.json");
    let runner = control.join("runner.ts");
    let ca = control.join("ca.pem");
    let readable = format!(
        "{},{},{}",
        workspace.display(),
        sdk.display(),
        control.display()
    );
    let writable = workspace.display().to_string();
    let proxy_address = proxy.address();
    let mut command = Command::new(&executable);
    command
        .arg("run")
        .arg("--quiet")
        .arg("--no-prompt")
        .arg("--no-config")
        .arg("--cached-only")
        .arg(format!("--allow-read={readable}"))
        .arg(format!("--allow-write={writable}"))
        .arg(format!(
            "--allow-net={}",
            deno_net_allowlist(&request, &proxy_address)
        ))
        .arg("--allow-env=HTTP_PROXY,HTTPS_PROXY,NO_PROXY,SSL_CERT_FILE,KEEL_MODEL_PROVIDER,KEEL_MODEL_REGION,KEEL_MODEL_AUTH_MODE,KEEL_MODEL_SENTINEL,ANTHROPIC_MODEL")
        .arg("--import-map")
        .arg(&import_map)
        .arg(&runner)
        .args(script_arguments)
        .current_dir(&workspace)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", &control)
        .env("DENO_DIR", control.join("deno-cache"))
        .env("HTTP_PROXY", &proxy_url)
        .env("HTTPS_PROXY", &proxy_url)
        .env("NO_PROXY", "127.0.0.1,localhost")
        // Deno's background update check would otherwise open a proxied
        // connection the workload never asked for.
        .env("DENO_NO_UPDATE_CHECK", "1")
        .env("SSL_CERT_FILE", &ca)
        .env("TERM", env::var("TERM").unwrap_or_else(|_| "xterm-256color".to_owned()));
    copy_optional_environment(
        &mut command,
        &[
            "KEEL_MODEL_PROVIDER",
            "KEEL_MODEL_REGION",
            "KEEL_MODEL_AUTH_MODE",
            "KEEL_MODEL_SENTINEL",
            "ANTHROPIC_MODEL",
        ],
    );
    eprintln!(
        "runtime preflight passed for session {}: v8 (v8-sandboxed) in {}",
        request.session_id,
        workspace.display()
    );
    let status = command.status();
    let proxy_result = proxy.shutdown();
    let cleanup = fs::remove_dir_all(&control);
    let status = status.map_err(|error| format!("start pinned Deno runtime: {error}"))?;
    proxy_result.map_err(|error| format!("stop host V8 egress proxy: {error}"))?;
    cleanup.map_err(|error| format!("remove host V8 control directory: {error}"))?;
    if !status.success() {
        return Err(format!("V8 harness exited with {status}").into());
    }
    Ok(())
}

fn inherited_v8_proxy_listener(expected_port: u16) -> Result<TcpListener, String> {
    let descriptor = env::var("KEEL_V8_PROXY_FD")
        .map_err(|_| "trusted launcher did not pass the V8 proxy listener")?
        .parse::<RawFd>()
        .map_err(|_| "trusted launcher passed an invalid V8 proxy listener")?;
    if descriptor < 3 {
        return Err("trusted launcher passed an invalid V8 proxy listener".to_owned());
    }
    // SAFETY: the trusted launcher passes one live duplicate of its pre-bound
    // TCP listener and transfers ownership to this process exactly once.
    let listener = unsafe { TcpListener::from_raw_fd(descriptor) };
    // The inherited descriptor was intentionally non-CLOEXEC for the
    // sandbox-exec hop. Restore CLOEXEC before starting Deno so the workload
    // cannot inherit the proxy listener itself.
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
    if flags < 0 || unsafe { libc::fcntl(descriptor, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0
    {
        return Err(format!(
            "configure inherited V8 proxy listener: {}",
            std::io::Error::last_os_error()
        ));
    }
    match listener.local_addr() {
        Ok(SocketAddr::V4(address))
            if *address.ip() == Ipv4Addr::LOCALHOST && address.port() == expected_port =>
        {
            Ok(listener)
        }
        Ok(address) => Err(format!(
            "inherited V8 proxy listener has unexpected address {address}"
        )),
        Err(error) => Err(format!("inspect inherited V8 proxy listener: {error}")),
    }
}

fn validate_host_v8_request(request: &RunRequest) -> Result<(), &'static str> {
    if request.harness != "v8" {
        return Err("v8-sandboxed isolation requires the v8 harness");
    }
    if !request
        .allow
        .iter()
        .any(|capability| capability == "isolation:v8-sandboxed")
    {
        return Err("v8-sandboxed isolation requires the isolation:v8-sandboxed capability");
    }
    Ok(())
}

fn create_host_v8_control(
    request: &RunRequest,
    sdk: &Path,
    script: &Path,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let root = runtime_scratch().join(format!(
        "keel-v8-control-{}-{}",
        std::process::id(),
        request.session_id
    ));
    fs::create_dir(&root)?;
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
    fs::create_dir(root.join("deno-cache"))?;
    let certificate =
        env::var("KEEL_RUN_CA_PEM").map_err(|_| "trusted run CA is unavailable for host V8")?;
    fs::write(root.join("ca.pem"), certificate)?;
    fs::write(
        root.join("import-map.json"),
        serde_json::to_vec(&serde_json::json!({
            "imports": {
                "keel:sdk": file_url(sdk)?
            }
        }))?,
    )?;
    fs::write(
        root.join("runner.ts"),
        format!(
            "import {{ keel }} from \"keel:sdk\";\nObject.defineProperty(globalThis, \"Keel\", {{ value: keel, writable: false, configurable: false }});\nawait import({:?});\n",
            file_url(script)?
        ),
    )?;
    Ok(root)
}

fn file_url(path: &Path) -> Result<String, String> {
    let path = path
        .canonicalize()
        .map_err(|error| format!("V8 SDK path: {error}"))?;
    let text = path
        .to_str()
        .ok_or_else(|| "V8 SDK path must be UTF-8".to_owned())?;
    let mut result = String::from("file://");
    for byte in text.bytes() {
        if byte == b'/' || byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
        {
            result.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            write!(result, "%{byte:02X}").expect("writing to a string cannot fail");
        }
    }
    Ok(result)
}

/// Names the hosts Deno's own permission check must accept for a proxied
/// `fetch`, which it checks against the destination even though the bytes go
/// to the loopback proxy. This widens no reachability: the outer sandbox lets
/// the process connect only to that proxy port, and the trusted kernel still
/// authorizes every request. The list mirrors the admitted host set: declared
/// `egress:` grants, the configured model endpoint, and GitHub for its
/// capabilities.
fn deno_net_allowlist(request: &RunRequest, proxy_address: &str) -> String {
    let mut hosts = vec![proxy_address.to_owned()];
    hosts.extend(
        request
            .allow
            .iter()
            .filter_map(|capability| capability.strip_prefix("egress:"))
            .map(str::to_owned),
    );
    match env::var("KEEL_MODEL_REGION") {
        Ok(region) if env::var("KEEL_MODEL_PROVIDER").as_deref() == Ok("bedrock") => {
            hosts.push(format!("bedrock-runtime.{region}.amazonaws.com"));
        }
        _ => hosts.push("api.anthropic.com".to_owned()),
    }
    if request
        .allow
        .iter()
        .any(|capability| capability == "pr:create" || capability == "github:read-private-issues")
    {
        hosts.push("api.github.com".to_owned());
    }
    hosts.retain(|host| {
        !host.is_empty()
            && host
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b':'))
    });
    hosts.sort();
    hosts.dedup();
    hosts.join(",")
}

fn copy_optional_environment(command: &mut Command, names: &[&str]) {
    for name in names {
        if let Some(value) = env::var_os(name) {
            command.env(name, value);
        }
    }
}

fn create_control(
    request: &RunRequest,
    ca_certificate: Option<&std::ffi::OsStr>,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let root = runtime_scratch().join(format!(
        "keel-control-{}-{}",
        std::process::id(),
        request.session_id
    ));
    fs::create_dir(&root)?;
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
    if let Some(certificate) = ca_certificate {
        let path = root.join("ca.pem");
        fs::write(&path, certificate.as_encoded_bytes())?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o444))?;
    }
    let rows = terminal_dimension("KEEL_TERMINAL_ROWS", 24);
    let columns = terminal_dimension("KEEL_TERMINAL_COLUMNS", 80);
    // The guest's pty is created by init, which runs long before the launch
    // script below. Init's environment comes from the kernel rather than from
    // this process, so the control mount is the only channel that carries the
    // size early enough for the pty to be created at it.
    let path = root.join("terminal-size");
    fs::write(&path, format!("{rows} {columns}\n"))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o444))?;
    let path = root.join("launch");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o500)
        .open(path)?;
    writeln!(file, "#!/bin/sh")?;
    if ca_certificate.is_some() {
        writeln!(file, "KEEL_CONTROL_DIR=${{0%/*}}")?;
        writeln!(
            file,
            "export SSL_CERT_FILE=\"$KEEL_CONTROL_DIR/ca.pem\" CURL_CA_BUNDLE=\"$KEEL_CONTROL_DIR/ca.pem\" GIT_SSL_CAINFO=\"$KEEL_CONTROL_DIR/ca.pem\" NODE_EXTRA_CA_CERTS=\"$KEEL_CONTROL_DIR/ca.pem\""
        )?;
    }
    let term = env::var("TERM")
        .ok()
        .filter(|term| {
            !term.is_empty()
                && term.len() <= 64
                && term
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        })
        .unwrap_or_else(|| "xterm-256color".to_owned());
    writeln!(
        file,
        "export KEEL_TERMINAL_ROWS={rows} KEEL_TERMINAL_COLUMNS={columns} TERM={}",
        shell_quote(&term)
    )?;
    writeln!(
        file,
        "export KEEL_REQUESTED_HARNESS={}",
        shell_quote(&request.harness)
    )?;
    writeln!(
        file,
        "export KEEL_ISOLATION={}",
        shell_quote(request.isolation.as_str())
    )?;
    // The trusted process decides which model provider a run uses and passes down
    // the sentinel; everything written here is non-secret, and the guest reaches
    // the endpoint only through the broker that authorizes each request.
    // The guest has no account session and nothing of the operator's
    // configuration is mounted, so the model it would otherwise default to is
    // the harness's, not theirs. Naming it here is the only way the choice
    // crosses the boundary.
    if let Some(model) = &request.model {
        writeln!(file, "export ANTHROPIC_MODEL={}", shell_quote(model))?;
    }
    let model_sentinel = env::var("KEEL_MODEL_SENTINEL").unwrap_or_default();
    writeln!(
        file,
        "export KEEL_MODEL_SENTINEL={}",
        shell_quote(&model_sentinel)
    )?;
    if env::var("KEEL_MODEL_PROVIDER").as_deref() == Ok("openrouter") {
        // OpenRouter takes the key as a bearer token, and the harness must send
        // every request, including its background ones, to the one model whose
        // price the operator admitted.
        writeln!(
            file,
            "export KEEL_MODEL_PROVIDER=openrouter ANTHROPIC_BASE_URL=https://openrouter.ai/api ANTHROPIC_AUTH_TOKEN={} ANTHROPIC_API_KEY=",
            shell_quote(&model_sentinel)
        )?;
        if let Some(model) = &request.model {
            let model = shell_quote(model);
            writeln!(
                file,
                "export ANTHROPIC_DEFAULT_OPUS_MODEL={model} ANTHROPIC_DEFAULT_SONNET_MODEL={model} ANTHROPIC_DEFAULT_HAIKU_MODEL={model} ANTHROPIC_SMALL_FAST_MODEL={model} CLAUDE_CODE_SUBAGENT_MODEL={model}"
            )?;
        }
    }
    if env::var("KEEL_MODEL_PROVIDER").as_deref() == Ok("bedrock") {
        let region = env::var("KEEL_MODEL_REGION").unwrap_or_default();
        if env::var("KEEL_MODEL_AUTH_MODE").as_deref() == Ok("sigv4") {
            // These are deliberately unusable public placeholders. Claude Code
            // creates an ordinary Bedrock Runtime request with them; the trusted
            // proxy removes every guest-controlled signing header and signs the
            // sanitized request with the host's scoped AWS credentials.
            writeln!(
                file,
                "export CLAUDE_CODE_USE_BEDROCK=1 AWS_REGION={} AWS_ACCESS_KEY_ID={} AWS_SECRET_ACCESS_KEY={}",
                shell_quote(&region),
                shell_quote("KEELPUBLICACCESSKEY"),
                shell_quote(&model_sentinel)
            )?;
        } else {
            writeln!(
                file,
                "export CLAUDE_CODE_USE_BEDROCK=1 AWS_REGION={} AWS_BEARER_TOKEN_BEDROCK={}",
                shell_quote(&region),
                shell_quote(&model_sentinel)
            )?;
        }
    }
    write!(file, "exec /usr/local/bin/keel-launch keel-harness")?;
    for argument in &request.harness_args {
        write!(file, " {}", shell_quote(argument))?;
    }
    writeln!(file)?;
    file.sync_all()?;
    Ok(root)
}

fn runtime_scratch() -> PathBuf {
    env::var_os("KEEL_RUNTIME_SCRATCH").map_or_else(env::temp_dir, PathBuf::from)
}

fn terminal_dimension(name: &str, default: u16) -> u16 {
    env::var(name)
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

#[cfg(test)]
mod tests {
    use super::{create_control, file_url, shell_quote};
    use keel_cli::{IsolationMode, ProvenanceMode, RunRequest};
    use std::{
        ffi::OsStr,
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    #[test]
    fn shell_quote_preserves_arguments_without_execution() {
        assert_eq!(shell_quote("plain"), "'plain'");
        assert_eq!(
            shell_quote("a'b; $(touch nope)"),
            "'a'\"'\"'b; $(touch nope)'"
        );
    }

    #[test]
    fn sdk_file_urls_escape_workspace_spaces() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("keel url test-{nonce:x}"));
        fs::create_dir(&root).unwrap();
        let path = root.join("sdk file.ts");
        fs::write(&path, "").unwrap();
        let url = file_url(&path).unwrap();
        assert!(url.starts_with("file:///"));
        assert!(url.contains("keel%20url%20test-"));
        assert!(url.ends_with("/sdk%20file.ts"));
        assert!(!url.contains(' '));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn control_mount_carries_only_the_public_run_certificate() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let request = RunRequest {
            session_id: format!("ca-test-{nonce:x}"),
            provenance: ProvenanceMode::Floor,
            reuse_connections: false,
            cpus: 2,
            memory_gib: 2,
            isolation: IsolationMode::Vm,
            mux: false,
            keep_alive: false,
            allow: Vec::new(),
            policy: None,
            policy_bundle_hash: None,
            workspace: None,
            harness: "test".to_owned(),
            harness_args: Vec::new(),
            model: Some("us.anthropic.claude-opus-5".to_owned()),
            auth: None,
            triage: keel_cli::TriageRequest::default(),
            model_token_budget: keel_cli::DEFAULT_MODEL_TOKEN_BUDGET,
            model_cost_budget_microusd: keel_cli::DEFAULT_MODEL_COST_BUDGET_MICROUSD,
        };
        let control =
            create_control(&request, Some(OsStr::new("PUBLIC CERTIFICATE"))).expect("control");
        assert_eq!(
            fs::read_to_string(control.join("ca.pem")).unwrap(),
            "PUBLIC CERTIFICATE"
        );
        let launch = fs::read_to_string(control.join("launch")).unwrap();
        assert!(launch.contains("SSL_CERT_FILE=\"$KEEL_CONTROL_DIR/ca.pem\""));
        assert!(!launch.contains("PRIVATE"));
        assert!(
            launch.contains("export ANTHROPIC_MODEL='us.anthropic.claude-opus-5'"),
            "the named model never reached the guest: {launch}"
        );
        fs::remove_dir_all(control).unwrap();
    }
}
