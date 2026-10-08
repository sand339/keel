use super::CliError;
use serde::{Deserialize, Serialize};
use std::{
    env,
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

const CONFIG_VERSION: u8 = 1;
type RuntimePath = fn(&RuntimeConfig) -> &Path;
const RUNTIME_ENVIRONMENT: [(&str, RuntimePath); 5] = [
    ("KEEL_RUNTIME_BACKEND", |config| &config.runtime_backend),
    ("KEEL_VZ_BACKEND", |config| &config.vz_backend),
    ("KEEL_RENDERER", |config| &config.renderer),
    ("KEEL_KERNEL", |config| &config.kernel),
    ("KEEL_INITRAMFS", |config| &config.initramfs),
];

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct RuntimeConfig {
    version: u8,
    input_runtime: PathBuf,
    runtime_backend: PathBuf,
    vz_backend: PathBuf,
    renderer: PathBuf,
    kernel: PathBuf,
    initramfs: PathBuf,
}

/// Result of checking the installed runtime and current workspace.
pub struct DoctorReport {
    /// Human-readable check results.
    pub output: String,
    /// Whether every required runtime check passed.
    pub healthy: bool,
}

/// Downloads pinned assets, builds Keel, and installs a self-contained runtime.
///
/// # Errors
///
/// Returns an error for an unsupported host, missing prerequisite, failed
/// build, invalid artifact, or installation failure.
pub fn install() -> Result<String, CliError> {
    require_supported_host()?;
    let source = source_root()?;
    for program in [
        "cargo", "clang", "codesign", "cpio", "curl", "docker", "gzip", "python3", "shasum", "tar",
    ] {
        if find_program(program).is_none() {
            return Err(CliError::new(format!(
                "required setup program is missing: {program}"
            )));
        }
    }
    if !Command::new("docker")
        .arg("info")
        .output()
        .is_ok_and(|output| output.status.success())
    {
        return Err(CliError::new("Docker is installed but is not running"));
    }
    for script in [
        "spikes/fetch-phase0.sh",
        "spikes/fetch-guest-kernel.sh",
        "spikes/fetch-deno.sh",
        "spikes/build-xterm-renderer.sh",
        "spikes/build-phase1-image.sh",
        "spikes/build-vz-runtime.sh",
    ] {
        run_script(&source, script)?;
    }

    let home = home_directory()?;
    let install_root = env::var_os("KEEL_INSTALL_DIR")
        .map_or_else(|| home.join(".local/share/keel"), PathBuf::from);
    let install_bin = install_root.join("bin");
    let install_images = install_root.join("images");
    let previous_config = runtime_config().ok().flatten();
    fs::create_dir_all(&install_bin).map_err(io_error)?;
    fs::create_dir_all(&install_images).map_err(io_error)?;
    for executable in [
        "keel",
        "keel-input-runtime",
        "keel-runtime",
        "keel-vz-spike",
        "keel-render-spike",
        "keel-xterm-renderer",
    ] {
        copy_file(
            &source.join("target/release").join(executable),
            &install_bin.join(executable),
        )?;
    }
    copy_file(
        &source.join(".phase1/deno/host/deno"),
        &install_bin.join("deno"),
    )?;
    copy_file(
        &source.join("spikes/keel-v8-sdk.ts"),
        &install_bin.join("keel-v8-sdk.ts"),
    )?;
    let kernel = install_images.join("vmlinuz-virt");
    let initramfs = install_images.join("keel-phase1-initramfs.cpio.zst");
    copy_file(&source.join(".phase1/kernel/Image"), &kernel)?;
    copy_file(
        &source.join(".phase1/kernel/release"),
        &install_images.join("kernel-release"),
    )?;
    copy_file(
        &source.join(".phase1/keel-phase1-rootfs.squashfs"),
        &install_images.join("keel-phase1-rootfs.squashfs"),
    )?;
    copy_file(
        &source.join(".phase1/keel-phase1-initramfs.cpio.zst"),
        &initramfs,
    )?;

    let config = RuntimeConfig {
        version: CONFIG_VERSION,
        input_runtime: install_bin.join("keel-input-runtime"),
        runtime_backend: install_bin.join("keel-runtime"),
        vz_backend: install_bin.join("keel-vz-spike"),
        renderer: install_bin.join("keel-render-spike"),
        kernel,
        initramfs,
    };
    let launcher = install_launcher(&home, &install_bin, previous_config.as_ref())?;
    save_config(&config)?;
    Ok(format!(
        "Keel setup complete.\nInstalled runtime: {}\nCommand: {}\nNext: {} doctor",
        install_root.display(),
        launcher.display(),
        launcher.display()
    ))
}

/// Checks the installed runtime, credentials, and current Git workspace.
#[must_use]
pub fn doctor() -> DoctorReport {
    let mut report = CheckReport::default();
    report.required(
        cfg!(target_os = "macos"),
        "host operating system is macOS",
        "Keel's packaged runtime currently requires macOS",
    );
    report.required(
        cfg!(target_arch = "aarch64"),
        "host architecture is Apple silicon",
        "the packaged guest currently requires Apple silicon",
    );
    let config = match runtime_config() {
        Ok(Some(config)) => {
            report.ok("runtime configuration loaded");
            Some(config)
        }
        Ok(None) => {
            report.fail("runtime configuration is missing; run `keel setup`");
            None
        }
        Err(error) => {
            report.fail(&format!("runtime configuration is invalid: {error}"));
            None
        }
    };
    if let Some(config) = config {
        report.required(
            config.version == CONFIG_VERSION,
            "runtime configuration version is supported",
            "runtime configuration version is unsupported; rerun `keel setup`",
        );
        for (label, path) in [
            ("trusted input runtime", &config.input_runtime),
            ("runtime backend", &config.runtime_backend),
            ("VZ backend", &config.vz_backend),
            ("renderer", &config.renderer),
        ] {
            report.required(
                is_executable(path),
                &format!("{label}: {}", path.display()),
                &format!("{label} is missing or not executable: {}", path.display()),
            );
        }
        let deno = config.runtime_backend.with_file_name("deno");
        report.required(
            is_executable(&deno),
            &format!("pinned Deno runtime: {}", deno.display()),
            &format!(
                "pinned Deno runtime is missing or not executable: {}",
                deno.display()
            ),
        );
        let terminal_renderer = config.input_runtime.with_file_name("keel-xterm-renderer");
        report.required(
            is_executable(&terminal_renderer),
            &format!("xterm-headless renderer: {}", terminal_renderer.display()),
            &format!(
                "xterm-headless renderer is missing or not executable: {}",
                terminal_renderer.display()
            ),
        );
        let sdk = config.runtime_backend.with_file_name("keel-v8-sdk.ts");
        report.required(
            sdk.is_file(),
            &format!("Keel V8 SDK: {}", sdk.display()),
            &format!("Keel V8 SDK is missing: {}", sdk.display()),
        );
        let root_disk = config
            .initramfs
            .with_file_name("keel-phase1-rootfs.squashfs");
        for (label, path) in [
            ("Linux kernel", &config.kernel),
            ("guest image", &config.initramfs),
            ("guest root disk", &root_disk),
        ] {
            report.required(
                path.is_file(),
                &format!("{label}: {}", path.display()),
                &format!("{label} is missing: {}", path.display()),
            );
        }
        check_guest_kernel(&mut report, &config.kernel);
        report.required(
            valid_vz_signature(&config.vz_backend),
            "VZ backend has virtualization entitlements",
            "VZ backend is unsigned or lacks virtualization entitlements",
        );
    }
    check_model_credentials(&mut report);
    report.optional(
        github_authenticated(),
        "GitHub credential is available",
        "GitHub authentication is unavailable; run `gh auth login` or set GH_TOKEN",
    );
    check_git_credentials(&mut report);
    check_workspace(&mut report);
    DoctorReport {
        output: report.output,
        healthy: report.healthy,
    }
}

/// Returns the configured trusted input runtime, honoring an environment
/// override before the saved setup configuration.
///
/// # Errors
///
/// Returns an error when a saved configuration exists but is malformed.
pub fn configured_input_runtime() -> Result<PathBuf, CliError> {
    if let Some(path) = env::var_os("KEEL_INPUT_RUNTIME") {
        return Ok(PathBuf::from(path));
    }
    Ok(runtime_config()?.map_or_else(
        || PathBuf::from("keel-input-runtime"),
        |config| config.input_runtime,
    ))
}

/// Applies saved runtime paths to a child command where the caller did not
/// provide an explicit environment override.
///
/// # Errors
///
/// Returns an error when a saved configuration exists but is malformed.
pub fn apply_runtime_config(command: &mut Command) -> Result<(), CliError> {
    let Some(config) = runtime_config()? else {
        return Ok(());
    };
    for (variable, path) in RUNTIME_ENVIRONMENT {
        if env::var_os(variable).is_none() {
            command.env(variable, path(&config));
        }
    }
    Ok(())
}

/// Loads the setup configuration when present.
///
/// # Errors
///
/// Returns an error when the file cannot be read or parsed.
fn runtime_config() -> Result<Option<RuntimeConfig>, CliError> {
    let path = config_path()?;
    match fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|error| CliError::new(format!("{}: {error}", path.display()))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(CliError::new(format!("{}: {error}", path.display()))),
    }
}

fn save_config(config: &RuntimeConfig) -> Result<(), CliError> {
    let path = config_path()?;
    let parent = path
        .parent()
        .ok_or_else(|| CliError::new("configuration path has no parent"))?;
    fs::create_dir_all(parent).map_err(io_error)?;
    let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
    let bytes = serde_json::to_vec_pretty(config).map_err(io_error)?;
    fs::write(&temporary, bytes).map_err(io_error)?;
    fs::rename(temporary, path).map_err(io_error)
}

fn config_path() -> Result<PathBuf, CliError> {
    if let Some(path) = env::var_os("KEEL_CONFIG") {
        return Ok(PathBuf::from(path));
    }
    Ok(home_directory()?.join(".keel/config.json"))
}

pub(crate) fn home_directory() -> Result<PathBuf, CliError> {
    env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| CliError::new("HOME is unset"))
}

fn source_root() -> Result<PathBuf, CliError> {
    if let Some(path) = env::var_os("KEEL_SOURCE_DIR") {
        return canonical_source(Path::new(&path));
    }
    let current = env::current_dir().map_err(io_error)?;
    for candidate in current.ancestors() {
        if candidate.join("Cargo.toml").is_file()
            && candidate.join("spikes/build-phase1-image.sh").is_file()
        {
            return canonical_source(candidate);
        }
    }
    Err(CliError::new(
        "cannot find a Keel source checkout; run from it or set KEEL_SOURCE_DIR",
    ))
}

fn canonical_source(path: &Path) -> Result<PathBuf, CliError> {
    let path = fs::canonicalize(path).map_err(io_error)?;
    if !path.join("spikes/build-vz-runtime.sh").is_file() {
        return Err(CliError::new("KEEL_SOURCE_DIR is not a Keel checkout"));
    }
    Ok(path)
}

fn run_script(source: &Path, relative: &str) -> Result<(), CliError> {
    let script = source.join(relative);
    let mut command = Command::new("/bin/sh");
    command.arg(&script);
    command.current_dir(source);
    if !status(&mut command) {
        return Err(CliError::new(format!("{relative} failed")));
    }
    Ok(())
}

fn copy_file(source: &Path, destination: &Path) -> Result<(), CliError> {
    if !source.is_file() {
        return Err(CliError::new(format!(
            "build artifact is missing: {}",
            source.display()
        )));
    }
    let temporary = destination.with_extension(format!("tmp-{}", std::process::id()));
    fs::copy(source, &temporary).map_err(io_error)?;
    fs::rename(temporary, destination).map_err(io_error)?;
    Ok(())
}

fn install_launcher(
    home: &Path,
    install_bin: &Path,
    previous_config: Option<&RuntimeConfig>,
) -> Result<PathBuf, CliError> {
    let launcher_directory =
        env::var_os("KEEL_BIN_DIR").map_or_else(|| home.join(".local/bin"), PathBuf::from);
    fs::create_dir_all(&launcher_directory).map_err(io_error)?;
    let launcher = launcher_directory.join("keel");
    if launcher.is_symlink() {
        let existing = fs::read_link(&launcher).map_err(io_error)?;
        if existing != install_bin.join("keel") {
            return Err(CliError::new(format!(
                "refusing to replace existing launcher: {}",
                launcher.display()
            )));
        }
        fs::remove_file(&launcher).map_err(io_error)?;
    } else if launcher.exists() {
        let managed = previous_config.is_some_and(|config| {
            config.input_runtime.parent() == Some(install_bin)
                && config.runtime_backend.parent() == Some(install_bin)
        });
        if !managed {
            return Err(CliError::new(format!(
                "refusing to replace existing launcher: {}",
                launcher.display()
            )));
        }
        fs::remove_file(&launcher).map_err(io_error)?;
    }
    #[cfg(unix)]
    std::os::unix::fs::symlink(install_bin.join("keel"), &launcher).map_err(io_error)?;
    Ok(launcher)
}

fn require_supported_host() -> Result<(), CliError> {
    if !cfg!(target_os = "macos") || !cfg!(target_arch = "aarch64") {
        return Err(CliError::new(
            "Keel setup currently supports Apple silicon macOS",
        ));
    }
    Ok(())
}

fn find_program(name: &str) -> Option<PathBuf> {
    env::var_os("PATH").and_then(|paths| {
        env::split_paths(&paths)
            .map(|directory| directory.join(name))
            .find(|path| is_executable(path))
    })
}

fn is_executable(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        path.metadata()
            .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
    }
    #[cfg(not(unix))]
    path.is_file()
}

fn status(command: &mut Command) -> bool {
    command.status().is_ok_and(|status| status.success())
}

fn valid_vz_signature(path: &Path) -> bool {
    Command::new("codesign")
        .args(["-d", "--entitlements", "-"])
        .arg(path)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .is_some_and(|output| {
            let mut text = output.stdout;
            text.extend(output.stderr);
            let text = String::from_utf8_lossy(&text);
            text.contains("com.apple.security.hypervisor")
                && text.contains("com.apple.security.virtualization")
        })
}

fn github_authenticated() -> bool {
    env::var_os("GH_TOKEN").is_some()
        || env::var_os("GITHUB_TOKEN").is_some()
        || Command::new("gh")
            .args(["auth", "status", "--hostname", "github.com"])
            .output()
            .is_ok_and(|output| output.status.success())
}

/// Reports which model provider a run would use, and says so when the choice is
/// ambiguous or incomplete: the trusted process takes the regional provider
/// whenever its bearer token is set, and leaves a direct key unbound.
fn check_model_credentials(report: &mut CheckReport) {
    let anthropic = env::var_os("ANTHROPIC_API_KEY").is_some();
    let bearer = env::var_os("AWS_BEARER_TOKEN_BEDROCK").is_some();
    // A bearer token selects the regional provider on its own because the
    // variable exists for nothing else. Signing credentials do not, so the
    // operator names the provider and the doctor mirrors that choice.
    let selected = env::var("KEEL_MODEL_PROVIDER").as_deref() == Ok("bedrock");
    // `keel run --auth` names the provider for one run and outranks both, so a
    // doctor that ignored it would describe a different run than the next one.
    let chosen = env::var("KEEL_MODEL_AUTH").ok();
    if env::var_os("OPENROUTER_API_KEY").is_some() || chosen.as_deref() == Some("openrouter") {
        report.optional(
            env::var_os("OPENROUTER_API_KEY").is_some(),
            "OpenRouter credential is available for `--auth openrouter --model PROVIDER/MODEL`",
            "KEEL_MODEL_AUTH selects OpenRouter, but OPENROUTER_API_KEY is not set",
        );
        if chosen.as_deref() == Some("openrouter") {
            return;
        }
    }
    if chosen.as_deref() == Some("api-key") {
        report.optional(
            anthropic,
            "Anthropic credential is available (selected by KEEL_MODEL_AUTH)",
            "KEEL_MODEL_AUTH selects the Anthropic API key, which is not set",
        );
        return;
    }
    if !bearer && !selected && chosen.as_deref() != Some("bedrock") {
        report.optional(
            anthropic,
            "Anthropic credential is available",
            "no model credential is set; live Claude requests will fail",
        );
        return;
    }
    if env::var_os("AWS_REGION").is_none() {
        report.warn(
            "the regional model provider is selected without AWS_REGION; `keel run` will refuse",
        );
        return;
    }
    if bearer {
        report.ok("regional model credential is available (bearer token)");
    } else {
        check_signing_credentials(report);
    }
    if anthropic {
        report.warn(
            "both model credentials are set; `keel run` asks which to use at a terminal and \
otherwise takes the regional provider, leaving ANTHROPIC_API_KEY unbound; `--auth \
api-key|bedrock` settles it",
        );
    }
}

/// Reports whether `SigV4` signing could resolve a credential for this run.
///
/// A `credential_process` command is reported without being run: it may prompt,
/// it may reach the network, and `keel doctor` is not where an operator should
/// discover either. What it can say is which of the three shapes is configured,
/// because the one that cannot survive a long run is also the one that looks
/// correct until it lapses.
fn check_signing_credentials(report: &mut CheckReport) {
    if env::var_os("KEEL_AWS_CREDENTIAL_PROCESS").is_some() {
        report.ok("regional model credential is signed via KEEL_AWS_CREDENTIAL_PROCESS");
    } else if env::var_os("AWS_ACCESS_KEY_ID").is_some()
        && env::var_os("AWS_SECRET_ACCESS_KEY").is_some()
    {
        if env::var_os("AWS_SESSION_TOKEN").is_some() {
            report.warn(
                "regional model credential is a session Keel cannot refresh; set \
KEEL_AWS_CREDENTIAL_PROCESS so a long run survives rotation",
            );
        } else {
            report.ok("regional model credential is signed from static AWS keys");
        }
    } else {
        report.warn(
            "the regional model provider is selected with no signing credential; set \
AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY, or KEEL_AWS_CREDENTIAL_PROCESS",
        );
    }
}

fn check_git_credentials(report: &mut CheckReport) {
    let configured = [
        env::var_os("KEEL_GIT_AUTHORIZATION").is_some(),
        env::var_os("KEEL_GIT_CREDENTIAL_HOST").is_some(),
        env::var_os("KEEL_GIT_CREDENTIAL_PATH").is_some(),
    ];
    if configured.iter().all(|value| *value) {
        report.ok("Git push credential scope is complete");
    } else if configured.iter().all(|value| !*value) {
        report.warn("Git push credential scope is unset; authenticated pushes are unavailable");
    } else {
        report.warn("set all three KEEL_GIT_* credential variables or unset all three");
    }
}

fn check_workspace(report: &mut CheckReport) {
    let inside = keel_provenance::trusted_git_command()
        .args(["rev-parse", "--is-inside-work-tree"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .is_some_and(|output| output.stdout.starts_with(b"true"));
    report.optional(
        inside,
        "current directory is a Git worktree",
        "current directory is not a Git worktree; change into a project before `keel run`",
    );
    if inside {
        let origin = keel_provenance::trusted_git_command()
            .args(["remote", "get-url", "origin"])
            .output()
            .ok()
            .filter(|output| output.status.success())
            .and_then(|output| String::from_utf8(output.stdout).ok())
            .map(|value| value.trim().to_owned());
        report.optional(
            origin
                .as_deref()
                .is_some_and(|value| value.starts_with("https://") || value.starts_with("http://")),
            "origin uses HTTP(S) for mediated Git",
            "origin is missing or is not HTTP(S); authenticated pushes need an HTTPS origin",
        );
    }
}

struct CheckReport {
    output: String,
    healthy: bool,
}

impl Default for CheckReport {
    fn default() -> Self {
        Self {
            output: String::new(),
            healthy: true,
        }
    }
}

impl CheckReport {
    fn ok(&mut self, message: &str) {
        let _ = writeln!(self.output, "[ok] {message}");
    }

    fn fail(&mut self, message: &str) {
        self.healthy = false;
        let _ = writeln!(self.output, "[fail] {message}");
    }

    fn required(&mut self, passed: bool, success: &str, failure: &str) {
        if passed {
            self.ok(success);
        } else {
            self.fail(failure);
        }
    }

    fn optional(&mut self, passed: bool, success: &str, warning: &str) {
        if passed {
            self.ok(success);
        } else {
            self.warn(warning);
        }
    }

    fn warn(&mut self, message: &str) {
        let _ = writeln!(self.output, "[warn] {message}");
    }
}

fn io_error(error: impl std::fmt::Display) -> CliError {
    CliError::new(error.to_string())
}

/// Reports whether the installed guest kernel provides Landlock ABI 6 signal
/// and abstract-socket scoping, which arrived in Linux 6.12. Older guests
/// confine with file rules only.
fn check_guest_kernel(report: &mut CheckReport, kernel: &Path) {
    let release = fs::read_to_string(kernel.with_file_name("kernel-release"))
        .map(|release| release.trim().to_owned())
        .unwrap_or_default();
    let scoped = release
        .split(['.', '-'])
        .take(2)
        .map(|part| part.parse::<u32>().unwrap_or_default())
        .collect::<Vec<_>>()
        >= vec![6, 12];
    report.optional(
        scoped,
        &format!("guest kernel {release} supports Landlock scoping"),
        "guest kernel predates Linux 6.12; rerun keel setup for Landlock scoping",
    );
}

#[cfg(test)]
mod tests {
    use super::{CONFIG_VERSION, CheckReport, RuntimeConfig, install_launcher};
    use std::{
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    #[test]
    fn required_failure_remains_unhealthy_after_later_success() {
        let mut report = CheckReport::default();
        report.fail("missing");
        report.ok("present");
        assert!(!report.healthy);
        assert_eq!(report.output, "[fail] missing\n[ok] present\n");
    }

    #[test]
    fn runtime_configuration_round_trips_without_credentials() {
        let config = RuntimeConfig {
            version: CONFIG_VERSION,
            input_runtime: PathBuf::from("/install/keel-input-runtime"),
            runtime_backend: PathBuf::from("/install/keel-runtime"),
            vz_backend: PathBuf::from("/install/keel-vz-spike"),
            renderer: PathBuf::from("/install/keel-render-spike"),
            kernel: PathBuf::from("/install/vmlinuz-virt"),
            initramfs: PathBuf::from("/install/keel.cpio.gz"),
        };
        let encoded = serde_json::to_vec(&config).unwrap();
        assert_eq!(
            serde_json::from_slice::<RuntimeConfig>(&encoded).unwrap(),
            config
        );
        let text = String::from_utf8(encoded).unwrap();
        assert!(!text.contains("TOKEN"));
        assert!(!text.contains("AUTHORIZATION"));
    }

    #[test]
    fn setup_upgrades_a_regular_launcher_owned_by_the_configured_install() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let home = std::env::temp_dir().join(format!("keel-setup-{nonce:x}"));
        let install_bin = home.join("install/bin");
        let launcher = home.join(".local/bin/keel");
        fs::create_dir_all(&install_bin).unwrap();
        fs::create_dir_all(launcher.parent().unwrap()).unwrap();
        fs::write(&launcher, b"old keel launcher").unwrap();
        let config = RuntimeConfig {
            version: CONFIG_VERSION,
            input_runtime: install_bin.join("keel-input-runtime"),
            runtime_backend: install_bin.join("keel-runtime"),
            vz_backend: install_bin.join("keel-vz-spike"),
            renderer: install_bin.join("keel-render-spike"),
            kernel: home.join("install/images/vmlinuz-virt"),
            initramfs: home.join("install/images/keel.cpio.gz"),
        };

        assert_eq!(
            install_launcher(&home, &install_bin, Some(&config)).unwrap(),
            launcher
        );
        assert!(
            fs::symlink_metadata(&launcher)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read_link(&launcher).unwrap(), install_bin.join("keel"));
        fs::remove_dir_all(home).unwrap();
    }
}
