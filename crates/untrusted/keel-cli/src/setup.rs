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
/// This platform's VM backend, installed beside the runtime.
const VM_BACKEND: &str = if cfg!(target_os = "linux") {
    "keel-ch"
} else {
    "keel-vz-spike"
};
/// The `AppArmor` profile Ubuntu 23.10 and later need before bubblewrap may
/// create the namespaces Keel confines its children in.
const BWRAP_APPARMOR_PROFILE: &str = "abi <abi/4.0>,\ninclude <tunables/global>\n\nprofile bwrap /usr/bin/bwrap flags=(unconfined) {\n  userns,\n  include if exists <local/bwrap>\n}\n";
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

/// Where an install takes each file from: a built source checkout, or an
/// unpacked release whose layout is the installed one.
struct Artifacts {
    bin: PathBuf,
    deno: PathBuf,
    sdk: PathBuf,
    kernel: PathBuf,
    kernel_release: PathBuf,
    rootfs: PathBuf,
    initramfs: PathBuf,
}

impl Artifacts {
    fn checkout(source: &Path) -> Self {
        // The image build keeps each guest architecture apart; x86_64 is the
        // only one that is not the historical default.
        let images = source.join(if cfg!(target_arch = "x86_64") {
            ".phase1-x86_64"
        } else {
            ".phase1"
        });
        Self {
            bin: source.join("target/release"),
            deno: source.join(".phase1/deno/host/deno"),
            sdk: source.join("spikes/keel-v8-sdk.ts"),
            kernel: images.join("kernel/Image"),
            kernel_release: images.join("kernel/release"),
            rootfs: images.join("keel-phase1-rootfs.squashfs"),
            initramfs: images.join("keel-phase1-initramfs.cpio.zst"),
        }
    }

    fn release(release: &Path) -> Self {
        let bin = release.join("bin");
        let images = release.join("images");
        Self {
            deno: bin.join("deno"),
            sdk: bin.join("keel-v8-sdk.ts"),
            bin,
            kernel: images.join("vmlinuz-virt"),
            kernel_release: images.join("kernel-release"),
            rootfs: images.join("keel-phase1-rootfs.squashfs"),
            initramfs: images.join("keel-phase1-initramfs.cpio.zst"),
        }
    }
}

/// This host's release platform, as `spikes/package-release.sh` names it.
fn release_platform() -> String {
    let os = if cfg!(target_os = "macos") {
        "macos"
    } else {
        env::consts::OS
    };
    format!("{os}-{}", env::consts::ARCH)
}

/// Installs a self-contained runtime: from an unpacked release when one is
/// named, after checking every file against its checksums; otherwise by
/// downloading pinned assets and building Keel from the source checkout.
///
/// # Errors
///
/// Returns an error for an unsupported host, missing prerequisite, failed
/// build, release that does not verify, or installation failure.
pub fn install(prebuilt: Option<&Path>) -> Result<String, CliError> {
    require_supported_host()?;
    let artifacts = if let Some(release) = prebuilt {
        let release = fs::canonicalize(release).map_err(io_error)?;
        verify_release(&release)?;
        Artifacts::release(&release)
    } else {
        let source = source_root()?;
        build_from_source(&source)?;
        Artifacts::checkout(&source)
    };
    let linux = cfg!(target_os = "linux");

    let home = home_directory()?;
    let install_root = env::var_os("KEEL_INSTALL_DIR")
        .map_or_else(|| home.join(".local/share/keel"), PathBuf::from);
    let install_bin = install_root.join("bin");
    let install_images = install_root.join("images");
    let previous_config = runtime_config().ok().flatten();
    fs::create_dir_all(&install_bin).map_err(io_error)?;
    fs::create_dir_all(&install_images).map_err(io_error)?;
    let platform_executables: &[&str] = if linux {
        &[VM_BACKEND, "cloud-hypervisor", "virtiofsd"]
    } else {
        &[VM_BACKEND]
    };
    for executable in [
        "keel",
        "keel-input-runtime",
        "keel-runtime",
        "keel-extract",
        "keel-render-spike",
        "keel-xterm-renderer",
    ]
    .iter()
    .chain(platform_executables)
    {
        copy_file(
            &artifacts.bin.join(executable),
            &install_bin.join(executable),
        )?;
    }
    copy_file(&artifacts.deno, &install_bin.join("deno"))?;
    copy_file(&artifacts.sdk, &install_bin.join("keel-v8-sdk.ts"))?;
    let kernel = install_images.join("vmlinuz-virt");
    let initramfs = install_images.join("keel-phase1-initramfs.cpio.zst");
    copy_file(&artifacts.kernel, &kernel)?;
    copy_file(
        &artifacts.kernel_release,
        &install_images.join("kernel-release"),
    )?;
    copy_file(
        &artifacts.rootfs,
        &install_images.join("keel-phase1-rootfs.squashfs"),
    )?;
    copy_file(&artifacts.initramfs, &initramfs)?;

    let config = RuntimeConfig {
        version: CONFIG_VERSION,
        input_runtime: install_bin.join("keel-input-runtime"),
        runtime_backend: install_bin.join("keel-runtime"),
        vz_backend: install_bin.join(VM_BACKEND),
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

/// Checks that an unpacked release is for this host and that every file under
/// `bin/` and `images/` is listed in its `SHA256SUMS` with a matching digest,
/// so nothing unverified is installed.
fn verify_release(release: &Path) -> Result<(), CliError> {
    let platform = fs::read_to_string(release.join("PLATFORM"))
        .map_err(|error| CliError::new(format!("release has no PLATFORM file: {error}")))?;
    if platform.trim() != release_platform() {
        return Err(CliError::new(format!(
            "this release is for {}, and this host is {}",
            platform.trim(),
            release_platform()
        )));
    }
    let sums = fs::read_to_string(release.join("SHA256SUMS"))
        .map_err(|error| CliError::new(format!("release has no SHA256SUMS: {error}")))?;
    let mut listed = std::collections::BTreeSet::new();
    for line in sums.lines().filter(|line| !line.is_empty()) {
        let (expected, name) = line
            .split_once("  ")
            .ok_or_else(|| CliError::new(format!("malformed SHA256SUMS line: {line}")))?;
        let relative = Path::new(name.strip_prefix("./").unwrap_or(name));
        if relative.is_absolute()
            || relative
                .components()
                .any(|part| !matches!(part, std::path::Component::Normal(_)))
        {
            return Err(CliError::new(format!("unsafe path in SHA256SUMS: {name}")));
        }
        let actual = sha256_file(&release.join(relative))?;
        if actual != expected {
            return Err(CliError::new(format!(
                "{name} does not match its checksum: expected {expected}, got {actual}"
            )));
        }
        listed.insert(relative.to_path_buf());
    }
    for directory in ["bin", "images"] {
        for entry in fs::read_dir(release.join(directory)).map_err(io_error)? {
            let path = entry.map_err(io_error)?.path();
            let relative = path.strip_prefix(release).map_err(io_error)?;
            if !listed.contains(relative) {
                return Err(CliError::new(format!(
                    "release file is not in SHA256SUMS: {}",
                    relative.display()
                )));
            }
        }
    }
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String, CliError> {
    use std::io::Read as _;
    let mut file = fs::File::open(path)
        .map_err(|error| CliError::new(format!("{}: {error}", path.display())))?;
    let mut context = ring::digest::Context::new(&ring::digest::SHA256);
    let mut buffer = vec![0_u8; 1 << 20];
    loop {
        let count = file.read(&mut buffer).map_err(io_error)?;
        if count == 0 {
            break;
        }
        context.update(&buffer[..count]);
    }
    Ok(context
        .finish()
        .as_ref()
        .iter()
        .fold(String::new(), |mut hex, byte| {
            let _ = write!(hex, "{byte:02x}");
            hex
        }))
}

const REAPER_LABEL: &str = "dev.keel.reaper";

/// Where the reaper's job definition lives on this platform.
fn reaper_files(home: &Path) -> Vec<PathBuf> {
    if cfg!(target_os = "macos") {
        vec![home.join(format!("Library/LaunchAgents/{REAPER_LABEL}.plist"))]
    } else {
        let units = home.join(".config/systemd/user");
        vec![
            units.join("keel-reaper.service"),
            units.join("keel-reaper.timer"),
        ]
    }
}

/// Installs an hourly `keel recover --all`, so a host where Keel then goes
/// unused does not keep a crashed session's backend until the next command.
/// It is opt-in because it changes host configuration.
///
/// # Errors
///
/// Returns an error when Keel is not installed or the job cannot be written
/// or loaded.
pub fn install_reaper() -> Result<String, CliError> {
    let config = runtime_config()?
        .ok_or_else(|| CliError::new("Keel is not installed; run `keel setup` first"))?;
    let keel = config.input_runtime.with_file_name("keel");
    if !is_executable(&keel) {
        return Err(CliError::new(format!(
            "installed keel is missing: {}",
            keel.display()
        )));
    }
    let home = home_directory()?;
    let files = reaper_files(&home);
    for file in &files {
        if let Some(parent) = file.parent() {
            fs::create_dir_all(parent).map_err(io_error)?;
        }
    }
    let log = home.join(".keel/reaper.log");
    if cfg!(target_os = "macos") {
        load_launchd_reaper(&files[0], &keel, &log)?;
    } else {
        load_systemd_reaper(&files, &keel)?;
    }
    let mut message = format!(
        "Installed the Keel crash reaper: `{} recover --all` runs hourly.\nRemove it with `keel setup --remove-reaper`.",
        keel.display()
    );
    if cfg!(target_os = "linux") {
        message.push_str(
            "\nSystemd runs user timers only while you are logged in, unless lingering is on \
(`loginctl enable-linger`).",
        );
    }
    Ok(message)
}

/// Writes and loads the launchd agent that runs the reaper hourly.
fn load_launchd_reaper(plist: &Path, keel: &Path, log: &Path) -> Result<(), CliError> {
    let xml = |path: &Path| {
        path.display()
            .to_string()
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
    };
    fs::write(
        plist,
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
<plist version=\"1.0\">\n<dict>\n\
  <key>Label</key><string>{REAPER_LABEL}</string>\n\
  <key>ProgramArguments</key><array><string>{}</string><string>recover</string><string>--all</string></array>\n\
  <key>StartInterval</key><integer>3600</integer>\n\
  <key>ProcessType</key><string>Background</string>\n\
  <key>StandardOutPath</key><string>{}</string>\n\
  <key>StandardErrorPath</key><string>{}</string>\n\
</dict>\n</plist>\n",
            xml(keel),
            xml(log),
            xml(log)
        ),
    )
    .map_err(io_error)?;
    let domain = format!("gui/{}", user_id()?);
    let _ = Command::new("launchctl")
        .args(["bootout", &format!("{domain}/{REAPER_LABEL}")])
        .output();
    let loaded = Command::new("launchctl")
        .args(["bootstrap", &domain])
        .arg(plist)
        .output()
        .map_err(io_error)?;
    if !loaded.status.success() {
        return Err(CliError::new(format!(
            "launchctl could not load the reaper: {}",
            String::from_utf8_lossy(&loaded.stderr).trim()
        )));
    }
    Ok(())
}

/// Writes and enables the systemd user timer that runs the reaper hourly.
fn load_systemd_reaper(files: &[PathBuf], keel: &Path) -> Result<(), CliError> {
    let quoted = format!("\"{}\"", keel.display().to_string().replace('"', "\\\""));
    fs::write(
        &files[0],
        format!(
            "[Unit]\nDescription=Release resources of crashed Keel sessions\n\n\
[Service]\nType=oneshot\nExecStart={quoted} recover --all\n"
        ),
    )
    .map_err(io_error)?;
    fs::write(
        &files[1],
        "[Unit]\nDescription=Hourly Keel crash recovery\n\n\
[Timer]\nOnBootSec=10min\nOnUnitActiveSec=1h\n\n[Install]\nWantedBy=timers.target\n",
    )
    .map_err(io_error)?;
    for arguments in [
        &["--user", "daemon-reload"][..],
        &["--user", "enable", "--now", "keel-reaper.timer"][..],
    ] {
        let ran = Command::new("systemctl")
            .args(arguments)
            .output()
            .map_err(io_error)?;
        if !ran.status.success() {
            return Err(CliError::new(format!(
                "systemctl {} failed: {}",
                arguments.join(" "),
                String::from_utf8_lossy(&ran.stderr).trim()
            )));
        }
    }
    Ok(())
}

/// Removes the hourly crash-recovery job.
///
/// # Errors
///
/// Returns an error when a job file cannot be removed.
pub fn remove_reaper() -> Result<String, CliError> {
    let home = home_directory()?;
    if cfg!(target_os = "macos") {
        let _ = Command::new("launchctl")
            .args(["bootout", &format!("gui/{}/{REAPER_LABEL}", user_id()?)])
            .output();
    } else {
        let _ = Command::new("systemctl")
            .args(["--user", "disable", "--now", "keel-reaper.timer"])
            .output();
    }
    let mut removed = false;
    for file in reaper_files(&home) {
        match fs::remove_file(&file) {
            Ok(()) => removed = true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(io_error(error)),
        }
    }
    if cfg!(target_os = "linux") {
        let _ = Command::new("systemctl")
            .args(["--user", "daemon-reload"])
            .output();
    }
    Ok(if removed {
        "Removed the Keel crash reaper.".to_owned()
    } else {
        "No Keel crash reaper was installed.".to_owned()
    })
}

fn user_id() -> Result<String, CliError> {
    let output = Command::new("id").arg("-u").output().map_err(io_error)?;
    let id = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if !output.status.success() || id.is_empty() || !id.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(CliError::new("cannot determine the user id"));
    }
    Ok(id)
}

/// Checks the build prerequisites, then fetches the pinned assets and builds
/// Keel and its guest image from the checkout.
fn build_from_source(source: &Path) -> Result<(), CliError> {
    let linux = cfg!(target_os = "linux");
    let programs: &[&str] = if linux {
        &[
            "bwrap",
            "cargo",
            "curl",
            "docker",
            "gzip",
            "pkg-config",
            "python3",
            "sha256sum",
            "tar",
        ]
    } else {
        &[
            "cargo", "clang", "codesign", "cpio", "curl", "docker", "gzip", "python3", "shasum",
            "tar",
        ]
    };
    for program in programs {
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
    // virtiofsd is built from source against these two libraries.
    if linux
        && !Command::new("pkg-config")
            .args(["--exists", "libseccomp", "libcap-ng"])
            .status()
            .is_ok_and(|status| status.success())
    {
        return Err(CliError::new(
            "virtiofsd needs libseccomp and libcap-ng headers: install libseccomp-dev and \
libcap-ng-dev (Debian, Ubuntu) or libseccomp-devel and libcap-ng-devel (Fedora)",
        ));
    }
    let scripts: &[&str] = if linux {
        &[
            "spikes/fetch-guest-kernel.sh",
            "spikes/fetch-deno.sh",
            "spikes/build-xterm-renderer.sh",
            "spikes/build-phase1-image.sh",
            "spikes/build-linux-runtime.sh",
        ]
    } else {
        &[
            "spikes/fetch-phase0.sh",
            "spikes/fetch-guest-kernel.sh",
            "spikes/fetch-deno.sh",
            "spikes/build-xterm-renderer.sh",
            "spikes/build-phase1-image.sh",
            "spikes/build-vz-runtime.sh",
        ]
    };
    for script in scripts {
        run_script(source, script)?;
    }

    Ok(())
}

/// Checks the installed runtime, credentials, and current Git workspace.
#[must_use]
pub fn doctor() -> DoctorReport {
    let mut report = CheckReport::default();
    check_host(&mut report);
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
            ("VM backend", &config.vz_backend),
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
        check_backend(&mut report, &config.vz_backend);
    }
    check_model_credentials(&mut report);
    report.optional(
        github_authenticated(),
        "GitHub credential is available",
        "GitHub authentication is unavailable; run `gh auth login` or set GH_TOKEN",
    );
    check_local_state(&mut report);
    if home_directory().is_ok_and(|home| reaper_files(&home).iter().all(|file| file.is_file())) {
        report.ok("crash reaper is installed (hourly `keel recover --all`)");
    }
    DoctorReport {
        output: report.output,
        healthy: report.healthy,
    }
}

fn check_local_state(report: &mut CheckReport) {
    check_git_credentials(report);
    check_workspace(report);
    let stale = super::stale_sessions();
    report.optional(
        stale.is_empty(),
        "no crashed session awaits recovery",
        &format!(
            "{} crashed session(s) await `keel recover SESSION`, most recent: {}",
            stale.len(),
            stale
                .iter()
                .rev()
                .take(3)
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        ),
    );
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
    let supported = (cfg!(target_os = "macos") && cfg!(target_arch = "aarch64"))
        || (cfg!(target_os = "linux")
            && cfg!(any(target_arch = "x86_64", target_arch = "aarch64")));
    if !supported {
        return Err(CliError::new(
            "Keel setup supports Apple silicon macOS, and Linux on x86_64 or ARM64",
        ));
    }
    Ok(())
}

/// Checks what the VM backend needs beside it: its hypervisor and file
/// sharing helpers on Linux, its virtualization entitlements on macOS.
fn check_backend(report: &mut CheckReport, backend: &Path) {
    if cfg!(target_os = "linux") {
        for name in ["cloud-hypervisor", "virtiofsd"] {
            let path = backend.with_file_name(name);
            report.required(
                is_executable(&path),
                &format!("{name}: {}", path.display()),
                &format!("{name} is missing or not executable: {}", path.display()),
            );
        }
    } else {
        report.required(
            valid_vz_signature(backend),
            "VZ backend has virtualization entitlements",
            "VZ backend is unsigned or lacks virtualization entitlements",
        );
    }
}

/// Checks the host platform, and on Linux what its runtime needs.
fn check_host(report: &mut CheckReport) {
    if cfg!(target_os = "linux") {
        report.required(
            cfg!(any(target_arch = "x86_64", target_arch = "aarch64")),
            "host is Linux on x86_64 or ARM64",
            "Keel on Linux requires an x86_64 or ARM64 host",
        );
        let ubuntu = fs::read_to_string("/etc/os-release").is_ok_and(|release| {
            release
                .lines()
                .any(|line| line == "ID=ubuntu" || line == "ID=\"ubuntu\"")
        });
        report.optional(
            ubuntu,
            "Linux distribution is Ubuntu",
            "this Linux distribution is not supported; Keel is tested on Ubuntu",
        );
        check_linux_host(report);
    } else {
        report.required(
            cfg!(target_os = "macos"),
            "host operating system is macOS",
            "Keel requires macOS on Apple silicon, or Linux with KVM",
        );
        report.required(
            cfg!(target_arch = "aarch64"),
            "host architecture is Apple silicon",
            "the packaged macOS guest requires Apple silicon",
        );
    }
}

/// Checks what the Linux runtime needs from the host: KVM for the guest, and
/// bubblewrap able to create the namespaces Keel confines its children in.
fn check_linux_host(report: &mut CheckReport) {
    let kvm = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm");
    report.required(
        kvm.is_ok(),
        "KVM is available (/dev/kvm)",
        &format!(
            "cannot open /dev/kvm ({}); enable virtualization and add this user to the kvm \
group (`sudo usermod -aG kvm $USER`, then log in again)",
            kvm.err()
                .map_or_else(String::new, |error| error.to_string())
        ),
    );
    let bwrap = Path::new("/usr/bin/bwrap");
    if !is_executable(bwrap) {
        report.fail("bubblewrap is missing at /usr/bin/bwrap; install the bubblewrap package");
        return;
    }
    let confines = Command::new(bwrap)
        .args([
            "--unshare-all",
            "--die-with-parent",
            "--ro-bind",
            "/",
            "/",
            "--",
            "/bin/true",
        ])
        .output()
        .is_ok_and(|output| output.status.success());
    if confines {
        report.ok("bubblewrap can create Keel's confinement namespaces");
        return;
    }
    let restricted = fs::read_to_string("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
        .is_ok_and(|value| value.trim() == "1");
    if restricted {
        report.fail(&format!(
            "AppArmor restricts user namespaces, so bubblewrap cannot confine Keel's children; \
allow it once with:\n  printf '{}' | sudo tee /etc/apparmor.d/bwrap >/dev/null && sudo \
apparmor_parser -r /etc/apparmor.d/bwrap",
            BWRAP_APPARMOR_PROFILE.replace('\n', "\\n")
        ));
    } else {
        report.fail(
            "bubblewrap cannot create user namespaces; enable unprivileged user namespaces \
(kernel.unprivileged_userns_clone=1 or user.max_user_namespaces > 0)",
        );
    }
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
    use super::{
        CONFIG_VERSION, CheckReport, RuntimeConfig, install_launcher, release_platform,
        sha256_file, verify_release,
    };
    use std::{
        fmt::Write as _,
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn release_fixture() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("keel-release-{nonce:x}"));
        fs::create_dir_all(root.join("bin")).unwrap();
        fs::create_dir_all(root.join("images")).unwrap();
        fs::write(root.join("bin/keel"), "launcher").unwrap();
        fs::write(root.join("images/vmlinuz-virt"), "kernel").unwrap();
        fs::write(root.join("PLATFORM"), format!("{}\n", release_platform())).unwrap();
        let mut sums = String::new();
        for name in ["bin/keel", "images/vmlinuz-virt"] {
            let _ = writeln!(sums, "{}  ./{name}", sha256_file(&root.join(name)).unwrap());
        }
        fs::write(root.join("SHA256SUMS"), sums).unwrap();
        root
    }

    #[test]
    fn a_release_installs_only_when_every_file_verifies() {
        let release = release_fixture();
        assert!(verify_release(&release).is_ok());

        fs::write(release.join("images/vmlinuz-virt"), "tampered").unwrap();
        let error = verify_release(&release).unwrap_err().to_string();
        assert!(error.contains("does not match its checksum"), "{error}");
        fs::remove_dir_all(&release).unwrap();

        let release = release_fixture();
        fs::write(release.join("bin/extra"), "unlisted").unwrap();
        let error = verify_release(&release).unwrap_err().to_string();
        assert!(error.contains("not in SHA256SUMS"), "{error}");
        fs::remove_dir_all(&release).unwrap();

        let release = release_fixture();
        let mut sums = fs::read_to_string(release.join("SHA256SUMS")).unwrap();
        let _ = writeln!(sums, "{}  ../outside", "0".repeat(64));
        fs::write(release.join("SHA256SUMS"), sums).unwrap();
        let error = verify_release(&release).unwrap_err().to_string();
        assert!(error.contains("unsafe path"), "{error}");
        fs::remove_dir_all(&release).unwrap();

        let release = release_fixture();
        fs::write(release.join("PLATFORM"), "plan9-mips\n").unwrap();
        let error = verify_release(&release).unwrap_err().to_string();
        assert!(error.contains("this release is for plan9-mips"), "{error}");
        fs::remove_dir_all(&release).unwrap();
    }

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
