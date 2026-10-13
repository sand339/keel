#![doc = "KVM microVM backend driven through Cloud Hypervisor."]

// Takes the same command line as the Virtualization.framework backend, so the
// runtime starts either the same way. Cloud Hypervisor and virtiofsd stay
// outside the trusted computing base: they provide the isolation mechanism,
// and every guest request still reaches the trusted kernel broker through the
// shared relays.

#[cfg(target_os = "linux")]
mod linux {
    use keel_isolate::relay::{
        EGRESS_VSOCK_PORT, GIT_VSOCK_PORT, LaunchArguments, MCP_VSOCK_PORT, RelayError,
        SERVICE_QUEUE_DEPTH, TERMINAL_VSOCK_PORT, initialize_git_service, parse_launch_arguments,
        record_guest_events, relay_terminal, run_egress, run_git, run_mcp, run_node_mcp,
        spawn_service,
    };
    use std::{
        env,
        ffi::{CString, OsString},
        fs,
        io::{BufRead as _, BufReader},
        os::{
            fd::OwnedFd,
            unix::{
                ffi::OsStrExt as _,
                fs::{DirBuilderExt as _, FileTypeExt as _},
                net::UnixListener,
            },
        },
        path::{Path, PathBuf},
        process::{Child, Command, Stdio},
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
            mpsc::{self, SyncSender},
        },
        thread,
        time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    };

    /// The guest's context identifier. Cloud Hypervisor's vsock is a hybrid
    /// device backed by this run's own Unix socket, so identifiers never meet
    /// across VMs.
    const GUEST_CID: u32 = 3;
    const HELPER_SOCKET_TIMEOUT: Duration = Duration::from_secs(10);
    /// How long the guest has to open its first connections. A nested or
    /// heavily shared host can take well over 30 seconds to boot it; waiting
    /// grants nothing.
    const GUEST_CONNECT_TIMEOUT: Duration = Duration::from_mins(2);
    const STOP_GRACE: Duration = Duration::from_secs(5);

    /// One run's private directory of sockets, removed with the run.
    struct RunDirectory(PathBuf);

    impl RunDirectory {
        fn create() -> Result<Self, RelayError> {
            let base =
                env::var_os("KEEL_RUNTIME_SCRATCH").map_or_else(env::temp_dir, PathBuf::from);
            let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
            let path = base.join(format!("keel-ch-{}-{nonce:x}", std::process::id()));
            fs::DirBuilder::new().mode(0o700).create(&path)?;
            Ok(Self(path))
        }

        fn join(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for RunDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// A helper process stopped, then killed, when the run ends.
    struct Supervised {
        name: &'static str,
        child: Child,
    }

    impl Supervised {
        fn spawn(name: &'static str, command: &mut Command) -> Result<Self, RelayError> {
            let child = command
                .spawn()
                .map_err(|error| format!("start {name}: {error}"))?;
            Ok(Self { name, child })
        }

        fn stop(&mut self) {
            if matches!(self.child.try_wait(), Ok(Some(_))) {
                return;
            }
            if let Ok(pid) = i32::try_from(self.child.id()) {
                // SAFETY: signals a child this process spawned and has not
                // yet reaped, so the identifier cannot have been reused.
                unsafe { libc::kill(pid, libc::SIGTERM) };
            }
            let deadline = Instant::now() + STOP_GRACE;
            while Instant::now() < deadline {
                if matches!(self.child.try_wait(), Ok(Some(_))) {
                    return;
                }
                thread::sleep(Duration::from_millis(50));
            }
            eprintln!("keel-ch: {} did not stop; killing it", self.name);
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    impl Drop for Supervised {
        fn drop(&mut self) {
            self.stop();
        }
    }

    fn component(variable: &str, name: &str) -> Result<PathBuf, RelayError> {
        let path = match env::var_os(variable) {
            Some(path) => PathBuf::from(path),
            None => env::current_exe()?.with_file_name(name),
        };
        if !path.is_file() {
            return Err(format!(
                "{name} is missing at {}; rerun `keel setup` or set {variable}",
                path.display()
            )
            .into());
        }
        Ok(path)
    }

    fn require_kvm() -> Result<(), RelayError> {
        fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/kvm")
            .map(drop)
            .map_err(|error| {
                format!(
                    "cannot open /dev/kvm: {error}; KVM must be enabled and this user in the kvm group"
                )
                .into()
            })
    }

    /// Listens on `<vsock>_<port>`, where Cloud Hypervisor delivers each guest
    /// connection to that host port, and queues accepted streams for one
    /// service. A full queue refuses the connection, as the VZ backend does.
    fn listen(vsock: &Path, port: u32, sender: SyncSender<OwnedFd>) -> Result<(), RelayError> {
        let mut path = vsock.as_os_str().to_owned();
        path.push(format!("_{port}"));
        let listener = UnixListener::bind(&path)?;
        thread::Builder::new()
            .name(format!("keel-ch-listen-{port}"))
            .spawn(move || {
                for stream in listener.incoming() {
                    match stream {
                        Ok(stream) => {
                            if sender.try_send(OwnedFd::from(stream)).is_err() {
                                eprintln!(
                                    "keel-vm: dropping vsock connection on port {port}: service queue is full"
                                );
                            }
                        }
                        Err(error) => {
                            eprintln!("keel-ch: vsock port {port} accept failed: {error}");
                            return;
                        }
                    }
                }
            })?;
        Ok(())
    }

    struct Services {
        mcp: mpsc::Receiver<OwnedFd>,
        terminal: mpsc::Receiver<OwnedFd>,
    }

    fn install_services(
        vsock: &Path,
        git_service: Option<Arc<keel_gitd::GitHttpService>>,
    ) -> Result<Services, RelayError> {
        let (mcp_tx, mcp_rx) = mpsc::sync_channel(1);
        let (egress_tx, egress_rx) = mpsc::sync_channel(SERVICE_QUEUE_DEPTH);
        let (git_tx, git_rx) = mpsc::sync_channel(SERVICE_QUEUE_DEPTH);
        let (terminal_tx, terminal_rx) = mpsc::sync_channel(1);
        let (telemetry_tx, telemetry_rx) = mpsc::sync_channel(1);
        listen(vsock, MCP_VSOCK_PORT, mcp_tx)?;
        listen(vsock, EGRESS_VSOCK_PORT, egress_tx)?;
        listen(vsock, GIT_VSOCK_PORT, git_tx)?;
        listen(vsock, TERMINAL_VSOCK_PORT, terminal_tx)?;
        listen(
            vsock,
            keel_mcp::telemetry::TELEMETRY_VSOCK_PORT,
            telemetry_tx,
        )?;
        spawn_service("egress", egress_rx, run_egress);
        spawn_service("Git", git_rx, move |fd| run_git(fd, git_service.as_deref()));
        spawn_service("telemetry", telemetry_rx, record_guest_events);
        Ok(Services {
            mcp: mcp_rx,
            terminal: terminal_rx,
        })
    }

    /// Starts one virtiofsd for a shared directory and waits for its socket.
    fn start_virtiofsd(
        virtiofsd: &Path,
        directory: &Path,
        socket: &Path,
        read_only: bool,
    ) -> Result<Supervised, RelayError> {
        let sandbox = env::var("KEEL_VIRTIOFSD_SANDBOX").unwrap_or_else(|_| "namespace".to_owned());
        if !matches!(sandbox.as_str(), "namespace" | "chroot" | "none") {
            return Err("KEEL_VIRTIOFSD_SANDBOX must be namespace, chroot, or none".into());
        }
        let mut command = Command::new(virtiofsd);
        command
            .arg("--socket-path")
            .arg(socket)
            .arg("--shared-dir")
            .arg(directory)
            .arg("--sandbox")
            .arg(&sandbox)
            .arg("--cache")
            .arg("auto")
            .arg("--log-level")
            .arg("error")
            // The guest workload is UID 0 without capabilities, so it reaches
            // the workspace only if guest root is the host user who owns it,
            // as the VZ share presents it.
            .arg("--translate-uid")
            // SAFETY: getuid and getgid cannot fail and touch no memory.
            .arg(format!("map:0:{}:1", unsafe { libc::getuid() }))
            .arg("--translate-gid")
            .arg(format!("map:0:{}:1", unsafe { libc::getgid() }))
            .env_clear()
            .stdin(Stdio::null());
        if read_only {
            command.arg("--readonly");
        }
        let helper = Supervised::spawn("virtiofsd", &mut command)?;
        wait_for_socket(socket)?;
        Ok(helper)
    }

    fn wait_for_socket(path: &Path) -> Result<(), RelayError> {
        let deadline = Instant::now() + HELPER_SOCKET_TIMEOUT;
        while Instant::now() < deadline {
            if fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_socket()) {
                return Ok(());
            }
            thread::sleep(Duration::from_millis(20));
        }
        Err(format!("{} did not appear within 10 seconds", path.display()).into())
    }

    /// Creates the FIFO Cloud Hypervisor writes its event stream to, and
    /// raises `reset` when the guest asks to reboot. Cloud Hypervisor answers
    /// a guest reset by booting the VM again; a Keel guest resets only after
    /// a panic, so the run ends instead.
    fn watch_events(path: &Path, reset: Arc<AtomicBool>) -> Result<(), RelayError> {
        let name = CString::new(path.as_os_str().as_bytes())?;
        // SAFETY: `name` is a valid NUL-terminated path for the duration of
        // the call.
        if unsafe { libc::mkfifo(name.as_ptr(), 0o600) } != 0 {
            return Err(format!("create event FIFO: {}", std::io::Error::last_os_error()).into());
        }
        let path = path.to_owned();
        thread::Builder::new()
            .name("keel-ch-events".to_owned())
            .spawn(move || {
                let Ok(file) = fs::File::open(&path) else {
                    return;
                };
                for line in BufReader::new(file).lines() {
                    let Ok(line) = line else {
                        return;
                    };
                    let event = serde_json::from_str::<serde_json::Value>(&line).ok();
                    let name = event
                        .as_ref()
                        .and_then(|event| event["event"].as_str())
                        .unwrap_or_default();
                    if matches!(name, "rebooting" | "reset") {
                        reset.store(true, Ordering::Release);
                    }
                }
            })?;
        Ok(())
    }

    fn command_line(arguments: &LaunchArguments) -> String {
        let mut command_line = "console=hvc0 panic=-1 reboot=k".to_owned();
        if arguments.workspace.is_some() {
            command_line.push_str(if arguments.ephemeral_workspace {
                " keel.workspace=overlay"
            } else {
                " keel.workspace=virtiofs"
            });
        }
        if arguments.control.is_some() {
            command_line.push_str(" keel.control=virtiofs");
        }
        command_line
    }

    /// Builds the Cloud Hypervisor command line. It names no network device,
    /// so the guest has no NIC; every byte leaves through a vsock relay.
    fn hypervisor_arguments(
        arguments: &LaunchArguments,
        run: &RunDirectory,
        shares: &[(&str, PathBuf)],
    ) -> Vec<OsString> {
        let memory_gib = if arguments.workspace.is_some() {
            arguments.memory_gib
        } else {
            1
        };
        let mut argv: Vec<OsString> = vec![
            "--kernel".into(),
            arguments.kernel.clone(),
            "--initramfs".into(),
            arguments.initramfs.clone(),
            "--cmdline".into(),
            command_line(arguments).into(),
            "--cpus".into(),
            format!("boot={}", arguments.cpus).into(),
            // virtio-fs needs guest memory the helper can map.
            "--memory".into(),
            format!("size={memory_gib}G,shared=on").into(),
            "--rng".into(),
            "src=/dev/urandom".into(),
            "--serial".into(),
            "off".into(),
            "--console".into(),
            // The guest console carries boot and init logs; the terminal
            // itself travels over vsock.
            "file=/proc/self/fd/2".into(),
            "--vsock".into(),
        ];
        let mut vsock = OsString::from(format!("cid={GUEST_CID},socket="));
        vsock.push(run.join("vsock.sock"));
        argv.push(vsock);
        argv.push("--event-monitor".into());
        let mut events = OsString::from("path=");
        events.push(run.join("events"));
        argv.push(events);
        if let Some(rootfs) = &arguments.rootfs {
            argv.push("--disk".into());
            let mut disk = OsString::from("path=");
            disk.push(rootfs);
            disk.push(",readonly=on");
            argv.push(disk);
        }
        if !shares.is_empty() {
            argv.push("--fs".into());
            for (tag, socket) in shares {
                let mut share = OsString::from(format!("tag={tag},socket="));
                share.push(socket);
                share.push(",num_queues=1,queue_size=1024");
                argv.push(share);
            }
        }
        argv
    }

    pub fn run() -> Result<(), RelayError> {
        let arguments = parse_launch_arguments(env::args_os().skip(1))?;
        require_kvm()?;
        let hypervisor = component("KEEL_CLOUD_HYPERVISOR", "cloud-hypervisor")?;
        let run = RunDirectory::create()?;
        let git_runtime = initialize_git_service(arguments.workspace.as_deref().map(Path::new))?;
        let services = install_services(&run.join("vsock.sock"), git_runtime.service)?;

        let mut helpers = Vec::new();
        let mut shares = Vec::new();
        for (path, tag, read_only) in [
            (
                arguments.workspace.as_deref(),
                "keel-workspace",
                arguments.ephemeral_workspace,
            ),
            (arguments.control.as_deref(), "keel-control", true),
        ] {
            let Some(path) = path else {
                continue;
            };
            let virtiofsd = component("KEEL_VIRTIOFSD", "virtiofsd")?;
            let socket = run.join(&format!("{tag}.sock"));
            helpers.push(start_virtiofsd(
                &virtiofsd,
                Path::new(path),
                &socket,
                read_only,
            )?);
            shares.push((tag, socket));
        }

        let reset = Arc::new(AtomicBool::new(false));
        watch_events(&run.join("events"), Arc::clone(&reset))?;
        let mut hypervisor = Supervised::spawn(
            "cloud-hypervisor",
            Command::new(&hypervisor)
                .args(hypervisor_arguments(&arguments, &run, &shares))
                .env_clear()
                .stdin(Stdio::null()),
        )?;

        let fd = services
            .mcp
            .recv_timeout(GUEST_CONNECT_TIMEOUT)
            .map_err(|_| "guest did not open the vsock within 120 seconds")?;
        let report = run_mcp(fd)?;
        let mcp_kernel_socket = env::var_os("KEEL_KERNEL_SOCKET").map(PathBuf::from);
        let mcp_ca = env::var("KEEL_RUN_CA_PEM").ok();
        spawn_service("mcp", services.mcp, move |fd| {
            run_node_mcp(fd, mcp_kernel_socket.clone(), mcp_ca.clone())
        });

        if arguments.workspace.is_some() {
            let terminal = services
                .terminal
                .recv_timeout(GUEST_CONNECT_TIMEOUT)
                .map_err(|_| "guest did not open the terminal vsock within 120 seconds")?;
            relay_terminal(terminal)?;
            loop {
                if let Some(status) = hypervisor.child.try_wait()? {
                    if !status.success() {
                        return Err(format!("Cloud Hypervisor exited with {status}").into());
                    }
                    break;
                }
                if reset.load(Ordering::Acquire) {
                    return Err("guest reset; ending the run rather than rebooting it".into());
                }
                thread::sleep(Duration::from_millis(100));
            }
        } else {
            hypervisor.stop();
        }
        for helper in &mut helpers {
            helper.stop();
        }

        eprintln!("{}", serde_json::to_string_pretty(&report)?);
        eprintln!("host preflight: Cloud Hypervisor configuration contains no network devices");
        if let Some(root) = git_runtime.root {
            fs::remove_dir_all(root)?;
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::{RunDirectory, command_line, hypervisor_arguments};
        use keel_isolate::relay::parse_launch_arguments;
        use std::{ffi::OsString, path::PathBuf};

        fn arguments(extra: &[&str]) -> keel_isolate::relay::LaunchArguments {
            parse_launch_arguments(
                ["kernel", "initramfs"]
                    .iter()
                    .chain(extra)
                    .map(OsString::from),
            )
            .unwrap()
        }

        #[test]
        fn the_hypervisor_gets_no_network_device() {
            let run = RunDirectory::create().unwrap();
            let shares = [("keel-workspace", PathBuf::from("/run/ws.sock"))];
            let argv = hypervisor_arguments(
                &arguments(&["workspace", "control", "--rootfs", "root.img"]),
                &run,
                &shares,
            );
            let argv = argv
                .iter()
                .map(|argument| argument.to_string_lossy().into_owned())
                .collect::<Vec<_>>();
            assert!(!argv.iter().any(|argument| argument == "--net"));
            assert!(argv.contains(&"path=root.img,readonly=on".to_owned()));
            assert!(argv.contains(&"size=2G,shared=on".to_owned()));
            assert!(
                argv.iter()
                    .any(|argument| argument.starts_with("tag=keel-workspace,socket=/run/ws.sock"))
            );
        }

        #[test]
        fn the_kernel_command_line_names_the_workspace_mode() {
            assert_eq!(
                command_line(&arguments(&["workspace", "control"])),
                "console=hvc0 panic=-1 reboot=k keel.workspace=virtiofs keel.control=virtiofs"
            );
            assert!(
                command_line(&arguments(&["workspace", "--ephemeral-workspace"]))
                    .contains("keel.workspace=overlay")
            );
        }
    }
}

#[cfg(target_os = "linux")]
fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    linux::run()
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("keel-ch requires Linux with KVM");
    std::process::exit(2);
}
