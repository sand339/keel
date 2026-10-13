#![doc = "Phase 0 native Virtualization.framework VM, vsock, and MCP spike."]

// The Objective-C VZ queue/listener pattern follows the MIT-licensed vmette
// 0.11 implementation by Chamuka, adapted here to expose Keel's MCP stream.

#[cfg(target_os = "macos")]
mod macos {
    use block2::RcBlock;
    use dispatch2::DispatchQueue;
    use keel_gitd::GitHttpService;
    use keel_isolate::relay::{
        EGRESS_VSOCK_PORT, GIT_VSOCK_PORT, MCP_VSOCK_PORT, RelayError, SERVICE_QUEUE_DEPTH,
        TERMINAL_VSOCK_PORT, initialize_git_service, parse_launch_arguments, record_guest_events,
        relay_terminal, run_egress, run_git, run_mcp, run_node_mcp, spawn_service,
    };
    use objc2::{
        AllocAnyThread, DefinedClass, define_class, msg_send,
        rc::Retained,
        runtime::{Bool, NSObject, NSObjectProtocol, ProtocolObject},
    };
    use objc2_foundation::{NSArray, NSError, NSFileHandle, NSString, NSURL};
    use objc2_virtualization::{
        VZDirectorySharingDeviceConfiguration, VZDiskImageStorageDeviceAttachment,
        VZEntropyDeviceConfiguration, VZFileHandleSerialPortAttachment, VZLinuxBootLoader,
        VZSerialPortConfiguration, VZSharedDirectory, VZSingleDirectoryShare,
        VZSocketDeviceConfiguration, VZStorageDeviceConfiguration,
        VZVirtioBlockDeviceConfiguration, VZVirtioConsoleDeviceSerialPortConfiguration,
        VZVirtioEntropyDeviceConfiguration, VZVirtioFileSystemDeviceConfiguration,
        VZVirtioSocketConnection, VZVirtioSocketDevice, VZVirtioSocketDeviceConfiguration,
        VZVirtioSocketListener, VZVirtioSocketListenerDelegate, VZVirtualMachine,
        VZVirtualMachineConfiguration, VZVirtualMachineState,
    };
    use std::{
        env, fs,
        os::fd::{FromRawFd, OwnedFd},
        path::{Path, PathBuf},
        sync::{
            Arc, Mutex,
            mpsc::{self, SyncSender},
        },
        thread,
        time::Duration,
    };

    struct QueueBound<T>(Retained<T>);

    // SAFETY: the wrapped Objective-C objects are only dereferenced in blocks
    // dispatched to the VM's private serial queue.
    unsafe impl<T> Send for QueueBound<T> {}
    // SAFETY: access remains serialized by the VM dispatch queue.
    unsafe impl<T> Sync for QueueBound<T> {}

    impl<T> std::ops::Deref for QueueBound<T> {
        type Target = T;

        fn deref(&self) -> &T {
            &self.0
        }
    }

    struct VsockState {
        fd_tx: Mutex<SyncSender<OwnedFd>>,
    }

    define_class!(
        #[unsafe(super(NSObject))]
        #[ivars = VsockState]
        #[name = "KeelVsockDelegate"]
        struct VsockDelegate;

        unsafe impl NSObjectProtocol for VsockDelegate {}

        unsafe impl VZVirtioSocketListenerDelegate for VsockDelegate {
            #[unsafe(method(listener:shouldAcceptNewConnection:fromSocketDevice:))]
            fn should_accept(
                &self,
                _listener: &VZVirtioSocketListener,
                connection: &VZVirtioSocketConnection,
                _device: &VZVirtioSocketDevice,
            ) -> Bool {
                // SAFETY: VZ owns the source descriptor for this callback. A
                // successful `dup` creates an independently owned descriptor.
                let fd = unsafe { libc::dup(connection.fileDescriptor()) };
                if fd >= 0 {
                    // SAFETY: `dup` returned a fresh descriptor whose ownership
                    // transfers to `OwnedFd` exactly once.
                    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
                    let accepted = self
                        .ivars()
                        .fd_tx
                        .lock()
                        .is_ok_and(|sender| sender.try_send(fd).is_ok());
                    if !accepted {
                        eprintln!("keel-vm: dropping vsock connection: service queue is full");
                    }
                    return if accepted { Bool::YES } else { Bool::NO };
                }
                eprintln!("keel-vm: could not duplicate incoming vsock descriptor");
                Bool::NO
            }
        }
    );

    impl VsockDelegate {
        fn new(fd_tx: SyncSender<OwnedFd>) -> Retained<Self> {
            let this = Self::alloc().set_ivars(VsockState {
                fd_tx: Mutex::new(fd_tx),
            });
            // SAFETY: initializes the NSObject superclass for this new object.
            unsafe { msg_send![super(this), init] }
        }
    }

    struct VsockServices {
        _mcp_listener: Retained<VZVirtioSocketListener>,
        _egress_listener: Retained<VZVirtioSocketListener>,
        _git_listener: Retained<VZVirtioSocketListener>,
        _terminal_listener: Retained<VZVirtioSocketListener>,
        _telemetry_listener: Retained<VZVirtioSocketListener>,
        _mcp_delegate: Retained<VsockDelegate>,
        _egress_delegate: Retained<VsockDelegate>,
        _git_delegate: Retained<VsockDelegate>,
        _terminal_delegate: Retained<VsockDelegate>,
        _telemetry_delegate: Retained<VsockDelegate>,
    }

    impl VsockServices {
        fn install(
            vm: &Retained<VZVirtualMachine>,
            queue: &DispatchQueue,
            git_service: Option<Arc<GitHttpService>>,
        ) -> (Self, mpsc::Receiver<OwnedFd>, mpsc::Receiver<OwnedFd>) {
            let (mcp_tx, mcp_rx) = mpsc::sync_channel(1);
            let (egress_tx, egress_rx) = mpsc::sync_channel(SERVICE_QUEUE_DEPTH);
            let (git_tx, git_rx) = mpsc::sync_channel(SERVICE_QUEUE_DEPTH);
            let (terminal_tx, terminal_rx) = mpsc::sync_channel(1);
            let (telemetry_tx, telemetry_rx) = mpsc::sync_channel(1);
            let mcp_delegate = VsockDelegate::new(mcp_tx);
            let egress_delegate = VsockDelegate::new(egress_tx);
            let git_delegate = VsockDelegate::new(git_tx);
            let terminal_delegate = VsockDelegate::new(terminal_tx);
            let telemetry_delegate = VsockDelegate::new(telemetry_tx);
            // SAFETY: listeners are configured before the VM starts and are
            // retained for the complete VM lifetime.
            let mcp_listener = unsafe { VZVirtioSocketListener::new() };
            let egress_listener = unsafe { VZVirtioSocketListener::new() };
            let git_listener = unsafe { VZVirtioSocketListener::new() };
            let terminal_listener = unsafe { VZVirtioSocketListener::new() };
            let telemetry_listener = unsafe { VZVirtioSocketListener::new() };
            unsafe {
                mcp_listener.setDelegate(Some(ProtocolObject::from_ref(&*mcp_delegate)));
                egress_listener.setDelegate(Some(ProtocolObject::from_ref(&*egress_delegate)));
                git_listener.setDelegate(Some(ProtocolObject::from_ref(&*git_delegate)));
                terminal_listener.setDelegate(Some(ProtocolObject::from_ref(&*terminal_delegate)));
                telemetry_listener
                    .setDelegate(Some(ProtocolObject::from_ref(&*telemetry_delegate)));
            }
            spawn_service("egress", egress_rx, run_egress);
            spawn_service("Git", git_rx, move |fd| run_git(fd, git_service.as_deref()));
            spawn_service("telemetry", telemetry_rx, record_guest_events);

            let setup_vm = QueueBound(vm.clone());
            let setup_mcp_listener = QueueBound(mcp_listener.clone());
            let setup_egress_listener = QueueBound(egress_listener.clone());
            let setup_git_listener = QueueBound(git_listener.clone());
            let setup_terminal_listener = QueueBound(terminal_listener.clone());
            let setup_telemetry_listener = QueueBound(telemetry_listener.clone());
            queue.exec_sync(move || unsafe {
                if let Some(device) = setup_vm.socketDevices().firstObject() {
                    let device: Retained<VZVirtioSocketDevice> = Retained::cast_unchecked(device);
                    device.setSocketListener_forPort(&setup_mcp_listener, MCP_VSOCK_PORT);
                    device.setSocketListener_forPort(&setup_egress_listener, EGRESS_VSOCK_PORT);
                    device.setSocketListener_forPort(&setup_git_listener, GIT_VSOCK_PORT);
                    device.setSocketListener_forPort(&setup_terminal_listener, TERMINAL_VSOCK_PORT);
                    device.setSocketListener_forPort(
                        &setup_telemetry_listener,
                        keel_mcp::telemetry::TELEMETRY_VSOCK_PORT,
                    );
                }
            });

            (
                Self {
                    _mcp_listener: mcp_listener,
                    _egress_listener: egress_listener,
                    _git_listener: git_listener,
                    _terminal_listener: terminal_listener,
                    _telemetry_listener: telemetry_listener,
                    _mcp_delegate: mcp_delegate,
                    _egress_delegate: egress_delegate,
                    _git_delegate: git_delegate,
                    _terminal_delegate: terminal_delegate,
                    _telemetry_delegate: telemetry_delegate,
                },
                mcp_rx,
                terminal_rx,
            )
        }
    }

    fn nsstr(value: &str) -> Retained<NSString> {
        NSString::from_str(value)
    }

    fn file_url(path: &Path) -> Retained<NSURL> {
        NSURL::fileURLWithPath(&nsstr(&path.to_string_lossy()))
    }

    /// Attaches the root filesystem disk read-only: the guest keeps its writes
    /// in a tmpfs overlay, so nothing it does reaches the installed image.
    fn attach_root_disk(
        configuration: &VZVirtualMachineConfiguration,
        rootfs: &Path,
    ) -> Result<(), RelayError> {
        // SAFETY: the attachment and device are retained by the configuration,
        // and the setter receives a correctly typed array.
        unsafe {
            let attachment = VZDiskImageStorageDeviceAttachment::initWithURL_readOnly_error(
                VZDiskImageStorageDeviceAttachment::alloc(),
                &file_url(rootfs),
                true,
            )
            .map_err(|error| format!("root disk: {}", error.localizedDescription()))?;
            let disk = VZVirtioBlockDeviceConfiguration::initWithAttachment(
                VZVirtioBlockDeviceConfiguration::alloc(),
                &attachment,
            );
            let disks: Retained<NSArray<VZStorageDeviceConfiguration>> =
                NSArray::from_retained_slice(&[Retained::into_super(disk)]);
            configuration.setStorageDevices(&disks);
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)] // VM configuration has many independent inputs
    fn build_configuration(
        kernel: &Path,
        initramfs: &Path,
        workspace: Option<&Path>,
        control: Option<&Path>,
        cpus: usize,
        rootfs: Option<&Path>,
        memory_gib: usize,
        ephemeral_workspace: bool,
    ) -> Result<Retained<VZVirtualMachineConfiguration>, RelayError> {
        // SAFETY: all Objective-C objects are retained for the resulting
        // configuration and setters receive correctly typed objects.
        unsafe {
            let configuration = VZVirtualMachineConfiguration::new();
            let bootloader =
                VZLinuxBootLoader::initWithKernelURL(VZLinuxBootLoader::alloc(), &file_url(kernel));
            bootloader.setInitialRamdiskURL(Some(&file_url(initramfs)));
            let mut command_line = "console=hvc0 panic=-1 reboot=k".to_owned();
            if workspace.is_some() {
                command_line.push_str(if ephemeral_workspace {
                    " keel.workspace=overlay"
                } else {
                    " keel.workspace=virtiofs"
                });
            }
            if control.is_some() {
                command_line.push_str(" keel.control=virtiofs");
            }
            bootloader.setCommandLine(&nsstr(&command_line));
            configuration.setBootLoader(Some(&bootloader.into_super()));
            configuration.setCPUCount(cpus);
            // The root filesystem is a read-only disk read on demand, so guest
            // memory holds only what the run uses: about 150 MiB idle. Builds
            // can ask for more with --memory.
            let requested = u64::try_from(memory_gib)? << 30;
            let allowed = VZVirtualMachineConfiguration::maximumAllowedMemorySize();
            if requested > allowed {
                return Err(format!(
                    "--memory {memory_gib} exceeds what this host allows ({} GiB)",
                    allowed >> 30
                )
                .into());
            }
            configuration.setMemorySize(if workspace.is_some() {
                requested
            } else {
                512 * 1024 * 1024
            });

            let serial_attachment = if workspace.is_some() {
                VZFileHandleSerialPortAttachment::initWithFileHandleForReading_fileHandleForWriting(
                    VZFileHandleSerialPortAttachment::alloc(),
                    None,
                    Some(&NSFileHandle::fileHandleWithStandardError()),
                )
            } else {
                VZFileHandleSerialPortAttachment::initWithFileHandleForReading_fileHandleForWriting(
                    VZFileHandleSerialPortAttachment::alloc(),
                    Some(&NSFileHandle::fileHandleWithStandardInput()),
                    Some(&NSFileHandle::fileHandleWithStandardOutput()),
                )
            };
            let serial = VZVirtioConsoleDeviceSerialPortConfiguration::new();
            serial.setAttachment(Some(&serial_attachment.into_super()));
            let serial_ports: Retained<NSArray<VZSerialPortConfiguration>> =
                NSArray::from_retained_slice(&[Retained::into_super(serial)]);
            configuration.setSerialPorts(&serial_ports);

            let entropy = VZVirtioEntropyDeviceConfiguration::new();
            let entropy_devices: Retained<NSArray<VZEntropyDeviceConfiguration>> =
                NSArray::from_retained_slice(&[Retained::into_super(entropy)]);
            configuration.setEntropyDevices(&entropy_devices);

            let socket = VZVirtioSocketDeviceConfiguration::new();
            let socket_devices: Retained<NSArray<VZSocketDeviceConfiguration>> =
                NSArray::from_retained_slice(&[Retained::into_super(socket)]);
            configuration.setSocketDevices(&socket_devices);

            if let Some(rootfs) = rootfs {
                attach_root_disk(&configuration, rootfs)?;
            }

            let mut directory_devices = Vec::new();
            for (path, tag, read_only) in [
                (workspace, "keel-workspace", ephemeral_workspace),
                (control, "keel-control", true),
            ] {
                let Some(path) = path else {
                    continue;
                };
                let directory = VZSharedDirectory::initWithURL_readOnly(
                    VZSharedDirectory::alloc(),
                    &file_url(path),
                    read_only,
                );
                let share = VZSingleDirectoryShare::initWithDirectory(
                    VZSingleDirectoryShare::alloc(),
                    &directory,
                );
                let device = VZVirtioFileSystemDeviceConfiguration::initWithTag(
                    VZVirtioFileSystemDeviceConfiguration::alloc(),
                    &nsstr(tag),
                );
                device.setShare(Some(&share));
                directory_devices.push(Retained::into_super(device));
            }
            if !directory_devices.is_empty() {
                let devices: Retained<NSArray<VZDirectorySharingDeviceConfiguration>> =
                    NSArray::from_retained_slice(&directory_devices);
                configuration.setDirectorySharingDevices(&devices);
            }

            configuration
                .validateWithError()
                .map_err(|error| error.localizedDescription().to_string())?;
            Ok(configuration)
        }
    }

    pub fn run() -> Result<(), RelayError> {
        let arguments = parse_launch_arguments(env::args_os().skip(1))?;
        let git_runtime = initialize_git_service(arguments.workspace.as_deref().map(Path::new))?;
        let configuration = build_configuration(
            Path::new(&arguments.kernel),
            Path::new(&arguments.initramfs),
            arguments.workspace.as_deref().map(Path::new),
            arguments.control.as_deref().map(Path::new),
            arguments.cpus,
            arguments.rootfs.as_deref().map(Path::new),
            arguments.memory_gib,
            arguments.ephemeral_workspace,
        )?;
        let queue = DispatchQueue::new("dev.keel.phase0.vm", None);
        // SAFETY: VZ requires VM creation with a validated configuration and
        // a private serial dispatch queue.
        let vm = unsafe {
            VZVirtualMachine::initWithConfiguration_queue(
                VZVirtualMachine::alloc(),
                &configuration,
                &queue,
            )
        };

        let (_services, mcp_rx, terminal_rx) =
            VsockServices::install(&vm, &queue, git_runtime.service);

        let (start_tx, start_rx) = mpsc::sync_channel(1);
        let start_vm = QueueBound(vm.clone());
        queue.exec_async(move || {
            let callback = RcBlock::new(move |error: *mut NSError| {
                let result = if error.is_null() {
                    Ok(())
                } else {
                    // SAFETY: non-null VZ callback errors are valid NSError
                    // objects for the duration of the callback.
                    Err(unsafe { &*error }.localizedDescription().to_string())
                };
                let _ = start_tx.send(result);
            });
            unsafe {
                start_vm.startWithCompletionHandler(&callback);
            }
        });
        start_rx
            .recv_timeout(Duration::from_secs(10))
            .map_err(|_| "timed out waiting for the VZ start callback")?
            .map_err(|error| format!("VM start failed: {error}"))?;

        let fd = mcp_rx
            .recv_timeout(Duration::from_secs(30))
            .map_err(|_| "guest did not open the vsock within 30 seconds")?;
        let report = run_mcp(fd)?;
        let mcp_kernel_socket = env::var_os("KEEL_KERNEL_SOCKET").map(PathBuf::from);
        let mcp_ca = env::var("KEEL_RUN_CA_PEM").ok();
        spawn_service("mcp", mcp_rx, move |fd| {
            run_node_mcp(fd, mcp_kernel_socket.clone(), mcp_ca.clone())
        });

        if arguments.workspace.is_some() {
            let terminal = terminal_rx
                .recv_timeout(Duration::from_secs(30))
                .map_err(|_| "guest did not open the terminal vsock within 30 seconds")?;
            relay_terminal(terminal)?;
            loop {
                let state_vm = QueueBound(vm.clone());
                let (state_tx, state_rx) = mpsc::sync_channel(1);
                queue.exec_sync(move || {
                    let _ = state_tx.send(unsafe { state_vm.state() });
                });
                let state = state_rx.recv()?;
                if state == VZVirtualMachineState::Stopped {
                    break;
                }
                if state == VZVirtualMachineState::Error {
                    return Err("VZ guest entered an error state".into());
                }
                thread::sleep(Duration::from_millis(100));
            }
        } else {
            let (stop_tx, stop_rx) = mpsc::sync_channel(1);
            let stop_vm = QueueBound(vm);
            queue.exec_async(move || {
                let callback = RcBlock::new(move |_error: *mut NSError| {
                    let _ = stop_tx.send(());
                });
                unsafe {
                    stop_vm.stopWithCompletionHandler(&callback);
                }
            });
            stop_rx
                .recv_timeout(Duration::from_secs(10))
                .map_err(|_| "timed out stopping the VZ guest")?;
        }

        eprintln!("{}", serde_json::to_string_pretty(&report)?);
        eprintln!("host preflight: VZ configuration contains no network devices");
        if let Some(root) = git_runtime.root {
            fs::remove_dir_all(root)?;
        }
        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    macos::run()
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("keel-vz-spike requires macOS");
    std::process::exit(2);
}
