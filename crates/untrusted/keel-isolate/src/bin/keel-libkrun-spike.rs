#![doc = "Phase 0 macOS `libkrun` VM, vsock, MCP, and network-isolation spike."]

#[cfg(target_os = "macos")]
mod macos {
    use keel_mcp::{GuestReport, serve_probe_with_reports};
    use std::{
        env,
        error::Error,
        ffi::{CStr, CString, c_char, c_void},
        fs, io, mem,
        os::unix::net::UnixListener,
        path::{Path, PathBuf},
        ptr, thread,
        time::Duration,
    };

    const VSOCK_PORT: u32 = 5_000;
    const VM_MEMORY_MIB: u32 = 2_048;
    const ROOTFS_SHARED_MEMORY: u64 = 64 * 1024 * 1024;
    const EXPECTED_PROBE: &str = "keel-phase0";
    const DEFAULT_LIBKRUN: &str =
        "/Applications/Docker.app/Contents/Resources/linuxkit/libkrun.dylib";

    type CreateContext = unsafe extern "C" fn() -> i32;
    type SetLogLevel = unsafe extern "C" fn(u32) -> i32;
    type SetVmConfig = unsafe extern "C" fn(u32, u8, u32) -> i32;
    type AddVirtiofs = unsafe extern "C" fn(u32, *const c_char, *const c_char, u64) -> i32;
    type SetKernel =
        unsafe extern "C" fn(u32, *const c_char, u32, *const c_char, *const c_char) -> i32;
    type AddVsockPort = unsafe extern "C" fn(u32, u32, *const c_char) -> i32;
    type SetExec =
        unsafe extern "C" fn(u32, *const c_char, *const *const c_char, *const *const c_char) -> i32;
    type StartEnter = unsafe extern "C" fn(u32) -> i32;

    struct Krun {
        handle: *mut c_void,
        create_context: CreateContext,
        set_log_level: SetLogLevel,
        set_vm_config: SetVmConfig,
        add_virtiofs: AddVirtiofs,
        set_kernel: SetKernel,
        add_vsock_port: AddVsockPort,
        set_exec: SetExec,
        start_enter: StartEnter,
    }

    impl Krun {
        fn load() -> Result<Self, Box<dyn Error + Send + Sync>> {
            let path =
                env::var("KEEL_LIBKRUN_DYLIB").unwrap_or_else(|_| DEFAULT_LIBKRUN.to_owned());
            let path = CString::new(path)?;
            // SAFETY: `path` is a valid C string and the handle is retained for
            // the lifetime of every loaded function pointer.
            let handle = unsafe { libc::dlopen(path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
            if handle.is_null() {
                return Err(format!("failed to load libkrun: {}", dlerror()).into());
            }
            // SAFETY: these names and signatures are from libkrun's stable C
            // API. Missing symbols return errors before `Krun` is constructed.
            unsafe {
                Ok(Self {
                    handle,
                    create_context: symbol(handle, c"krun_create_ctx")?,
                    set_log_level: symbol(handle, c"krun_set_log_level")?,
                    set_vm_config: symbol(handle, c"krun_set_vm_config")?,
                    add_virtiofs: symbol(handle, c"krun_add_virtiofs2")?,
                    set_kernel: symbol(handle, c"krun_set_kernel")?,
                    add_vsock_port: symbol(handle, c"krun_add_vsock_port")?,
                    set_exec: symbol(handle, c"krun_set_exec")?,
                    start_enter: symbol(handle, c"krun_start_enter")?,
                })
            }
        }
    }

    impl Drop for Krun {
        fn drop(&mut self) {
            // SAFETY: the handle was returned by `dlopen` and is closed once,
            // after all function pointers have stopped being used.
            unsafe {
                libc::dlclose(self.handle);
            }
        }
    }

    unsafe fn symbol<T: Copy>(
        handle: *mut c_void,
        name: &CStr,
    ) -> Result<T, Box<dyn Error + Send + Sync>> {
        // SAFETY: the caller keeps `handle` live and supplies a NUL-terminated
        // symbol name.
        let pointer = unsafe { libc::dlsym(handle, name.as_ptr()) };
        if pointer.is_null() {
            return Err(format!(
                "missing libkrun symbol {}: {}",
                name.to_string_lossy(),
                dlerror()
            )
            .into());
        }
        if mem::size_of::<T>() != mem::size_of_val(&pointer) {
            return Err("function pointer has an unexpected size".into());
        }
        // SAFETY: the caller chooses the function-pointer type corresponding
        // to the named stable C API symbol and the sizes were checked above.
        Ok(unsafe { mem::transmute_copy(&pointer) })
    }

    fn dlerror() -> String {
        // SAFETY: `dlerror` returns either null or a NUL-terminated string
        // managed by the dynamic loader.
        let error = unsafe { libc::dlerror() };
        if error.is_null() {
            "unknown dynamic-loader error".to_owned()
        } else {
            // SAFETY: non-null `dlerror` output is a valid C string until the
            // next dynamic-loader operation on this thread.
            unsafe { CStr::from_ptr(error) }
                .to_string_lossy()
                .into_owned()
        }
    }

    struct Config {
        kernel: CString,
        initramfs: Option<CString>,
        root: CString,
        socket: CString,
        socket_path: PathBuf,
    }

    impl Config {
        fn from_args() -> Result<Self, Box<dyn Error + Send + Sync>> {
            let mut args = env::args_os().skip(1);
            let kernel = args
                .next()
                .ok_or("usage: keel-libkrun-spike KERNEL INITRAMFS ROOTFS SOCKET")?;
            let initramfs = args
                .next()
                .ok_or("usage: keel-libkrun-spike KERNEL INITRAMFS ROOTFS SOCKET")?;
            let root = args
                .next()
                .ok_or("usage: keel-libkrun-spike KERNEL INITRAMFS ROOTFS SOCKET")?;
            let socket_path = PathBuf::from(
                args.next()
                    .ok_or("usage: keel-libkrun-spike KERNEL INITRAMFS ROOTFS SOCKET")?,
            );
            if args.next().is_some() {
                return Err("too many arguments".into());
            }

            let initramfs = if initramfs == "none" {
                None
            } else {
                Some(path_to_cstring(Path::new(&initramfs))?)
            };
            Ok(Self {
                kernel: path_to_cstring(Path::new(&kernel))?,
                initramfs,
                root: path_to_cstring(Path::new(&root))?,
                socket: path_to_cstring(&socket_path)?,
                socket_path,
            })
        }
    }

    fn path_to_cstring(path: &Path) -> Result<CString, Box<dyn Error + Send + Sync>> {
        Ok(CString::new(path.as_os_str().as_encoded_bytes())?)
    }

    fn check(operation: &str, result: i32) -> Result<(), Box<dyn Error + Send + Sync>> {
        if result < 0 {
            Err(format!("{operation} failed with errno {}", -result).into())
        } else {
            Ok(())
        }
    }

    fn validate_report(report: &GuestReport) -> Result<(), Box<dyn Error + Send + Sync>> {
        if report.probe != EXPECTED_PROBE {
            return Err(format!("unexpected probe marker: {}", report.probe).into());
        }
        let network = &report.network;
        if network.has_default_route
            || network.has_dns
            || network.metadata_reachable
            || network.private_network_reachable
        {
            return Err(format!("guest network preflight failed: {network:?}").into());
        }
        Ok(())
    }

    fn start_mcp_listener(
        listener: UnixListener,
    ) -> thread::JoinHandle<Result<GuestReport, Box<dyn Error + Send + Sync>>> {
        thread::spawn(move || {
            listener.set_nonblocking(true)?;
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            runtime.block_on(async move {
                let listener = tokio::net::UnixListener::from_std(listener)?;
                let (stream, _) =
                    tokio::time::timeout(Duration::from_secs(30), listener.accept()).await??;
                let (report_tx, mut report_rx) = tokio::sync::mpsc::unbounded_channel();
                let server = tokio::spawn(serve_probe_with_reports(stream, report_tx));
                let report = tokio::time::timeout(Duration::from_secs(30), report_rx.recv())
                    .await?
                    .ok_or("MCP stream closed without a guest report")?;
                validate_report(&report)?;
                server.await??;
                Ok(report)
            })
        })
    }

    pub fn run() -> Result<(), Box<dyn Error + Send + Sync>> {
        let config = Config::from_args()?;
        let krun = Krun::load()?;
        if config.socket_path.exists() {
            fs::remove_file(&config.socket_path)?;
        }
        let listener = UnixListener::bind(&config.socket_path)?;
        let listener_thread = start_mcp_listener(listener);

        // SAFETY: loaded pointers use libkrun's stable C signatures and the
        // `Krun` value keeps the dynamic library loaded.
        unsafe {
            (krun.set_log_level)(3);
        }
        // SAFETY: context creation takes no pointers.
        let context = unsafe { (krun.create_context)() };
        if context < 0 {
            return Err(format!("krun_create_ctx failed with errno {}", -context).into());
        }
        let context = context.cast_unsigned();

        // SAFETY: the context is live and these scalar values are valid.
        check("krun_set_vm_config", unsafe {
            (krun.set_vm_config)(context, 1, VM_MEMORY_MIB)
        })?;
        // SAFETY: each pointer comes from a live `CString`; libkrun copies each
        // value into the context before this call returns.
        unsafe {
            check(
                "krun_add_virtiofs2",
                (krun.add_virtiofs)(
                    context,
                    c"/dev/root".as_ptr(),
                    config.root.as_ptr(),
                    ROOTFS_SHARED_MEMORY,
                ),
            )?;
            let initramfs = config
                .initramfs
                .as_ref()
                .map_or(ptr::null(), |path| path.as_ptr());
            check(
                "krun_set_kernel",
                (krun.set_kernel)(context, config.kernel.as_ptr(), 0, initramfs, ptr::null()),
            )?;
            check(
                "krun_add_vsock_port",
                (krun.add_vsock_port)(context, VSOCK_PORT, config.socket.as_ptr()),
            )?;
            check(
                "krun_set_exec",
                (krun.set_exec)(
                    context,
                    c"/usr/local/bin/keel-mcp-guest".as_ptr(),
                    ptr::null::<*const c_char>(),
                    ptr::null::<*const c_char>(),
                ),
            )?;
        }

        // SAFETY: configuration is complete and the live context is consumed
        // by libkrun's blocking VM event loop.
        check("krun_start_enter", unsafe { (krun.start_enter)(context) })?;
        let report = listener_thread
            .join()
            .map_err(|_| io::Error::other("MCP listener thread panicked"))??;
        println!("{}", serde_json::to_string_pretty(&report)?);
        println!("host preflight: no network device configured in libkrun");
        let _ = fs::remove_file(&config.socket_path);
        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    macos::run()
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("keel-libkrun-spike requires macOS");
    std::process::exit(2);
}
