//! Second confinement layer for the guest workload.
//!
//! Virtiofs presents the workspace as owned by root, so the workload keeps
//! UID 0 but holds no capability and cannot regain one: its bounding set is
//! empty, `SECBIT_NOROOT` is locked, and `no_new_privs` is set. Landlock limits
//! writes to the workspace and scratch paths, seccomp removes kernel attack
//! surface and direct vsock access, and a cgroup bounds its process count.
//! Guest services drop to [`SERVICE_UID`], so a workload without capabilities
//! can neither signal nor inspect them.
//!
//! This layer sits inside the VM boundary. A guest kernel exploit defeats it;
//! its purpose is to make the workload need one.

// BPF opcodes, syscall numbers, and descriptor values below are small kernel
// ABI constants; the casts cannot truncate.
#![allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]

use keel_mcp::ConfinementPreflight;
use std::{
    ffi::CString,
    fs, io, mem,
    os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd},
    process::Command,
    ptr,
};

/// UID for guest relays and the terminal bridge.
pub const SERVICE_UID: libc::uid_t = 900;

const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const CGROUP: &str = "/sys/fs/cgroup/keel-workload";
const PIDS_MAX: &str = "4096";
const WRITABLE_DIRECTORIES: &[&str] = &[
    "/workspace",
    "/tmp",
    "/var/tmp",
    "/root",
    "/dev/pts",
    "/dev/shm",
];
const WRITABLE_FILES: &[&str] = &[
    "/dev/null",
    "/dev/zero",
    "/dev/full",
    "/dev/tty",
    "/dev/ptmx",
];

// Landlock filesystem rights, by the ABI that introduced them.
const ACCESS_EXECUTE: u64 = 1 << 0;
const ACCESS_WRITE_FILE: u64 = 1 << 1;
const ACCESS_READ_FILE: u64 = 1 << 2;
const ACCESS_READ_DIR: u64 = 1 << 3;
const ACCESS_ABI1: u64 = (1 << 13) - 1;
const ACCESS_REFER: u64 = 1 << 13;
const ACCESS_TRUNCATE: u64 = 1 << 14;
const ACCESS_MAKE_CHAR: u64 = 1 << 6;
const ACCESS_MAKE_BLOCK: u64 = 1 << 11;
const LANDLOCK_RULE_PATH_BENEATH: libc::c_int = 1;
const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;
const LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET: u64 = 1 << 0;
const LANDLOCK_SCOPE_SIGNAL: u64 = 1 << 1;

/// The full ABI 6 layout. Older kernels accept it while the fields they do
/// not know are zero.
#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
    /// TCP bind and connect stay unhandled: with no network device, TCP
    /// reaches only loopback, and port rules would break local test servers.
    handled_access_net: u64,
    scoped: u64,
}

#[repr(C, packed)]
struct PathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

/// Drops a guest service to [`SERVICE_UID`] with no supplementary groups.
///
/// # Errors
///
/// Returns an error if any identity change fails, in which case the caller
/// must not continue as root.
pub fn drop_to_service_uid() -> io::Result<()> {
    // SAFETY: these calls take scalar arguments and a null group list of
    // length zero; failures are reported through errno.
    unsafe {
        check(libc::setgroups(0, ptr::null()))?;
        check(libc::setgid(SERVICE_UID))?;
        check(libc::setuid(SERVICE_UID))?;
    }
    Ok(())
}

/// Applies every confinement step to the current process and replaces it with
/// `command`. Any failure aborts before the command runs.
///
/// # Errors
///
/// Returns the first confinement or exec failure.
pub fn confine_and_exec(command: &[String]) -> io::Result<()> {
    let arguments = command
        .iter()
        .map(|argument| CString::new(argument.as_bytes()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "argument has a null byte"))?;
    let mut pointers = arguments
        .iter()
        .map(|argument| argument.as_ptr())
        .collect::<Vec<_>>();
    pointers.push(ptr::null());
    if arguments.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "no command to confine",
        ));
    }
    join_workload_cgroup()?;
    // SAFETY: prctl with scalar arguments.
    check(unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) })?;
    restrict_filesystem()?;
    drop_capabilities()?;
    install_seccomp()?;
    // SAFETY: the argument vector is null-terminated and every pointer refers
    // to a live `CString` owned by `arguments`.
    unsafe { libc::execvp(pointers[0], pointers.as_ptr()) };
    Err(io::Error::last_os_error())
}

fn check(result: libc::c_int) -> io::Result<()> {
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn check_long(result: libc::c_long) -> io::Result<libc::c_long> {
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result)
    }
}

fn join_workload_cgroup() -> io::Result<()> {
    if !std::path::Path::new(CGROUP_ROOT)
        .join("cgroup.controllers")
        .exists()
    {
        return Err(io::Error::other("cgroup v2 is not mounted"));
    }
    match fs::create_dir(CGROUP) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    // The pids controller must be enabled for children of the root group.
    let _ = fs::write(format!("{CGROUP_ROOT}/cgroup.subtree_control"), "+pids");
    fs::write(format!("{CGROUP}/pids.max"), PIDS_MAX)?;
    fs::write(
        format!("{CGROUP}/cgroup.procs"),
        std::process::id().to_string(),
    )
}

fn landlock_abi() -> io::Result<u32> {
    // SAFETY: a null attribute with the version flag only queries the ABI.
    let abi = check_long(unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            ptr::null::<RulesetAttr>(),
            0_usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    })?;
    u32::try_from(abi).map_err(|_| io::Error::other("invalid Landlock ABI"))
}

/// Rights handled for this kernel. ABI 4 and later add network and scoping
/// rules; until the guest kernel moves to them, only file rights are handled,
/// so behavior is identical on every supported kernel.
fn handled_access(abi: u32) -> u64 {
    let mut handled = ACCESS_ABI1;
    if abi >= 2 {
        handled |= ACCESS_REFER;
    }
    if abi >= 3 {
        handled |= ACCESS_TRUNCATE;
    }
    handled
}

fn restrict_filesystem() -> io::Result<()> {
    let abi = landlock_abi()?;
    let handled = handled_access(abi);
    // ABI 6 scoping keeps signals and abstract Unix sockets from crossing
    // out of the workload's domain, independent of the UID arrangement.
    let attr = RulesetAttr {
        handled_access_fs: handled,
        handled_access_net: 0,
        scoped: if abi >= 6 {
            LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET | LANDLOCK_SCOPE_SIGNAL
        } else {
            0
        },
    };
    // SAFETY: `attr` is a valid ruleset attribute for the duration of the call.
    let ruleset = check_long(unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &raw const attr,
            mem::size_of::<RulesetAttr>(),
            0_u32,
        )
    })?;
    // SAFETY: a successful call returns a new descriptor owned here.
    let ruleset =
        unsafe { OwnedFd::from_raw_fd(i32::try_from(ruleset).map_err(io::Error::other)?) };
    let read = ACCESS_EXECUTE | ACCESS_READ_FILE | ACCESS_READ_DIR;
    add_rule(&ruleset, "/", read)?;
    let directory_write = handled & !(ACCESS_MAKE_CHAR | ACCESS_MAKE_BLOCK);
    for path in WRITABLE_DIRECTORIES {
        if std::path::Path::new(path).is_dir() {
            add_rule(&ruleset, path, directory_write)?;
        }
    }
    let file_write = ACCESS_READ_FILE | ACCESS_WRITE_FILE | (handled & ACCESS_TRUNCATE);
    for path in WRITABLE_FILES {
        if std::path::Path::new(path).exists() {
            add_rule(&ruleset, path, file_write)?;
        }
    }
    // SAFETY: `ruleset` is a valid Landlock ruleset descriptor and
    // `no_new_privs` is already set.
    check_long(unsafe {
        libc::syscall(libc::SYS_landlock_restrict_self, ruleset.as_raw_fd(), 0_u32)
    })?;
    Ok(())
}

fn add_rule(ruleset: &OwnedFd, path: &str, allowed_access: u64) -> io::Result<()> {
    let path = CString::new(path).map_err(io::Error::other)?;
    // SAFETY: `path` is a valid C string; the descriptor is checked below.
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `open` returned a new descriptor owned here.
    let parent = unsafe { OwnedFd::from_raw_fd(fd) };
    let rule = PathBeneathAttr {
        allowed_access,
        parent_fd: parent.as_raw_fd(),
    };
    // SAFETY: `rule` is a valid path-beneath attribute for the call.
    check_long(unsafe {
        libc::syscall(
            libc::SYS_landlock_add_rule,
            ruleset.as_raw_fd(),
            LANDLOCK_RULE_PATH_BENEATH,
            &raw const rule,
            0_u32,
        )
    })?;
    Ok(())
}

#[repr(C)]
struct CapHeader {
    version: u32,
    pid: libc::c_int,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
// SECBIT_NOROOT, NO_SETUID_FIXUP, NO_CAP_AMBIENT_RAISE, and the locks for
// those and for KEEP_CAPS (which stays off).
const SECURE_BITS: libc::c_ulong = 0b1110_1111;

fn drop_capabilities() -> io::Result<()> {
    let last = fs::read_to_string("/proc/sys/kernel/cap_last_cap")?
        .trim()
        .parse::<libc::c_ulong>()
        .map_err(io::Error::other)?;
    for capability in 0..=last {
        // SAFETY: prctl with scalar arguments.
        check(unsafe { libc::prctl(libc::PR_CAPBSET_DROP, capability, 0, 0, 0) })?;
    }
    // SAFETY: prctl with scalar arguments.
    unsafe {
        check(libc::prctl(libc::PR_SET_SECUREBITS, SECURE_BITS, 0, 0, 0))?;
        check(libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        ))?;
    }
    let header = CapHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let data = [CapData::default(); 2];
    // SAFETY: `header` and the two-element `data` array match the version 3
    // capability ABI and stay valid for the call.
    check_long(unsafe { libc::syscall(libc::SYS_capset, &raw const header, data.as_ptr()) })?;
    Ok(())
}

/// `kexec_file_load` on aarch64; the musl `libc` bindings omit it.
const SYS_KEXEC_FILE_LOAD: libc::c_long = 294;

/// Syscalls the workload never needs and that widen kernel attack surface or
/// would let it escape the other layers.
const DENIED_SYSCALLS: &[libc::c_long] = &[
    libc::SYS_mount,
    libc::SYS_umount2,
    libc::SYS_pivot_root,
    libc::SYS_chroot,
    libc::SYS_unshare,
    libc::SYS_setns,
    libc::SYS_open_tree,
    libc::SYS_move_mount,
    libc::SYS_fsopen,
    libc::SYS_fsconfig,
    libc::SYS_fsmount,
    libc::SYS_fspick,
    libc::SYS_mount_setattr,
    libc::SYS_bpf,
    libc::SYS_perf_event_open,
    libc::SYS_userfaultfd,
    libc::SYS_io_uring_setup,
    libc::SYS_io_uring_enter,
    libc::SYS_io_uring_register,
    libc::SYS_kexec_load,
    SYS_KEXEC_FILE_LOAD,
    libc::SYS_init_module,
    libc::SYS_finit_module,
    libc::SYS_delete_module,
    libc::SYS_keyctl,
    libc::SYS_add_key,
    libc::SYS_request_key,
    libc::SYS_ptrace,
    libc::SYS_process_vm_readv,
    libc::SYS_process_vm_writev,
    libc::SYS_seccomp,
    libc::SYS_swapon,
    libc::SYS_swapoff,
    libc::SYS_reboot,
    libc::SYS_acct,
    libc::SYS_quotactl,
];

const AUDIT_ARCH_AARCH64: u32 = 0xC000_00B7;
const RET_ALLOW: u32 = 0x7fff_0000;
const RET_KILL_PROCESS: u32 = 0x8000_0000;
const RET_ERRNO: u32 = 0x0005_0000;
const OFFSET_NR: u32 = 0;
const OFFSET_ARCH: u32 = 4;
const fn offset_arg(index: u32) -> u32 {
    16 + 8 * index
}
const NAMESPACE_FLAGS: u32 = (libc::CLONE_NEWNS
    | libc::CLONE_NEWCGROUP
    | libc::CLONE_NEWUTS
    | libc::CLONE_NEWIPC
    | libc::CLONE_NEWUSER
    | libc::CLONE_NEWPID
    | libc::CLONE_NEWNET) as u32;

fn statement(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

fn jump(k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter {
        code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
        jt,
        jf,
        k,
    }
}

fn load(offset: u32) -> libc::sock_filter {
    statement((libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16, offset)
}

fn ret(value: u32) -> libc::sock_filter {
    statement((libc::BPF_RET | libc::BPF_K) as u16, value)
}

fn errno(code: libc::c_int) -> u32 {
    RET_ERRNO | u32::try_from(code).unwrap_or(1)
}

/// Builds the workload filter. Every syscall-specific block ends in a return,
/// so a block is skipped by jumping over its exact length.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn seccomp_program() -> Vec<libc::sock_filter> {
    let eperm = errno(libc::EPERM);
    let mut program = vec![
        load(OFFSET_ARCH),
        jump(AUDIT_ARCH_AARCH64, 1, 0),
        ret(RET_KILL_PROCESS),
        load(OFFSET_NR),
    ];
    for nr in DENIED_SYSCALLS {
        program.extend([jump(*nr as u32, 0, 1), ret(eperm)]);
    }
    // clone3 passes its flags through memory a filter cannot read. Report it
    // unimplemented so the C library falls back to inspectable clone.
    program.extend([
        jump(libc::SYS_clone3 as u32, 0, 1),
        ret(errno(libc::ENOSYS)),
    ]);

    let clone_block = [
        load(offset_arg(0)),
        statement(
            (libc::BPF_ALU | libc::BPF_AND | libc::BPF_K) as u16,
            NAMESPACE_FLAGS,
        ),
        jump(0, 0, 1),
        ret(RET_ALLOW),
        ret(eperm),
    ];
    program.push(jump(libc::SYS_clone as u32, 0, clone_block.len() as u8));
    program.extend(clone_block);

    let prctl_block = [
        load(offset_arg(0)),
        jump(libc::PR_SET_SECCOMP as u32, 0, 1),
        ret(eperm),
        ret(RET_ALLOW),
    ];
    program.push(jump(libc::SYS_prctl as u32, 0, prctl_block.len() as u8));
    program.extend(prctl_block);

    let socket_block = [
        load(offset_arg(0)),
        jump(libc::AF_VSOCK as u32, 0, 1),
        ret(eperm),
        jump(libc::AF_PACKET as u32, 0, 1),
        ret(eperm),
        // Netlink only for routing queries, which getifaddrs needs.
        jump(libc::AF_NETLINK as u32, 0, 4),
        load(offset_arg(2)),
        jump(libc::NETLINK_ROUTE as u32, 0, 1),
        ret(RET_ALLOW),
        ret(eperm),
        jump(libc::AF_INET as u32, 1, 0),
        jump(libc::AF_INET6 as u32, 0, 4),
        load(offset_arg(1)),
        statement((libc::BPF_ALU | libc::BPF_AND | libc::BPF_K) as u16, 0xf),
        jump(libc::SOCK_RAW as u32, 0, 1),
        ret(eperm),
        ret(RET_ALLOW),
    ];
    program.push(jump(libc::SYS_socket as u32, 0, socket_block.len() as u8));
    program.extend(socket_block);
    program.push(ret(RET_ALLOW));
    program
}

fn install_seccomp() -> io::Result<()> {
    let program = seccomp_program();
    let filter = libc::sock_fprog {
        len: u16::try_from(program.len()).map_err(io::Error::other)?,
        filter: program.as_ptr().cast_mut(),
    };
    // SAFETY: `filter` points at `program`, which outlives the call, and
    // `no_new_privs` is already set.
    check(unsafe {
        libc::prctl(
            libc::PR_SET_SECCOMP,
            libc::SECCOMP_MODE_FILTER,
            &raw const filter,
            0,
            0,
        )
    })
}

/// Confines a child copy of this binary and asks it to try what the layer
/// forbids. Run by the boot report so the host can refuse an unconfined guest.
pub fn preflight() -> ConfinementPreflight {
    let output = Command::new("/proc/self/exe")
        .args([
            "confine",
            "--",
            "/usr/local/bin/keel-mcp-guest",
            "confine-check",
        ])
        .output();
    match output {
        Ok(output) if output.status.success() => {
            serde_json::from_slice(&output.stdout).unwrap_or_default()
        }
        _ => ConfinementPreflight::default(),
    }
}

/// Finds a guest service process and checks that signal 0 to it is refused.
/// Services drop privilege just after starting, so this waits briefly for
/// one; finding none counts as a failed check.
fn service_signal_denied() -> bool {
    let service = format!("Uid:\t{SERVICE_UID}\t");
    for _ in 0..40 {
        let found = fs::read_dir("/proc")
            .into_iter()
            .flatten()
            .flatten()
            .find_map(|entry| {
                let pid = entry.file_name().to_str()?.parse::<libc::pid_t>().ok()?;
                let status = fs::read_to_string(entry.path().join("status")).ok()?;
                status.contains(&service).then_some(pid)
            });
        if let Some(pid) = found {
            // SAFETY: signal 0 only checks permission and existence.
            let result = unsafe { libc::kill(pid, 0) };
            return result < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EPERM);
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    false
}

/// Runs inside the confined child: every forbidden operation must fail and
/// ordinary scratch writes must still work.
pub fn check_from_inside() -> ConfinementPreflight {
    let status = fs::read_to_string("/proc/self/status").unwrap_or_default();
    let field = |name: &str| {
        status
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .map(str::trim)
            .unwrap_or_default()
            .to_owned()
    };
    // SAFETY: each probe is a single syscall with scalar arguments; any
    // descriptor that is unexpectedly returned is closed immediately.
    let denied = |result: libc::c_long| {
        if result >= 0 {
            unsafe { libc::close(result as libc::c_int) };
            false
        } else {
            true
        }
    };
    let socket = |domain: libc::c_int, kind: libc::c_int, protocol: libc::c_int| {
        // SAFETY: socket takes scalar arguments.
        denied(libc::c_long::from(unsafe {
            libc::socket(domain, kind, protocol)
        }))
    };
    let scratch = "/tmp/.keel-confine-probe";
    let scratch_write_allowed =
        fs::write(scratch, b"ok").is_ok() && fs::remove_file(scratch).is_ok();
    ConfinementPreflight {
        capabilities_empty: field("CapEff:") == "0000000000000000"
            && field("CapPrm:") == "0000000000000000"
            && field("CapBnd:") == "0000000000000000",
        no_new_privs: field("NoNewPrivs:") == "1",
        seccomp_filtered: field("Seccomp:") == "2",
        vsock_denied: socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0),
        packet_socket_denied: socket(libc::AF_PACKET, libc::SOCK_RAW, 0),
        raw_socket_denied: socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP),
        // SAFETY: unshare and io_uring_setup take scalar arguments or null.
        namespace_denied: denied(libc::c_long::from(unsafe {
            libc::unshare(libc::CLONE_NEWUSER)
        })),
        io_uring_denied: denied(unsafe {
            libc::syscall(libc::SYS_io_uring_setup, 1_u32, ptr::null_mut::<u8>())
        }),
        // SAFETY: mount and finit_module take valid C strings or scalars.
        mount_denied: denied(libc::c_long::from(unsafe {
            libc::mount(
                c"none".as_ptr(),
                c"/tmp".as_ptr(),
                c"tmpfs".as_ptr(),
                0,
                ptr::null(),
            )
        })),
        module_load_denied: denied(unsafe {
            libc::syscall(libc::SYS_finit_module, -1_i32, c"".as_ptr(), 0_u32)
        }) && io::Error::last_os_error().raw_os_error() != Some(libc::EBADF),
        service_signal_denied: service_signal_denied(),
        // The parent is the boot report process, outside the domain and of
        // the same UID, so only Landlock scoping refuses this.
        // SAFETY: signal 0 only checks permission and existence.
        signal_scoped: unsafe { libc::kill(libc::getppid(), 0) } < 0
            && io::Error::last_os_error().raw_os_error() == Some(libc::EPERM),
        system_write_denied: fs::write("/usr/local/bin/.keel-confine-probe", b"x").is_err(),
        scratch_write_allowed,
        cgroup_bounded: fs::read_to_string("/proc/self/cgroup")
            .is_ok_and(|cgroup| cgroup.contains("/keel-workload")),
        landlock_abi: landlock_abi().unwrap_or(0),
    }
}
