#![doc = "Guest network probe and stdio/TCP bridges over `AF_VSOCK`."]

#[cfg(target_os = "linux")]
#[path = "keel-mcp-guest/confine.rs"]
mod confine;

#[cfg(target_os = "linux")]
#[path = "keel-mcp-guest/supervise.rs"]
mod supervise;

#[cfg(target_os = "linux")]
mod linux {
    use keel_mcp::{GuestReport, NetworkPreflight, submit_guest_report};
    use std::{
        env,
        ffi::CString,
        fs,
        io::{self, Read as _, Write as _},
        mem,
        net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream},
        os::fd::{AsRawFd as _, FromRawFd, RawFd},
        os::unix::net::UnixStream,
        ptr, thread,
        time::Duration,
    };

    const CONNECT_TIMEOUT: Duration = Duration::from_millis(250);

    fn connect_vsock(port: u32) -> io::Result<UnixStream> {
        // SAFETY: `socket` has no Rust-side aliasing requirements. The returned
        // descriptor is checked before ownership is transferred below.
        let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        let family = libc::sa_family_t::try_from(libc::AF_VSOCK).map_err(io::Error::other)?;
        let length = libc::socklen_t::try_from(mem::size_of::<libc::sockaddr_vm>())
            .map_err(io::Error::other)?;
        let address = libc::sockaddr_vm {
            svm_family: family,
            svm_reserved1: 0,
            svm_port: port,
            svm_cid: libc::VMADDR_CID_HOST,
            svm_zero: [0; 4],
        };
        // SAFETY: `address` is initialized for AF_VSOCK and the pointer and
        // length remain valid for the duration of the call.
        let result =
            unsafe { libc::connect(fd, (&raw const address).cast::<libc::sockaddr>(), length) };
        if result < 0 {
            let error = io::Error::last_os_error();
            // SAFETY: this branch still exclusively owns the valid descriptor.
            unsafe {
                libc::close(fd);
            }
            return Err(error);
        }

        // SAFETY: ownership of the connected descriptor is transferred exactly
        // once to `UnixStream`, whose stream semantics match AF_VSOCK.
        Ok(unsafe { UnixStream::from_raw_fd(fd as RawFd) })
    }

    fn route_present() -> bool {
        fs::read_to_string("/proc/net/route").is_ok_and(|routes| {
            routes
                .lines()
                .skip(1)
                .filter_map(|line| line.split_whitespace().nth(1))
                .any(|destination| destination == "00000000")
        })
    }

    fn dns_present() -> bool {
        fs::read_to_string("/etc/resolv.conf").is_ok_and(|config| {
            config.lines().any(|line| {
                let line = line.trim();
                line.starts_with("nameserver ") && !line.ends_with(" 0.0.0.0")
            })
        })
    }

    fn tcp_reachable(ip: Ipv4Addr, port: u16) -> bool {
        TcpStream::connect_timeout(&SocketAddr::new(IpAddr::V4(ip), port), CONNECT_TIMEOUT).is_ok()
    }

    fn observe_network() -> NetworkPreflight {
        NetworkPreflight {
            has_default_route: route_present(),
            has_dns: dns_present(),
            metadata_reachable: tcp_reachable(Ipv4Addr::new(169, 254, 169, 254), 80),
            private_network_reachable: tcp_reachable(Ipv4Addr::new(10, 0, 0, 1), 80),
        }
    }

    async fn report(
        port: u32,
        probe: String,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let stream = connect_vsock(port)?;
        stream.set_nonblocking(true)?;
        let stream = tokio::net::UnixStream::from_std(stream)?;
        let report = GuestReport {
            probe,
            network: observe_network(),
            confinement: super::confine::preflight(),
        };
        let echoed = submit_guest_report(stream, &report).await?;
        if echoed != report {
            return Err("host returned a mismatched guest report".into());
        }
        println!("{}", serde_json::to_string(&echoed)?);
        Ok(())
    }

    fn bridge_stdio(port: u32) -> io::Result<()> {
        bridge_stdio_stream(connect_vsock(port)?)
    }

    /// The confined workload cannot open vsock, so the MCP server it spawns
    /// reaches the host through a guest-service relay on loopback.
    fn bridge_stdio_tcp(port: u16) -> io::Result<()> {
        let stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port))?;
        let reader = stream.try_clone()?;
        let mut writer = stream;
        let mut reader = reader;
        let upload = thread::spawn(move || {
            let result = io::copy(&mut io::stdin().lock(), &mut writer);
            let _ = writer.shutdown(Shutdown::Write);
            result
        });
        io::copy(&mut reader, &mut io::stdout().lock())?;
        io::stdout().flush()?;
        upload
            .join()
            .map_err(|_| io::Error::other("stdio upload thread panicked"))??;
        Ok(())
    }

    fn bridge_stdio_stream(stream: UnixStream) -> io::Result<()> {
        let mut reader = stream;
        let mut writer = reader.try_clone()?;
        let upload = thread::spawn(move || {
            let result = io::copy(&mut io::stdin().lock(), &mut writer);
            let _ = writer.shutdown(Shutdown::Write);
            result
        });
        io::copy(&mut reader, &mut io::stdout().lock())?;
        io::stdout().flush()?;
        upload
            .join()
            .map_err(|_| io::Error::other("stdio upload thread panicked"))??;
        Ok(())
    }

    fn parse_terminal_dimension(value: &str, name: &str) -> io::Result<u16> {
        value
            .parse::<u16>()
            .ok()
            .filter(|dimension| *dimension > 0)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("{name} must be between 1 and 65535"),
                )
            })
    }

    /// Introduces a control message on the host's terminal input stream.
    ///
    /// The host half of this codec lives in the trusted `keel-input` crate and
    /// the two must agree. The operator's keystrokes and Keel's own messages
    /// share this stream, so a control byte the operator actually typed arrives
    /// doubled.
    const CONTROL: u8 = 0x07;
    const CONTROL_REDRAW: u8 = b'r';
    const CONTROL_RESIZE: u8 = b's';
    const REDRAW_KEY: u8 = 0x0c;

    enum HostInput {
        Text,
        Prefix,
        Resize { payload: [u8; 4], filled: usize },
    }

    fn set_terminal_size(terminal: &fs::File, rows: u16, columns: u16) -> io::Result<()> {
        let size = libc::winsize {
            ws_row: rows,
            ws_col: columns,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // SAFETY: the descriptor is the live pty master this process owns, and
        // `size` remains valid for the duration of the call. The request type is
        // `c_ulong` on glibc and `c_int` on musl, where the guest is built, so the
        // conversion is needed on one of them.
        #[allow(clippy::useless_conversion)]
        let result = unsafe {
            libc::ioctl(
                terminal.as_raw_fd(),
                libc::TIOCSWINSZ.into(),
                &raw const size,
            )
        };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Relays host keystrokes into the pty, applying Keel's control messages.
    ///
    /// The window size arrives here rather than as a signal because the host
    /// terminal is several hops away, and the harness inside the pty only
    /// repaints at the right geometry once the pty itself has been resized.
    fn relay_host_input(host: &mut UnixStream, terminal: &mut fs::File) -> io::Result<()> {
        let mut state = HostInput::Text;
        let mut buffer = [0_u8; 4096];
        let mut keystrokes = Vec::with_capacity(buffer.len());
        loop {
            let count = host.read(&mut buffer)?;
            if count == 0 {
                return Ok(());
            }
            keystrokes.clear();
            let mut size = None;
            for byte in &buffer[..count] {
                match &mut state {
                    HostInput::Text if *byte == CONTROL => state = HostInput::Prefix,
                    HostInput::Text => keystrokes.push(*byte),
                    HostInput::Prefix => {
                        state = HostInput::Text;
                        match *byte {
                            CONTROL => keystrokes.push(CONTROL),
                            CONTROL_REDRAW => keystrokes.push(REDRAW_KEY),
                            CONTROL_RESIZE => {
                                state = HostInput::Resize {
                                    payload: [0; 4],
                                    filled: 0,
                                };
                            }
                            // An unrecognized message is dropped rather than
                            // typed into the harness, so a newer host cannot
                            // corrupt this session's input line.
                            _ => {}
                        }
                    }
                    HostInput::Resize { payload, filled } => {
                        payload[*filled] = *byte;
                        *filled += 1;
                        if *filled == payload.len() {
                            size = Some((
                                u16::from_be_bytes([payload[0], payload[1]]),
                                u16::from_be_bytes([payload[2], payload[3]]),
                            ));
                            state = HostInput::Text;
                        }
                    }
                }
            }
            if !keystrokes.is_empty() {
                terminal.write_all(&keystrokes)?;
                terminal.flush()?;
            }
            if let Some((rows, columns)) = size {
                set_terminal_size(terminal, rows, columns)?;
            }
        }
    }

    fn copy_pty_output(reader: &mut fs::File, writer: &mut UnixStream) -> io::Result<u64> {
        match io::copy(reader, writer) {
            Err(error) if error.raw_os_error() == Some(libc::EIO) => Ok(0),
            result => result,
        }
    }

    fn wait_for_child(pid: libc::pid_t) -> io::Result<()> {
        let mut status = 0;
        loop {
            // SAFETY: `pid` identifies the child returned by `forkpty`, and
            // `status` points to writable storage for the complete call.
            let result = unsafe { libc::waitpid(pid, &raw mut status, 0) };
            if result == pid {
                break;
            }
            if result < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            if result < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 {
            Ok(())
        } else if libc::WIFEXITED(status) {
            Err(io::Error::other(format!(
                "terminal command exited with status {}",
                libc::WEXITSTATUS(status)
            )))
        } else if libc::WIFSIGNALED(status) {
            Err(io::Error::other(format!(
                "terminal command exited on signal {}",
                libc::WTERMSIG(status)
            )))
        } else {
            Err(io::Error::other("terminal command ended unexpectedly"))
        }
    }

    fn bridge_terminal(port: u32, rows: u16, columns: u16, command: &[String]) -> io::Result<()> {
        let command = command
            .iter()
            .map(|argument| {
                CString::new(argument.as_bytes()).map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "terminal command contains a null byte",
                    )
                })
            })
            .collect::<io::Result<Vec<_>>>()?;
        let mut command_pointers = command
            .iter()
            .map(|argument| argument.as_ptr())
            .collect::<Vec<_>>();
        command_pointers.push(ptr::null());

        let mut master = -1;
        let size = libc::winsize {
            ws_row: rows,
            ws_col: columns,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // SAFETY: `master` points to writable descriptor storage, `size`
        // remains valid for the call, and the child immediately invokes only
        // async-signal-safe `execvp` or `_exit`.
        let pid = unsafe {
            libc::forkpty(
                &raw mut master,
                ptr::null_mut(),
                ptr::null(),
                &raw const size,
            )
        };
        if pid < 0 {
            return Err(io::Error::last_os_error());
        }
        if pid == 0 {
            // SAFETY: the argument vector is null-terminated and every pointer
            // refers to a live `CString` allocated before the fork.
            unsafe {
                libc::execvp(command_pointers[0], command_pointers.as_ptr());
                libc::_exit(127);
            }
        }

        // The child confines itself before exec. The bridge keeps only the
        // PTY master and its vsock stream, so it gives up root now.
        super::confine::drop_to_service_uid()?;
        // SAFETY: the parent exclusively owns the valid PTY master returned by
        // `forkpty`, and transfers that ownership exactly once.
        let mut terminal = unsafe { fs::File::from_raw_fd(master) };
        let mut terminal_input = terminal.try_clone()?;
        let mut host = connect_vsock(port)?;
        let mut host_input = host.try_clone()?;
        let upload = thread::spawn(move || relay_host_input(&mut host_input, &mut terminal_input));
        let output = copy_pty_output(&mut terminal, &mut host);
        let _ = host.shutdown(Shutdown::Both);
        upload
            .join()
            .map_err(|_| io::Error::other("terminal input thread panicked"))??;
        output?;
        wait_for_child(pid)
    }

    fn bridge_tcp(mut guest: TcpStream, port: u32, attributed: bool) -> io::Result<()> {
        let mut host = connect_vsock(port)?;
        if attributed {
            // Which guest process opened this connection, as PID 1 sees it.
            // The host forwards it to the kernel as a guest-reported origin.
            let origin =
                super::supervise::query(guest.local_addr()?.port(), guest.peer_addr()?.port());
            let origin = if origin.len() > keel_kernel::MAX_ORIGIN_BYTES {
                Vec::new()
            } else {
                origin
            };
            host.write_all(keel_kernel::ORIGIN_MAGIC)?;
            host.write_all(
                &u16::try_from(origin.len())
                    .unwrap_or_default()
                    .to_be_bytes(),
            )?;
            host.write_all(&origin)?;
        }
        let mut guest_writer = guest.try_clone()?;
        let mut host_reader = host.try_clone()?;
        let upload = thread::spawn(move || {
            let result = io::copy(&mut guest, &mut host);
            let _ = host.shutdown(Shutdown::Write);
            result
        });
        io::copy(&mut host_reader, &mut guest_writer)?;
        let _ = guest_writer.shutdown(Shutdown::Write);
        upload
            .join()
            .map_err(|_| io::Error::other("TCP upload thread panicked"))??;
        Ok(())
    }

    fn relay(local_port: u16, vsock_port: u32, attributed: bool) -> io::Result<()> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, local_port))?;
        super::confine::drop_to_service_uid()?;
        for stream in listener.incoming() {
            let stream = stream?;
            thread::spawn(move || {
                if let Err(error) = bridge_tcp(stream, vsock_port, attributed) {
                    eprintln!("keel guest relay failed: {error}");
                }
            });
        }
        Ok(())
    }

    pub async fn run() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let arguments = env::args().skip(1).collect::<Vec<_>>();
        match arguments.as_slice() {
            [mode] if mode == "stdio" => bridge_stdio(5_000)?,
            [mode, transport, port] if mode == "stdio" && transport == "tcp" => {
                bridge_stdio_tcp(port.parse()?)?;
            }
            [mode, port] if mode == "stdio" => bridge_stdio(port.parse()?)?,
            [mode, separator, command @ ..]
                if mode == "confine" && separator == "--" && !command.is_empty() =>
            {
                super::confine::confine_and_exec(command)?;
            }
            [mode] if mode == "confine-check" => {
                println!(
                    "{}",
                    serde_json::to_string(&super::confine::check_from_inside())?
                );
            }
            [mode, local_port, vsock_port] if mode == "relay" => {
                relay(local_port.parse()?, vsock_port.parse()?, false)?;
            }
            [mode, local_port, vsock_port, flag] if mode == "relay" && flag == "--attribute" => {
                relay(local_port.parse()?, vsock_port.parse()?, true)?;
            }
            [mode, separator, command @ ..]
                if mode == "supervise" && separator == "--" && !command.is_empty() =>
            {
                super::supervise::supervise(command);
            }
            [mode, port, rows, columns, command @ ..]
                if mode == "terminal" && !command.is_empty() =>
            {
                bridge_terminal(
                    port.parse()?,
                    parse_terminal_dimension(rows, "rows")?,
                    parse_terminal_dimension(columns, "columns")?,
                    command,
                )?;
            }
            [] => report(5_000, "keel-phase0".to_owned()).await?,
            [port] => report(port.parse()?, "keel-phase0".to_owned()).await?,
            [port, probe] => report(port.parse()?, probe.clone()).await?,
            _ => {
                return Err(
                    "usage: keel-mcp-guest [PORT [PROBE]] | stdio [PORT] | stdio tcp LOCAL_PORT | relay LOCAL_PORT VSOCK_PORT [--attribute] | supervise -- COMMAND [ARG...] | terminal VSOCK_PORT ROWS COLUMNS COMMAND [ARG...] | confine -- COMMAND [ARG...] | confine-check"
                        .into(),
                );
            }
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    linux::run().await
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("keel-mcp-guest only runs inside a Linux guest");
    std::process::exit(2);
}
