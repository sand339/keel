//! PID 1's account of what happens inside the guest, streamed to the host.
//!
//! The kernel's process-events connector reports every exec and exit, and
//! fanotify reports every file closed after writing on the workload's
//! writable mounts. Each becomes a `GuestEvent` line on the telemetry vsock.
//! The stream is bounded and lossy by design: when the host falls behind,
//! events are counted as dropped instead of slowing the workload. Like the
//! connection origins, every event is the guest's claim (PLAN D68).

use keel_mcp::telemetry::{GuestEvent, TELEMETRY_VSOCK_PORT};
use std::{
    collections::HashSet,
    ffi::CString,
    fs,
    io::{self, BufWriter, Write as _},
    mem,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
        mpsc::{self, Receiver, SyncSender, TrySendError},
    },
    thread,
    time::Duration,
};

use super::supervise::{describe, parent_of};

/// Mounts the workload can write: the overlay root (`/tmp`, `/root`,
/// `/var/tmp`) and the shared workspace.
const WATCHED_MOUNTS: &[&str] = &["/", "/workspace"];
const QUEUE_DEPTH: usize = 4_096;
/// Distinct file writes and processes remembered, to report each once.
const MAX_REMEMBERED: usize = 65_536;
const NETLINK_CONNECTOR: i32 = 11;
const CN_IDX_PROC: u32 = 1;
const CN_VAL_PROC: u32 = 1;
const PROC_CN_MCAST_LISTEN: u32 = 1;
const PROC_EVENT_EXEC: u32 = 0x0000_0002;
const PROC_EVENT_EXIT: u32 = 0x8000_0000;
const NLMSG_HEADER: usize = 16;
const CN_MSG_HEADER: usize = 20;
const NLMSG_DONE: u16 = 3;

/// A process event decoded from the connector.
#[derive(Debug, Eq, PartialEq)]
pub enum ProcEvent {
    Exec { pid: u32 },
    Exit { pid: u32, code: i32 },
}

/// Starts the observers and the stream to the host. Failures are reported
/// and leave the guest running without telemetry.
pub fn start() {
    let (sender, receiver) = mpsc::sync_channel(QUEUE_DEPTH);
    let dropped = Arc::new(AtomicU64::new(0));
    let queue = Queue {
        sender,
        dropped: Arc::clone(&dropped),
    };
    let processes = queue.clone();
    thread::spawn(move || {
        if let Err(error) = watch_processes(&processes) {
            eprintln!("[keel-init] process events unavailable: {error}");
        }
    });
    thread::spawn(move || {
        if let Err(error) = watch_writes(&queue) {
            eprintln!("[keel-init] file events unavailable: {error}");
        }
    });
    thread::spawn(move || {
        if let Err(error) = stream(&receiver, &dropped) {
            eprintln!("[keel-init] guest event stream ended: {error}");
        }
    });
}

#[derive(Clone)]
struct Queue {
    sender: SyncSender<GuestEvent>,
    dropped: Arc<AtomicU64>,
}

impl Queue {
    fn push(&self, event: GuestEvent) {
        if let Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) =
            self.sender.try_send(event)
        {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

fn stream(receiver: &Receiver<GuestEvent>, dropped: &AtomicU64) -> io::Result<()> {
    let mut host = None;
    for _ in 0..50 {
        match crate::linux::connect_vsock(TELEMETRY_VSOCK_PORT) {
            Ok(connection) => {
                host = Some(connection);
                break;
            }
            Err(_) => thread::sleep(Duration::from_millis(100)),
        }
    }
    let mut host = BufWriter::new(host.ok_or_else(|| io::Error::other("no telemetry listener"))?);
    loop {
        match receiver.recv_timeout(Duration::from_millis(500)) {
            Ok(event) => {
                write_event(&mut host, &event)?;
                // Write what is already queued, then flush once.
                while let Ok(event) = receiver.try_recv() {
                    write_event(&mut host, &event)?;
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => return host.flush(),
        }
        let lost = dropped.swap(0, Ordering::Relaxed);
        if lost > 0 {
            write_event(&mut host, &GuestEvent::Dropped { count: lost })?;
        }
        host.flush()?;
    }
}

fn write_event(host: &mut impl io::Write, event: &GuestEvent) -> io::Result<()> {
    serde_json::to_writer(&mut *host, event).map_err(io::Error::other)?;
    host.write_all(b"\n")
}

fn watch_processes(queue: &Queue) -> io::Result<()> {
    // SAFETY: socket takes no pointers; the descriptor is checked below.
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
            NETLINK_CONNECTOR,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: an all-zero sockaddr_nl is valid; the fields are set below.
    let mut address: libc::sockaddr_nl = unsafe { mem::zeroed() };
    address.nl_family = libc::sa_family_t::try_from(libc::AF_NETLINK).map_err(io::Error::other)?;
    address.nl_groups = CN_IDX_PROC;
    let length =
        libc::socklen_t::try_from(mem::size_of::<libc::sockaddr_nl>()).map_err(io::Error::other)?;
    // SAFETY: `address` is a valid sockaddr_nl of `length` bytes.
    if unsafe { libc::bind(fd, (&raw const address).cast(), length) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let subscribe = subscription();
    // SAFETY: the buffer is valid for its length for the duration of the call.
    if unsafe { libc::send(fd, subscribe.as_ptr().cast(), subscribe.len(), 0) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut seen = HashSet::new();
    let mut buffer = vec![0_u8; 8_192];
    loop {
        // SAFETY: the buffer is valid and writable for its length.
        let read = unsafe { libc::recv(fd, buffer.as_mut_ptr().cast(), buffer.len(), 0) };
        let Ok(read) = usize::try_from(read) else {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            // ENOBUFS: the kernel dropped events for a slow reader.
            queue.dropped.fetch_add(1, Ordering::Relaxed);
            continue;
        };
        for event in parse_proc_events(&buffer[..read]) {
            match event {
                ProcEvent::Exec { pid } => {
                    let process = describe(pid);
                    if process.workspace_code {
                        super::supervise::remember_workspace_code(pid);
                    }
                    if seen.len() < MAX_REMEMBERED {
                        seen.insert(pid);
                    }
                    queue.push(GuestEvent::Exec {
                        pid,
                        ppid: parent_of(pid).unwrap_or_default(),
                        cwd: fs::read_link(format!("/proc/{pid}/cwd"))
                            .map(|path| path.display().to_string())
                            .unwrap_or_default(),
                        exe: process.exe,
                        argv: process.argv,
                        workspace_code: process.workspace_code,
                    });
                }
                ProcEvent::Exit { pid, code } if seen.remove(&pid) => {
                    super::supervise::forget(pid);
                    queue.push(GuestEvent::Exit { pid, code });
                }
                ProcEvent::Exit { .. } => {}
            }
        }
    }
}

/// The netlink message that subscribes to process events.
fn subscription() -> Vec<u8> {
    let total = NLMSG_HEADER + CN_MSG_HEADER + 4;
    let mut message = Vec::with_capacity(total);
    message.extend_from_slice(&u32::try_from(total).unwrap_or_default().to_ne_bytes());
    message.extend_from_slice(&NLMSG_DONE.to_ne_bytes());
    message.extend_from_slice(&0_u16.to_ne_bytes());
    message.extend_from_slice(&0_u32.to_ne_bytes());
    message.extend_from_slice(&std::process::id().to_ne_bytes());
    message.extend_from_slice(&CN_IDX_PROC.to_ne_bytes());
    message.extend_from_slice(&CN_VAL_PROC.to_ne_bytes());
    message.extend_from_slice(&0_u32.to_ne_bytes());
    message.extend_from_slice(&0_u32.to_ne_bytes());
    message.extend_from_slice(&4_u16.to_ne_bytes());
    message.extend_from_slice(&0_u16.to_ne_bytes());
    message.extend_from_slice(&PROC_CN_MCAST_LISTEN.to_ne_bytes());
    message
}

fn field(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

/// Decodes the process events in one netlink datagram. Thread events are
/// skipped: only a thread-group leader's exec and exit are reported.
pub fn parse_proc_events(datagram: &[u8]) -> Vec<ProcEvent> {
    let mut events = Vec::new();
    let mut offset = 0;
    while let Some(length) = field(datagram, offset) {
        let length = length as usize;
        if length < NLMSG_HEADER || offset + length > datagram.len() {
            break;
        }
        // proc_event: what, cpu, timestamp (u64), then the event's fields.
        let event = offset + NLMSG_HEADER + CN_MSG_HEADER;
        let data = event + 16;
        match field(datagram, event) {
            Some(PROC_EVENT_EXEC) => {
                if let (Some(pid), Some(tgid)) = (field(datagram, data), field(datagram, data + 4))
                    && pid == tgid
                {
                    events.push(ProcEvent::Exec { pid });
                }
            }
            Some(PROC_EVENT_EXIT) => {
                if let (Some(pid), Some(tgid), Some(status)) = (
                    field(datagram, data),
                    field(datagram, data + 4),
                    field(datagram, data + 8),
                ) && pid == tgid
                {
                    events.push(ProcEvent::Exit {
                        pid,
                        code: exit_code(status),
                    });
                }
            }
            _ => {}
        }
        offset += (length + 3) & !3;
    }
    events
}

/// A wait status as a code: the exit status, or the negated signal.
fn exit_code(status: u32) -> i32 {
    let signal = status & 0x7f;
    if signal == 0 {
        i32::try_from((status >> 8) & 0xff).unwrap_or_default()
    } else {
        -i32::try_from(signal).unwrap_or_default()
    }
}

fn watch_writes(queue: &Queue) -> io::Result<()> {
    // SAFETY: fanotify_init takes no pointers; the descriptor is checked.
    let fd = unsafe {
        libc::fanotify_init(
            libc::FAN_CLASS_NOTIF | libc::FAN_CLOEXEC,
            u32::try_from(libc::O_RDONLY | libc::O_LARGEFILE | libc::O_CLOEXEC)
                .map_err(io::Error::other)?,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    for mount in WATCHED_MOUNTS {
        let path = CString::new(*mount).map_err(io::Error::other)?;
        // SAFETY: `path` is a valid NUL-terminated string for the call.
        let marked = unsafe {
            libc::fanotify_mark(
                fd,
                libc::FAN_MARK_ADD | libc::FAN_MARK_MOUNT,
                libc::FAN_CLOSE_WRITE,
                libc::AT_FDCWD,
                path.as_ptr(),
            )
        };
        if marked < 0 {
            eprintln!(
                "[keel-init] cannot watch writes on {mount}: {}",
                io::Error::last_os_error()
            );
        }
    }
    let own = std::process::id();
    let mut seen = HashSet::new();
    let header = mem::size_of::<libc::fanotify_event_metadata>();
    let mut buffer = vec![0_u8; 16 * 1_024];
    loop {
        // SAFETY: the buffer is valid and writable for its length.
        let read = unsafe { libc::read(fd, buffer.as_mut_ptr().cast(), buffer.len()) };
        let Ok(read) = usize::try_from(read) else {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(io::Error::last_os_error());
        };
        let mut offset = 0;
        while offset + header <= read {
            // SAFETY: at least `header` bytes remain; read_unaligned copies
            // them without requiring the buffer's alignment.
            let metadata: libc::fanotify_event_metadata = unsafe {
                buffer
                    .as_ptr()
                    .add(offset)
                    .cast::<libc::fanotify_event_metadata>()
                    .read_unaligned()
            };
            let length = metadata.event_len as usize;
            if length < header {
                break;
            }
            if metadata.fd >= 0 {
                let path = fs::read_link(format!("/proc/self/fd/{}", metadata.fd))
                    .map(|path| path.display().to_string())
                    .unwrap_or_default();
                // SAFETY: fanotify handed this process its own descriptor.
                unsafe {
                    libc::close(metadata.fd);
                }
                let pid = u32::try_from(metadata.pid).unwrap_or_default();
                if pid != own
                    && !path.is_empty()
                    && !path.starts_with("/proc/")
                    && !path.starts_with("/dev/")
                    && !path.starts_with("/sys/")
                    && seen.len() < MAX_REMEMBERED
                    && seen.insert((pid, path.clone()))
                {
                    queue.push(GuestEvent::FileWrite { pid, path });
                }
            }
            offset += length;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(what: u32, fields: &[u32]) -> Vec<u8> {
        let length = NLMSG_HEADER + CN_MSG_HEADER + 16 + fields.len() * 4;
        let mut bytes = vec![0_u8; NLMSG_HEADER + CN_MSG_HEADER];
        bytes[..4].copy_from_slice(&u32::try_from(length).unwrap().to_ne_bytes());
        bytes.extend_from_slice(&what.to_ne_bytes());
        bytes.extend_from_slice(&[0; 12]);
        for value in fields {
            bytes.extend_from_slice(&value.to_ne_bytes());
        }
        bytes
    }

    #[test]
    fn process_events_report_leaders_and_decode_exit_status() {
        let mut datagram = message(PROC_EVENT_EXEC, &[42, 42]);
        datagram.extend(message(PROC_EVENT_EXEC, &[43, 42]));
        datagram.extend(message(PROC_EVENT_EXIT, &[42, 42, 3 << 8, 17, 1, 1]));
        datagram.extend(message(PROC_EVENT_EXIT, &[44, 44, 9, 17, 1, 1]));
        datagram.extend(message(0x0000_0001, &[45, 45, 46, 46]));
        assert_eq!(
            parse_proc_events(&datagram),
            [
                ProcEvent::Exec { pid: 42 },
                ProcEvent::Exit { pid: 42, code: 3 },
                ProcEvent::Exit { pid: 44, code: -9 },
            ]
        );
        assert!(parse_proc_events(&datagram[..10]).is_empty());
    }

    #[test]
    fn the_subscription_is_one_complete_netlink_message() {
        let message = subscription();
        assert_eq!(message.len(), NLMSG_HEADER + CN_MSG_HEADER + 4);
        assert_eq!(
            field(&message, 0),
            Some(u32::try_from(message.len()).unwrap())
        );
        assert_eq!(
            field(&message, NLMSG_HEADER + CN_MSG_HEADER),
            Some(PROC_CN_MCAST_LISTEN)
        );
    }
}
