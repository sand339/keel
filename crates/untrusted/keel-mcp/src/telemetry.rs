//! What the guest reports about its own processes and file writes.
//!
//! The guest's PID 1 observer streams one JSON event per line over vsock; the
//! host stamps each with its own clock and appends it to the session's
//! `guest-*.ndjson`. Every event is the guest's claim: a compromised guest
//! kernel or supervisor can report anything, so nothing here is authority and
//! none of it enters the audit chain (PLAN D68).

use serde::{Deserialize, Serialize};
use std::io::{self, BufRead, Read as _, Write};

/// The vsock port the guest streams events to.
pub const TELEMETRY_VSOCK_PORT: u32 = 5_004;
/// Longest accepted event line, newline included.
pub const MAX_EVENT_LINE: usize = 4 * 1024;
/// Most bytes recorded per stream; later events are counted, not written.
pub const MAX_RECORDED_BYTES: u64 = 64 * 1024 * 1024;

/// One observation by the guest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum GuestEvent {
    /// A process replaced its image.
    Exec {
        /// Process id in the guest.
        pid: u32,
        /// Parent process id.
        ppid: u32,
        /// Resolved executable path.
        exe: String,
        /// Leading arguments, bounded in count and length.
        argv: Vec<String>,
        /// Working directory.
        cwd: String,
        /// Whether the image or a script argument lives in a workload-writable path.
        workspace_code: bool,
    },
    /// A process ended.
    Exit {
        /// Process id in the guest.
        pid: u32,
        /// Exit status, or the negated signal number for a killed process.
        code: i32,
    },
    /// A process closed a file it had open for writing.
    FileWrite {
        /// The writing process.
        pid: u32,
        /// Absolute path in the guest.
        path: String,
    },
    /// The observer dropped events it could not keep up with.
    Dropped {
        /// How many events were lost.
        count: u64,
    },
}

/// An event as the host recorded it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RecordedEvent {
    /// Host wall-clock time of receipt, in milliseconds since the Unix epoch.
    pub received_ms: u64,
    /// The guest's claim.
    #[serde(flatten)]
    pub event: GuestEvent,
}

/// What one recorded stream contained.
#[derive(Debug, Default, Eq, PartialEq)]
pub struct RecordStats {
    /// Events written.
    pub recorded: u64,
    /// Malformed, oversized, or unknown lines discarded.
    pub rejected: u64,
    /// Well-formed events past the size limit, counted but not written.
    pub over_limit: u64,
}

/// Records a guest event stream: each well-formed, bounded line is re-encoded
/// with the host's receipt time; anything else is counted and discarded.
///
/// # Errors
///
/// Returns an error when reading the stream or writing the record fails.
pub fn record_events(
    mut stream: impl BufRead,
    mut out: impl Write,
    now_ms: impl Fn() -> u64,
) -> io::Result<RecordStats> {
    let mut stats = RecordStats::default();
    let mut written = 0_u64;
    let mut line = Vec::with_capacity(MAX_EVENT_LINE);
    loop {
        line.clear();
        let read = stream
            .by_ref()
            .take(MAX_EVENT_LINE as u64)
            .read_until(b'\n', &mut line)?;
        if read == 0 {
            break;
        }
        if line.last() != Some(&b'\n') {
            // Too long, or cut off at end of stream: skip to the next line.
            stats.rejected += 1;
            if read == MAX_EVENT_LINE {
                let mut rest = Vec::new();
                stream.read_until(b'\n', &mut rest)?;
            }
            continue;
        }
        let Ok(event) = serde_json::from_slice::<GuestEvent>(&line) else {
            stats.rejected += 1;
            continue;
        };
        let mut encoded = serde_json::to_vec(&RecordedEvent {
            received_ms: now_ms(),
            event,
        })?;
        encoded.push(b'\n');
        if written + encoded.len() as u64 > MAX_RECORDED_BYTES {
            stats.over_limit += 1;
            continue;
        }
        out.write_all(&encoded)?;
        written += encoded.len() as u64;
        stats.recorded += 1;
    }
    if stats.over_limit > 0 {
        let mut marker = serde_json::to_vec(&RecordedEvent {
            received_ms: now_ms(),
            event: GuestEvent::Dropped {
                count: stats.over_limit,
            },
        })?;
        marker.push(b'\n');
        out.write_all(&marker)?;
    }
    out.flush()?;
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(input: &[u8]) -> (Vec<RecordedEvent>, RecordStats) {
        let mut out = Vec::new();
        let stats = record_events(input, &mut out, || 7).unwrap();
        let events = out
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice(line).unwrap())
            .collect();
        (events, stats)
    }

    #[test]
    fn well_formed_events_are_stamped_and_the_rest_counted() {
        let long = format!(
            "{{\"kind\":\"file-write\",\"pid\":1,\"path\":\"{}\"}}\n",
            "a".repeat(MAX_EVENT_LINE)
        );
        let input = [
            "{\"kind\":\"exec\",\"pid\":9,\"ppid\":1,\"exe\":\"/usr/bin/node\",\"argv\":[\"node\",\"a.js\"],\"cwd\":\"/workspace\",\"workspace_code\":true}\n",
            "not json\n",
            "{\"kind\":\"exit\",\"pid\":9,\"code\":0,\"extra\":1}\n",
            long.as_str(),
            "{\"kind\":\"exit\",\"pid\":9,\"code\":0}\n",
            "{\"kind\":\"file-write\",\"pid\":9,\"path\":\"/workspace/x\"}",
        ]
        .concat();
        let (events, stats) = record(input.as_bytes());
        assert_eq!(
            stats,
            RecordStats {
                recorded: 2,
                rejected: 4,
                over_limit: 0
            }
        );
        assert_eq!(events.len(), 2);
        assert!(events.iter().all(|event| event.received_ms == 7));
        assert_eq!(events[1].event, GuestEvent::Exit { pid: 9, code: 0 });
    }
}
