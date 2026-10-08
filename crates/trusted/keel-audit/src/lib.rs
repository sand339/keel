#![forbid(unsafe_code)]
#![doc = "Trusted append-only audit primitives for Keel."]

use keel_kernel::{
    AuditEvent, AuditSink, ContextEvent, EnforcementStateEvent, GateDecision,
    ModelReservationEvent, ModelUsageEvent, ProvenanceEvent, ProvenanceMode, ReportedOutcomeEvent,
    RunAdmittedEvent, StructuralRejectionEvent,
};
use ring::{
    digest::{SHA256, digest},
    rand::{SecureRandom, SystemRandom},
    signature::{ED25519, Ed25519KeyPair, KeyPair as _, UnparsedPublicKey},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    error::Error,
    fmt,
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, BufWriter, Write},
    path::Path,
    sync::mpsc::{self, Receiver, SyncSender},
    thread::{self, JoinHandle},
    time::{SystemTime, UNIX_EPOCH},
};

const HASH_DOMAIN: &[u8] = b"keel-audit-record-v1\0";
const SIGNATURE_DOMAIN: &[u8] = b"keel-audit-signature-v1\0";
const REDACTED: &str = "[REDACTED]";
const SEAL_EVENT: &str = "audit.sealed";

/// Per-run audit signing or verification key.
///
/// A generated or seeded value contains the private signing key in memory.
/// `from_hex` constructs a verifier from the public key written beside the
/// audit stream; the private key is never persisted.
pub struct RunKey {
    signing: Option<Ed25519KeyPair>,
    public: [u8; 32],
}

impl RunKey {
    /// Generates a fresh key from operating-system randomness.
    ///
    /// # Errors
    ///
    /// Returns an error when secure randomness is unavailable.
    pub fn generate() -> Result<Self, AuditError> {
        let mut bytes = [0_u8; 32];
        SystemRandom::new()
            .fill(&mut bytes)
            .map_err(|_| AuditError::RandomUnavailable)?;
        Self::from_seed(bytes)
    }

    /// Creates a run key from exactly 32 bytes.
    ///
    /// # Panics
    ///
    /// This cannot panic with ring's Ed25519 implementation, which accepts
    /// every 32-byte seed; the assertion preserves the infallible test API.
    #[must_use]
    pub fn new(bytes: [u8; 32]) -> Self {
        Self::from_seed(bytes).expect("32-byte Ed25519 seeds are valid")
    }

    fn from_seed(seed: [u8; 32]) -> Result<Self, AuditError> {
        let signing = Ed25519KeyPair::from_seed_unchecked(&seed)
            .map_err(|_| AuditError::InvalidSigningKey)?;
        let mut public = [0_u8; 32];
        public.copy_from_slice(signing.public_key().as_ref());
        Ok(Self {
            signing: Some(signing),
            public,
        })
    }

    /// Parses a 64-character hexadecimal public verification key.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed or incorrectly sized input.
    pub fn from_hex(value: &str) -> Result<Self, AuditError> {
        Ok(Self {
            signing: None,
            public: decode_hex::<32>(value.trim(), "audit verification key")?,
        })
    }

    /// Writes the public verification key to a newly created mode-0600 file.
    ///
    /// Existing files are never replaced.
    ///
    /// # Errors
    ///
    /// Returns an error when the file cannot be created, written, or synced.
    pub fn write_new(&self, path: &Path) -> Result<(), AuditError> {
        let mut file = open_new(path)?;
        file.write_all(encode_hex(&self.public).as_bytes())
            .and_then(|()| file.write_all(b"\n"))
            .and_then(|()| file.sync_all())
            .map_err(|error| AuditError::Io(error.to_string()))
    }
}

/// Exact values that must never enter the audit stream.
#[derive(Clone, Debug)]
pub struct Redactor {
    secrets: Vec<String>,
}

impl Redactor {
    /// Builds a redactor for real and sentinel credential forms.
    ///
    /// # Errors
    ///
    /// Returns an error if any configured value is empty.
    pub fn new(secrets: impl IntoIterator<Item = impl Into<String>>) -> Result<Self, AuditError> {
        let secrets = secrets.into_iter().map(Into::into).collect::<Vec<_>>();
        if secrets.iter().any(String::is_empty) {
            return Err(AuditError::InvalidRedaction);
        }
        let mut secrets = secrets
            .into_iter()
            .flat_map(|secret| {
                let standard = base64(secret.as_bytes(), b'+', b'/');
                let url_safe = base64(secret.as_bytes(), b'-', b'_');
                [
                    secret.clone(),
                    percent_encode(&secret),
                    standard.clone(),
                    standard.trim_end_matches('=').to_owned(),
                    url_safe.clone(),
                    url_safe.trim_end_matches('=').to_owned(),
                ]
            })
            .filter(|secret| !secret.is_empty())
            .collect::<Vec<_>>();
        secrets.sort_by_key(|secret| std::cmp::Reverse(secret.len()));
        secrets.dedup();
        Ok(Self { secrets })
    }

    /// Returns a copy with every configured value replaced.
    #[must_use]
    pub fn redact(&self, value: &str) -> String {
        self.secrets
            .iter()
            .fold(value.to_owned(), |redacted, secret| {
                redacted.replace(secret, REDACTED)
            })
    }
}

fn percent_encode(value: &str) -> String {
    use std::fmt::Write as _;

    let mut encoded = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(char::from(byte));
        } else {
            let _ = write!(encoded, "%{byte:02X}");
        }
    }
    encoded
}

fn base64(value: &[u8], char62: u8, char63: u8) -> String {
    let mut alphabet = *b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    alphabet[62] = char62;
    alphabet[63] = char63;
    let mut output = String::with_capacity(value.len().div_ceil(3) * 4);
    for chunk in value.chunks(3) {
        let bits = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        output.push(char::from(alphabet[((bits >> 18) & 63) as usize]));
        output.push(char::from(alphabet[((bits >> 12) & 63) as usize]));
        output.push(if chunk.len() > 1 {
            char::from(alphabet[((bits >> 6) & 63) as usize])
        } else {
            '='
        });
        output.push(if chunk.len() > 2 {
            char::from(alphabet[(bits & 63) as usize])
        } else {
            '='
        });
    }
    output
}

/// Secret-free logical event supplied to the audit writer.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuditPayload {
    /// Milliseconds since the Unix epoch, supplied by the trusted runtime.
    pub timestamp_ms: u64,
    /// Stable event name.
    pub event: String,
    /// Session-unique action identifier, when applicable.
    pub action_id: Option<u64>,
    /// Structured fields in deterministic key order.
    pub fields: BTreeMap<String, String>,
}

impl AuditPayload {
    fn redacted(mut self, redactor: &Redactor) -> Self {
        self.event = redactor.redact(&self.event);
        self.fields = self
            .fields
            .into_iter()
            .map(|(key, value)| (redactor.redact(&key), redactor.redact(&value)))
            .collect();
        self
    }
}

/// Authenticated line written to the NDJSON audit stream.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuditRecord {
    /// Monotonic record sequence starting at zero.
    pub seq: u64,
    /// Caller-selected run identifier.
    pub run_id: String,
    /// SHA-256 digest of the preceding record, or zeroes for sequence zero.
    pub previous_hash: String,
    /// Redacted event body.
    pub payload: AuditPayload,
    /// SHA-256 digest of this record's framed content.
    pub record_hash: String,
    /// Ed25519 signature over the record digest and sequence number.
    pub mac: String,
}

enum WriterMessage {
    Record(AuditPayload, SyncSender<Result<(), AuditError>>),
    Shutdown(SyncSender<Result<(), AuditError>>),
}

/// Handle to the sole thread allowed to extend an audit chain.
pub struct AuditWriter {
    sender: SyncSender<WriterMessage>,
    thread: Option<JoinHandle<()>>,
}

impl AuditWriter {
    /// Creates a new append-only audit file and starts its single writer.
    ///
    /// Existing paths are rejected to prevent accidental chain replacement.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be created or the writer thread
    /// cannot be started.
    pub fn spawn(
        path: &Path,
        run_id: impl Into<String>,
        run_key: RunKey,
        redactor: Redactor,
    ) -> Result<Self, AuditError> {
        let run_id = run_id.into();
        if run_id.is_empty() || run_id.chars().any(char::is_control) {
            return Err(AuditError::InvalidRunId);
        }
        let file = open_new(path)?;
        let (sender, receiver) = mpsc::sync_channel(64);
        let thread = thread::Builder::new()
            .name("keel-audit-writer".to_owned())
            .spawn(move || writer_loop(file, &receiver, &run_id, &run_key, &redactor))
            .map_err(|error| AuditError::Io(error.to_string()))?;
        Ok(Self {
            sender,
            thread: Some(thread),
        })
    }

    /// Redacts, authenticates, writes, and flushes one event.
    ///
    /// # Errors
    ///
    /// Returns an error when the writer is unavailable or persistence fails.
    pub fn record(&self, payload: AuditPayload) -> Result<(), AuditError> {
        let (sender, receiver) = mpsc::sync_channel(1);
        self.sender
            .send(WriterMessage::Record(payload, sender))
            .map_err(|_| AuditError::WriterUnavailable)?;
        receiver.recv().map_err(|_| AuditError::WriterUnavailable)?
    }

    /// Flushes the stream and joins the writer.
    ///
    /// # Errors
    ///
    /// Returns an error when flushing, shutdown, or joining fails.
    pub fn shutdown(mut self) -> Result<(), AuditError> {
        let (sender, receiver) = mpsc::sync_channel(1);
        self.sender
            .send(WriterMessage::Shutdown(sender))
            .map_err(|_| AuditError::WriterUnavailable)?;
        receiver
            .recv()
            .map_err(|_| AuditError::WriterUnavailable)??;
        self.thread
            .take()
            .ok_or(AuditError::WriterUnavailable)?
            .join()
            .map_err(|_| AuditError::WriterPanicked)
    }
}

/// Durable adapter for every kernel audit event class.
pub struct KernelAudit {
    writer: Option<AuditWriter>,
}

impl KernelAudit {
    /// Wraps a newly spawned audit writer.
    #[must_use]
    pub const fn new(writer: AuditWriter) -> Self {
        Self {
            writer: Some(writer),
        }
    }

    fn write(&self, payload: AuditPayload) -> Result<(), String> {
        self.writer
            .as_ref()
            .ok_or_else(|| "audit writer is closed".to_owned())?
            .record(payload)
            .map_err(|error| error.to_string())
    }
}

impl AuditSink for KernelAudit {
    fn record(&mut self, event: AuditEvent) -> Result<(), String> {
        let mut fields = BTreeMap::from([
            ("principal".to_owned(), event.principal.as_str().to_owned()),
            ("action_class".to_owned(), event.class.as_str().to_owned()),
            ("target_kind".to_owned(), event.target_kind.to_owned()),
            ("target_hash".to_owned(), encode_hex(&event.target_hash)),
            ("outcome".to_owned(), event.outcome.as_str().to_owned()),
            ("intent".to_owned(), event.intent.to_owned()),
            ("flow".to_owned(), event.flow),
            (
                "rules".to_owned(),
                serde_json::to_string(&event.rules).map_err(|error| error.to_string())?,
            ),
        ]);
        if let Some(origin) = event.origin {
            fields.insert("origin".to_owned(), origin);
        }
        if let Some(integrity) = event.integrity {
            fields.insert("integrity".to_owned(), integrity);
        }
        if let Some(gate) = event.gate {
            fields.insert(
                "gate_decision".to_owned(),
                match gate.decision {
                    GateDecision::Approve => "approve",
                    GateDecision::ApproveGrant => "approve-grant",
                    GateDecision::Deny => "deny",
                    GateDecision::Unavailable => "unavailable",
                }
                .to_owned(),
            );
            fields.insert(
                "gate_time_ms".to_owned(),
                gate.time_to_decision_ms.to_string(),
            );
            fields.insert("gate_floor".to_owned(), gate.floor_at_gate.to_string());
            fields.insert(
                "provenance_mode".to_owned(),
                match gate.mode {
                    ProvenanceMode::Floor => "floor",
                    ProvenanceMode::GateContext => "gate-context",
                }
                .to_owned(),
            );
            fields.insert("gate_authority".to_owned(), gate.authority.to_owned());
            fields.insert(
                "prompt_presented".to_owned(),
                gate.prompt_presented.to_string(),
            );
        }
        if let Some(denial) = event.denial {
            let origin = serde_json::to_value(denial.origin)
                .map_err(|error| error.to_string())?
                .as_str()
                .ok_or_else(|| "denial origin did not serialize as a string".to_owned())?
                .to_owned();
            fields.insert("denial_origin".to_owned(), origin);
            fields.insert(
                "denial_scope".to_owned(),
                encode_hex(&denial.scope.digest()),
            );
            fields.insert(
                "denial_counted_for_repeated_review".to_owned(),
                denial.counted_for_repeated_review.to_string(),
            );
            fields.insert(
                "denial_recent_behavioral_denials_in_scope".to_owned(),
                denial.recent_behavioral_denials_in_scope.to_string(),
            );
        }
        self.write(AuditPayload {
            timestamp_ms: timestamp_ms()?,
            event: "kernel.action".to_owned(),
            action_id: Some(event.action_id),
            fields,
        })
    }

    fn record_structural_rejection(
        &mut self,
        event: StructuralRejectionEvent,
    ) -> Result<(), String> {
        self.write(AuditPayload {
            timestamp_ms: timestamp_ms()?,
            event: "kernel.structural-rejection".to_owned(),
            action_id: None,
            fields: BTreeMap::from([
                ("channel_hash".to_owned(), encode_hex(&event.channel_hash)),
                (
                    "principal_hash".to_owned(),
                    encode_hex(&event.principal_hash),
                ),
                ("action_class".to_owned(), event.class.as_str().to_owned()),
                ("target_kind".to_owned(), event.target_kind.to_owned()),
                ("target_hash".to_owned(), encode_hex(&event.target_hash)),
                ("rule".to_owned(), event.rule.to_owned()),
            ]),
        })
    }

    fn record_run_admitted(&mut self, event: RunAdmittedEvent) -> Result<(), String> {
        self.write(AuditPayload {
            timestamp_ms: timestamp_ms()?,
            event: "kernel.run-admitted".to_owned(),
            action_id: None,
            fields: BTreeMap::from([
                ("manifest".to_owned(), event.manifest),
                ("manifest_sha256".to_owned(), encode_hex(&event.digest)),
            ]),
        })
    }

    fn record_context(&mut self, event: ContextEvent) -> Result<(), String> {
        let described = event
            .described
            .iter()
            .map(|block| {
                serde_json::json!({
                    "place": block.place,
                    "kind": block.kind,
                    "bytes": block.bytes,
                    "digest": encode_hex(&block.digest),
                    "tool_use": block.tool_use,
                })
            })
            .collect::<Vec<_>>();
        let sequence = event
            .sequence
            .iter()
            .map(|digest| encode_hex(digest))
            .collect::<Vec<_>>();
        self.write(AuditPayload {
            timestamp_ms: timestamp_ms()?,
            event: "kernel.model-context".to_owned(),
            action_id: Some(event.action_id),
            fields: BTreeMap::from([
                ("phase".to_owned(), event.phase.to_owned()),
                ("sequence".to_owned(), sequence.join(" ")),
                (
                    "blocks".to_owned(),
                    serde_json::to_string(&described).map_err(|error| error.to_string())?,
                ),
            ]),
        })
    }

    fn record_model_usage(&mut self, event: ModelUsageEvent) -> Result<(), String> {
        self.write(AuditPayload {
            timestamp_ms: timestamp_ms()?,
            event: "kernel.model-usage".to_owned(),
            action_id: Some(event.action_id),
            fields: BTreeMap::from([
                (
                    "reserved_tokens".to_owned(),
                    event.reserved_tokens.to_string(),
                ),
                (
                    "reserved_cost_microusd".to_owned(),
                    event.reserved_cost_microusd.to_string(),
                ),
                ("actual_tokens".to_owned(), event.actual_tokens.to_string()),
                (
                    "actual_cost_microusd".to_owned(),
                    event.actual_cost_microusd.to_string(),
                ),
            ]),
        })
    }

    fn record_model_reservation(&mut self, event: ModelReservationEvent) -> Result<(), String> {
        let mut fields = BTreeMap::from([
            (
                "reservation_id".to_owned(),
                event.reservation_id.get().to_string(),
            ),
            ("outcome".to_owned(), event.outcome.as_str().to_owned()),
            (
                "reserved_tokens".to_owned(),
                event.reserved_tokens.to_string(),
            ),
            (
                "reserved_cost_microusd".to_owned(),
                event.reserved_cost_microusd.to_string(),
            ),
        ]);
        if let Some(actual_tokens) = event.actual_tokens {
            fields.insert("actual_tokens".to_owned(), actual_tokens.to_string());
        }
        if let Some(actual_cost_microusd) = event.actual_cost_microusd {
            fields.insert(
                "actual_cost_microusd".to_owned(),
                actual_cost_microusd.to_string(),
            );
        }
        self.write(AuditPayload {
            timestamp_ms: timestamp_ms()?,
            event: "kernel.model-reservation".to_owned(),
            action_id: Some(event.action_id),
            fields,
        })
    }

    fn record_reported_outcome(&mut self, event: ReportedOutcomeEvent) -> Result<(), String> {
        self.write(AuditPayload {
            timestamp_ms: timestamp_ms()?,
            // A distinct event name, because the kernel did not observe this. A
            // reader must not be able to mistake a relay's claim for a kernel fact.
            event: "kernel.reported-outcome".to_owned(),
            action_id: Some(event.action_id),
            fields: BTreeMap::from([
                ("reporter".to_owned(), event.reporter.to_owned()),
                ("reported_outcome".to_owned(), event.outcome),
            ]),
        })
    }

    fn record_enforcement_state(&mut self, event: EnforcementStateEvent) -> Result<(), String> {
        // Boundary keys are prefixed so no boundary name can ever collide with
        // a field of the record itself.
        let mut fields = BTreeMap::from([("phase".to_owned(), event.phase.to_owned())]);
        for boundary in event.boundaries {
            fields.insert(
                format!("boundary.{}", boundary.name),
                format!("{}: {}", boundary.state.as_str(), boundary.detail),
            );
        }
        self.write(AuditPayload {
            timestamp_ms: timestamp_ms()?,
            event: "kernel.enforcement-state".to_owned(),
            action_id: None,
            fields,
        })
    }

    fn is_durable(&self) -> bool {
        self.writer.is_some()
    }

    fn record_provenance(&mut self, event: ProvenanceEvent) -> Result<(), String> {
        self.write(AuditPayload {
            timestamp_ms: event.timestamp_ms,
            event: "kernel.provenance".to_owned(),
            action_id: None,
            fields: BTreeMap::from([
                ("rank".to_owned(), event.rank.to_string()),
                ("floor_before".to_owned(), event.floor_before.to_string()),
                ("floor_after".to_owned(), event.floor_after.to_string()),
                (
                    "source".to_owned(),
                    serde_json::to_string(&event.source).map_err(|error| error.to_string())?,
                ),
            ]),
        })
    }

    fn shutdown(&mut self) -> Result<(), String> {
        self.writer
            .take()
            .ok_or_else(|| "audit writer is already closed".to_owned())?
            .shutdown()
            .map_err(|error| error.to_string())
    }
}

fn timestamp_ms() -> Result<u64, String> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX))
}

fn writer_loop(
    file: File,
    receiver: &Receiver<WriterMessage>,
    run_id: &str,
    run_key: &RunKey,
    redactor: &Redactor,
) {
    let mut writer = BufWriter::new(file);
    let mut previous = [0_u8; 32];
    let mut seq = 0_u64;
    let mut failed: Option<AuditError> = None;
    while let Ok(message) = receiver.recv() {
        match message {
            WriterMessage::Record(payload, response) => {
                let result = if let Some(error) = &failed {
                    Err(error.clone())
                } else {
                    write_record(
                        &mut writer,
                        run_id,
                        run_key,
                        redactor,
                        payload,
                        seq,
                        &mut previous,
                    )
                };
                if let Err(error) = &result {
                    failed = Some(error.clone());
                } else {
                    seq = seq.saturating_add(1);
                }
                let _ = response.send(result);
            }
            WriterMessage::Shutdown(response) => {
                let result = failed.map_or_else(
                    || {
                        let payload = AuditPayload {
                            timestamp_ms: SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .map_err(|error| AuditError::Io(error.to_string()))?
                                .as_millis()
                                .try_into()
                                .unwrap_or(u64::MAX),
                            event: SEAL_EVENT.to_owned(),
                            action_id: None,
                            fields: BTreeMap::from([
                                ("records".to_owned(), seq.to_string()),
                                ("tip".to_owned(), encode_hex(&previous)),
                            ]),
                        };
                        write_record(
                            &mut writer,
                            run_id,
                            run_key,
                            redactor,
                            payload,
                            seq,
                            &mut previous,
                        )
                    },
                    Err,
                );
                let _ = response.send(result);
                break;
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn write_record(
    writer: &mut BufWriter<File>,
    run_id: &str,
    run_key: &RunKey,
    redactor: &Redactor,
    payload: AuditPayload,
    seq: u64,
    previous: &mut [u8; 32],
) -> Result<(), AuditError> {
    let payload = payload.redacted(redactor);
    let record_hash = calculate_record_hash(seq, run_id, previous, &payload)?;
    let mac = calculate_mac(run_key, seq, &record_hash)?;
    let record = AuditRecord {
        seq,
        run_id: run_id.to_owned(),
        previous_hash: encode_hex(previous),
        payload,
        record_hash: encode_hex(&record_hash),
        mac: encode_hex(&mac),
    };
    serde_json::to_writer(&mut *writer, &record)
        .map_err(|error| AuditError::Serialization(error.to_string()))?;
    writer
        .write_all(b"\n")
        .and_then(|()| writer.flush())
        .and_then(|()| writer.get_ref().sync_data())
        .map_err(|error| AuditError::Io(error.to_string()))?;
    *previous = record_hash;
    Ok(())
}

/// Verifies sequence continuity, hash links, record digests, and signatures for an
/// audit file.
///
/// # Errors
///
/// Returns the first malformed, reordered, removed, inserted, or modified
/// record as an error.
pub fn verify_file(path: &Path, run_key: &RunKey) -> Result<u64, AuditError> {
    let status = inspect_file(path, run_key)?;
    status
        .sealed
        .then_some(status.records)
        .ok_or(AuditError::Unsealed)
}

/// Result of authenticating every complete record in an audit stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerificationStatus {
    /// Number of authenticated non-seal records.
    pub records: u64,
    /// Whether a valid terminal seal completed the stream.
    pub sealed: bool,
}

/// Authenticates the complete available stream and reports whether it is sealed.
///
/// Unlike [`verify_file`], this distinguishes a valid live/crashed prefix from
/// a completed stream. Malformed, legacy, and cryptographically invalid data
/// still fail closed.
///
/// # Errors
/// Returns the first malformed or unauthenticated record as an error.
pub fn inspect_file(path: &Path, run_key: &RunKey) -> Result<VerificationStatus, AuditError> {
    walk_verified_file(path, run_key, |_| {})
}

/// Reads an audit file only after verifying every record's sequence, hash
/// link, content digest, and signature.
///
/// # Errors
///
/// Returns the first malformed or unauthenticated record as an error.
pub fn read_verified_file(path: &Path, run_key: &RunKey) -> Result<Vec<AuditRecord>, AuditError> {
    let mut records = Vec::new();
    let status = walk_verified_file(path, run_key, |record| records.push(record))?;
    if !status.sealed {
        return Err(AuditError::Unsealed);
    }
    Ok(records)
}

/// Reads every authenticated record of an audit file, sealed or not, with its
/// verification status. Callers must check `sealed` before treating the
/// records as a complete run.
///
/// # Errors
///
/// Returns the first malformed or unauthenticated record as an error.
pub fn read_verified_prefix(
    path: &Path,
    run_key: &RunKey,
) -> Result<(Vec<AuditRecord>, VerificationStatus), AuditError> {
    let mut records = Vec::new();
    let status = walk_verified_file(path, run_key, |record| records.push(record))?;
    Ok((records, status))
}

fn walk_verified_file(
    path: &Path,
    run_key: &RunKey,
    mut accept: impl FnMut(AuditRecord),
) -> Result<VerificationStatus, AuditError> {
    let file = File::open(path).map_err(|error| AuditError::Io(error.to_string()))?;
    let mut previous = [0_u8; 32];
    let mut expected_seq = 0_u64;
    let mut logical_records = 0_u64;
    let mut expected_run_id: Option<String> = None;
    let mut sealed = false;
    for line in BufReader::new(file).lines() {
        if sealed {
            return Err(AuditError::SealNotTerminal);
        }
        let line = line.map_err(|error| AuditError::Io(error.to_string()))?;
        let record: AuditRecord = serde_json::from_str(&line)
            .map_err(|error| AuditError::Serialization(error.to_string()))?;
        if record.seq != expected_seq {
            return Err(AuditError::Sequence {
                expected: expected_seq,
                actual: record.seq,
            });
        }
        if let Some(run_id) = &expected_run_id {
            if record.run_id != *run_id {
                return Err(AuditError::RunIdChanged);
            }
        } else {
            expected_run_id = Some(record.run_id.clone());
        }
        if decode_hex::<32>(&record.previous_hash, "previous hash")? != previous {
            return Err(AuditError::BrokenChain(record.seq));
        }
        let actual_hash =
            calculate_record_hash(record.seq, &record.run_id, &previous, &record.payload)?;
        if decode_hex::<32>(&record.record_hash, "record hash")? != actual_hash {
            return Err(AuditError::RecordHash(record.seq));
        }
        if record.mac.len() == 64 {
            return Err(AuditError::LegacySignature(record.seq));
        }
        UnparsedPublicKey::new(&ED25519, run_key.public)
            .verify(
                &signature_message(record.seq, &actual_hash),
                &decode_hex::<64>(&record.mac, "record signature")?,
            )
            .map_err(|_| AuditError::Mac(record.seq))?;
        let is_seal = record.payload.event == SEAL_EVENT;
        if is_seal {
            if record.payload.action_id.is_some()
                || record.payload.fields.len() != 2
                || record.payload.fields.get("records") != Some(&logical_records.to_string())
                || record.payload.fields.get("tip") != Some(&record.previous_hash)
            {
                return Err(AuditError::InvalidSeal(record.seq));
            }
            sealed = true;
        } else {
            logical_records = logical_records
                .checked_add(1)
                .ok_or(AuditError::SequenceOverflow)?;
            accept(record.clone());
        }
        previous = actual_hash;
        expected_seq = expected_seq
            .checked_add(1)
            .ok_or(AuditError::SequenceOverflow)?;
    }
    Ok(VerificationStatus {
        records: logical_records,
        sealed,
    })
}

fn calculate_record_hash(
    seq: u64,
    run_id: &str,
    previous: &[u8; 32],
    payload: &AuditPayload,
) -> Result<[u8; 32], AuditError> {
    let payload = serde_json::to_vec(payload)
        .map_err(|error| AuditError::Serialization(error.to_string()))?;
    let mut framed =
        Vec::with_capacity(HASH_DOMAIN.len() + 8 + 8 + run_id.len() + 32 + 8 + payload.len());
    framed.extend_from_slice(HASH_DOMAIN);
    framed.extend_from_slice(&seq.to_be_bytes());
    framed.extend_from_slice(&(run_id.len() as u64).to_be_bytes());
    framed.extend_from_slice(run_id.as_bytes());
    framed.extend_from_slice(previous);
    framed.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    framed.extend_from_slice(&payload);
    let hash = digest(&SHA256, &framed);
    let mut bytes = [0_u8; 32];
    bytes.copy_from_slice(hash.as_ref());
    Ok(bytes)
}

fn signature_message(seq: u64, record_hash: &[u8; 32]) -> Vec<u8> {
    let mut message = Vec::with_capacity(SIGNATURE_DOMAIN.len() + 8 + record_hash.len());
    message.extend_from_slice(SIGNATURE_DOMAIN);
    message.extend_from_slice(&seq.to_be_bytes());
    message.extend_from_slice(record_hash);
    message
}

fn calculate_mac(
    run_key: &RunKey,
    seq: u64,
    record_hash: &[u8; 32],
) -> Result<[u8; 64], AuditError> {
    let signing = run_key
        .signing
        .as_ref()
        .ok_or(AuditError::SigningKeyUnavailable)?;
    let signature = signing.sign(&signature_message(seq, record_hash));
    let mut bytes = [0_u8; 64];
    bytes.copy_from_slice(signature.as_ref());
    Ok(bytes)
}

fn open_new(path: &Path) -> Result<File, AuditError> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .map_err(|error| AuditError::Io(error.to_string()))
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn decode_hex<const N: usize>(value: &str, label: &str) -> Result<[u8; N], AuditError> {
    if value.len() != N * 2 {
        return Err(AuditError::InvalidHex(label.to_owned()));
    }
    let mut output = [0_u8; N];
    for (index, byte) in output.iter_mut().enumerate() {
        let offset = index * 2;
        *byte = u8::from_str_radix(&value[offset..offset + 2], 16)
            .map_err(|_| AuditError::InvalidHex(label.to_owned()))?;
    }
    Ok(output)
}

/// Audit writer or verifier error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuditError {
    /// A redaction value was empty.
    InvalidRedaction,
    /// Run identifier was empty or contained controls.
    InvalidRunId,
    /// Operating-system randomness was unavailable.
    RandomUnavailable,
    /// An Ed25519 signing seed was rejected.
    InvalidSigningKey,
    /// A public-only verification key was passed to the writer.
    SigningKeyUnavailable,
    /// Filesystem operation failed.
    Io(String),
    /// JSON encoding or decoding failed.
    Serialization(String),
    /// Writer thread or response channel is unavailable.
    WriterUnavailable,
    /// Writer thread panicked.
    WriterPanicked,
    /// A fixed-size hexadecimal field was malformed.
    InvalidHex(String),
    /// Record sequence was discontinuous.
    Sequence {
        /// Required next sequence.
        expected: u64,
        /// Sequence found in the file.
        actual: u64,
    },
    /// Run identifier changed within one file.
    RunIdChanged,
    /// Previous-hash link was invalid.
    BrokenChain(u64),
    /// Record content digest was invalid.
    RecordHash(u64),
    /// Record signature was invalid.
    Mac(u64),
    /// Record uses Keel's retired 32-byte MAC format.
    LegacySignature(u64),
    /// The stream ended without a signed terminal seal.
    Unsealed,
    /// A seal contained an invalid count, tip, or shape.
    InvalidSeal(u64),
    /// Records appeared after the terminal seal.
    SealNotTerminal,
    /// Sequence counter overflowed.
    SequenceOverflow,
}

impl fmt::Display for AuditError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRedaction => formatter.write_str("redaction values cannot be empty"),
            Self::InvalidRunId => formatter.write_str("invalid audit run identifier"),
            Self::RandomUnavailable => formatter.write_str("audit randomness unavailable"),
            Self::InvalidSigningKey => formatter.write_str("invalid audit signing key"),
            Self::SigningKeyUnavailable => formatter.write_str("audit signing key unavailable"),
            Self::Io(error) => write!(formatter, "audit I/O failed: {error}"),
            Self::Serialization(error) => write!(formatter, "audit JSON failed: {error}"),
            Self::WriterUnavailable => formatter.write_str("audit writer unavailable"),
            Self::WriterPanicked => formatter.write_str("audit writer panicked"),
            Self::InvalidHex(label) => write!(formatter, "invalid hexadecimal {label}"),
            Self::Sequence { expected, actual } => {
                write!(
                    formatter,
                    "audit sequence discontinuity: expected {expected}, got {actual}"
                )
            }
            Self::RunIdChanged => formatter.write_str("audit run identifier changed"),
            Self::BrokenChain(seq) => write!(formatter, "broken audit chain at record {seq}"),
            Self::RecordHash(seq) => write!(formatter, "invalid record hash at record {seq}"),
            Self::Mac(seq) => write!(formatter, "invalid record signature at record {seq}"),
            Self::LegacySignature(seq) => write!(
                formatter,
                "legacy audit signature at record {seq}; verify with the Keel version that created it"
            ),
            Self::Unsealed => {
                formatter.write_str("audit stream is incomplete: terminal seal missing")
            }
            Self::InvalidSeal(seq) => write!(formatter, "invalid audit seal at record {seq}"),
            Self::SealNotTerminal => formatter.write_str("audit seal is not the terminal record"),
            Self::SequenceOverflow => formatter.write_str("audit sequence overflow"),
        }
    }
}

impl Error for AuditError {}

#[cfg(test)]
mod tests {
    use super::{
        AuditError, AuditPayload, AuditRecord, AuditSink as _, AuditWriter, KernelAudit, Redactor,
        RunKey, verify_file,
    };
    use keel_kernel::{
        ActionClass, AuditEvent, AuditOutcome, DenialTelemetry, EnforcementBoundary,
        EnforcementState, EnforcementStateEvent, ModelReservationEvent, ModelReservationId,
        ModelReservationOutcome, PrincipalId,
    };
    use keel_provenance::{DenialOrigin, DenialScope};
    use std::{
        collections::BTreeMap,
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    #[test]
    fn writer_redacts_and_verifier_accepts_complete_chain() {
        let path = scratch_file("valid");
        let redactor = Redactor::new(["real-secret", "sentinel-secret"]).expect("redactor");
        assert_eq!(redactor.redact("cmVhbC1zZWNyZXQ="), super::REDACTED);
        let writer =
            AuditWriter::spawn(&path, "run-1", RunKey::new([7; 32]), redactor).expect("writer");
        writer
            .record(payload("request", "token=real-secret"))
            .expect("first record");
        writer
            .record(payload("response", "token=sentinel-secret"))
            .expect("second record");
        writer.shutdown().expect("clean shutdown");

        assert_eq!(
            verify_file(&path, &RunKey::new([7; 32])).expect("valid chain"),
            2
        );
        let contents = fs::read_to_string(&path).expect("audit contents");
        assert!(!contents.contains("real-secret"));
        assert!(!contents.contains("sentinel-secret"));
        assert!(contents.contains("[REDACTED]"));
        fs::remove_file(path).expect("remove audit");
    }

    #[test]
    fn verifier_rejects_tampered_payload_and_wrong_key() {
        let path = scratch_file("tampered");
        let writer = AuditWriter::spawn(
            &path,
            "run-2",
            RunKey::new([9; 32]),
            Redactor::new(Vec::<String>::new()).expect("redactor"),
        )
        .expect("writer");
        writer
            .record(payload("execute", "original"))
            .expect("record");
        writer.shutdown().expect("clean shutdown");

        assert_eq!(
            verify_file(&path, &RunKey::new([8; 32])),
            Err(AuditError::Mac(0))
        );

        let contents = fs::read_to_string(&path).expect("read record");
        let mut lines = contents.lines().map(str::to_owned).collect::<Vec<_>>();
        let mut record: AuditRecord = serde_json::from_str(&lines[0]).expect("parse record");
        record
            .payload
            .fields
            .insert("detail".to_owned(), "changed".to_owned());
        lines[0] = serde_json::to_string(&record).expect("serialize");
        fs::write(&path, format!("{}\n", lines.join("\n"))).expect("tamper record");

        assert_eq!(
            verify_file(&path, &RunKey::new([9; 32])),
            Err(AuditError::RecordHash(0))
        );
        fs::remove_file(path).expect("remove audit");
    }

    #[test]
    fn verifier_rejects_a_valid_prefix_without_its_terminal_seal() {
        let path = scratch_file("truncated");
        let writer = AuditWriter::spawn(
            &path,
            "run-truncated",
            RunKey::new([11; 32]),
            Redactor::new(Vec::<String>::new()).expect("redactor"),
        )
        .expect("writer");
        writer
            .record(payload("execute", "complete"))
            .expect("record");
        writer.shutdown().expect("shutdown");

        let contents = fs::read_to_string(&path).expect("read chain");
        let first = contents.lines().next().expect("event record");
        fs::write(&path, format!("{first}\n")).expect("truncate seal");
        assert_eq!(
            verify_file(&path, &RunKey::new([11; 32])),
            Err(AuditError::Unsealed)
        );
        fs::remove_file(path).expect("remove audit");
    }

    #[test]
    fn writer_refuses_to_replace_an_existing_chain() {
        let path = scratch_file("existing");
        fs::write(&path, "existing").expect("create existing path");
        let result = AuditWriter::spawn(
            &path,
            "run-3",
            RunKey::new([3; 32]),
            Redactor::new(Vec::<String>::new()).expect("redactor"),
        );
        assert!(matches!(result, Err(AuditError::Io(_))));
        fs::remove_file(path).expect("remove audit");
    }

    #[test]
    fn generated_run_key_writes_only_a_public_verifier() {
        let path = scratch_file("run-key");
        let key = RunKey::generate().expect("generate key");
        key.write_new(&path).expect("write key");
        let encoded = fs::read_to_string(&path).expect("read key");
        assert_eq!(encoded.trim().len(), 64);
        let public_only = RunKey::from_hex(&encoded).expect("parse generated key");
        let audit_path = scratch_file("public-key-cannot-sign");
        let writer = AuditWriter::spawn(
            &audit_path,
            "verify-only",
            public_only,
            Redactor::new(Vec::<String>::new()).expect("redactor"),
        )
        .expect("writer thread");
        assert_eq!(
            writer.record(payload("request", "not signable")),
            Err(AuditError::SigningKeyUnavailable)
        );
        assert_eq!(writer.shutdown(), Err(AuditError::SigningKeyUnavailable));
        assert!(matches!(key.write_new(&path), Err(AuditError::Io(_))));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            assert_eq!(
                fs::metadata(&path)
                    .expect("key metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        fs::remove_file(audit_path).expect("remove audit");
        fs::remove_file(path).expect("remove key");
    }

    /// The enforcement record describes the boundaries rather than their
    /// contents, but it is written by the same path as every other record, so
    /// redaction has to hold for it too — a host list is the one field where an
    /// operator could plausibly put a credential-bearing name.
    #[test]
    fn an_enforcement_state_record_is_redacted_and_chain_verifiable() {
        let path = scratch_file("enforcement");
        let mut audit = KernelAudit::new(
            AuditWriter::spawn(
                &path,
                "run-4",
                RunKey::new([5; 32]),
                Redactor::new(["real-secret"]).expect("redactor"),
            )
            .expect("writer"),
        );
        assert!(audit.is_durable());
        audit
            .record_enforcement_state(EnforcementStateEvent {
                phase: "start",
                boundaries: vec![
                    EnforcementBoundary {
                        name: "egress-allowlist",
                        state: EnforcementState::Active,
                        detail: "hosts=1 [real-secret.example]".to_owned(),
                    },
                    EnforcementBoundary {
                        name: "audit-chain",
                        state: EnforcementState::Absent,
                        detail: "signed hash chain with terminal seal".to_owned(),
                    },
                ],
            })
            .expect("record enforcement state");
        audit.shutdown().expect("clean shutdown");

        assert_eq!(
            verify_file(&path, &RunKey::new([5; 32])).expect("valid chain"),
            1
        );
        let contents = fs::read_to_string(&path).expect("audit contents");
        assert!(!contents.contains("real-secret"));
        assert!(contents.contains("kernel.enforcement-state"));
        assert!(contents.contains("boundary.egress-allowlist"));
        assert!(contents.contains("active: hosts=1 [[REDACTED].example]"));
        assert!(contents.contains("absent: signed hash chain with terminal seal"));
        assert!(!audit.is_durable());
        fs::remove_file(path).expect("remove audit");
    }

    #[test]
    fn denied_action_records_typed_opaque_scope_metadata() {
        let path = scratch_file("denial-telemetry");
        let mut audit = KernelAudit::new(
            AuditWriter::spawn(
                &path,
                "run-denial",
                RunKey::new([17; 32]),
                Redactor::new(Vec::<String>::new()).expect("redactor"),
            )
            .expect("writer"),
        );
        audit
            .record(AuditEvent {
                action_id: 41,
                principal: PrincipalId::new("vertex-1").expect("principal"),
                class: ActionClass::Egress,
                target_kind: "network",
                target_hash: [0x11; 32],
                outcome: AuditOutcome::Denied,
                intent: "inside",
                flow: "clean".to_owned(),
                origin: None,
                integrity: None,
                rules: vec!["repeated-denials-same-scope".to_owned()],
                gate: None,
                denial: Some(DenialTelemetry {
                    origin: DenialOrigin::Operator,
                    scope: DenialScope::from_digest([0xab; 32]),
                    counted_for_repeated_review: true,
                    recent_behavioral_denials_in_scope: 3,
                }),
            })
            .expect("record denial");
        audit.shutdown().expect("clean shutdown");

        let records = read_records(&path);
        assert_eq!(records[0].payload.event, "kernel.action");
        assert_eq!(
            records[0]
                .payload
                .fields
                .get("denial_origin")
                .map(String::as_str),
            Some("operator")
        );
        assert_eq!(
            records[0]
                .payload
                .fields
                .get("denial_scope")
                .map(String::as_str),
            Some("abababababababababababababababababababababababababababababababab")
        );
        assert_eq!(
            records[0]
                .payload
                .fields
                .get("denial_counted_for_repeated_review")
                .map(String::as_str),
            Some("true")
        );
        assert_eq!(
            records[0]
                .payload
                .fields
                .get("denial_recent_behavioral_denials_in_scope")
                .map(String::as_str),
            Some("3")
        );
        assert!(
            records[0]
                .payload
                .fields
                .values()
                .all(|value| !value.contains("host.example"))
        );
        fs::remove_file(path).expect("remove audit");
    }

    #[test]
    fn model_reservation_records_terminal_outcomes_without_response_content() {
        let path = scratch_file("model-reservation");
        let mut audit = KernelAudit::new(
            AuditWriter::spawn(
                &path,
                "run-reservation",
                RunKey::new([19; 32]),
                Redactor::new(Vec::<String>::new()).expect("redactor"),
            )
            .expect("writer"),
        );
        audit
            .record_model_reservation(ModelReservationEvent {
                reservation_id: ModelReservationId::from_run_local(7),
                action_id: 51,
                outcome: ModelReservationOutcome::ReleasedUnsent,
                reserved_tokens: 4_096,
                reserved_cost_microusd: 12_500,
                actual_tokens: None,
                actual_cost_microusd: None,
            })
            .expect("record unsent release");
        audit
            .record_model_reservation(ModelReservationEvent {
                reservation_id: ModelReservationId::from_run_local(8),
                action_id: 52,
                outcome: ModelReservationOutcome::SettledActual,
                reserved_tokens: 8_192,
                reserved_cost_microusd: 25_000,
                actual_tokens: Some(1_234),
                actual_cost_microusd: Some(5_678),
            })
            .expect("record actual settlement");
        audit.shutdown().expect("clean shutdown");

        let records = read_records(&path);
        let unsent = &records[0].payload;
        assert_eq!(unsent.event, "kernel.model-reservation");
        assert_eq!(unsent.action_id, Some(51));
        assert_eq!(
            unsent.fields.get("reservation_id").map(String::as_str),
            Some("7")
        );
        assert_eq!(
            unsent.fields.get("outcome").map(String::as_str),
            Some("released-unsent")
        );
        assert!(!unsent.fields.contains_key("actual_tokens"));
        assert!(!unsent.fields.contains_key("actual_cost_microusd"));

        let settled = &records[1].payload;
        assert_eq!(settled.event, "kernel.model-reservation");
        assert_eq!(settled.action_id, Some(52));
        assert_eq!(
            settled.fields.get("outcome").map(String::as_str),
            Some("settled-actual")
        );
        assert_eq!(
            settled.fields.get("actual_tokens").map(String::as_str),
            Some("1234")
        );
        assert_eq!(
            settled
                .fields
                .get("actual_cost_microusd")
                .map(String::as_str),
            Some("5678")
        );
        for record in records.iter().take(2) {
            assert!(!record.payload.fields.contains_key("response"));
            assert!(!record.payload.fields.contains_key("body"));
            assert!(!record.payload.fields.contains_key("content"));
        }
        fs::remove_file(path).expect("remove audit");
    }

    fn payload(event: &str, detail: &str) -> AuditPayload {
        AuditPayload {
            timestamp_ms: 1,
            event: event.to_owned(),
            action_id: Some(1),
            fields: BTreeMap::from([("detail".to_owned(), detail.to_owned())]),
        }
    }

    fn read_records(path: &PathBuf) -> Vec<AuditRecord> {
        fs::read_to_string(path)
            .expect("audit contents")
            .lines()
            .map(|line| serde_json::from_str(line).expect("audit record"))
            .collect()
    }

    fn scratch_file(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("keel-audit-{label}-{}-{nonce}", std::process::id()))
    }
}
