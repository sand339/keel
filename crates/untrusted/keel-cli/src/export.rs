//! Exports sessions as OpenTelemetry traces (OTLP/JSON).
//!
//! Each run is one trace. The audit chain is authenticated before anything is
//! read from it, and the export says whether the chain was sealed. The run is
//! the root span; mediated actions and model requests are its children; floor
//! changes and enforcement state are events on it. The guest's own account of
//! its processes and file writes, when recorded, becomes process spans marked
//! `keel.trust = guest-claim`: they come from the guest, not the kernel, and
//! are not covered by the audit chain (PLAN D68).

use crate::{CliError, session_directory, validate_session_id};
use keel_audit::{AuditRecord, RunKey, read_verified_prefix};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, HashMap},
    ffi::OsStr,
    fs,
    io::{Read as _, Write as _},
    net::TcpStream,
    path::{Path, PathBuf},
    time::Duration,
};

/// Default OTLP/HTTP path for traces.
const TRACES_PATH: &str = "/v1/traces";
const SPAN_KIND_INTERNAL: u8 = 1;
const STATUS_OK: u8 = 1;
const STATUS_ERROR: u8 = 2;

/// Builds one OTLP/JSON document holding every run of the given sessions.
///
/// # Errors
///
/// Returns an error when a session has no authenticated audit chain or a chain
/// fails authentication.
pub fn export_sessions(sessions: &[String]) -> Result<Value, CliError> {
    let mut resource_spans = Vec::new();
    for session in sessions {
        validate_session_id(session)?;
        let directory = session_directory(session)?;
        let chains = audit_chains(&directory)?;
        if chains.is_empty() {
            return Err(CliError::new(format!(
                "{} holds no authenticated audit chain",
                directory.display()
            )));
        }
        for chain in chains {
            resource_spans.push(export_run(session, &chain)?);
        }
    }
    Ok(json!({ "resourceSpans": resource_spans }))
}

/// Sends an OTLP/JSON document to an OTLP/HTTP collector, for example
/// `http://localhost:4318`.
///
/// # Errors
///
/// Returns an error for a non-`http` URL, a connection failure, or a
/// non-success response.
pub fn send_otlp(endpoint: &str, document: &Value) -> Result<(), CliError> {
    let rest = endpoint.strip_prefix("http://").ok_or_else(|| {
        CliError::new("--otlp takes an http:// collector URL, such as http://localhost:4318")
    })?;
    let (authority, path) = rest
        .split_once('/')
        .map_or((rest, TRACES_PATH.to_owned()), |(authority, path)| {
            (authority, format!("/{path}"))
        });
    let path = if path == "/" {
        TRACES_PATH.to_owned()
    } else {
        path
    };
    let address = if authority.contains(':') {
        authority.to_owned()
    } else {
        format!("{authority}:80")
    };
    let body = serde_json::to_vec(document).map_err(|error| CliError::new(error.to_string()))?;
    let io = |error: std::io::Error| CliError::new(format!("{endpoint}: {error}"));
    let mut stream = TcpStream::connect(&address).map_err(io)?;
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .map_err(io)?;
    write!(
        stream,
        "POST {path} HTTP/1.1\r\nHost: {authority}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .map_err(io)?;
    stream.write_all(&body).map_err(io)?;
    let mut response = Vec::new();
    stream
        .take(64 * 1024)
        .read_to_end(&mut response)
        .map_err(io)?;
    let response = String::from_utf8_lossy(&response);
    let status = response.lines().next().unwrap_or_default();
    if status
        .split_whitespace()
        .nth(1)
        .is_some_and(|code| code.starts_with('2'))
    {
        Ok(())
    } else {
        Err(CliError::new(format!(
            "{endpoint} refused the export: {}",
            if status.is_empty() {
                "no response"
            } else {
                status
            }
        )))
    }
}

/// Every authenticated chain in a session directory, oldest first.
fn audit_chains(directory: &Path) -> Result<Vec<PathBuf>, CliError> {
    let entries = fs::read_dir(directory)
        .map_err(|error| CliError::new(format!("cannot read {}: {error}", directory.display())))?;
    let mut chains = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(OsStr::to_str)
                .is_some_and(|name| name.starts_with("audit-") && name.ends_with(".ndjson"))
                && path.with_extension("key").exists()
        })
        .map(|path| {
            let modified = fs::metadata(&path)
                .and_then(|metadata| metadata.modified())
                .ok();
            (modified, path)
        })
        .collect::<Vec<_>>();
    chains.sort();
    Ok(chains.into_iter().map(|(_, path)| path).collect())
}

fn export_run(session: &str, audit: &Path) -> Result<Value, CliError> {
    let key_path = audit.with_extension("key");
    let key = fs::read_to_string(&key_path)
        .map_err(|error| CliError::new(format!("cannot read {}: {error}", key_path.display())))?;
    let key = RunKey::from_hex(&key).map_err(|error| CliError::new(error.to_string()))?;
    let (records, status) = read_verified_prefix(audit, &key)
        .map_err(|error| CliError::new(format!("{}: {error}", audit.display())))?;
    let guest = guest_events_path(audit)
        .and_then(|path| fs::read_to_string(path).ok())
        .unwrap_or_default();
    Ok(build_run(session, &records, status.sealed, &guest))
}

/// `audit-X.ndjson` pairs with `guest-X.ndjson` in the same directory.
fn guest_events_path(audit: &Path) -> Option<PathBuf> {
    let name = audit.file_name()?.to_str()?;
    Some(audit.with_file_name(name.replacen("audit-", "guest-", 1)))
}

/// Builds one run's resource spans from its authenticated records and the
/// guest's recorded events.
#[must_use]
#[allow(clippy::too_many_lines)] // one pass over the records, one arm per event
pub fn build_run(session: &str, records: &[AuditRecord], sealed: bool, guest: &str) -> Value {
    let run_id = records
        .first()
        .map_or_else(|| session.to_owned(), |record| record.run_id.clone());
    let trace_id = format!(
        "{:016x}{:016x}",
        fnv(&run_id),
        fnv(&format!("{run_id}#trace"))
    );
    let root_id = span_id(&run_id, "run");
    let start = records
        .first()
        .map_or(0, |record| record.payload.timestamp_ms);
    let mut end = records
        .last()
        .map_or(start, |record| record.payload.timestamp_ms);
    let mut root_attributes = vec![
        attribute("keel.session", session),
        attribute("keel.run_id", &run_id),
        attribute("keel.audit.sealed", sealed),
        attribute("keel.audit.records", records.len()),
    ];
    let mut root_events = Vec::new();
    let mut spans = Vec::new();
    for record in records {
        let payload = &record.payload;
        let at = payload.timestamp_ms;
        match payload.event.as_str() {
            "kernel.action" => {
                let fields = &payload.fields;
                let waited = fields
                    .get("gate_time_ms")
                    .and_then(|value| value.parse::<u64>().ok())
                    .unwrap_or(0);
                let class = fields.get("action_class").map_or("unknown", String::as_str);
                let outcome = fields.get("outcome").map_or("", String::as_str);
                let failed = matches!(outcome, "denied" | "execution-failed");
                let mut attributes = field_attributes(fields);
                if let Some(action) = payload.action_id {
                    attributes.push(attribute("keel.action_id", action));
                }
                spans.push(span(
                    &trace_id,
                    &span_id(&run_id, &format!("action-{}", record.seq)),
                    Some(&root_id),
                    &format!("keel.action {class}"),
                    (at.saturating_sub(waited), at),
                    attributes,
                    Vec::new(),
                    if failed { STATUS_ERROR } else { STATUS_OK },
                ));
            }
            "kernel.model-reservation" | "kernel.model-usage" => {
                spans.push(span(
                    &trace_id,
                    &span_id(&run_id, &format!("model-{}", record.seq)),
                    Some(&root_id),
                    "keel.model.request",
                    (at, at),
                    field_attributes(&payload.fields),
                    Vec::new(),
                    if payload
                        .fields
                        .get("outcome")
                        .is_some_and(|outcome| outcome == "overrun")
                    {
                        STATUS_ERROR
                    } else {
                        STATUS_OK
                    },
                ));
            }
            "kernel.run-admitted" => {
                root_attributes.extend(manifest_attributes(&payload.fields));
                root_events.push(event(at, "keel.run-admitted", Vec::new()));
            }
            "audit.sealed" => {}
            other => root_events.push(event(at, other, field_attributes(&payload.fields))),
        }
    }
    let (guest_spans, guest_events, guest_end) = guest_spans(&trace_id, &run_id, &root_id, guest);
    spans.extend(guest_spans);
    root_events.extend(guest_events);
    end = end.max(guest_end);
    spans.insert(
        0,
        span(
            &trace_id,
            &root_id,
            None,
            "keel.run",
            (start, end),
            root_attributes,
            root_events,
            STATUS_OK,
        ),
    );
    json!({
        "resource": { "attributes": [
            attribute("service.name", "keel"),
            attribute("service.version", env!("CARGO_PKG_VERSION")),
        ] },
        "scopeSpans": [{
            "scope": { "name": "keel", "version": env!("CARGO_PKG_VERSION") },
            "spans": spans,
        }],
    })
}

/// Process spans from the guest's events, parented by the process tree where
/// the parent was seen, and the latest event time.
#[allow(clippy::too_many_lines)] // decodes, then links, the guest's process tree
fn guest_spans(
    trace_id: &str,
    run_id: &str,
    root_id: &str,
    guest: &str,
) -> (Vec<Value>, Vec<Value>, u64) {
    struct Process {
        start: u64,
        end: Option<u64>,
        ppid: u32,
        attributes: Vec<Value>,
        writes: Vec<Value>,
        code: Option<i64>,
        id: String,
    }
    let mut processes: BTreeMap<u32, Vec<Process>> = BTreeMap::new();
    let mut root_events = Vec::new();
    let mut last = 0;
    for line in guest.lines() {
        let Ok(value) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        let at = value["received_ms"].as_u64().unwrap_or(0);
        last = last.max(at);
        let pid = value["pid"]
            .as_u64()
            .and_then(|pid| u32::try_from(pid).ok());
        match (value["kind"].as_str(), pid) {
            (Some("exec"), Some(pid)) => {
                let argv = value["argv"]
                    .as_array()
                    .map(|argv| {
                        argv.iter()
                            .filter_map(Value::as_str)
                            .collect::<Vec<_>>()
                            .join(" ")
                    })
                    .unwrap_or_default();
                let exe = value["exe"].as_str().unwrap_or_default();
                let generation = processes.get(&pid).map_or(0, Vec::len);
                processes.entry(pid).or_default().push(Process {
                    start: at,
                    end: None,
                    ppid: value["ppid"]
                        .as_u64()
                        .and_then(|ppid| u32::try_from(ppid).ok())
                        .unwrap_or_default(),
                    attributes: vec![
                        attribute("keel.trust", "guest-claim"),
                        attribute("guest.pid", u64::from(pid)),
                        attribute("guest.exe", exe),
                        attribute("guest.argv", argv.as_str()),
                        attribute("guest.cwd", value["cwd"].as_str().unwrap_or_default()),
                        attribute(
                            "guest.workspace_code",
                            value["workspace_code"].as_bool().unwrap_or(false),
                        ),
                    ],
                    writes: Vec::new(),
                    code: None,
                    id: span_id(run_id, &format!("guest-{pid}-{generation}-{at}")),
                });
            }
            (Some("exit"), Some(pid)) => {
                if let Some(process) = processes.get_mut(&pid).and_then(|list| list.last_mut())
                    && process.end.is_none()
                {
                    process.end = Some(at);
                    process.code = value["code"].as_i64();
                }
            }
            (Some("file-write"), Some(pid)) => {
                let write = event(
                    at,
                    "guest.file-write",
                    vec![
                        attribute("keel.trust", "guest-claim"),
                        attribute("guest.path", value["path"].as_str().unwrap_or_default()),
                        attribute("guest.pid", u64::from(pid)),
                    ],
                );
                match processes.get_mut(&pid).and_then(|list| list.last_mut()) {
                    Some(process) => process.writes.push(write),
                    None => root_events.push(write),
                }
            }
            (Some("dropped"), _) => root_events.push(event(
                at,
                "guest.events-dropped",
                vec![attribute(
                    "guest.count",
                    value["count"].as_u64().unwrap_or(0),
                )],
            )),
            _ => {}
        }
    }
    // A process's parent is the latest exec of its parent pid that began
    // no later than it did.
    let parents: HashMap<(u32, u64), String> = processes
        .iter()
        .flat_map(|(pid, list)| {
            list.iter()
                .map(move |process| ((*pid, process.start), process.id.clone()))
        })
        .collect();
    let mut spans = Vec::new();
    for (pid, list) in &processes {
        for process in list {
            let parent = parents
                .iter()
                .filter(|((candidate, started), _)| {
                    *candidate == process.ppid && *started <= process.start && candidate != pid
                })
                .max_by_key(|((_, started), _)| *started)
                .map_or(root_id, |(_, id)| id.as_str());
            let exe = process
                .attributes
                .iter()
                .find(|attribute| attribute["key"] == "guest.exe")
                .and_then(|attribute| attribute["value"]["stringValue"].as_str())
                .unwrap_or_default();
            let name = Path::new(exe)
                .file_name()
                .and_then(OsStr::to_str)
                .unwrap_or(exe);
            let mut attributes = process.attributes.clone();
            if let Some(code) = process.code {
                attributes.push(attribute("guest.exit_code", code));
            }
            spans.push(span(
                trace_id,
                &process.id,
                Some(parent),
                &format!("guest.process {name}"),
                (
                    process.start,
                    process.end.unwrap_or(last).max(process.start),
                ),
                attributes,
                process.writes.clone(),
                if process.code.is_some_and(|code| code != 0) {
                    STATUS_ERROR
                } else {
                    STATUS_OK
                },
            ));
        }
    }
    (spans, root_events, last)
}

fn manifest_attributes(fields: &BTreeMap<String, String>) -> Vec<Value> {
    let mut attributes = Vec::new();
    if let Some(digest) = fields.get("manifest_sha256") {
        attributes.push(attribute("keel.manifest_sha256", digest.as_str()));
    }
    let Some(manifest) = fields
        .get("manifest")
        .and_then(|manifest| serde_json::from_str::<Value>(manifest).ok())
    else {
        return attributes;
    };
    for (key, pointer) in [
        ("keel.run.harness", "/run/harness"),
        ("keel.run.isolation", "/run/isolation"),
        ("keel.run.provenance_mode", "/run/provenance_mode"),
        ("keel.model.provider", "/model/provider"),
        ("keel.model.host", "/model/host"),
        ("keel.model.name", "/model/model"),
        ("keel.profile", "/authority/profile"),
        ("keel.build", "/keel_build"),
    ] {
        if let Some(value) = manifest.pointer(pointer) {
            match value {
                Value::String(text) => attributes.push(attribute(key, text.as_str())),
                Value::Bool(flag) => attributes.push(attribute(key, *flag)),
                Value::Number(number) => {
                    attributes.push(attribute(key, number.to_string().as_str()));
                }
                _ => {}
            }
        }
    }
    attributes
}

fn field_attributes(fields: &BTreeMap<String, String>) -> Vec<Value> {
    fields
        .iter()
        .map(|(key, value)| attribute(&format!("keel.{key}"), value.as_str()))
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn span(
    trace_id: &str,
    id: &str,
    parent: Option<&str>,
    name: &str,
    (start_ms, end_ms): (u64, u64),
    attributes: Vec<Value>,
    events: Vec<Value>,
    status: u8,
) -> Value {
    let mut span = json!({
        "traceId": trace_id,
        "spanId": id,
        "name": name,
        "kind": SPAN_KIND_INTERNAL,
        "startTimeUnixNano": nanos(start_ms),
        "endTimeUnixNano": nanos(end_ms.max(start_ms)),
        "attributes": Value::Array(attributes),
        "events": Value::Array(events),
        "status": { "code": status },
    });
    if let Some(parent) = parent {
        span["parentSpanId"] = json!(parent);
    }
    span
}

fn event(at_ms: u64, name: &str, attributes: Vec<Value>) -> Value {
    json!({ "timeUnixNano": nanos(at_ms), "name": name, "attributes": Value::Array(attributes) })
}

fn nanos(milliseconds: u64) -> String {
    (u128::from(milliseconds) * 1_000_000).to_string()
}

trait AttributeValue {
    fn otlp(self) -> Value;
}

impl AttributeValue for &str {
    fn otlp(self) -> Value {
        json!({ "stringValue": self })
    }
}

impl AttributeValue for &String {
    fn otlp(self) -> Value {
        json!({ "stringValue": self })
    }
}

impl AttributeValue for bool {
    fn otlp(self) -> Value {
        json!({ "boolValue": self })
    }
}

impl AttributeValue for u64 {
    fn otlp(self) -> Value {
        json!({ "intValue": self.to_string() })
    }
}

impl AttributeValue for i64 {
    fn otlp(self) -> Value {
        json!({ "intValue": self.to_string() })
    }
}

impl AttributeValue for usize {
    fn otlp(self) -> Value {
        json!({ "intValue": self.to_string() })
    }
}

fn attribute(key: &str, value: impl AttributeValue) -> Value {
    json!({ "key": key, "value": value.otlp() })
}

fn span_id(run_id: &str, label: &str) -> String {
    format!("{:016x}", fnv(&format!("{run_id}/{label}")))
}

/// FNV-1a: stable, so exporting a run twice gives the same span ids.
fn fnv(text: &str) -> u64 {
    text.bytes().fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Command, parse_args};
    use std::ffi::OsString;

    fn record(seq: u64, at: u64, event: &str, fields: &[(&str, &str)]) -> AuditRecord {
        serde_json::from_value(json!({
            "seq": seq,
            "run_id": "run-1",
            "previous_hash": "",
            "payload": {
                "timestamp_ms": at,
                "event": event,
                "action_id": (event == "kernel.action").then_some(seq),
                "fields": fields.iter().copied().collect::<BTreeMap<_, _>>(),
            },
            "record_hash": "",
            "mac": "",
        }))
        .unwrap()
    }

    fn attribute_of<'a>(span: &'a Value, key: &str) -> Option<&'a Value> {
        span["attributes"]
            .as_array()?
            .iter()
            .find(|attribute| attribute["key"] == key)
            .map(|attribute| &attribute["value"])
    }

    fn fixture() -> Value {
        let manifest =
            r#"{"run":{"harness":"claude","isolation":"vm"},"model":{"provider":"bedrock"}}"#;
        let records = [
            record(
                0,
                1_000,
                "kernel.run-admitted",
                &[("manifest", manifest), ("manifest_sha256", "ab")],
            ),
            record(
                1,
                2_000,
                "kernel.action",
                &[
                    ("action_class", "egress"),
                    ("outcome", "denied"),
                    ("gate_time_ms", "500"),
                ],
            ),
            record(
                2,
                2_500,
                "kernel.model-reservation",
                &[("outcome", "settled-actual")],
            ),
            record(3, 2_600, "kernel.provenance", &[("floor_after", "0")]),
            record(4, 3_000, "audit.sealed", &[]),
        ];
        let guest = [
            r#"{"received_ms":1100,"kind":"exec","pid":10,"ppid":1,"exe":"/usr/local/bin/claude","argv":["claude"],"cwd":"/workspace","workspace_code":false}"#,
            r#"{"received_ms":1200,"kind":"exec","pid":11,"ppid":10,"exe":"/bin/bash","argv":["bash","-c","x"],"cwd":"/workspace","workspace_code":false}"#,
            r#"{"received_ms":1300,"kind":"file-write","pid":11,"path":"/workspace/note.txt"}"#,
            r#"{"received_ms":1400,"kind":"exit","pid":11,"code":2}"#,
            r#"{"received_ms":1500,"kind":"file-write","pid":99,"path":"/tmp/x"}"#,
            r#"{"received_ms":3500,"kind":"dropped","count":4}"#,
            "not json",
        ]
        .join("\n");
        let run = build_run("session-1", &records, true, &guest);
        assert_eq!(
            build_run("session-1", &records, true, &guest),
            run,
            "exports are deterministic"
        );
        run
    }

    fn named<'a>(spans: &'a [Value], prefix: &str) -> &'a Value {
        spans
            .iter()
            .find(|span| span["name"].as_str().unwrap().starts_with(prefix))
            .unwrap()
    }

    #[test]
    fn a_run_is_one_trace_with_its_actions_and_model_requests() {
        let run = fixture();
        let spans = run["scopeSpans"][0]["spans"].as_array().unwrap();
        let root = &spans[0];
        assert_eq!(root["name"], "keel.run");
        assert_eq!(
            root["endTimeUnixNano"], "3500000000",
            "guest events extend the run"
        );
        assert_eq!(
            attribute_of(root, "keel.run.harness").unwrap()["stringValue"],
            "claude"
        );
        assert_eq!(
            attribute_of(root, "keel.audit.sealed").unwrap()["boolValue"],
            true
        );
        let root_events = root["events"].as_array().unwrap();
        assert!(
            root_events
                .iter()
                .any(|event| event["name"] == "kernel.provenance")
        );
        assert!(
            root_events
                .iter()
                .any(|event| event["name"] == "guest.events-dropped")
        );
        assert!(
            root_events
                .iter()
                .any(|event| event["name"] == "guest.file-write"),
            "an unknown writer lands on the run"
        );

        let action = named(spans, "keel.action egress");
        assert_eq!(
            action["status"]["code"], STATUS_ERROR,
            "a denial is an error"
        );
        assert_eq!(
            action["startTimeUnixNano"], "1500000000",
            "the span covers the gate wait"
        );
        assert_eq!(action["parentSpanId"], root["spanId"]);
        assert_eq!(
            named(spans, "keel.model.request")["status"]["code"],
            STATUS_OK
        );
    }

    #[test]
    fn guest_processes_form_a_tree_of_claims() {
        let run = fixture();
        let spans = run["scopeSpans"][0]["spans"].as_array().unwrap();
        let root = &spans[0];
        let claude = named(spans, "guest.process claude");
        let bash = named(spans, "guest.process bash");
        assert_eq!(claude["parentSpanId"], root["spanId"]);
        assert_eq!(bash["parentSpanId"], claude["spanId"]);
        assert_eq!(bash["status"]["code"], STATUS_ERROR);
        assert_eq!(
            attribute_of(bash, "keel.trust").unwrap()["stringValue"],
            "guest-claim"
        );
        assert_eq!(bash["events"][0]["name"], "guest.file-write");
        assert_eq!(
            claude["endTimeUnixNano"], "3500000000",
            "a process never seen to exit runs to the end"
        );
    }

    #[test]
    fn export_takes_sessions_and_an_output_or_collector() {
        let parse = |arguments: &[&str]| {
            parse_args(arguments.iter().map(OsString::from).collect::<Vec<_>>())
        };
        let Command::Export {
            sessions,
            out,
            otlp,
        } = parse(&[
            "export",
            "run-1",
            "run-2",
            "--otlp",
            "http://localhost:4318",
        ])
        .unwrap()
        else {
            panic!("expected an export");
        };
        assert_eq!(sessions, ["run-1", "run-2"]);
        assert_eq!(out, None);
        assert_eq!(otlp.as_deref(), Some("http://localhost:4318"));
        assert!(parse(&["export"]).is_err());
        assert!(parse(&["export", "run-1", "--out"]).is_err());
        assert!(parse(&["export", "../escape"]).is_err());
        assert!(send_otlp("https://collector.example", &json!({})).is_err());
    }
}
