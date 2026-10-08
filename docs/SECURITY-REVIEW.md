# Security review results

Date: 2026-09-25

Scope: the complete working tree, including uncommitted and untracked files.

Method: two read-only passes with the built-in Codex CLI, followed by manual
call-path validation and regression testing. This document tracks remediation
work performed after the review.

## Status

Twenty-three reviewed findings are remediated with focused regression tests or
platform-level sandbox assertions. KSR-021 remains explicitly open: affected
content fails closed at rank zero until the per-turn provenance ledger is
implemented. The full workspace, lint, formatting, and invariant suites pass.

| ID | Severity | Finding | Status |
| --- | --- | --- | --- |
| KSR-001 | P0 | Untrusted host components retain ambient user authority | Fixed and verified |
| KSR-002 | P1 | Policy and capabilities are not bound to trusted admission | Fixed and verified |
| KSR-003 | P1 | Credential sentinels are replaced inside request bodies | Fixed and verified |
| KSR-004 | P1 | Git and GitHub approval is not bound to credential use | Fixed and verified |
| KSR-005 | P1 | Persistent-session IPC can forge trusted approval input | Fixed and verified |
| KSR-006 | P1 | Audit keys and continuation state share an untrusted namespace | Fixed and verified |
| KSR-007 | P1 | Workspace, shell, and MCP influence bypasses provenance tracking | Fixed and verified |
| KSR-008 | P3 | An idle broker client can stall authorization | Fixed and verified |
| KSR-009 | P1 | Trusted-input provenance defaults to trusted | Fixed and verified |
| KSR-010 | P1 | Repository Git configuration can influence host Git | Fixed and verified |
| KSR-011 | P1 | A valid audit-chain suffix can be removed undetected | Fixed and verified |
| KSR-012 | P2 | Structural rejection and pre-execution evidence is missing | Fixed and verified |
| KSR-013 | P2 | Approval signatures cross no trust boundary | Fixed and verified |
| KSR-014 | P2 | GitHub credentials are acquired without declared GitHub intent | Fixed and verified |
| KSR-015 | P2 | Host runtime can reach every loopback service | Fixed and verified |
| KSR-016 | P3 | Line-budget documentation hides per-crate ratchet semantics | Fixed and verified |
| KSR-017 | P2 | Audit fatigue metrics count deny-only decisions as human prompts | Fixed and verified |
| KSR-018 | P2 | Audit verification does not distinguish live/unsealed and legacy streams | Fixed and verified |
| KSR-019 | P2 | One-action approval silently creates a reusable egress grant | Fixed and verified |
| KSR-020 | P1 | Unauthenticated Git author text can raise provenance rank | Fixed and verified |
| KSR-021 | P1 | Session-wide provenance cannot follow the model's current context | Open; fail-closed rank zero |
| KSR-022 | P1 | Five-second relay timeout includes unbounded human approval | Fixed and verified |
| KSR-023 | P1 | Global denial count turns unrelated resource failures into approval loops | Fixed and verified |
| KSR-024 | P1 | Post-send model failure has no durable conservative reservation outcome | Fixed and verified |

## Findings

### KSR-001: host component isolation

The trusted terminal owner launched a caller-selected runtime backend without a
default-deny OS sandbox. The display renderer used an allow-by-default sandbox.
Compromise of either explicitly untrusted component could therefore inherit the
operator's ordinary host authority.

### KSR-002: trusted admission

The untrusted CLI wrote a policy bundle, its digest, and requested capabilities
into the same session namespace. The trusted loader verified byte consistency,
but had no independent evidence that the operator accepted that authority.

### KSR-003: credential substitution

Credential injection searched and replaced a public sentinel throughout the
entire serialized HTTP request. A sentinel placed in a model request body could
therefore be replaced with the real credential and disclosed to the provider.

### KSR-004: effect binding

Git and GitHub authorization did not produce a one-use capability consumed by
the later credential-bearing HTTP request. A hostile relay could authorize one
logical action and exercise broader credential scope in a separate request.

### KSR-005: persistent-session approval input

The persistent attach socket forwarded client bytes into the trusted input
state machine without proving that they came from the operator's terminal. A
same-UID untrusted component could replay a visible approval challenge.

### KSR-006: security-state custody

Audit keys, policy artifacts, diagnostics, and unsigned continuation state were
stored beneath a directory selected through the untrusted run request. File
mode alone does not isolate those assets from an untrusted same-UID process.

### KSR-007: provenance completeness

The provenance library defined workspace, shell, Git, and MCP classifications,
but the production broker had no observation messages for those sources.
Direct workspace exposure could influence an action without lowering the live
session floor.

### KSR-008: broker availability

The broker parsed each newly accepted connection synchronously before accepting
the next client. An incomplete client could repeatedly consume the read timeout
and starve legitimate authorization traffic.

## Remediation

### KSR-001

The trusted terminal owner now resolves installed child components relative to
its own executable, ignores production environment overrides, clears child
environments, creates private scratch storage, and launches the runtime,
renderer, and launcher under explicit macOS sandbox profiles. The runtime may
read only the selected workspace, installed Keel artifacts, its request and
scratch directory, and required operating-system files. It may write only the
workspace and scratch directory, execute only the selected pinned backend, and
reach only the preselected V8 proxy port plus the exact broker socket.
Credential directories, Keychain services, general network access, and
unrelated host files are denied.

### KSR-002

Accepted session policy is now layered beneath the immutable built-in policy;
it can add restrictions but cannot replace baseline safeguards. Extra Git and
egress authority is rendered as a trusted-terminal task manifest before the
workload starts. Lockfiles can suggest registry hosts, but those suggestions do
not become authority until the operator types `APPROVE`. Admitted registry
traffic and ordinary feature-branch pushes avoid repeated prompts; exact PR and
dangerous push gates remain.
Lower-assurance host V8 additionally requires the operator to type the exact
`HOST V8` confirmation into the directly owned trusted terminal. Persistent
attach input cannot provide that confirmation. Missing or unknown input-source
metadata is untrusted, and a direct source must also be the terminal's foreground
process group.

### KSR-003

Credential substitution now parses the HTTP header section and permits exactly
one sentinel only as the complete value of `Authorization`, `Bearer` inside
`Authorization`, or `x-api-key`. A sentinel in the request line, body,
unrelated header, or multiple headers fails closed. GitHub and Git credentials
also require exact endpoint shapes. Git credentials are used only for the
selected repository's exact `service=git-receive-pack` advertisement GET and
the authorized `git-receive-pack` POST. The GET is an exact-scope protocol
preflight recorded as inspected egress, not a typed push authorization.
Upload-pack and all other discovery requests carry no credential.

### KSR-004

Trusted authorization now creates an exact pending effect permit containing
host/path and a SHA-256 digest of the body. The later credential-bearing Git or
GitHub request must match that permit, and a successful match consumes it once.
Wrong bodies, wrong paths, direct credential calls, and replays are rejected.

### KSR-005

Persistent supervisors label their child as supervisor-filtered and admit an
attach client only when its kernel-reported peer PID belongs to the foreground
process group of its controlling terminal. Background, terminal-less, and raw
socket clients are rejected before their bytes reach the secure-attention state
machine. A directly attached mux can therefore approve; detached sessions
cannot.

### KSR-006

Audit records are now signed with an in-memory per-run Ed25519 private key. Only
the public verification key is persisted, so reading the file beside an audit
does not grant forgery authority. The untrusted session directory is no longer
used for broker diagnostic append paths, and unsigned continuation state is
never used to authorize a new run.

### KSR-007

Every run begins with an explicit rank-zero observation for direct workspace
exposure and marks existing targets as not created by the vertex. This
conservatively accounts for workspace, shell, and MCP influence that can reach
the workload outside a typed observation channel. Unsigned saved floors cannot
raise or reset this starting point; they are continuity metadata only.

### KSR-008

Accepted broker sockets are handled by bounded worker threads, with at most 64
concurrent clients and a 500 ms initial-handshake timeout. One idle client no
longer blocks acceptance or authorization of a second valid client.

### KSR-009 through KSR-016

The follow-up review tightened the remaining host and evidence boundaries:

- trusted input is fail closed and checks foreground process-group ownership;
- every production host-Git invocation uses an environment-cleared hardened
  constructor, while admission and teardown hash `.git/config` and `.git/hooks`;
- audits call `sync_data`, end in a signed count-and-tip seal, reject valid-prefix
  truncation, record hashed structural rejections, and persist `attempted` before
  external execution;
- the in-process mint-and-immediately-consume approval signature was removed;
- GitHub credentials are loaded only for a declared GitHub effect. PR creation
  and authenticated private issue reads are distinct capabilities; issue reads
  are restricted to an exact positive issue path in the admitted repository
  scope, and GitHub cannot receive a same-host grant;
- host V8 can bind and connect only to its one preselected loopback proxy port;
- the launcher renderer starts at the current Git worktree or Keel's managed
  workspace root instead of receiving a broad arbitrary starting subtree; and
- documentation now distinguishes the hard aggregate ceiling from test-inclusive
  per-crate review ratchets.

### KSR-017 through KSR-021

Gate audit records now include the deciding authority and an explicit
`prompt_presented` bit. Reports separate visible prompts from automatic
decisions and flag legacy inference. Verification reports sealed completion,
an authenticated unsealed prefix, a retired signature shape, or invalid data
as distinct states.

Routine approval no longer creates a reusable host grant: the trusted screen
offers `A` for once and `G` for its displayed 15-minute/64-action scope.
Credential-bearing effects remain ineligible. Git-author trust was removed
because author name and email are commit-controlled strings; the compatibility
classifier now fails closed and unmatched workspace/history content stays rank
zero. A content-digest ledger tied to each
model request is still open work, so Keel does not claim per-turn provenance.

### KSR-022 through KSR-024

The original egress protocol returned only its terminal decision. Its short
read timeout therefore covered both machine handling and an operator who might
reasonably take longer than five seconds, allowing the relay to disconnect
while the trusted approval remained live. `KEEL-EGRESS-V2` now acknowledges a
complete request with non-authorizing `P` inside that short window only after
acquiring the serialized adjudication slot; queued requests have no active
decision clock. It then waits up to five minutes for terminal `A`, `D`, or `E`.
The kernel expires at 4 minutes 45 seconds, invalidates late input, clears
trusted UI state, and sends denial before the relay's deadline. Peer hangup
cancels a still-pending gate; cancellation is checked again around execution
and before grant creation. An effect already in flight cannot be rolled back.

The prior `three-denials` stateful rule consumed one cumulative session count.
An operator denial followed by unrelated provider or model-budget failures
could therefore force admitted Bedrock traffic through repeated prompts. The
replacement rule considers only a 15-minute trailing window for the canonical
scope currently under review. Resource, provider, quota, transport, and budget
outcomes do not count. Approving the repeated-denial escalation clears only
that exact scope, while the cumulative total remains available for audit.

Model accounting now has explicit kernel-owned reservation identities and
states. A reservation is `authorized-unsent` until trusted TLS custody is about
to write the first upstream application byte, then `send-attempted`. Only the
former can be released. Complete trusted usage settles actual cost; an
ambiguous post-send disconnect, timeout, non-success response (even with a
usage-shaped body), malformed or missing usage record, or shutdown commits the
conservative reservation.
Terminal outcomes are written durably as `kernel.model-reservation` events,
and denial records include typed origin and opaque scope metadata. This
prevents a broken return path from converting provider work into free usage and
makes conservative charges distinguishable in audit analysis.

### KSR-025 through KSR-032

Release-signoff testing found eight integration failures that component tests
had not exposed. Their remediations are now explicit contracts:

- a relay half-close or readable EOF cancels the corresponding pending gate
  without consuming live protocol bytes. Reusable grants are action-owned and
  remain provisional until an upstream response is ready for the live origin;
  failed decision delivery, model reservation, DNS/TCP/TLS setup, forwarding,
  response acquisition, or origin liveness revokes them;
- CONNECT and front-side TLS are local inspected setup only. Trusted code does
  not resolve or connect externally until it has parsed and authorized the
  exact decrypted HTTP request;
- canonical renderer frames and trusted takeover/teardown reset the alternate
  buffer, horizontal margins, origin mode, vertical margins, paste/focus/mouse
  modes, cursor state, and SGR before clearing and repainting the terminal.
  Both trusted terminal paths invoke the fixed `/bin/stty` with a cleared
  environment for mode capture, raw-mode entry, size reads, and restoration;
- a late terminal-query reply and the first-attach race cannot replace a
  successful short V8 result with `EPIPE`; persistent runtime exit status is
  retained for the attaching client;
- `keel stop` uses cooperative runtime control, waits for broker shutdown and
  the terminal audit seal, and reports its forced-kill fallback as failure;
- reviewed Bedrock tariffs include `global.anthropic.*` inference profiles,
  while explicitly pinned unsupported models fail before guest boot;
- Git credentials are acquired only for `push:branch`; PR-only and private-
  issue-only runs keep repository identity without activating the Git sentinel.
  Private receive-pack discovery/POST remain bound to the selected exact
  repository, and descendant paths fail closed; and
- authenticated private-issue GETs are limited to the admitted exact GitHub
  repository. Without the distinct GitHub read credential, public reads remain
  anonymous.

The transport regression terminates a real front-side TLS connection, denies
the decrypted request, and asserts that the injected resolver/connector was
never called. This closes the DNS/port-probing gap that would otherwise be
created by treating a setup-only CONNECT as an automatic allow.

## Deliberate compatibility changes

- Protected actions in a persistent session require a foreground terminal
  attachment authenticated by the trusted supervisor.
- Host V8 requires foreground-terminal confirmation in addition to its
  capability flag.
- Unsigned continuation files do not restore authority into a new run.
- Private push negotiation may authenticate only the exact
  `service=git-receive-pack` advertisement GET for the selected repository.
  This protocol preflight is authorized and audited as inspected egress, not as
  a typed push action. Upload-pack and other Git discovery requests remain
  unauthenticated; the receive-pack POST retains separate push authorization.
- The legacy `.key` audit filename now contains a public verification key, not
  a secret signing key.
- A clean audit must contain a valid terminal seal. A crash produces an
  intentionally incomplete, unsealed stream.
- Launching the workspace browser outside a Git worktree starts it in Keel's
  managed workspace root instead of granting it read access to the current tree.

## Verification log

All commands were run from the repository root on Apple silicon macOS:

| Command | Result |
| --- | --- |
| `cargo test --workspace --all-targets` | Pass; isolated-child wrapper cases are intentionally ignored in the parent process and their child runs pass |
| `cargo clippy --workspace --all-targets -- -D warnings` | Pass |
| `cargo fmt --all -- --check` | Pass |
| `python3 ci/check_invariants.py` | Pass; I1-I12 |
| `codex review --uncommitted` post-remediation pass | Tool unavailable before analysis: this CLI installation is missing `codex-code-mode-host`; no clean post-review result is claimed |

Focused coverage includes structural sentinel substitution, public-only audit
verification, immutable baseline policy, exact/replay-resistant Git and GitHub
permits, trusted host-V8 confirmation, background-attach refusal, macOS sandbox
profile compilation plus an out-of-scope read denial, conservative continuation
admission, and valid-client progress while another broker client is idle.

The D39 approval-liveness, scoped-denial, and model-settlement remediation
required an explicit cap reconsideration. The aggregate hard ceiling remains
16,000 lines. D40 moved regression-only coverage out of production `src`, and
D41 reconciled the measured per-crate ratchets to 12,913 lines. D42 then
assigned 83 reserve lines to atomic grant revocation and peer-EOF detection,
and D43 assigned 38 to TLS-only credential substitution and embedded-IPv4
address denial, and D44 assigned 313 to off-lock adjudication, post-approval
re-derivation, scoped grants, and windowed loop detection, and D45 assigned 155 to
task-envelope verdicts stamped on every action and branch-scoped push and PR
narrowing, and D47 assigned 435 to the admission-time confidentiality index and
shadow payload-flow verdicts, and D48 assigned 168 to a model-only upstream idle timeout and charging interrupted model streams their observed usage bound, and D49 assigned 19 to waiting for in-flight model reservations instead of refusing a request that will fit, and D50 assigned 7 to marking connection-setup legs not-applicable in the task-envelope verdict, and D51 assigned 193 to guest-reported process origins carried on every mediated channel, stamped, audited, shown at the gate, and used to gate pushes and pull requests from workspace code, and D52 assigned 243 to recording model tool-call output and judging lines pushed into protected places against it, and D54 assigned 235 to the shadow per-turn context digest log, and D56 assigned 83 to the OpenRouter provider and its admitted price snapshot, and D57 assigned 249 to the audited run admission manifest, and D58 assigned 176 to the triage profile's declared scope, and D61 assigned 5 to the read-only root disk, and D62 assigned 6 to recording guest memory, and D63 assigned 8 to reading an unsealed chain's authenticated prefix, and D64 assigned 2 to building the trusted runtime cleanly on Linux, so 15,331 lines are allocated and 669 remain
unallocated. The ratchet counts
trusted production `src`, including binaries and any inline tests located
there; separate integration/support test files are not part of that production
LOC count. Decision D16 in the condensed
`DECISIONS.md` log maps to D39 in `PLAN.md`; D18 and D19 map to D41 and D42.
