# Keel architecture

This document describes the current architecture of Keel. Planned components are called out explicitly and belong in the [roadmap](ROADMAP.md).

## 1. Design objective

Keel runs one AI coding or research workload while assuming that the workload, its model, repository content, tool output, and network input may be malicious.

The architecture separates two responsibilities:

1. **Untrusted execution** runs the harness, model-driven code, terminal rendering, and protocol adapters.
2. **Trusted mediation** decides whether sensitive actions may occur and performs the narrow subset that is allowed.

The central rule is that an untrusted component may request authority but may not create it.

## 2. System overview

~~~text
                              host

  operator
     |
     | trusted keystrokes / approval
     v
  +---------------------+
  | keel-input          |
  +----------+----------+
             |
             v
  +------------------------------------------------------+
  | trusted kernel                                      |
  | structural checks -> provenance -> policy -> budget |
  |                    -> approval -> audit              |
  +------------+----------------------+------------------+
               |                      |
         action result          host relays (untrusted)
               |                      |
     +---------+---------+      +-----+------------------+
     | untrusted runtime |      | model / Git / MCP     |
     |                   |      | brokered transport     |
     | VZ microVM        |      +------------------------+
     | or host Deno      |
     +---------+---------+
               |
        untrusted output
               |
               v
        keel-render / mux
~~~

The diagram is a trust map, not a process map. Some trusted crates are linked into one host process; some untrusted functions run in separate processes or the guest.

## 3. Trust boundary

### Trusted

Keel's intended trusted computing base includes:

- the local operator;
- the host operating system and Apple Virtualization.framework;
- the six trusted Keel crates;
- pinned dependencies of those crates;
- runtime artifacts admitted by the local setup and configuration;
- the host mechanisms that protect process memory, files, and local IPC.

### Treated as hostile

Keel does not trust:

- the model or agent;
- Claude Code, Node, Deno, or another harness;
- the guest operating system;
- repository files and generated code;
- web pages, model output, MCP responses, Git remotes, and tool output;
- the launcher, mux renderer, policy translator, and protocol relays to make authorization decisions;
- text displayed inside the ordinary terminal.

An untrusted component can still contain important correctness logic. “Untrusted” means a bug or compromise in that component must not be sufficient to grant a protected action.

## 4. Trusted crates

Keel keeps the hand-written first-party trusted Rust surface small and enforces a
hard 16,000-line aggregate ceiling in CI. Per-crate limits are review ratchets:
moving or adding capacity requires a recorded decision. The `tokei` count includes
inline tests and trusted binaries as well as production library code.

| Crate | Responsibility |
| --- | --- |
| keel-kernel | Action lifecycle, structural validation, authorization ordering, budgets, session state |
| keel-policy | Typed policy decisions and Cedar evaluation |
| keel-provenance | Labels, read-set joins, floors, write inheritance, operator floor lifts |
| keel-audit | Authenticated hash-chained event records and verification |
| keel-secrets | Secret handles, sentinel replacement, scoped credential use, zeroization |
| keel-input | Secure-attention handling and trusted approval interaction |

The ceiling is a reviewability mechanism, not evidence that these crates are bug-free. Dependency versions are pinned and CI checks the intended dependency boundary.

## 5. Untrusted crates

| Crate | Responsibility |
| --- | --- |
| keel-cli | Setup, doctor, command-line parsing, launcher orchestration, status and reports |
| keel-compile | Natural-language policy translation and differential compilation |
| keel-conn | Connection relay and TLS-facing protocol handling |
| keel-gitd | Git transport integration |
| keel-isolate | Virtualization and host-sandbox lifecycle |
| keel-mcp | MCP integration |
| keel-render | Launcher UI and bounded legacy stream compatibility |

The installed `keel-xterm-renderer` executable is built from the pinned
`@xterm/headless` and serialize-addon modules. It is an untrusted, sandboxed
display component rather than a Rust crate or part of the trusted computing
base.

These components do not get to convert their own claims directly into authority. Security-relevant requests are reconstructed or checked by the trusted path.

## 6. Action model

The guest side of a request is an **asserted action**: a description supplied by an untrusted caller. The trusted kernel adds facts it can establish and produces a **stamped action**.

A protected action proceeds through this order:

~~~text
request
  -> parse and bound
  -> reconstruct trusted facts
  -> structural denial checks
  -> repeated-action loop check
  -> policy evaluation (hard `deny:` rules stop here)
  -> provenance minimum-rank check
  -> action budget reservation
  -> trusted approval when required
  -> perform through a narrow backend
  -> append authenticated audit event
  -> return bounded result
~~~

While stamping, the kernel also records whether the action falls inside the
operator-admitted **task envelope**: its capabilities, egress hosts, and any
`push:ref:` and `pr:target:` branch scopes. The verdict is written to every
audit record for the action. Pushes and pull requests outside a declared
branch scope add a gate-requiring violation; other verdicts are recorded in
shadow while the action-centric rules in the
[provenance design note](design/guest-confinement-attribution-and-turn-provenance.md)
are measured.

Ordering matters. For example, an approval cannot make a structurally forbidden operation valid, and an allowed policy rule does not erase a provenance violation. Provenance is evaluated after policy because an action's minimum rank depends on policy's verdict: egress outside the admitted host set (policy's `intent:egress-host` violation) requires rank 2, in-intent egress does not. A policy result therefore never removes a rank violation; it only determines which rank applies. Every stage that rejects records an audit event, including the loop check.

Typical protected actions include network connections, Git mutations, MCP calls, credential-bearing model requests, provenance floor changes, and high-impact filesystem or session operations.

## 7. Isolation profiles

### Claude Code microVM

Claude Code runs in a macOS Virtualization.framework guest. The guest has no ordinary NIC or DNS path. Keel communicates over a constrained host/guest channel and performs permitted external operations through host relays.

The guest is not trusted merely because it boots from a prepared image.

The Claude guest also carries a headless Chromium, driven by `agent-browser`,
an MCP server for the agent and a CLI for the operator that share one browser
(DECISIONS D36). It runs inside the confinement below without Chromium's own
sandbox (DECISIONS D35), proxies every request through the guest egress relay,
and has its background calls to Google services disabled. Screenshots,
downloads, and HAR files go to a self-ignoring `.keel-browser/` directory in
the workspace.

Inside the guest, a second confinement layer wraps everything the operator's
terminal runs: tmux, the harness, and every tool it starts. Virtiofs presents
the workspace as root-owned, so the workload keeps UID 0 but holds no
capabilities and cannot regain any: its bounding set is empty,
`SECBIT_NOROOT` is locked, and `no_new_privs` is set. On top of that:

- **Landlock** permits reads everywhere but writes only to the workspace,
  `/tmp`, `/var/tmp`, `/root`, and terminal devices, and on the 6.12 guest
  kernel (Landlock ABI 6) confines signals and abstract Unix sockets to the
  workload's own domain;
- **seccomp** refuses `AF_VSOCK`, packet, and raw IP sockets, namespace
  creation, mounts, `bpf`, `perf_event_open`, `io_uring`, `userfaultfd`,
  `ptrace`, module loading, and keyring calls;
- **a cgroup** bounds the process count.

Guest services (the Git, egress, and MCP relays and the terminal bridge) bind
as root and then drop to a separate service UID, so the workload can neither
signal nor inspect them. The workload reaches the host only through those
relays. At boot, a confined child tries every forbidden operation and reports
the result in the guest report; the host refuses to start the workload unless
every layer holds.

**Process attribution.** PID 1 in the guest is a Rust supervisor. It keeps
root, but the kernel delivers no signal to PID 1 from inside the guest unless
it installs a handler, so the workload cannot kill it. When the Git, egress, or
MCP relay accepts a connection, it asks the supervisor which process owns it. The
supervisor finds the owner through `/proc/net/tcp` and per-process file
tables, walks its ancestry, and marks every ancestor that runs code the
workload could have written:

- executables or scripts under the workspace, `/tmp`, `/var/tmp`, or `/root`;
- anything running from inside a `node_modules` under one of those roots.

Read-only system paths, such as the guest's bundled browser server, are not
workspace code: Landlock keeps the workload from writing them.

The relay sends this ahead of its traffic as an origin frame. The host
forwards it to the kernel, which stamps it on the action as a
**guest-reported** origin, audits it as `origin`, and shows it at the gate as
"issued by". It is never verified, so it only narrows: a Git push or pull
request from workspace code adds `origin:workspace-code` and reaches the
gate.

This layer lives inside the VM boundary. It makes a
compromised workload need a guest kernel exploit, but it does not replace the
VM.

### V8 microVM

The V8 workload runs under Node inside the same class of microVM boundary. It uses an existing workspace and a JavaScript entry file. Sensitive effects still pass through the trusted action path.

This is the recommended V8 profile when isolation strength matters.

### V8 host sandbox

The lower-assurance profile runs a pinned Deno binary on the host with:

- a cleaned environment;
- bounded workspace access;
- cached-only module behavior;
- no general network permission;
- access only to the local Keel proxy needed for brokered actions, which
  requires a per-run credential.

Deno checks `--allow-net` against a proxied request's destination, so the
profile names the admitted hosts (declared `egress:` grants, the model
endpoint, and GitHub for its capabilities) in addition to the proxy. The outer
sandbox still allows outbound connections only to the proxy port, and the
kernel still authorizes each request. A host outside the admitted set is
refused by Deno before it can reach the trusted gate, so this profile cannot
approve undeclared egress interactively.

The profile requires the explicit isolation:v8-sandboxed grant. Deno permissions reduce accidental and common direct access, but a Deno/V8 escape reaches the host process boundary rather than a microVM boundary.

See [V8 isolation](design/v8-isolation.md) for detailed profile design.

## 8. Network and credentials

The microVM has no general-purpose network interface. Network intent is sent to a host relay that:

1. validates the requested destination and operation;
2. asks the trusted kernel for authorization;
3. establishes an allowed connection;
4. terminates or originates the relevant TLS session;
5. substitutes a real credential only at the authorized boundary;
6. accounts for bytes, requests, cost, and session constraints;
7. records the result.

The workload sees a sentinel credential, not the real model or service secret.

Current model authentication paths are:

- Anthropic API key held by the host relay;
- Amazon Bedrock credentials obtained on the host, with requests signed using SigV4.

Host Claude Code SSO import is not currently implemented.

Before a run with extra authority starts, the trusted terminal renders its task
manifest: declared push, PR, private-issue-read capabilities plus explicit or
lockfile-derived egress hosts. Private issue reads use the distinct
`github:read-private-issues` capability; `pr:create` does not silently grant it.
The operator must type `APPROVE`. Admitted registry traffic and ordinary
feature-branch pushes do not prompt again. Pull requests and dangerous pushes
remain bound to their exact action-level approval.

For undeclared egress, `A` approves only the current request and is consumed
once. `G` explicitly accepts the displayed bounded host, port, and method
grant so repeated traffic does not require a full approval round trip. It
expires after 15 minutes or 64 actions. It waives only the violation reasons
the operator saw, and only while the provenance floor is at least what it was
at approval: lower-ranked content read afterwards brings the request back to
the gate. Credential-bearing and high-impact effects cannot create or use that
reusable grant.

For HTTPS, CONNECT and the guest-facing TLS handshake are local setup inside
the terminating relay. They do not perform external DNS or TCP. The relay first
decrypts, bounds, and authorizes the exact HTTP method, path, and body digest;
only then may trusted code resolve the admitted name, reject forbidden address
classes, open the upstream socket, and substitute a scoped credential. This
keeps one user-visible request at one meaningful gate and prevents a generic
CONNECT allowance from becoming a DNS or port-probing primitive.

The egress broker uses a two-stage V2 handshake. After it has received and
bounded a complete request **and acquired the serialized adjudication slot**,
the trusted broker returns `P` (pending) within the client's five-second
machine timeout. A queued request has no `P` and no active human-decision
clock. `P` grants nothing; it only proves that the request is now being
adjudicated. The relay then waits as long as five minutes for one terminal
byte: `A` (allowed), `D` (denied), or `E` (trusted execution failed). The
kernel's human-decision deadline is 4 minutes 45 seconds so it can close the
gate and return `D` before the outer relay deadline. Peer hangup or broker
shutdown while the gate is pending cancels that decision; late input cannot
start the effect or create a grant. This
separation prevents a legitimate human approval from being mistaken for an
unresponsive broker and tearing down the model connection.

Model budgets use a kernel-owned reservation lifecycle rather than treating a
connection close as evidence that no provider work occurred. Authorization
creates an `authorized-unsent` reservation; trusted TLS custody marks it
`send-attempted` immediately before the first upstream application byte. Only
a request proved not to have reached that point may be released in full. A
complete trusted usage record settles actual tokens and cost. A successful
stream that ends early after the provider's opening usage event commits a
trusted upper bound instead (`committed-observed`):

- the exact input the provider stated;
- plus the bytes of text, thinking, and tool input already streamed, since a
  token is at least one byte;
- plus a 4,096-token margin for output generated but not yet delivered;
- capped at the reservation.

A failure before that event, a malformed or missing usage record, a
non-success response, or any other ambiguous post-send outcome commits the
full conservative reservation. A model request that fits only once in-flight reservations settle waits for
them, for up to 30 seconds and outside the broker lock, instead of being
refused. A request that cannot fit even then is refused at once.

Model connections use a ten-minute upstream
idle timeout, because a large request can take minutes to produce its first
event. Other upstream connections keep ten seconds. Every terminal
transition is written to the authenticated audit stream.

## 9. Policy

The trusted policy evaluator consumes a closed, typed action and explicit session facts. It does not interpret arbitrary natural language at authorization time.

The natural-language compiler is outside the trusted computing base:

~~~text
operator text
  -> untrusted translation
  -> closed intermediate representation
  -> Cedar policy
  -> Rego artifact
  -> Rust expectation
  -> differential checks
  -> explicit acceptance
  -> content-addressed policy artifact
~~~

This pipeline catches disagreement between generated representations and prevents an unreviewed draft from authorizing a run. It cannot prove that the source sentence expressed the operator's intended policy.

Repeated-denial review is scoped rather than session-global. The kernel hashes
a canonical action class and target into an opaque denial scope and Cedar sees
only the recent behavioral-denial count for the scope currently being
evaluated. The active window is 15 minutes. Operator, policy, and structural
denials can contribute; resource outcomes such as provider failures, exhausted
model budgets, and transport errors do not. Approving the
`repeated-denials-same-scope` escalation clears behavioral history only for the
exact reviewed scope. Cumulative denial totals remain audit statistics and do
not silently make unrelated Bedrock or GitHub traffic require approval.

## 10. Provenance

Keel records ranks for classified results that cross a mediated boundary and
keeps a scalar floor for the live broker. A workspace is directly readable by
the guest, so production runs conservatively record
`workspace://direct-exposure` at rank 0 during admission. Successful workspace
writes record the floor that was active when they occurred for same-broker
write inheritance. A new broker does not import those unsigned write labels and
treats the directly exposed workspace conservatively at rank 0.

In `floor` mode, an action below its minimum rank escalates to the trusted gate.
The default minimum-rank table is:

| Action shape | Minimum rank |
| --- | ---: |
| Force/default-branch/manifest-touching Git push | 2 |
| Pull request or publication | 2 |
| Egress outside the admitted host set | 2 |
| In-intent egress and other local actions | 0 |

An `A` approval authorizes only the exact action shown. It does not change the
floor. Raising the floor is a distinct high-risk operator attestation against
the live broker and its displayed read history. In an attached mux session use
`Ctrl-A`, `/floor-lift [1-3]`, Enter; `keel floor lift SESSION [1-3]` submits the
same request to that live session, and the trusted challenge is completed in
the attached terminal. Both routes use the kernel's operator channel and the
same audit chain as the action they affect.

The default floor mode therefore prevents lower-ranked influence from being
used for a higher-ranked effect without either exact-action approval or an
explicit operator floor lift. This addresses a common prompt-injection pattern:

~~~text
untrusted repository or network text
  -> influences the model
  -> model proposes a sensitive action
  -> provenance floor escalates the action
~~~

`gate-context` records the same floor and shows it at gates, but does not add a
minimum-rank violation. It is observability, not rank enforcement.

The floor is monotonic downward between explicit live lifts. A later classified
observation can lower it again. `floor.json` is written at shutdown for status
and continuity evidence, but the session directory is unsigned and untrusted;
a new or continued run never imports that file as authorization and begins
again with the rank-0 direct-workspace observation.

Keel also records **payload provenance** in shadow. At admission, trusted
code indexes the committed `HEAD` tree with the hardened host Git as winnowed
fingerprints: text blobs are private and credential-shaped paths secret,
unless the operator declares `workspace:public`. Every decrypted non-model
request target and body is scanned against that index and judged against its
destination's clearance. The workspace's own GitHub origin may receive
private content, the model endpoint anything, and every other host only
public content. The resulting `FlowVerdict` is stamped with the action and
audited as `flow`; no decision reads it yet. It detects verbatim and
escape-encoded copies, not paraphrase or compression.

The integrity direction is recorded the same way. After each complete model
response, trusted code records the line fingerprints of every string the
model placed in a tool call. For a push that changes a dependency manifest or
CI configuration, or updates the default branch, `keel-gitd` sends the diff,
and the kernel counts added lines the model never wrote. The resulting
`IntegrityVerdict` is stamped, audited as `integrity`, and shown at the gate.
The diff is computed by untrusted `keel-gitd`, as its push flags already are.

Provenance is conservative metadata, not semantic understanding. Git author
text is not authentication. The scalar is session-wide and cannot tell when
content leaves the model's current context. Per-turn content-digest provenance,
which would bind influence to the exact model request and let taint leave only
when the corresponding content leaves context, remains planned. Its first
increment is a shadow digest log: trusted termination digests every block of
each model request and complete response, and the kernel audits them as
`kernel.model-context` records, describing each digest once per session.
`keel report --context` measures the log; nothing decides on it yet.

## 11. Trusted input and rendering

The terminal renderer and normal PTY are untrusted. They may display arbitrary text, including a fake approval prompt.

The sandboxed renderer terminates the guest's incremental terminal stream in
the pinned `@xterm/headless` 6.0.0 model and uses
`@xterm/addon-serialize` 0.14.0 to emit bounded, length-prefixed complete
snapshots. It adds no permanent chrome, so guest tmux still reserves the familiar one-row footer listing
the `Ctrl-A` commands; this is persistent discoverability, not authority. When
a gate is pending, the renderer temporarily replaces that footer with a
reverse-video approval notice and trusted input changes the terminal title.
Both can be imitated by the workload, so they remain notification rather than
authority.

Terminal-generated replies, such as cursor-position reports, return to the
guest as a separate bounded frame type. They never reach the operator terminal
and cannot enter the trusted approval-input path.

Ctrl-] is the secure-attention key. In mux sessions, the trusted `Ctrl-A` command mode can emit the same event with `/approve` for terminals that intercept Ctrl-]. It switches input to the trusted approval path, which renders the action from trusted data. High-risk actions can require a challenge rather than a single-key approval.

During that takeover the renderer continues updating its private screen while
trusted input discards complete display snapshots. Resume clears the trusted
view and requests one fresh snapshot. No guest delta is replayed, and no
terminal-sequence seam has to cross the trust boundary. Resize events update
the guest PTY and renderer viewport from the same dimensions.

Exact-action `A` approvals are:

- bound to the exact action;
- short-lived;
- single use;
- recorded in the audit chain.

When the trusted screen offers it, `G` is a separate decision that creates
only the displayed host, port, and method grant. It expires after 15 minutes,
64 actions, or a drop in the floor; credential-bearing and high-impact effects
remain ineligible.

A pending gate also has a bounded lifecycle. Once the 4-minute-45-second
kernel deadline expires, the pending decision becomes inactive, the trusted
input process clears its approval state and notification, and a later keypress
cannot approve the expired action. The relay receives a terminal denial before
its five-minute wait expires. A peer disconnect or broker shutdown cancels the
same pending state immediately. The kernel rechecks cancellation before and after the executor and
creates a grant only after successful execution. A disconnect cannot roll back
an effect that had already begun.

The operator's decision does not hold the broker's state. The kernel runs
every check up to the gate under the broker lock, releases it, and waits
holding only the gate's own lock, which serializes prompts. Traffic that needs
no decision, and in-flight model and response accounting, continue meanwhile.
After the decision the kernel re-derives the action's reasons against the
session as it then stands and refuses the approval if any reason was not on
the operator's screen, for example because another request lowered the floor
during the wait.

The persistent mux is a usability layer. Its tab UI and terminal painting do
not make authorization decisions. The trusted supervisor accepts attachment
input only from a peer in its controlling terminal's foreground process group;
background and terminal-less socket clients cannot enter secure-attention mode.

## 12. Audit and session state

Each security-relevant decision produces a structured event. Events are chained
and signed with an in-memory per-run Ed25519 key. Keel persists only the public
verification key, prints the audit and verifier paths at exit, and the CLI can
verify the chain or produce a report.

Before the runtime backend starts, trusted input records `kernel.run-admitted`:
a canonical manifest of everything the run was admitted with (component and
boot-artifact digests, policy, workspace state, authority and credential
scopes, model terms, and run shape) and its SHA-256. A run whose manifest
cannot be hashed or written does not start. The digests are evidence of what
was admitted, not proof of what the untrusted backend booted.

The verifier reports a sealed complete stream separately from an authenticated
but unsealed prefix, and names the retired signature format instead of treating
it as generic corruption. Gate events state whether a trusted operator prompt
was actually presented; deny-only decisions are not counted as prompt fatigue.
Denial events also record the typed origin, opaque canonical-scope digest,
whether the denial counted toward repeated-behavior review, and the recent
same-scope count. Model reservation events name their run-local reservation and
terminal outcome (`released-unsent`, `settled-actual`, `committed-observed`,
`committed-conservative`, or `overrun`) without recording response content.
The audit design provides local tamper evidence relative to the key and verifier.
It is not remote attestation, cannot prove that a compromised host recorded
reality, and does not yet provide fully verified crash recovery and teardown
receipts.

Session state also records enforcement boundaries, provenance floors, budgets,
runtime identity, and continuation metadata. Because the session directory is
not a trusted namespace, a new run does not use unsigned continuation metadata
as authority: it starts with a conservative untrusted-workspace observation.

## 13. Run lifecycle

The current lifecycle is:

1. Resolve configuration and pinned runtime artifacts.
2. Select an isolation profile, workspace, harness, policy, and provider.
3. Derive registry hosts from lockfiles and obtain trusted task admission for
   the exact declared authority, including the exact model token and cost
   ceilings. Values above the kernel defaults require admission; lower values
   are authority narrowing.
4. Create session state, audit material, relays, and the isolation boundary.
5. Run the workload while mediating protected actions.
6. Detach, continue, or request cooperative stop according to mux and run
   options. A persistent stop waits for broker shutdown and reports a forced
   fallback as failure.
7. Close relays, write the terminal audit seal, finalize local evidence, and
   report audit locations.

A canonical pre-boot admission manifest and cryptographically verified teardown receipt are planned, not current guarantees.

## 14. Source layout

~~~text
crates/
  trusted/
    keel-audit/
    keel-input/
    keel-kernel/
    keel-policy/
    keel-provenance/
    keel-secrets/
  untrusted/
    keel-cli/
    keel-compile/
    keel-conn/
    keel-gitd/
    keel-isolate/
    keel-mcp/
    keel-render/
docs/
  design/
  examples/
ci/
~~~

Top-level planning records preserve project history. Local .phase0 and .phase1 directories, when present, contain generated development artifacts and are not source documentation or part of the runtime trust boundary.

## 15. Invariants and verification

Repository checks enforce the intended crate partition, trusted-code ceiling, dependency restrictions, forbidden patterns, and scenario tests. The CI suite currently groups these as invariants I1 through I12.

Run:

~~~sh
cargo fmt --all -- --check
cargo check --workspace
cargo test --workspace
./ci/check.sh
~~~

These checks are necessary evidence for the architecture. They are not a formal proof of memory safety, policy correctness, hypervisor isolation, or end-to-end security.

## 16. Implemented versus planned

Implemented today:

- VZ microVM execution for Claude and V8 workloads;
- lower-assurance host V8 sandbox with an explicit grant;
- trusted action stamping and structural denials;
- Cedar policy enforcement;
- provenance floors and inherited write labels;
- trusted approvals through secure attention;
- request, rate, cost, and loop constraints;
- credential-aware Anthropic and Bedrock relays;
- authenticated hash-chained audit records;
- persistent mux sessions;
- differential natural-language policy compilation and artifact acceptance.

Planned:

- canonical pre-boot run admission;
- verified teardown, crash recovery, and stale-session reconciliation;
- Linux KVM and Cloud Hypervisor support;
- a distributed evaluation and reinforcement-learning substrate;
- stronger packaging, release reproducibility, and evaluation evidence.

See the [threat model](THREAT-MODEL.md) for the security consequences and the [roadmap](ROADMAP.md) for future work.
