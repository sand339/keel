# Action-centric provenance, guest confinement, and process attribution

Status: in progress on branch `provenance-axes`. Sections marked
**Implemented** describe current behavior; everything else is proposal.
Security claims about Keel must still be judged from the source, tests, and
[threat model](../THREAT-MODEL.md).

| Workstream | State |
|---|---|
| W1 intent envelopes | **Implemented (shadow)**, D45: verdicts stamped and audited on every action; branch scopes enforced |
| W2 payload provenance | **Implemented (shadow)**: egress confidentiality (D47) and push-content integrity (D52) |
| W3 quarantine extraction | Planned |
| W4 per-turn context provenance | **Digest log implemented (shadow)**, D54; walker ranking, operator matching, and turn binding planned |
| W5 guest confinement | **Implemented** (Landlock file rules, and ABI 6 signal and abstract-socket scoping on the 6.12 guest kernel), D46, D53 |
| W6 process attribution | **Implemented** for Git, egress, and MCP channels, D51, D55 |

## 1. Decision

Replace Keel's single agent-level trust floor with a per-action judgment on
three axes:

1. **Intent:** did the operator ask for this action?
2. **Data flow:** what does the effect carry, and where to?
3. **Control influence:** could low-integrity content have steered the
   decision?

Intent and data flow become the primary inputs to authorization, because Keel
can compute both soundly from facts it already owns: the admitted task and the
bytes that cross its trusted relays. Control influence, today's floor,
remains the third axis. Per-turn content provenance refines it, but only after
shadow measurement shows it helps. Untrusted content gets principled ways to
regain integrity through schema-bounded quarantine extraction, instead of
relying on operator floor lifts alone.

Two guest-side workstreams make the attribution half of this sound: a second
confinement layer inside the guest, and per-process attribution of every
mediated request.

## 2. Problem

### 2.1 The floor is a low-water mark, with that design's known failures

Keel gives the agent one integrity label, lowers it on every classified read,
and gates actions against it. That is the Biba/LOMAC low-water-mark model, and
Keel shows its well-known failure modes:

- **Label creep.** The guest reads the workspace directly over virtiofs, so
  admission records `workspace://direct-exposure` at rank 0. In `floor` mode
  every rank-2 action escalates for the whole session, whatever the agent
  read. The floor starts at the bottom and has nowhere to go.
- **Integrity only.** The floor says nothing about confidentiality, yet
  exfiltration is the most damaging prompt-injection outcome. The threat
  model therefore lists lawful-output exfiltration as residual.
- **One question for every action.** "Is the agent tainted?" cannot
  distinguish a tainted agent opening the PR the operator asked for from a
  clean agent posting the private repository to a paste site.
- **The operator is the only declassifier.** A floor lift is the only way
  back up, so every recovery costs a human decision.

Per-turn provenance, which tracks the exact content in each model request,
makes the label more accurate. It does not fix any of these: on coding tasks,
shell output is unattestable and can keep even a precise per-turn label at 0
(§8.6).

### 2.2 The kernel cannot tell who asked

Every mediated request is "the guest". A `git push` the model's Bash tool ran,
a `postinstall` script in `node_modules`, and the harness's own housekeeping
are indistinguishable to policy and to the gate.

### 2.3 The VM is the only layer

Inside the guest, PID 1 is a shell, the harness runs as root, and any process
can open `AF_VSOCK` sockets to the host broker directly. Nothing in the guest is
trustworthy enough to attribute anything, and a guest kernel exploit plus a
host relay parser bug is the whole escape chain.

## 3. Principles

- **Judge flows, not agents.** Authorization asks whether this action's
  intent, payload, and control inputs violate a rule. It does not ask how
  tainted the agent is overall.
- **Prefer facts Keel observes to facts the harness assembles.** Payload bytes
  at the trusted relay, and the operator's admitted task, are sound without
  harness cooperation. The model request body is sound as a record of model
  input, but matching its parts to sources depends on the harness's
  formatting.
- **Guest claims narrow, never widen.** Attribution arrives from an untrusted
  guest. It may add violations or lower a rank. It may never remove a
  violation or raise a rank.
- **Fail closed on both labels.** Unmatched content is rank 0 for integrity.
  Confidentiality matching errs toward flagging: a fragment that matches
  private content is treated as private, whatever produced it.
- **Integrity rises only through narrow channels.** These are admission-time
  commitments, schema-bounded quarantine extraction, and content-addressed
  operator attestation.
- **Measure before enforcing.** Every new axis first runs in shadow mode
  beside today's decisions.

## 4. The action model

### 4.1 Labels

Each content source carries two labels:

| Label | Values | Meaning |
|---|---|---|
| Integrity | rank 0–3, as today | How much the source can be trusted to instruct |
| Confidentiality | `public`, `private`, `secret` | Who may receive it |

Each sink, meaning a destination or effect, carries:

| Sink property | Values | Meaning |
|---|---|---|
| Clearance | `public`, `private`, `secret` | The highest confidentiality it may receive |
| Integrity requirement | `none`, `protected` | Whether untrusted bytes entering it need review |

Default sink assignments:

| Sink | Clearance | Integrity |
|---|---|---|
| The run's model endpoint | `secret` (it receives the full context by design) | `none` |
| The workspace's own origin repository, feature branches | `private` | `none` |
| Origin default branch, release tags, CI configuration paths, dependency manifests | `private` | `protected` |
| Admitted registries, read requests | `public` | `none` |
| Registry publish | `public` | `protected` |
| Any other egress host | `public` | `none` |
| PR and issue text on the origin | `private` | `none` |

### 4.2 The three axes

| Axis | Computed from | Soundness |
|---|---|---|
| **Intent** | The operator-admitted task envelope (§5) | High: explicit and trusted |
| **Data flow** | Payload provenance of the effect's bytes (§6) | High for verbatim content; blind to paraphrase and encoding |
| **Control influence** | Context provenance: the session floor today, per-turn floors later (§8) | Conservative and coarse |

### 4.3 Decision rules

| Intent | Data flow | Control influence | Result |
|---|---|---|---|
| inside the envelope | no violation | any | allow |
| inside the envelope | violation | any | escalate, showing the exact flagged spans |
| outside the envelope | no violation | high (rank ≥ 2) | escalate (exact action) |
| outside the envelope | no violation | low | escalate, showing the low-rank sources |
| outside the envelope | violation | low | deny, with an operator override only through the challenge gate |
| any | `secret` content to a sink below `secret` | any | deny |

Today's built-in restrictions, structural denials, budgets, and accepted Cedar
policy still apply first. These rules replace only the minimum-rank check.

**The lethal trifecta follows from these rules.** Private data in context,
untrusted content in context, and an external channel together produce an
escalation, because an off-intent egress carrying private content is a
data-flow violation with low control influence. Any one of the three alone
does not escalate if the action is inside intent.

## 5. Workstream 1: intent envelopes

Keel already has structured intent (`IntentFlags`: `allow_push_branch`,
`allow_pr_create`, `deny_force_push`, `allowed_egress_hosts`) and trusted task
admission. An envelope generalizes those flags into a closed, scoped grammar:

- **refs:** branch patterns that may be pushed, with force and deletion
  explicit and off by default;
- **pull requests:** target branches and a maximum count;
- **egress:** hosts with permitted methods and optional path prefixes;
- **publication:** named registries and packages, off by default;
- **files:** optional protected path patterns beyond the defaults.

Envelopes are written three ways, all ending in the same closed IR:

1. CLI flags and launcher fields, as today;
2. a lockfile-derived default (registries), as today;
3. the natural-language policy compiler: untrusted translation to the closed
   IR, deterministic validation, and an accepted, content-addressed artifact.
   This reuses the existing pipeline.

Trusted task admission renders the envelope and requires `APPROVE`, as it does
for capabilities today. The kernel matches every action against it
structurally.

**Implemented (shadow), D45.** The first increment derives the envelope from
the existing closed capabilities plus two branch scopes:

- `push:ref:refs/heads/PATTERN` (trailing `*` allowed) implies push authority
  and narrows it; a default-branch push is inside only when a pattern names it
  exactly;
- `pr:target:BRANCH` narrows `pr:create` to named base branches.

The kernel computes an `IntentVerdict` while stamping each action
(`Stamped::intent`) and writes it to every audit record as `intent`: `inside`,
`not-applicable`, or a reason such as `default-branch`, `force-or-delete`,
`ref-outside-envelope`, `pr-target`, `registry-write`, `egress-host`, or
`not-admissible`. Lockfile-derived registry hosts admit reads only. Because
the two branch scopes only narrow authority, they are enforced now: an
out-of-scope push or PR adds `intent:push-ref` or `intent:pr-target`, which
gates the exact action. Every other verdict is shadow. Trusted task admission
lists the scopes, and both policy compilers accept them with case preserved.

Not yet in the grammar: per-host egress methods and path prefixes, a
publication grant, PR counts, and additional protected file patterns.

Exit criteria:

- every action class has an envelope match function with positive and
  negative tests;
- Example A's suite runs with envelope-derived approval counts recorded beside
  today's floor-derived counts;
- envelopes round-trip through the policy compiler with differential checks.

## 6. Workstream 2: payload provenance

This is the main trusted-code workstream. It needs no harness cooperation.

### 6.1 Content store and confidentiality index

The broker keeps a bounded, run-local store of content fingerprints with
`(integrity, confidentiality, source)`:

- **Admitted workspace content.** At admission, trusted code reads the `HEAD`
  tree with the existing hardened Git constructor
  (`keel_provenance::trusted_git_command`) and indexes text blobs under a size
  bound.
  - Integrity: rank 2 by operator acceptance at admission ("the repository as
    committed").
  - Confidentiality: `private` by default; `public` only if the operator
    declares a public repository at admission.
  - Paths matching secret patterns (`.env*`, `*.pem`, `id_*`, credential
    files) are `secret`.
- **Mediated egress responses:** rank as classified today, `public`.
- **MCP results** delivered through the trusted path, labeled per tool.
- **Model `tool_use` inputs** reassembled from responses, carrying the
  producing turn's control-influence rank (§8).

Fingerprints use line hashes for structured matching and winnowed byte
shingles for fragment matching (MOSS-style: rolling hashes over k-byte
windows, keeping each window's minimum). That detects verbatim fragments of at
least *k* bytes, embedded anywhere in a payload, with bounded memory.

### 6.2 Effects whose payloads are checked

| Effect | Where trusted code sees the bytes | Check |
|---|---|---|
| Egress request bodies, paths, and query strings | Decrypted at trusted TLS termination (the body digest is already computed) | Confidentiality fragments against sink clearance |
| PR title and body | The trusted PR POST through TLS, already bound by an effect permit | Confidentiality against clearance; integrity of text |
| Git push | The digest-bound pack in the receive-pack POST | Integrity of every new blob entering a `protected` ref or path; confidentiality against clearance |

**Push derivation without new trusted parsing.** The kernel writes the exact
digest-bound pack bytes into a kernel-private directory and runs
`index-pack` and `cat-file --batch` with the hardened host Git. It never trusts
untrusted `keel-gitd`'s object enumeration. Pack parsing therefore stays in
Git, which is already a pinned host dependency, rather than in Keel's TCB.

Each changed blob is classified:

- **unchanged:** matches an admitted blob;
- **model-authored:** matches a model `tool_use` input, and carries that
  turn's rank;
- **unmatched:** produced by a build, a tool, a workspace process, or fetched
  content. Rank 0.

A push of unmatched or rank-0 content into a `protected` sink is a data-flow
violation. The gate shows the exact hunks and their classification.

### 6.3 Implemented increment (shadow), D47

- **Index.** `keel_provenance::PayloadIndex` reads the `HEAD` tree with the
  hardened host Git at admission.
  - It indexes text blobs up to 1 MiB, and 64 MiB in total, as winnowed
    fingerprints with *k* = 48 and *w* = 24. Any shared run of at least 71
    normalized bytes is detected.
  - Credential-shaped paths are `secret`; everything else is `private`.
  - Submodules, binaries, and uncommitted files are not indexed.
  - `workspace:public` skips the index.
- **Scan.** At trusted TLS termination, every decrypted non-model request
  calls `EgressRequestAuthorizer::observe_payload`. The broker scans the
  target and body, after undoing percent and JSON string escaping, and judges
  them against the destination's clearance:
  - the GitHub origin's Git and API paths are cleared for `private`;
  - the model host is cleared for everything and is not scanned;
  - every other host is `public`.
- **Record.** The `FlowVerdict` is stamped on the action and audited as
  `flow`. It is shadow only.
- **Live check.** Run on a synthetic repository, a host V8 script that POSTed
  a committed note to an admitted registry was recorded as
  `intent=registry-write flow=private-to-public:9`.

**Push-content integrity, implemented (shadow), D52.** The plan's blob
classification needed a record of model-authored content, which is part of
workstream 4. So this increment builds that piece first:

- after each complete, successful model response, `keel-secrets` reassembles
  tool-call inputs (including streamed `input_json_delta` fragments) and
  records the line fingerprints of every string argument in a run-local
  `ModelOutputIndex`;
- `keel-gitd` protects CI configuration alongside manifests and sends the
  diff of protected files, plus every file of a default-branch push, capped
  with a truncation marker;
- the kernel counts added lines the model never emitted and stamps
  `IntegrityVerdict` (`accounted`, `unaccounted:U/N`, `uninspectable`).

It is audited as `integrity`, shown at the gate, and counted as a prompt by
`keel report --axes`.

Still to do:

- kernel-private derivation of pushed content from the digest-bound pack,
  instead of trusting `keel-gitd`'s diff;
- PR bodies sent through the external-action channel rather than raw egress;
- the §4.3 enforcement rules;
- shingle-size tuning against the Example suites.

### 6.4 Exit criteria

- planted canaries in admitted private files are detected in egress bodies,
  PR bodies, and pushes, verbatim and embedded, above *k* bytes;
- pushed blobs are re-derived from the digest-bound pack, with tests that
  `keel-gitd` lying about object contents changes nothing;
- the false-positive rate of fragment matching on Example A and B suites is
  measured and reported;
- paraphrased and encoded exfiltration are included as negative tests that
  document what is not caught.

## 7. Workstream 3: schema-bounded quarantine extraction

This is a trusted channel for raising the integrity of untrusted content. It
uses the same move Keel already makes for policy compilation:

1. The harness calls a Keel-provided MCP tool, `keel.extract`, naming the
   content: a mediated response digest, or an MCP result. It also names a
   schema from a closed, operator-accepted registry, for example
   `issue-triage: {kind: enum[bug, feature, question], files: [path ≤ 8],
   severity: enum[low, medium, high]}`.
2. The kernel runs a separate model call over the content it holds by digest,
   with tools disabled and structured output constrained to the schema. The
   call goes through the broker under the run's model budget. Keel does not
   trust the harness to perform it.
3. Trusted code validates the output against the schema. Only enums, bounded
   numbers, and identifiers that must match admitted names (paths in the
   admitted tree, refs in the envelope) are permitted. Free text is not.
4. The result is delivered at rank 2, with a source of "extracted from digest
   D by schema S".

The bound comes from the schema's bandwidth, not from the model behaving well.
A schema with a few enums cannot carry "force-push to main". Schemas are
reviewed artifacts, like policy IR.

A compartmented variant runs the same extraction in a fresh quarantine vertex
for content that must not touch the main guest at all. This is the project
brief's "fresh vertex per untrusted read", as a designed feature.

Exit criteria:

- the extraction output validator rejects free text, unadmitted identifiers,
  and out-of-range values, and is fuzzed;
- Example B tasks complete with extraction replacing a measured share of
  floor lifts;
- an injection suite shows that adversarial content cannot move an extracted
  result outside its schema.

## 8. Workstream 4: per-turn context provenance (control-influence axis)

This refines axis 3 and implements the
[roadmap item](../ROADMAP.md#per-turn-content-provenance). It runs in shadow
mode until measured.

### 8.1 Request walking

At trusted termination, after `sanitize_model_request` parses the JSON, the
walker ranks every content block in `system`, `tools`, and `messages`. It
supports the Anthropic Messages shape and Bedrock `InvokeModel` with the
Anthropic body.

| Block | Rule |
|---|---|
| assistant `text`, `tool_use`, `thinking` | exact digest match to a recorded response block |
| `tool_result` | exact match to recorded content; or a contiguous run of lines from one admitted blob after a fixed per-harness line-number normalization; otherwise 0 |
| user `text` | exact match to an operator submission (§8.2); otherwise 0 |
| `system`, `tools` | match to pinned harness constants or admitted blobs; otherwise 0 |
| images, documents | whole-payload digest match; otherwise 0 |

The turn floor is the minimum over its blocks. The audit record names the
lowest-ranked blocks by digest, source, and position, without content. Line
runs must be contiguous and come from a single blob, so trusted lines cannot be
reassembled into a new instruction.

### 8.2 Operator input

Trusted `keel-input` reconstructs submitted lines from keystrokes with a
minimal line-editing model (printable characters, backspace, bracketed paste,
Enter) and records their digests at rank 3.

### 8.3 Binding actions to turns by host-observed timing

The guest cannot raise an action's rank by claiming it came from a clean turn.
Binding therefore uses timing the host observes:

- a turn is **open** from the response that issued its `tool_use` blocks
  until a later request carries a `tool_result` for each of them;
- an action's control-influence rank is the minimum turn floor over all turns
  open when it arrives;
- an action with no open turn gets rank 0, because it was not model-directed;
- parallel subagents produce several open turns, and the minimum applies;
- attribution (§10) may only lower the result.

### 8.4 Content-addressed lifts

The gate lists the specific low-rank blocks behind a control-influence rank. A
floor lift vouches for those digests for the rest of the run, rather than
raising a session number.

### 8.5 Shadow mode

`turn-shadow` computes and audits per-turn floors beside the session scalar
and changes no decision. Promotion to enforcement requires, on the Example A
and B suites:

- the share of actions where the per-turn rank differs from the session
  scalar, and the resulting change in escalations under §4.3;
- the block match rate by kind;
- time to recovery after untrusted content enters context;
- zero planted-canary cases where an action causally downstream of rank-0
  content receives a higher rank.

### 8.5.1 Implemented increment: the digest log, D54

Trusted termination now records every model request's blocks and every
complete, successful response's blocks, as one `kernel.model-context` audit
record each, bound to the authorizing action. A block's digest covers its
identity-bearing fields (text; thinking without its signature; tool-use id,
name, and input; tool-result id, content, and error flag) with cache markers
removed, so a response block and the same block carried back in a later
request share a digest. Each record holds the ordered digest sequence; place,
kind, size, and tool-use identifier are written only the first time a digest
appears in the session, which keeps a long conversation's log roughly linear
in new content.

`keel report --context` reads only sealed, authenticated chains and reports,
per session:

- assistant blocks the model emitted versus those it did not (compaction
  summaries, harness-written history, or forgery);
- tool results bound to a model tool call versus unbound;
- requests with no tool output in context, the only ones a per-turn rank could
  place above 0 under §8.1;
- how many distinct system prompts and tool sets the harness sent.

Not yet recorded: operator-input digests (§8.2), admitted-blob line runs for
tool results, and action-to-turn binding (§8.3). The log changes no decision,
and a failure to write it is ignored.

### 8.6 Expected weakness

Bash tool results match nothing and stay rank 0 while in context, and
harnesses inject dynamic system and user content. On coding tasks, the
per-turn rank may rarely exceed the session scalar. Under this design that is
an acceptable outcome. Axis 3 then stays coarse, while axes 1 and 2 carry most
decisions. A negative result is still publishable, and the gate improves
anyway, because it can name the exact content behind a low rank.

## 9. Workstream 5: second confinement layer inside the guest

This workstream is untrusted guest code and image configuration only. It adds
no trusted host lines.

**Implemented, D46, with one design change.** In the guest, virtiofs presents
the workspace as owned by `0:0`, so a separate workload UID could not write
it. The UIDs are therefore inverted:

- **The workload keeps UID 0 without capabilities.** The bounding set is
  empty, `SECBIT_NOROOT` and its siblings are locked, ambient capabilities are
  cleared, `no_new_privs` is set, and the capability sets are zeroed, so
  `exec` cannot regain privilege.
- **Guest services drop to service UID 900** after binding: the Git, egress,
  and MCP relays and the terminal bridge.

A workload without capabilities cannot signal, ptrace, or read the memory of
a different UID, so the plan's `hidepid` step is unnecessary.

The pieces:

- `keel-mcp-guest confine -- COMMAND` applies the cgroup, Landlock, capability
  removal, and seccomp, then `exec`s. The terminal bridge runs tmux through
  it.
- MCP moves to a service relay on loopback port 18082, since the confined
  harness cannot open vsock.
- The boot report runs `confine-check` in a confined child. That child tries
  vsock, packet, and raw sockets, user namespaces, `io_uring`, `mount`,
  module loading, signalling a service process, and a system-path write, and
  confirms a scratch write still works. The host refuses the boot unless
  every check holds.

`keel-mcp-guest` is the supervisor here, rather than a new `keel-guestd`
crate. A separate crate is deferred to W6, when it gains lineage tracking.

The guest kernel is Alpine `linux-virt` 6.12 LTS (D53), which provides
Landlock ABI 6. The workload's ruleset also scopes signals and abstract Unix
sockets to its own domain, so it cannot signal the supervisor or relays even
though it shares their UID namespace. The preflight checks that a signal to
PID 1 is refused. TCP rules (ABI 4) are deliberately left unhandled: the guest
has no network interface, so TCP reaches only loopback, where the relays are,
and port rules would break local test servers without narrowing egress.

Not yet done: the confinement result appears only in the boot report and the
host's refusal, not in `keel doctor` or the trusted audit enforcement-state
record. Carrying it into the audit record needs the runtime to hand it to the
kernel as an asserted, guest-reported fact.

- **Supervisor.** A Rust `keel-guestd` replaces the shell PID 1. It runs as
  root, owns every vsock connection to the host, and starts the harness. The
  current relays and terminal bridge move under it.
- **Unprivileged workload.** The harness runs as non-root, with a UID that
  matches the workspace owner. It has `no_new_privs`, no capabilities, its own
  cgroup v2 group with `pids.max` and memory limits, and `/proc` mounted
  `hidepid=invisible` so it cannot see or signal the supervisor.
- **Seccomp.** Deny with `EPERM`:
  - `socket` for `AF_VSOCK`, `AF_PACKET`, raw IP, and most `AF_NETLINK`;
  - `mount`, `pivot_root`, and namespace creation;
  - `bpf`, `perf_event_open`, `userfaultfd`, `io_uring_*`, module loading,
    `keyctl`;
  - `ptrace`, `process_vm_*`, and nested user-notification filters.
  
  `connect` routes to user notification for attribution (§10.2).
- **Landlock.** The pinned guest kernel is Alpine `linux-virt` 6.12 LTS, with
  Landlock compiled in and first in the default LSM order. It provides ABI 6:
  read-only system paths; read-write `/workspace`, `$HOME`, and `/tmp`; no
  `/run/keel` beyond the public CA and launch script; and scoping of abstract
  sockets and signals. ABI 4 TCP rules are not used (see above).
- **Limit.** This does not defend against a guest kernel exploit; the VM
  remains the outer wall. If the guest kernel falls, attribution degrades to
  `Unknown`, which is never more permissive than today.

Exit criteria:

- the workload runs non-root, without capabilities, under seccomp and
  Landlock, in its own cgroup;
- an adversarial suite fails, covering:
  - direct `AF_VSOCK` connect;
  - inspecting or signalling `keel-guestd`;
  - `mount`, `unshare -U`, module load, raw sockets;
  - writes outside allowed paths;
- a dev-workflow suite passes unchanged: `cargo test`, `npm ci && npm test`,
  `pytest`, and Git operations;
- confinement state appears in doctor, guest preflight, and the audit
  enforcement-state record.

## 10. Workstream 6: per-process attribution

**Implemented, D51, with these design choices:**

- **Supervisor.** The init script ends by `exec`ing
  `keel-mcp-guest supervise`, which becomes PID 1. It keeps root to read
  every process's file table. The kernel delivers no signal to PID 1 from
  inside the guest unless it installs a handler, so the UID-0 workload cannot
  kill it.
- **Lookup instead of seccomp interception.** The supervisor answers
  `tcp LOCAL PEER` on a socket only the service UID can reach. It finds the
  owning process through `/proc/net/tcp` and `/proc/*/fd`, rather than by
  intercepting `connect` with seccomp. `cn_proc` lineage and
  `SECCOMP_ADDFD` stay deferred: a process that exits before its connection is
  examined is reported as unknown, which never widens authority.
- **Ancestry.** The supervisor walks parent links to PID 1, keeping up to 16
  processes. A process is workspace code if its executable or a script
  argument lies under a writable root, or its working directory is a
  `node_modules` under one. Read-only system paths are not, because Landlock
  keeps the workload from writing them.
- **Transport.** The Git, egress, and MCP relays (`relay ... --attribute`)
  send a `KEEL-ORIGIN-V1` frame ahead of their traffic. The host VZ backend
  and gitd forward it to the kernel, which accepts the frame before any
  broker request. The MCP service forwards its connection's origin on each
  pull-request action and on the GitHub API connections behind pull requests
  and issue reads (D55).
- **Use.** The kernel stamps a `ReportedOrigin` on the action, audits it as
  `origin`, and renders "issued by (guest-reported)" at the gate. It adds
  `origin:workspace-code` for Git pushes and pull requests whose ancestry
  includes workspace code.
- **Not yet.** An MCP connection is attributed once, when it opens, so every
  call on it shares the origin of the process that opened it (normally the
  harness's stdio bridge). Unknown origins are recorded but not gated. Matching origins to model tool
  calls waits for workstream 4.

### 10.1 Lineage

`keel-guestd` follows fork, exec, and exit events through the `cn_proc`
netlink connector, which is present in the pinned kernel. It keeps a process
table keyed by `(pid, start_time)`, with executable path and cached digest,
bounded `argv`, and parent links. Each process gets a code-origin class:

- `image`: executable under read-only image paths;
- `workspace`: code under `/workspace`, `$HOME`, or `/tmp`, including
  `node_modules/.bin` and build outputs;
- `unknown`: anything the table cannot classify.

A process is workspace-tainted if it, or any ancestor up to the harness, ran
workspace code.

### 10.2 Exact connection attribution

`keel-guestd` handles the workload's `connect` through
`SECCOMP_RET_USER_NOTIF`:

1. It validates the destination.
2. It snapshots the caller's lineage while the caller is stopped.
3. It installs a supervisor-relayed socket into the caller's file descriptor
   with `SECCOMP_ADDFD_FLAG_SETFD`, and returns success.

The relay prefixes a bounded attribution frame. Each connection is attributed
at creation, with no race against `/proc`.

### 10.3 Host handling and use

The trusted kernel parses the frame into an `AssertedOrigin` on `Asserted`.
Missing or malformed frames produce `Unknown`. Origin feeds every axis, only
as a narrowing input:

- **data flow:** a blob or body written or sent by a workspace-tainted
  process is unmatched-origin content (rank 0), even if it would otherwise
  match a model `tool_use`;
- **intent:** Git push, PR creation, publication, and credential-bearing
  egress from workspace-tainted processes are outside any envelope unless the
  envelope names that build step;
- **control influence:** `Unknown` origin, or no matching tool call, yields
  rank 0.

The gate renders the origin, for example: "issued by `git push origin main`,
from Bash tool call `toolu_…` in turn 14; ancestors claude → bash → git".

Exit criteria:

- every relayed connection carries a parsed origin, and the audit record
  includes its digest;
- tests cover PID reuse, short-lived processes, fork-exec races, and attempted
  frame forgery;
- a poisoned `postinstall` attempting a push and an exfiltration POST is
  refused, with a rule naming the tainted ancestor.

## 11. Trusted-code budget

The reserve was 2,653 lines under the 16,000 ceiling at D44. Spending so far:

- W1's first increment used 155 lines (D45).
- W2's confidentiality increment used 435 lines (D47).
- The unrelated model-budget fixes used 187 lines (D48 and D49).
- Marking setup legs `not-applicable` used 7 lines (D50).
- W6 process attribution used 193 lines (D51).
- W2 push-content integrity used 243 lines (D52).
- The W4 context digest log used 235 lines (D54).
- The unrelated OpenRouter provider used 83 lines (D56).
- The run admission manifest used 249 lines (D57).
- The triage profile's scope used 176 lines (D58).
- The read-only root disk used 5 lines (D61).
- Recording guest memory used 6 lines (D62).
- Reading an unsealed chain's prefix used 8 lines (D63).
- Building the trusted runtime cleanly on Linux used 2 lines (D64).

That leaves 669. `keel report --axes` (untrusted) now measures the
action-centric rules against today's prompts. Estimates:

| Workstream | Item | Crate | Lines |
|---|---|---|---:|
| 1 Intent | Envelope IR, matching, admission rendering | keel-policy, keel-kernel, keel-input | 250 |
| 2 Payload | Content store, labels, winnowing index | keel-provenance | 300 |
| 2 Payload | Body and PR checks at trusted TLS | keel-secrets | 120 |
| 2 Payload | Digest-bound pack derivation with host Git | keel-provenance | 150 |
| 2 Payload | Sink labels and §4.3 rules | keel-kernel, keel-policy | 130 |
| 3 Extraction | Schema registry, validator, kernel-run model call | keel-kernel, keel-secrets | 250 |
| 4 Context | Request walker and block ranking | keel-secrets | 300 |
| 4 Context | Response block reassembly (SSE and event stream) | keel-secrets | 250 |
| 4 Context | Operator submissions, turn table, digest lifts | keel-input, keel-kernel | 280 |
| 6 Attribution | `AssertedOrigin`, policy facts, gate rendering | keel-kernel | 170 |
| **Total** | | | **~2,200** |

Workstreams 1–3 and 6 total about 1,370 lines. Workstream 4 adds about 830 and
would leave under 500 lines of reserve. Workstream 4's trusted code therefore
lands last, and only if its shadow results justify it.

Workstream 4's shadow phase can start cheaper. Record only a per-block digest
log at trusted termination, using the walker without streaming reassembly or
lifts (about 250 lines), and analyze it offline against the content store.

## 12. Sequencing

~~~text
W5 confinement (guest-only) ─────► W6 attribution ───────────────┐
W1 intent envelopes ──► W2 payload provenance (shadow → enforce) ─┼─► §4.3 rules
                         W3 quarantine extraction ────────────────┘
W4 per-turn: digest-log shadow ──► measure ──► enforce only if justified
~~~

1. **First:** W1 and W2 in shadow, W5, and the W4 digest log, all in
   parallel. They change no decision, and the shadow data answers whether the
   three-axis rules reduce escalations at equal safety.
2. **Second:** W2 enforcement with the §4.3 rules, and W6 attribution.
3. **Third:** W3 extraction, which needs the content store and a model-call
   path the kernel owns.
4. **Last:** W4 enforcement, gated on its measurements.

This work fits after R1, since admission must bind the envelope, workspace
commitments, sink labels, harness constants, and the new guest image. It feeds
R2, whose adversarial suite gains canary exfiltration, pack-forgery,
schema-escape, attribution-forgery, and confinement-escape cases.

## 13. Relationship to prior work

- **Low-water-mark integrity (Biba, LOMAC):** today's floor, with its
  label-creep failure.
- **Decentralized IFC with declassifiers (Asbestos, HiStar, Flume):** source
  of the compartment and narrow-declassifier structure in §7.
- **CaMeL (dual-LLM with capability-tracked values) and FIDES (IFC for agent
  planners):** the strongest designs, but they need a harness the runtime
  controls. Keel cannot impose them on Claude Code. Keel's own V8 harness and
  SDK could adopt value-level labels as a later research track.
- **The "lethal trifecta":** private data, untrusted content, and an external
  channel. The §4.3 rules make it an emergent condition rather than a
  hand-written rule.

## 14. Limits

- Paraphrased, summarized, or encoded exfiltration defeats fragment matching.
  This is strictly better than today, which detects none.
- Envelopes cost operator effort. If too broad they are meaningless; if too
  narrow they produce escalation spam. Defaults must be measured.
- Quarantine extraction is bounded by schema bandwidth, not model behavior.
  Schemas need review.
- Attribution is only as sound as the guest kernel.
- The model endpoint is cleared for `secret` by necessity. Keel cannot stop
  the model provider from receiving context.

## 15. Open questions

1. Should admitted workspace content default to `private` and rank 2, or
   should the operator designate paths and leave the rest at `public` and
   rank 0?
2. What shingle size *k* balances fragment detection against false positives
   on common code idioms?
3. Which Claude Code settings minimize dynamic content injection without
   breaking it?
4. Can the kernel-owned extraction call share the run's model credential and
   budget without widening the harness's model authority?
5. Should `keel-guestd` be a new untrusted crate or live in `keel-mcp`?
6. Does a 6.12 guest kernel boot cleanly on the current Virtualization.framework
   and virtiofs path?
