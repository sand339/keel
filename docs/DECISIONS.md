# Keel — open decisions

Decisions that shape the build and are not yet made. Each has a recommendation and
the thing that would change it. Resolve D1–D3 in Phase 0.

---

## D1 — Isolation backend and primary platform

**Options.** (a) Linux-primary via cloud-hypervisor or Firecracker, macOS as a
degraded dev environment. (b) macOS-primary via libkrun or Virtualization.framework.
(c) Both as equals behind a trait.

**Recommendation: (b), reluctantly and conditionally.** The usual advice is
Linux-primary — the microVM path is mature there and the minimal-device-surface
argument is strongest. But this is a *personal* runtime and you are on darwin. A
runtime whose good path is a Linux box you do not use daily fails success criterion
2, and macOS-native isolation is contribution 6. Choose (b) if the Phase 0 spike
gives a real VM-per-vertex with a workable vsock story; fall back to (a) if not.

**What changes it.** The spike. Do not decide this from documentation.

**Do not choose (c) by default.** Two first-class backends is the most common way a
security project becomes a portability project.

---

## D2 — Policy engine: Cedar, Rego, or both

**Recommendation: Cedar at runtime, Rego as oracle.** Cedar is Rust-native, has
formal semantics, and ships automated permissiveness analysis — exactly the missing
check on LLM-compiled policy. Its forbid-wins default-deny matches the
violations-set pattern. `regorus` earns its place as an independent second
implementation for differential testing, reusing the bundles in `../paper/policy/`
that already have passing suites.

**What changes it.** If Cedar cannot cleanly express stateful predicates over
`SessionFacts` — the set membership and rate questions in `ARCHITECTURE.md` §7 —
flip it: Rego at runtime, Cedar as oracle. Test this in Phase 0 with three real
rules, not later.

**Watch for.** Computing the interesting parts in Rust and handing the engine a
pre-digested boolean. That is not policy, it is a rubber stamp with a DSL attached.
The engine must see the facts.

---

## D3 — How the harness gets into the vertex

The practical question that decides daily usability.

**Options.** (a) A pre-verified base image with Claude Code / Codex preinstalled,
mounted read-only. (b) Install the harness at vertex boot, before the first model
call, then lock the network. (c) Mount the host's installed harness into the guest.

**Recommendation: (a), with (b) as the transitional posture.** (a) is the
supply-chain-inverted form the paper argues for: admission to the base is the single
trust decision, made once, offline, with provenance and signature checks. (b) is
weaker — the install step is itself attack surface and runs at trust-zero time —
but it is strictly better than an open network throughout the session, and it is
honest about being an intermediate step. (c) is tempting and wrong: your host
harness install is not a verified artifact, and it drags host paths into the guest.

**Consequence to plan for.** Harness updates become a base-image rebuild. That
friction is the cost of the property; do not relieve it by opening a registry route.

---

## D4 — Vertex granularity

**Options.** (a) One long-lived vertex, reused across tasks. (b) One vertex per
task. (c) One vertex per *trust epoch* — fork a fresh vertex whenever the floor
would drop, or before a privileged step.

**Recommendation: (b) by default, (c) as the Phase 4 experiment.** Per-task is the
honest ephemeral posture and the cheapest reset path. (c) is the brute-force
alternative to provenance flooring and may beat it outright: a vertex that has
never read untrusted content needs no floor at all.

**Note the tension.** (c) fights hard against harness session continuity — Claude
Code's context, its `--continue` state, in-guest package state. That tension is a
real finding about the design space, not an implementation detail, and it is worth
writing up either way.

---

## D5 — Credential model for the harness itself

Claude Code authenticates with either an API key or an OAuth token; Codex differs.
The harness must believe it has credentials while holding none.

**Recommendation: sentinel values in the guest, swapped host-side at the proxy,
with OAuth preferred where available** (the token is short-lived and the refresh
token never enters the guest). The kernel refreshes proactively and rewrites the
guest-visible credential file before expiry, so the guest never holds anything with
a long life.

**Watch for.** Two failure modes worth naming: a refresh-token rotation race if
both kernel and guest can refresh (so only the kernel may), and audit logs
capturing the *real* value after swap (so redaction must cover both forms).

---

## D6 — Does Keel wrap the harness, or host it?

**Options.** (a) Keel launches the harness inside the vertex and bridges its TUI.
(b) Keel exposes only MCP and you launch the harness yourself.

**Recommendation: (a).** (b) is architecturally cleaner and practically useless —
the whole value proposition is `keel run claude` being as pleasant as `claude`.

**The line to hold:** launching is not trusting. The harness is untrusted whether
Keel started it or not, and no code path may treat "we spawned it" as evidence of
anything. The launcher lives outside the TCB.

---

## D7 — Provenance rank granularity

**Options.** (a) The four ranks from the paper. (b) A per-source-domain lattice.
(c) Four ranks plus a queryable read-set the policy can inspect.

**Recommendation: (a) for v1, (c) as the likely v2.** Four ranks is coarse and that
coarseness is the honest starting point; a lattice invites the illusion of precision
the mechanism cannot deliver. (c) becomes attractive once stateful policy exists —
"escalate if this vertex has read anything from outside my own organisation" is a
rule people actually want, and it needs the read-set rather than a finer rank.

**Known cost of (a).** Your own wiki page and a random forum post are both rank 0.
Users will find this maddening within a week, and their complaints are data about
where (c) needs to land.

---

## D8 — Positioning

Is this *a runtime you use* or *the artifact behind a write-up*?

**Recommendation: both, artifact-first, honestly labelled.** "Research prototype,
APIs will change, here is the threat model, here are the residuals" ages better
than an implied production claim — and a security tool that oversells is worse than
one that undersells. But criterion 2 means you must genuinely use it, so the
usability work is not optional decoration.

---

## D9 — Relationship to IronCurtain

Keel overlaps IronCurtain substantially, and IronCurtain is ahead on the node
contract: shipped, tested, with a working policy compiler, a mux TUI, and
Docker agent mode that already runs Claude Code with a MITM credential swap.

**Recommendation: be explicit in the write-up.** Cite it as prior art, state the two
real differences — a size-capped TCB and native macOS isolation — and do not pretend
the node contract is novel. Where their design is better (argument role
classification, conditional annotations, the verify-and-repair loop, trusted input
capture in command mode), adopt the idea and say where it came from.

**The uncomfortable option, kept on the table.** Contributions 2, 3, and 4 —
provenance accounting, stateful policy, egress-as-policy — are engine-agnostic and
are already on IronCurtain's own TODO as its top-priority gaps. They would land
upstream as real features, benefiting from a codebase that already solved the
boring 80%. The only reasons to build separately are the TCB thesis, which cannot
be retrofitted, and native isolation, which is a rewrite in their stack.

**Decide this honestly before Phase 2**, because that is where the divergence
becomes expensive. Phase 1 is a reimplementation of things that already work; the
sunk cost after Phase 2 will make this question harder to ask, not easier.

---

## D10 — V8 isolation profile

**Options.** (a) V8 only inside the microVM. (b) V8 only as a fast host
sandbox. (c) Both, with different assurance claims.

**Decision: (c), with `vm-v8` recommended.** Node/V8 inside the existing
microVM preserves Keel's assumption that the interpreter will be escaped.
Pinned Deno on the host is useful for short source-controlled evaluators, but
its engine and permission system become a semi-trusted core. The host mode is
therefore named `v8-sandboxed`, requires the exact
`isolation:v8-sandboxed` policy capability, starts with a clean environment,
and can reach only Keel's loopback broker proxy.

There is no fallback between profiles. A VM startup failure remains a failure.
Engines, launchers, SDKs, and the loopback proxy stay outside the first-party
Rust TCB. Trusted `keel-input` spends 25 lines of the D29 reserve to validate
the mode/harness pair and downgrade grant independently of the CLI.

Bare `keel mux` exposes all three profiles before workspace selection. V8
profiles require an existing worktree and relative JavaScript entry file; the
CLI independently canonicalizes the renderer's candidate. Selecting the host
profile does not manufacture its policy capability, and V8 tab labels report
the active boundary. This launcher work adds no trusted code.

**What would change it.** If benchmarked VM startup is acceptable, remove the
host mode. If a host engine escape is demonstrated in the supported Deno
version, disable `v8-sandboxed` until the pinned artifact is replaced and the
regression is covered. Do not describe host V8 as equivalent to the VM.

---

## D11 — Follow-up security hardening and line-budget reallocation

**Decision.** Input provenance is fail closed; only the direct terminal launch
marker is approval-capable. Trusted host Git uses one environment-cleared
constructor with repository execution hooks, credentials, SSH, prompts, and
pagers disabled. Admission and teardown hash `.git/config` and `.git/hooks`,
and a change is both audited and printed as a security warning.

Audit streams end with a signed seal committing to the record count and prior
tip, call `sync_data` after each record, record structural rejections, and write
an `attempted` event before external execution. The verifier rejects missing,
malformed, or non-terminal seals. The former in-process approval signature was
removed because it crossed no trust boundary; the synchronous trusted gate
already receives the exact kernel-owned action.

GitHub credentials are acquired only for runs declaring a GitHub effect,
GitHub is excluded from fungible same-host grants, repository recipients are
parsed as exact `owner/repository` values, and authenticated issue reads are
restricted to the admitted exact repository scope. Private Git push credentials
are loaded only for `push:branch` and cover only that repository's receive-pack
advertisement and authorized receive-pack POST. Host V8 receives only one
preselected loopback proxy port. D18 separates the issue-read and PR effects.

**Budget.** The aggregate 14,000-line ceiling remains unchanged. The removal of
the approval-token machinery and the remaining reserve are reallocated across
`keel-provenance`, `keel-audit`, `keel-secrets`, and `keel-input`. Per-crate
limits remain ratchets and include tests and binaries.

---

## D12 — Task admission, explicit grants, and honest audit metrics

**Decision.** Keel reviews declared task authority once on the trusted terminal.
Registry egress inferred from lockfiles is a suggestion in that manifest, not
an ambient grant. Admitted non-model hosts and ordinary feature-branch pushes
do not prompt again; pull requests, force/default-branch pushes, manifest
changes, and undeclared effects retain their action-level gates.

A one-action approval no longer silently creates a reusable egress grant. The
operator must choose `G` for the displayed bounded grant; credential-bearing
and high-impact effects remain ineligible. Audit gate events record their
authority and whether a human prompt was actually presented, so `keel report`
separates visible prompts from automatic deny-only decisions. Verification
distinguishes a sealed stream, an authenticated but unsealed prefix, legacy
signatures, and invalid data.

Git author strings are no longer treated as authenticated provenance. Direct
workspace/history classification fails closed at rank zero pending the planned
per-turn content ledger.

**Budget.** Removing the Git-author classification path funds the trusted
admission and audit changes without raising the 14,000-line ceiling. New crate
ratchets total 13,977 lines and restore a 23-line unallocated reserve.

---

## D13 — Lossless trusted terminal takeover

**Decision.** The sandboxed untrusted renderer owns a canonical terminal model
implemented by pinned `@xterm/headless` 6.0.0, the same emulator architecture
used by IronCurtain, with pinned `@xterm/addon-serialize` 0.14.0 producing
replayable screen state. It consumes every guest byte in order and sends the
trusted terminal owner only bounded, length-prefixed complete-screen snapshots. Trusted approval can discard
snapshots while it owns the display, then request one current snapshot on
resume. The guest's incremental renderer and the physical terminal therefore
cannot diverge because Keel withheld a delta.

Replies produced by the terminal model for device and cursor queries use a
separate bounded frame and are routed back to the untrusted guest, never to the
physical terminal or trusted input path.

Pending approval changes the terminal title and temporarily replaces guest
tmux's controls footer with a reverse-video notification; the trusted takeover
remains the only approval authority. Resize updates are serialized into the
same renderer protocol and sent to the guest PTY with identical dimensions. The old
seam parser, takeover replay buffer, width bounce, tmux refresh injection, and
Ctrl-L repair path are removed from the trusted component.

**Budget.** The change reduces `keel-input` below its existing allocation; the
14,000-line aggregate ceiling does not move.

---

## D14 — Live floor lifts and non-authoritative continuation state

**Decision.** A floor lift must mutate the exact live kernel that will evaluate
later actions. The attached mux command `Ctrl-A /floor-lift [rank]` and the host
command `keel floor lift SESSION [rank]` both send a bounded request to that
session. The trusted runtime invokes the kernel's operator channel, renders the
read history through secure attention, applies the lift only after the typed
challenge, and records it in the session's audit chain. Detached and
terminal-less sessions cannot lift.

`floor.json` is kept as shutdown status evidence, not authorization. It sits in
an untrusted session directory, so a new or continued broker never imports its
floor or attestations. Production admission instead records direct workspace
exposure at rank 0. This deliberately supersedes the earlier persisted-floor
continuation design.

**Budget.** Removing the obsolete parallel lift kernel from `keel-input` funds
the live control in `keel-kernel`: kernel 4,758, input 2,892, and
`13,997 allocated + 3 reserved = 14,000`.

---

## D15 — Admitted per-run model ceilings

**Decision.** Model token and cost ceilings are explicit run inputs. The CLI
accepts `--model-token-budget` as an integer and `--model-cost-budget` as an
exact decimal US-dollar amount, converting the latter to micro-US-dollars
without floating point. Defaults remain 1,000,000 cumulative tokens and USD
10.00 per run. D49 later raised the cost default to USD 20.00.

The request file is untrusted. Trusted input independently parses and validates
both integers. A value at or below the corresponding kernel default narrows
authority; raising either value requires foreground trusted task admission.
The admission view prints both exact ceilings, the parsed values stay in the
trusted runtime intent, and that intent supplies them directly to the broker.
The authenticated enforcement-state record reports the same installed values.

**Budget.** The hard ceiling and crate allocations do not move. Existing model
budget and runtime-sandbox tests were preserved as integration/support tests
outside production `src`; recording that relocation matters because the TCB
ratchet deliberately counts `src` with any inline tests it contains. The
trusted implementation remains below its existing kernel and input ratchets,
with `13,997 allocated + 3 reserved = 14,000`.

---

## D16 (condensed log; PLAN D39) — Approval waits, denial history, and model charges have explicit lifecycles

**Plan mapping.** This file is a condensed decision log with its own sequence;
this entry records the current guarantees established as D39 in `PLAN.md`.

**Decision.** Egress authorization uses the two-stage `KEEL-EGRESS-V2`
protocol. A trusted broker that has parsed a complete request and acquired the
serialized adjudication slot returns `P` within the five-second machine
acknowledgement window; this byte grants no authority. A queued request has no
`P` and no active human-decision clock. The client then waits up to five
minutes for terminal `A`, `D`, or `E`. The trusted gate expires after 4 minutes
45 seconds, invalidates its pending decision, clears the trusted-input
notification, and returns denial before the client deadline. Peer hangup or
broker shutdown cancels a still-pending decision, with cancellation checked again around
execution and before grant creation. Late approval cannot start an action or
create a grant; an effect already in flight cannot be rolled back.

Repeated-denial policy is no longer driven by the cumulative session counter.
The kernel canonicalizes the current action class and target into an opaque
scope digest, and Cedar evaluates behavioral denials for that exact scope in a
15-minute trailing window. Resource outcomes—including model-budget, quota,
provider, and transport failures—do not count. An approval prompted by
`repeated-denials-same-scope` clears only that reviewed scope; cumulative
denial totals remain immutable audit statistics.

Model requests have a kernel-owned reservation state machine:
`authorized-unsent` becomes `send-attempted` immediately before the first
upstream application byte and then reaches exactly one terminal outcome.
Definitely unsent work is `released-unsent`; complete trusted usage is
`settled-actual` (or `overrun`); an ambiguous post-send failure is
`committed-conservative`. Non-success responses, even those carrying a
usage-shaped body, and disconnects are not proof that a provider performed no
work. Terminal reservation outcomes and typed,
scoped denial metadata are written to the authenticated audit stream.

**Why.** The former single short timeout made a correct human gate look like a
dead broker, while the global denial counter let unrelated budget failures
turn admitted Bedrock traffic into an approval loop. Refunding a request after
a post-send reset created the opposite accounting error: an attacker could
obtain uncharged provider work by breaking the return path. Explicit states
make liveness, behavioral review, and resource accounting separate concerns.

**Budget.** The prior 14,000-line ceiling was exhausted and this cross-cutting
change could not be represented as a truthful reallocation. Measured final
ratchets are kernel 5,885, policy 852, provenance 914, audit 1,164, secrets
4,140, and input 2,865: 15,820 allocated lines. The ceiling is explicitly
raised to 16,000 with 180 lines left unallocated. No crate receives speculative
headroom; subsequent growth still requires a recorded reallocation or another
explicit reconsideration of the small-reviewable-kernel claim.

---

## D17 (condensed log; PLAN D40) — Gate the decrypted request and make teardown observable

**Decision.** CONNECT and the front-side TLS handshake are inspected local
setup, not network authority. They may establish Keel's terminating side of the
connection, but may not resolve a name or open an outbound socket. Keel first
parses and authorizes the decrypted HTTP method, path, and body digest; only an
allowed request can invoke the resolver/connector and later credential
substitution. A caller half-close cancels any pending operator decision, makes
late `A` and `G` invalid, and prevents grant creation.

Persistent sessions now preserve their terminal exit status for a bounded late
attach. Renderer replies that race a completed short-lived workload are
advisory and cannot replace its successful status with `EPIPE`. `keel stop`
sends a cooperative shutdown control, waits for broker shutdown and the audit
seal, and reports forced fallback as failure. Canonical xterm frames and tty
cleanup reset horizontal margins, origin mode, and vertical margins before a
full repaint.

Provider and repository compatibility stays fail closed. Reviewed Bedrock
tariffs recognize `global.anthropic.*` inference-profile IDs; an explicitly
pinned unknown model is rejected before guest boot. Ambient Git credentials
are ignored unless the task declares repository authority. When loaded, they
authenticate only the selected repository's receive-pack advertisement and
authorized receive-pack POST. Private GitHub issue GETs receive a credential
only under the distinct `github:read-private-issues` authority and for the exact
repository derived from that same trusted scope. `pr:create` remains a separate
write authority; public reads remain anonymous when no matching GitHub
credential was acquired.

**Why.** The release E2E found one request split into two prompts, approved
CONNECTs that never produced usable TLS, stale prompts surviving their client,
margin-dependent terminal corruption, short V8 jobs reported as broken pipes,
unsealed detached stops, rejected global Bedrock profiles, and private GitHub
operations that failed before policy evaluation. Each fix belongs at the
boundary that owns the missing fact rather than in UI retries or broader
credentials.

**Budget.** Regression-only support code is kept outside production `src`. The
16,000-line hard ceiling remains unchanged. `keel-input` receives 113 lines of
the prior reserve, moving from 2,865 to 2,978; total allocation is 15,933 with
67 lines still unallocated. This decision is D40 in the full plan.

---

## D18 (condensed log; PLAN D41) — Private issue reads are separate authority

**Decision.** `github:read-private-issues` is a closed, visible task capability.
It loads GitHub credentials only for an admitted run and binds authenticated
GETs to one positive issue number under the admitted exact GitHub repository
scope. `pr:create` neither grants nor exposes
private issue reads, and private reads do not authorize PR creation.

The authenticated receive-pack advertisement GET remains a Git protocol
preflight for that exact repository. It is authorized and recorded as inspected
egress, not misrepresented as a typed push decision; the later receive-pack
POST retains its independent push authorization and outcome audit.

**Budget.** The hard 16,000-line trusted ceiling does not move. After D17 moved
regression-only coverage out of production `src`, the final measured ratchets
are kernel 4,179, policy 852, provenance 914, audit 1,164, secrets 2,805, and
input 2,999: 12,913 allocated with 3,087 unallocated. The new authority stays
inside those ratchets; integration tests and untrusted endpoint normalization
do not enter the trusted production count.

## D19 (condensed log; PLAN D42) — A reusable grant dies with its originating request

**Decision.** An approval that requests a reusable egress grant does not make
that grant independently durable before trusted transport has an upstream
response ready for delivery to the still-live origin. Failed terminal-decision
delivery, model reservation, DNS/TCP/TLS setup, request forwarding, response
acquisition, or origin liveness revokes the action-owned grant. The broker's
peer monitor uses a non-consuming socket peek to distinguish live queued bytes
from readable EOF, so FIN cancels pending authority without taking bytes from
the application protocol.

**Budget.** The hard 16,000-line trusted ceiling does not move. This guarantee
assigns 83 lines of D41 reserve to `keel-kernel`, raising that crate's ratchet
to 4,262. Allocated ratchets total 12,996 and leave 3,004 unallocated.

## D20 (condensed log; PLAN D43) — Credentials cross only encrypted connections; host acceptance authorizes a policy

**Decision.** Sentinel substitution requires a TLS connection to port 443;
plaintext egress refuses any request that still carries a sentinel, so no
credential is written to an unencrypted upstream. The structural address check
judges IPv6 forms that embed an IPv4 address (mapped, compatible, NAT64, 6to4)
by that address and also forbids `0/8`, `100.64/10`, `198.18/15`, and `240/4`.
Git push assessment protects every default-branch candidate (`main`, `master`,
workspace HEAD, `origin/HEAD`) because the workspace is guest-writable, and a
ref deletion counts as force. A policy authorizes a run only when its content
hash appears in the host acceptance ledger written by `keel policy accept`;
the artifact's own status and hash can be recomputed by anything that can
write it.

**Residual.** A repository whose remote default is none of the candidates is
protected only when HEAD or `origin/HEAD` names it at mirror creation. Reading
the remote's own symref through the broker remains future work.

**Budget.** The hard 16,000-line trusted ceiling does not move. This decision
assigns 38 reserve lines to `keel-secrets`, raising that crate's ratchet to
2,843. Allocated ratchets total 13,034 and leave 2,966 unallocated.

## D21 (condensed log; PLAN D44) — The operator's wait holds only the adjudication slot

**Decision.** The kernel pipeline is `begin` (structural checks, windowed loop
detection, policy, provenance rank, budget reservation, reusable-grant use), a
gate decision, and `finish`. The broker holds its state lock for `begin` and
`finish` only; the human decision holds a separate gate mutex, which is the
serialized adjudication slot and still precedes `P`. Traffic that needs no
operator, and in-flight model and response bookkeeping, proceed while a prompt
is open. `finish` re-derives the action's reasons against the current session
and refuses an approval when any reason was not displayed. Reusable `G` grants
bind host, port, and method, waive only the rules the operator saw, and lapse
when the floor drops below its value at approval. Identical actions are a loop
only within a 60-second window, and the rejection is audited. The host V8
loopback proxy requires a per-run credential.

**Residual.** Same-user host processes outside Keel's sandboxes can drive the
trusted runtime from a pseudo-terminal they create; this is now a stated trust
assumption rather than a property the input-source checks claim.

**Budget.** The hard 16,000-line trusted ceiling does not move. This decision
assigns 312 reserve lines to `keel-kernel` (ratchet 4,574) and 1 to
`keel-secrets` (2,844). Allocated ratchets total 13,347 and leave 2,653
unallocated.

## D22 (condensed log; PLAN D45) — Every action carries its task-envelope verdict

**Decision.** The kernel stamps each action with whether it lies inside the
operator-admitted task envelope and records that verdict in the audit stream.
The envelope comes from the closed capabilities plus two branch scopes,
`push:ref:refs/heads/PATTERN` and `pr:target:BRANCH`. The scopes only narrow,
so a push or pull request outside them gates now. Every other verdict is
recorded in shadow, so the action-centric rules can be measured against
today's floor before they decide anything.

**Budget.** The hard 16,000-line trusted ceiling does not move. This decision
assigns 155 reserve lines: kernel 110 (ratchet 4,684), input 41 (3,040),
provenance 2 (916), and audit 2 (1,166). Allocated ratchets total 13,502 and
leave 2,498 unallocated.

## D23 (condensed log; PLAN D46) — The guest workload is confined a second time

**Decision.** Everything the guest terminal runs is wrapped by
`keel-mcp-guest confine`, which applies:

- capability removal: UID 0 kept, but no capabilities and no path to regain
  them;
- Landlock write restriction;
- a seccomp filter that removes vsock access and high-risk kernel interfaces;
- a bounded cgroup.

Guest services run under a separate service UID, so the workload cannot
signal or inspect them. The host refuses to boot a guest whose confined
self-check reports any missing layer.

**Why UID 0.** Virtiofs presents the workspace as root-owned inside the guest,
so a separate workload UID could not write it. Capability removal gives the
same separation from services without remapping files.

**Residual.** The layer is self-reported and sits inside the VM boundary: a
guest kernel exploit defeats it. Signal and abstract-socket scoping arrived
with the 6.12 guest kernel (D30); Landlock TCP rules are deliberately unused.

**Budget.** No trusted lines.

## D24 (condensed log; PLAN D47) — Outgoing payloads are judged against the committed repository

**Decision.** At admission the trusted runtime fingerprints the committed
`HEAD` tree: text blobs are private, and credential-shaped paths are secret.
The trusted TLS relay shows each decrypted non-model request to the broker,
which scans the request target and body and compares any matches with the
destination's clearance. The verdict is stamped on the action and audited as
`flow`. This increment is shadow: no decision reads it.

**Why fingerprints.** Winnowing guarantees detection of any shared run of at
least 71 normalized bytes with bounded memory, and it needs no harness
cooperation, because Keel already sees the decrypted bytes.

**Residual.** Paraphrased, summarized, compressed, or re-encoded content is not
detected. Uncommitted files are not indexed.

**Budget.** The hard 16,000-line trusted ceiling does not move. This decision
assigns 435 reserve lines: provenance 269 (ratchet 1,185), kernel 131 (4,815),
input 30 (3,070), secrets 3 (2,847), and audit 2 (1,168). Allocated ratchets
total 13,937 and leave 2,063 unallocated.

## D25 (condensed log; PLAN D48) — Interrupted model streams are charged an observed bound

**Decision.** Model connections get a ten-minute upstream idle timeout instead
of ten seconds. A successful stream that ends early after the provider's
opening usage event is charged a trusted upper bound: the stated input, plus
the bytes of output already streamed, plus a 4,096-token margin, capped at the
reservation. A stream that fails before that event, or any non-success or
malformed response, keeps the full conservative charge.

**Why.** The short timeout made slow first responses fail mid-request. Each
failure kept a reservation sized for 128,000 output tokens, so harness retries
exhausted a USD 10 run on about USD 0.17 of real spend.

**Residual.** The margin assumes the provider stops generating soon after a
disconnect. If it generates more, Keel's ledger undercounts real spend for that
request.

**Budget.** The hard 16,000-line trusted ceiling does not move. This decision
assigns 168 reserve lines: secrets 148 (ratchet 2,995) and kernel 20 (4,835).
Allocated ratchets total 14,105 and leave 1,895 unallocated.

## D26 (condensed log; PLAN D49) — Model requests wait for room, and the default ceiling is USD 20

**Decision.** A model request that would fit once in-flight reservations
settle waits for them, for up to 30 seconds and outside the broker lock,
instead of being refused. A request that cannot fit even with nothing in
flight is refused at once. The default cost ceiling rises to USD 20; values
above it still require trusted task admission.

**Why.** The harness sends helper requests beside its main one, so a
worst-case main reservation plus a helper exceeded USD 10. The resulting
refusal surfaced as an API error that cleared on retry.

**Trade-off.** Every run now carries USD 20 of model authority without a
prompt. The ceiling is still enforced on every reservation.

**Budget.** The hard 16,000-line trusted ceiling does not move. This decision
assigns 19 reserve lines to `keel-kernel` (ratchet 4,854). Allocated ratchets
total 14,124 and leave 1,876 unallocated.

## D27 (condensed log; PLAN D50) — Measure the action-centric rules before enforcing them

**Decision.** Connection-setup legs record `not-applicable` intent, because
they send nothing upstream. `keel report --axes` compares, for each finished
session, the prompts Keel presented with what the action-centric decision
table would do from the recorded verdicts, and lists every prompt avoided or
added. This report is the evidence for deciding when the shadow verdicts start
deciding.

**Budget.** The hard 16,000-line trusted ceiling does not move. This decision
assigns 7 reserve lines to `keel-kernel` (ratchet 4,861). Allocated ratchets
total 14,131 and leave 1,869 unallocated.

## D28 (condensed log; PLAN D51) — Guest requests carry the process that made them

**Decision.** The guest's PID 1 supervisor attributes each Git and egress
connection to its owning process and ancestry, and marks ancestors that run
workspace-controlled code. The relays send that as an origin frame, and the
kernel stamps, audits, and displays it. A Git push or pull request from
workspace code always reaches the gate.

**Why PID 1.** The workload is UID 0 without capabilities, so any other root
helper would be signal-able. PID 1 is not, and attribution needs root to read
other processes' file tables.

**Residual.** The origin is guest-reported and unverified, so it only narrows
authority. A process that exits before inspection is reported as unknown. MCP
connections gained attribution in PLAN D55.

**Budget.** The hard 16,000-line trusted ceiling does not move. This decision
assigns 193 reserve lines: kernel 189 (ratchet 5,050) and audit 4 (1,172).
Allocated ratchets total 14,324 and leave 1,676 unallocated.

## D29 (condensed log; PLAN D52) — Lines pushed into protected places are traced to the model

**Decision.** Trusted code records every string the model places in a tool
call of a complete, successful response. A push that adds lines to a
protected place (manifests, CI configuration, or anything on the default
branch) is judged by how many of those lines the model never wrote. The
verdict is stamped, audited as `integrity`, and shown at the gate, in shadow.

**Why.** It separates the agent's own edits from content produced by builds,
install hooks, downloads, or other processes. A postinstall script rewriting a
CI workflow is the attack this is meant to surface.

**Residual.**

- The protected diff comes from untrusted `keel-gitd`.
- Model output is recorded only from complete responses, so content from an
  interrupted response counts as unaccounted.
- Matching is by exact line, so a model-written line later reformatted by a
  tool also counts as unaccounted.

**Budget.** The hard 16,000-line trusted ceiling does not move. This decision
assigns 243 reserve lines: kernel 113 (ratchet 5,163), secrets 88 (3,083),
provenance 38 (1,223), and audit 4 (1,176). Allocated ratchets total 14,567
and leave 1,433 unallocated.

## D30 (condensed log; PLAN D53) — The guest kernel moves to 6.12 LTS

**Decision.** Setup downloads Alpine's `linux-virt` 6.12 package at a pinned
version and digest, extracts the raw ARM64 image from its EFI zboot wrapper,
and installs the package's own modules into the guest image. The confined
workload's Landlock ruleset adds ABI 6 scoping of signals and abstract Unix
sockets, and the preflight requires a signal to PID 1 to be refused whenever
the kernel reports ABI 6. Doctor reports the installed kernel release.

**Why.** UID 0 without capabilities can still signal other root processes;
the supervisor survives only because PID 1 ignores unhandled signals. Scoping
removes that dependence and closes abstract-socket rendezvous with services.

**Not done.** Landlock TCP rules are unused. Without a network interface, TCP
reaches only loopback relays and local test servers, so port rules would
break tests without narrowing egress.

**Residual.** Alpine drops superseded packages from its CDN, so the pin must be
bumped by hand when the download returns 404. A guest kernel exploit still
defeats the layer.

**Budget.** No trusted lines.

## D31 (condensed log; PLAN D54) — Model context is logged block by block, in shadow

**Decision.** Trusted termination digests every content block of each model
request and of each complete, successful response, and the kernel audits them
as `kernel.model-context` records bound to the authorizing action. Each
digest is described once per session. Untrusted `keel report --context`
analyzes the log.

**Why.** Workstream 4's per-turn floors cost about 830 trusted lines. The
design gates that spend on measurement: whether per-turn ranks would ever
exceed the session floor on real coding sessions. This log answers that
question offline for a quarter of the cost.

**Residual.**

- It changes no decision, and write failures are ignored.
- User text is not yet matched to operator keystrokes, and tool results are
  not matched to admitted content, so both count as unverified.
- Digest equality depends on the harness echoing blocks unchanged; the
  report's "assistant, not emitted by the model" count measures exactly that.

**Budget.** The hard 16,000-line trusted ceiling does not move. This decision
assigns 235 reserve lines: kernel 57 (ratchet 5,220), audit 33 (1,209), and
secrets 145 (3,228). Allocated ratchets total 14,802 and leave 1,198
unallocated.

## D32 (condensed log; PLAN D56) — OpenRouter is a third model provider, priced from an admitted snapshot

**Decision.** `--auth openrouter --model PROVIDER/MODEL` sends the Claude
harness through OpenRouter's Anthropic-compatible Messages endpoint. The host
key is injected as a bearer token on that endpoint only. The run is pinned to
one model, charged at a price snapshot the untrusted launcher fetches and
trusted admission shows to the operator. The trusted proxy strips OpenRouter's
routing and plugin fields.

**Why a snapshot.** OpenRouter serves hundreds of models whose prices change
and differ by provider; a reviewed table cannot keep up. The snapshot takes
the worst price across every provider and tier, and the operator admits it,
which is the same trust Keel already gives an operator-chosen budget ceiling.

**Residual.**

- OpenRouter is one more party that receives the full model context,
  including any secret the agent reads.
- The snapshot is only as honest as the launcher and the price list; admission
  is the check.
- Rounding to whole micro-USD per token overstates very cheap models, which
  spends the budget faster but never undercharges.
- Claude Code with non-Anthropic models is best-effort; OpenRouter itself
  guarantees Claude Code only on Anthropic's own provider.

**Budget.** The hard 16,000-line trusted ceiling does not move. This decision
assigns 83 reserve lines: secrets 66 (ratchet 3,294) and input 17 (3,087).
Allocated ratchets total 14,885 and leave 1,115 unallocated.

## D33 (condensed log; PLAN D57) — Every run records a canonical admission manifest

**Decision.** Before the runtime backend is spawned, trusted `keel-input`
audits `kernel.run-admitted`: canonical JSON of what the run was admitted with
(boot-artifact and component digests, policy, workspace state, authority and
credential scopes, model terms, run shape, and admission) and its SHA-256. A
failure to hash or record it refuses the run. `keel status` reports `active`,
`closed`, or `interrupted` with the manifest summary, and the shadow reports
print it per session.

**Why.** The shadow reports decide whether verdicts start deciding. Without a
manifest, sessions run on different images, kernels, policies, providers, or
prices blend into one result, and later enforcement work has nothing to bind
to.

**Residual.**

- Artifact digests are evidence, not enforcement: the untrusted backend reads
  the files after admission, and they are not staged privately.
- Workspace `HEAD` and dirtiness describe admission time only.
- Liveness for `active` is the writer's process id and name, which a host
  process could imitate; the host is trusted.
- The teardown receipt, two-stage stop, and crash recovery remain planned.

**Budget.** The hard 16,000-line trusted ceiling does not move. This decision
assigns 249 reserve lines: input 184 (ratchet 3,271), secrets 34 (3,328),
kernel 20 (5,240), and audit 11 (1,220). Allocated ratchets total 15,134 and
leave 866 unallocated.

## D34 (condensed log; PLAN D58) — Triage runs are confined to an analyst-declared scope

**Decision.** `--profile triage` with `--scope`, `--exclude`, `--scope-file`,
or `--report` runs a reproduction confined to the hosts the analyst declares.
The trusted side parses the rules strictly and always requires the operator
to admit them on the trusted terminal. It also requires an approved model
provider (`KEEL_TRIAGE_PROVIDERS`, default `anthropic,bedrock`). Anything
outside the scope and the run's admitted hosts is refused without a prompt.

**Why.** A reproduction runs hostile code against a customer target. Scope
admitted up front is the only workable control once a browser loads dozens of
hosts per page, and it makes the audit chain a record of staying in scope.

**Residual.**

- The scope is the analyst's statement. Nothing checks it against the
  program's authorization.
- A scope proposed from a report includes every URL host the report names,
  including reference links; the admission screen is the check.
- Test credentials, request limits, enforced report flow, and the browser are
  not built.

**Budget.** The hard 16,000-line trusted ceiling does not move. This decision
assigns 176 reserve lines: provenance 98 (ratchet 1,321), input 42 (3,313),
kernel 26 (5,266), and secrets 10 (3,338). Allocated ratchets total 15,310 and
leave 690 unallocated.

## D35 (condensed log; PLAN D59) — The guest has a headless browser, without Chromium's own sandbox

**Decision.**
- **Browser.** Every Claude guest has headless Chromium driven by Playwright's
  MCP server. Its traffic goes through the guest egress relay, and its
  background calls to Google services are disabled or sent to a closed
  loopback port.
- **No Chromium sandbox.** Chromium runs with `--no-sandbox`.
- **Image.** The guest base moves to Alpine 3.23, the initramfs to zstd, and
  workspace VMs to 4 GB.

**Why no sandbox.** Chromium's sandbox needs user namespaces, which the
workload confinement denies to everything. Granting them to the workload
would reopen the kernel surface the confinement removes. The VM is the
boundary for a hostile page, as it is for a hostile PoC. Landlock, seccomp,
capability removal, and the cgroup still apply to Chromium.

**Residual.**

- **Browser exploits.** A browser exploit reaches the workload's privileges
  inside the VM, where an unsandboxed renderer is weaker than a sandboxed one.
- **Image size.** The image is 2.2 times larger. The whole root filesystem sat
  in guest RAM until D61 (PLAN) moved it to a read-only disk.
- **Patching.** Chromium is as current as Alpine 3.23's package and must be
  rebuilt into the image to be patched.
- **Protocols.** The proxy speaks HTTP/1.1 only and does not relay
  WebSockets.

**Budget.** No trusted lines. The trusted runtime's initramfs path changed from
`.cpio.gz` to `.cpio.zst`.

## D36 (condensed log; PLAN D60) — The guest browser is driven by agent-browser

**Decision.** `agent-browser` 0.38.2 (vercel-labs, Apache-2.0) replaces
Playwright's MCP server. Only its musl arm64 binary is used, pinned by the npm
package checksum and its own. It serves the agent as the `browser` MCP server
and the analyst as a CLI, and both share one browser through its daemon.
- **Launch.** It launches Chromium through `keel-chromium`, which appends
  Keel's flags and merges `--disable-features` lists.
- **Output.** Screenshots, downloads, and HAR files go to a self-ignoring
  `.keel-browser/` directory in the workspace, created when the browser first
  launches.

**Why.**
- **Analyst use.** Analysts reproduce without the agent and need screenshots.
  A CLI in the guest shell gives them the same browser without a host viewer
  or a new host channel.
- **Triage evidence.** HAR capture and request listing are exactly what
  triage evidence needs.
- **Smaller supply chain.** One 15 MB static binary replaces a Node
  dependency tree.

**Alternatives.**
- **browser-use** was refused: it is an agent framework that makes its own
  model calls, which Keel's single admitted model endpoint refuses, and it
  would need its own key in the guest and hide decisions from the visible tool
  calls.
- **Browserbase** runs the browser in a third party's cloud.
- **chrome-devtools-mcp** keeps the Node runtime and has no operator CLI.

**Residual.**

- **Release drift.** The published release differs from the project's `main`
  documentation, and the project moves quickly; upgrades need the same
  checksum review as Claude Code.
- **Unusable features.** `chat` (a second model path) and the cloud providers
  are present but unusable: they need credentials the guest never holds.
  WebMCP is disabled because it would surface page-defined tools.
- **Hostile files.** Downloaded files reach the host workspace and must be
  treated as hostile.
- **Verified so far.** The binary's own network calls were checked
  empirically in one run, which showed no traffic beyond the model's.

**Budget.** No trusted lines.
