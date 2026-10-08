# Design note — the render vertex

> **Status: design only. Nothing here is built.** This is a sketch for a capability
> that is *not* in Phases 0–4 and that conflicts with two of Keel's founding
> constraints (§12). It exists so the reasoning is in the tree rather than in a chat
> log. Do not start it before Phase 2's exit criteria are green.

---

## 1. The problem this solves

The motivating task is automated *validation*: given a claimed vulnerability in a
report, drive a browser at the target and produce evidence of whether the claimed
condition holds. That requires a browser somewhere. The obvious move — add Chromium
to the vertex the agent already runs in — is wrong, and it is wrong for a reason
specific to Keel's design rather than a generic size complaint.

**The guest-side relays are unauthenticated by construction.** `phase1-init.sh` starts
two byte relays on guest loopback: `127.0.0.1:18080` is the git remote and
`127.0.0.1:18081` is the egress proxy. Both bind `Ipv4Addr::LOCALHOST`
(`crates/untrusted/keel-mcp/src/bin/keel-mcp-guest.rs:364`) with no authentication,
which is correct today because the only things inside the vertex are the harness and
init. Credential injection in `keel-secrets` is scoped by
`(host, method, path-prefix)` — deliberately *not* by which guest process asked,
since the guest cannot be trusted to identify itself.

Put a browser in that vertex and hostile page JavaScript inherits both relays. It can
issue an authenticated `POST /v1/messages` through the proxy — write-only, opaque
response, but it burns the run's token and dollar budget — and it can attempt
`POST /origin/git-receive-pack`. The second is contained by the PDP, which denies it
without `push:branch` and gates it with a visible diff if granted. The first is
contained only by budget.

The containment is not the point. The point is what the arrangement breaks:

> Today, every path to the exits runs through convincing the model. A browser in the
> agent's vertex gives attacker-controlled content a **direct** path to the exits with
> no model in the loop.

That is a new row in `THREAT-MODEL.md`, not a variation on an existing one. Every node
threat N1–N20 assumes the adversary's leverage is the model's credulity.

## 2. The shape

Split the browser away from everything worth stealing.

```
  host (trusted)
  ┌──────────────────────────────────────────────────────────────────────┐
  │  keel-input      owns the tty, secure attention, bound approvals     │
  │  keel-kernel     the only thing that decides                         │
  │  keel-secrets    every credential. tiered. see §5.                   │
  │  keel-audit      hash chain + run-bound HMAC                         │
  └───┬───────────────────────────┬──────────────────────┬───────────────┘
      │ vsock 5000-5003           │ vsock (artifact      │ outbound TLS,
      │ (mcp, egress, git, pty)   │  channel only)       │ host-initiated
  ┌───▼───────────────────────┐ ┌─▼──────────────────┐   │
  │  ANALYSIS VERTEX          │ │  RENDER VERTEX     │   ▼
  │                           │ │                    │  exactly one
  │  claude, git, tmux        │ │  chromium, glibc   │  allowlisted host
  │  model credential         │ │                    │  per job
  │    as a sentinel          │ │  no model cred     │
  │  git relay  :18080        │ │  no git relay      │
  │  proxy relay :18081       │ │  no mcp tools      │
  │                           │ │  no workspace      │
  │  reads artifacts at       │ │  may hold a tier-1 │
  │  rank 0                   │ │  session for that  │
  │  never touches the target │ │  one host (§5)     │
  └───────────────────────────┘ └────────────────────┘
```

The governing principle, stated precisely enough to be checkable:

> **The render vertex may hold credentials only for the single host it is allowed to
> reach, and only at a tier where their compromise is uninteresting. Nothing that
> holds a credential of consequence ever touches attacker-controlled content.**

An earlier draft of this note said the render vertex holds *nothing*. That is wrong,
and §5 is why. The useful invariant is not emptiness — it is that the blast radius of
everything inside the vertex is a throwaway.

This is the vertex-fork idea from `PLAN.md` D4c run in reverse. Forking is normally
proposed as a way to get a *clean* vertex for a privileged step. Here it produces a
*dirty* vertex for a hostile read.

## 3. What each vertex holds

| | Analysis vertex | Render vertex |
|---|---|---|
| Model credential | sentinel, swapped host-side | none, not even a sentinel |
| Platform / git credential | none; host-side swap | none |
| Target application session | none | tier 1 or 2 only, for the one allowlisted host (§5) |
| Loopback relays | git `:18080`, proxy `:18081` | proxy only, one host |
| Egress allowlist | `api.anthropic.com` + declared hosts | exactly one target host, per job |
| Workspace mount | read-write virtiofs | none |
| MCP tool surface | four tools | none |
| Lifetime | the task | one render |
| Rank of what it produces | inherits the floor | always 0 |

`keel-secrets` currently derives a credential binding and an egress allowlist entry
from overlapping inputs. For the render path these must be separated structurally, or
a job's allowlist entry will silently become a credential grant.

## 4. The artifact channel

One vsock port, request/response, no streaming and no tools:

- **In:** `{ job_id, target_host, credential_ref?, steps[], budget_ms, viewport }`.
  `steps` is a closed vocabulary — navigate, click by selector, type a literal,
  type a secret by reference (§5), wait for a selector, assert a selector or status or
  body substring, screenshot. No free-form script, no eval, no arbitrary header.
- **Out:** `{ job_id, assertions[], screenshots[], extracted_text, console[], timings }`.

Deliberately absent:

- **No HAR by default.** HAR from a real authenticated target carries session tokens,
  bearer headers in query strings, and PII in response bodies. Redacting it reliably
  is a research problem, not a function. Screenshots plus an assertion trace first;
  HAR only behind an explicit per-job flag, treated as the most sensitive artifact the
  system produces.
- **No UDP, so no QUIC.** There is no UDP path out of a Keel vertex. Chromium must be
  launched with HTTP/3 and QUIC disabled or it will prefer a transport that silently
  does not exist.

Chromium's own sandbox is redundant here — the VM *is* the sandbox, and the usual
objection to `--no-sandbox` inverts inside a microVM with no route and no DNS.

## 5. Authenticated validation

Most vulnerability classes worth validating are post-authentication. Broken access
control, IDOR, privilege escalation, and tenant isolation cannot be reached by an
anonymous browser. A design that only handles unauthenticated targets handles the
uninteresting fraction. So the render vertex has to be able to log in, and the
question is which credentials may enter it.

### 5.1 Tiers

| Tier | What it is | May a render vertex hold it? |
|---|---|---|
| **T1** | Synthetic account, non-production environment, no real data | **Yes** — the default path |
| **T2** | Synthetic account, production environment, no real data | **Yes**, with destructive steps blocked and a gate at job submission |
| **T3** | Any real identity: a researcher's account, a customer employee's, an admin, a service credential, anything with real data or real authority | **Never.** Not gated, not with approval. |

The tier is a property of the credential recorded where the credential lives, not a
property of the job. `CredentialScope` in `keel-secrets/src/lib.rs:412` already carries
`{ host, methods, path_prefix }`; it gains a `tier`, and the render path refuses
anything above T2 before a vertex is created.

What makes T1 safe is not containment. It is that **the browser leaking the credential
is an anticipated outcome of testing** — the vulnerability under test may literally be
session theft — and the leak is worthless. That is the whole argument, and it only
holds if the account really is a throwaway. The moment an operator registers their own
account as T1 to save time, the design is defeated silently. That failure mode is
social, so the control has to be social too: tier is asserted at registration, shown
on every run, and recorded in the audit chain.

### 5.2 How the credential gets in

Two mechanisms, in preference order:

**(a) Proxy injection.** `keel-secrets` attaches the session cookie host-side on
requests to the allowlisted host. The browser's JS-reachable storage never holds it.
This is the same swap the model credential already uses and it is strictly better when
it works — which is for cookie-session applications. It fails for single-page
applications that read a token out of `localStorage` to construct `Authorization`
headers in their own JavaScript: inject at the proxy and the application's own code
cannot find the token, so the app breaks rather than authenticates.

**(b) A typed-secret step.** `{ type_secret: { credential_ref: "program-x-user-a" } }`.
The literal crosses the artifact channel only at the moment of typing, is added to the
redaction set for every artifact the run produces, and is never echoed back. The
credential does end up in the page and in the cookie jar — that is what logging in
means. This is accepted precisely because of the tier rule, and it is the general
primitive; (a) is an optimization where the application's shape permits it.

### 5.3 Interactive login and session reuse — the MFA answer

Scripted login breaks on multi-factor authentication, device checks, and login rate
limits. Any plan that assumes a username and password in a vault is sufficient has not
met a real application.

    keel validate login --target app.example.com --tier 1 --role admin

boots an interactive render vertex on the operator's own terminal. The human completes
the login, including MFA, watching it happen. The resulting storage state — cookies
plus `localStorage` — is captured, encrypted host-side, and tagged
`(host, tier, role, expiry)`. Subsequent validation runs inject that state instead of
logging in again.

This reuses machinery Keel already has rather than inventing a UI: `keel-input` owns a
real tty, the secure-attention chord already exists, and the approval path already
mints tokens bound to a target hash. An interactive login is a gate with a longer
interaction.

### 5.4 Multi-principal validation

Access-control findings are inherently two-principal: validating an IDOR needs user
B's object identifier *and* user A's session. Run it as two sequential render
vertices — log in as B, capture the identifier, die; log in as A, attempt access to
that identifier — rather than two browser contexts in one vertex.

The reason is evidentiary, not architectural. Two vertices produce exactly the
structure the finding requires: *as B this object is mine; as A I could read it.* The
isolation benefit is a bonus.

### 5.5 The precondition assertion

This is the rule that makes authenticated validation trustworthy, and it is easy to
omit.

Once a session is required, a stale session makes every test fail, and that failure is
indistinguishable from the vulnerability being absent. So:

> Every authenticated play must begin by asserting it is logged in as the expected
> principal. If that assertion fails, the result is `blocked: no_valid_session`, and it
> must be **structurally impossible** for the run to emit `not_reproduced`.

Without this, session expiry manufactures false negatives at scale — and in
vulnerability validation, false negatives are the expensive direction. The same applies
to insufficient role: assert the expected privilege level, not merely that some session
exists.

### 5.6 What this re-admits, honestly

Handing the render vertex a session for the target partially reinstates the threat §1
exists to remove. Hostile JavaScript in that vertex can now act *as the test user
against the target*. Four things bound it, and they should be read as a set because no
one of them is sufficient:

1. The account is a throwaway (§5.1).
2. The environment is non-production by default (T2 is the exception, gated).
3. Exactly one host is reachable, so there is nowhere to exfiltrate to.
4. Destructive steps are absent from the vocabulary, not merely discouraged.

Point 3 carries more weight than it appears to. Without it, the browser's same-origin
policy would be the thing preventing a target cookie from reaching an attacker's
origin — which would put Chromium inside the TCB for that property. A strictly
single-host allowlist means cross-origin exfiltration has nowhere to go regardless of
whether SOP holds, so the browser does not have to be trusted for it. This is the
strongest argument against the wildcard allowlist discussed in §13.

The residual is real: an attacker who controls the target can influence what the
validation run reports about the target. Detection is not containment, so this belongs
in `THREAT-MODEL.md` as a named residual rather than as a solved problem.

### 5.7 Provisioning is the adoption bottleneck

Someone has to create the T1 accounts. This, not the isolation design, is what will
limit coverage.

- **Customer pre-provisions per program, per role.** Realistic and correct, but manual
  enough that it will happen for a handful of programs rather than all of them.
- **Give the runner an admin credential to self-provision.** That is a T3 credential.
  Refuse it — it is the single change that would convert this design into a liability.
- **Use test accounts programs already publish in their scope documentation.** The
  pragmatic first version, and the reason to start with programs that already do this.

State the constraint rather than hand-waving it: validation coverage is bounded by
test-account availability, and the work to expand coverage is customer onboarding
work, not engineering work.

## 6. Provenance

This is the part that already works and needs no new mechanism.

A browser is a pure rank-0 firehose. Everything the render vertex returns is
`Rank::UntrustedContent` with `SourceRef::Host { host, path }` — exactly what
`observe_egress_response` already produces for a fetched page
(`crates/trusted/keel-kernel/src/lib.rs:2729`). The analysis vertex ingests artifacts,
its floor drops to 0, and per-capability minimum ranks withdraw authority mechanically.

That yields the correct semantics for validation for free: a vertex that has looked at
a target cannot then take a consequential action on the strength of what it saw. The
rule "a validation run may accelerate review but must never suppress, downgrade, or
close" stops being a policy convention someone can edit and becomes a structural
property of the floor.

Write-inheritance (P3) matters more here than anywhere else in Keel. An artifact
written by the analysis vertex after ingesting a render result must carry the floor at
write time, or the laundering path is trivial: render → summarise → write summary →
treat summary as trusted.

## 7. What it costs

Measured against the pinned `alpine:3.20` arm64 base, each package set built into its
own root:

| Package set | Size |
|---|---|
| current guest — `alpine-base bash ca-certificates git tmux` | 34 MB |
| `+ ripgrep jq` | 39 MB |
| `+ python3` | 79 MB |
| `+ nodejs npm` | 99 MB |
| **`+ chromium`** | **633 MB** |
| **`+ chromium swiftshader ttf-freefont font-noto`** | **673 MB** |

For reference the current vertex rootfs is 272 MB total — 214 MB of which is the
`claude` binary — compressing to a 127 MB gzipped cpio initramfs.

Two consequences:

1. **The initramfs model does not survive this.** The current image is a gzipped cpio
   decompressed *entirely into guest RAM* at boot, paid per vertex under
   one-vertex-per-task (D4). A ~920 MB rootfs cannot be a RAM-resident initramfs. The
   render vertex needs a real read-only block image — virtio-blk, content-hashed, built
   once and shared across runs. That is the single largest new engineering item.
2. **musl is not an option.** Playwright's bundled Chromium requires glibc and does not
   support Alpine. Either drive Alpine's system Chromium over CDP directly, or base the
   render image on Debian slim. The second is more honest about what is being run and is
   probably correct, at the cost of the render image no longer sharing a base with the
   analysis vertex.

The costs land on the render image alone. The analysis vertex stays at 272 MB, which is
the reason to do it this way even setting security aside.

## 8. Per-operator deployment

The motivating deployment is one runner per operator, on the operator's own machine.
That is not incidental — local is the point. Reaching a private staging environment and
using credentials that never leave the laptop are things a hosted runner cannot do.
Four consequences follow:

1. **Reproducibility becomes an explicit field.** Two operators must not reach
   different verdicts on the same input. Every result carries `play_hash`,
   `image_hash`, `runner_version`, and — given §5 — the `credential_ref` and role the
   run authenticated as. Results with mismatched hashes are not comparable and the
   platform should refuse to aggregate them rather than quietly averaging across image
   versions.
2. **No shared queue, and that is a feature.** Per-operator runners cannot atomically
   claim work from a pool. Do not build one. Make the trigger explicit — the operator
   requests validation, the job is addressed to *their* runner — which matches the
   workflow anyway and sidesteps the claim race entirely.
3. **Revocation is per device.** Each runner registers its own key. One compromised
   laptop is one revocation with no blast radius.
4. **The local state store holds sensitive material from day one.** Not just a job
   ledger: after §5.3 it holds live application sessions. Encrypted at rest, with
   expiry enforced rather than advisory, designed before it exists.

## 9. Platform credentials: attribution is not authorization

§5 is about credentials for the *target*. This section is about the credential used to
write results back to the platform. They are different axes and conflating them is a
mistake.

The tempting shortcut is to have the runner write back using the operator's existing
authenticated platform session. Reject it.

**The mechanism would work.** `keel-secrets` could inject a session cookie host-side,
scoped to a narrow method and path prefix, with no vertex ever seeing it.

**The credential's authority is what fails.** A session is a bearer token carrying
everything its holder can do — read every report in every program visible to them,
comment, change state, close. You can constrain which requests the runner *makes*; you
cannot constrain what the credential *could* do once it exists on that machine, and you
cannot audit runner activity separately from the human's own activity because to the
platform they are one actor. Rotation, re-authentication, and extracting cookies from a
browser keychain are the operational tax on top.

Separate the three roles a session conflates:

| Role | Mechanism |
|---|---|
| **Authorization** | A dedicated runner identity, program-scoped, with an endpoint allowlist of three or four paths. Held in `keel-secrets`, applied after the target/method/path check, never inside a vertex. Leak blast radius: validation fields on one program's reports. |
| **Attribution** | The requesting human's identity travels in the job and lands in the result record as metadata. *Who asked* is not *what may be written*. |
| **Non-repudiation** | The `Ctrl-]` approval on the host terminal, minting a single-use token bound to `(session, action_id, target_hash)` and hash-chained into the audit log. |

The third row is a *stronger* record than a session provides. A session cookie proves
only that a request came from a logged-in browser. A bound approval token in a
verifiable chain proves a specific human authorized a specific write to a specific
target at a specific time.

## 10. Writeback and event chaining

Writing a structured result into the platform is what makes any of this useful, and it
is therefore the trust boundary. Three hazards to design against before the first
write:

**The write is the boundary, so verify at the write.** Once downstream automation
reacts to `status = validated`, anything that can influence a runner's output can drive
that automation. The platform must verify the result signature and the runner identity
before accepting the write — not treat the field as free text a runner happens to set.

**Only positive results are automation-actionable.** In a first version, automation may
read `validated` and `partially_validated` and nothing else. Negative and blocked
results write a field for a human and trigger nothing. "Not reproduced" becoming a soft
close reason is not a hypothetical; it is the default outcome of exposing it as a
condition, because incentive gradients beat guidelines. §5.5 makes this sharper: with
authentication in the loop, a large share of negative results will be credential
problems wearing a verdict's clothing.

**Loop risk is structural.** Runner writes a field → a field-change event fires →
automation could request another validation. Requests must be idempotent on
`(report_id, play_hash)` with a hard per-report run cap, or this is discovered in
production on a report that is already noisy.

**Plays are content-hashed artifacts, not generated code.** A model may *propose*
validation steps. What executes is a hash a human approved, and the same hash appears in
the result. This is I10 applied to a second artifact class, and it is load-bearing for a
specific reason: a model-authored play derived from report text is attacker-influenced
code laundered through a model. Human review of a plausible-looking play is not
sufficient, because the reviewer sees the play and not the injection that shaped it.
Approval must bind to bytes. With §5 in play this tightens further — a play that can
name a `credential_ref` is a play that can point a session at a chosen target, so the
approved hash must cover the credential reference too.

## 11. Reuse ledger

**Exists, CI-enforced:**

- Credential custody with host-side swap after target/method/path check
- Egress allowlist; RFC1918, loopback, link-local and metadata denied *below* policy as
  an I11-class invariant, so it cannot be configured away
- Hash-chained audit with per-record run-bound HMAC and an offline verifier
- Gate with single-use tokens bound to `(session, action_id, target_hash)`
- Content-hashed policy artifacts, never hot-loaded (I10) — the pattern plays reuse
- Provenance ranks, monotonic floor, write-inheritance
- One VM per task, no route, no DNS, no network device
- An interactive trusted terminal, which §5.3's login flow reuses

**New:**

- The render image: glibc base, virtio-blk read-only disk, content-hashed
- The artifact channel and its closed step vocabulary
- Credential tiering on `CredentialScope`, and the host-equals-allowlist assertion
- The session store: capture, encryption, expiry, role tagging
- The play DSL and its executor
- The platform adapter and runner identity, registration, revocation
- Separating allowlist entries from credential bindings in `keel-secrets` (§3)

**Not true today, stated plainly:** the vertex toolchain is exactly
`alpine-base bash ca-certificates git tmux` plus the `claude` binary
(`spikes/build-phase1-image.sh:80`). There is no browser, no Python, no Playwright.
(Since D59 and D60 the guest does carry a headless Chromium driven by
`agent-browser`; the rest of this section describes the state when it was
written.)
Keel has not closed Phase 1's exit criteria. Any plan that assumes "Keel can already
run browser tasks, or can be extended with Playwright" is wrong on both counts.

## 12. The charter conflict

`ROADMAP.md` lists **remote or cloud execution** under deliberately deferred, with the
note that it *breaks the co-located trust model outright*. A runner that receives jobs
from a platform is remote-controlled by definition: the job source is a network
service, which in Keel's model is an untrusted input. It also needs registration,
revocation, and auto-update — none of which a single-operator local runtime has. §5
adds a second conflict: a persistent encrypted session store is close kin to
**persistent cross-session memory**, also deferred, and for a related reason — a stored
session is durable state whose trust rank is not obvious.

Two honest options:

- **(a) Borrow the design; build a separate product.** Keel stays a research prototype
  and proves the controls. The runner is a different codebase reusing the architecture.
  Slower, cleaner, and the only option that preserves Keel's research result.
- **(b) Extend Keel's charter.** Accept the TCB growth and record it as a decision with
  the same rigour as D1–D9. For scale: the trusted crates are already over their
  per-crate budgets, and `PROJECT-BRIEF.md` names scope gravity as the central risk —
  *"anything that wants inside must displace something."*

What cannot happen is claiming (a) while doing (b). That is how a 12k reviewable kernel
becomes a 40k one nobody reads, and `ROADMAP.md`'s kill criteria already say the right
response is retracting the thesis rather than quietly dropping it.

If (b) is chosen: **signed declarative jobs come first, not last.** The moment a remote
service can direct a local runner to point a session at a customer asset, job
authenticity *is* the security model. A first version that uses mutable report fields as
the queue has no job authenticity at all — the job is whatever anyone with edit rights
typed into a field. Acceptable for proving the workflow, provided everyone understands
it demonstrates the UX and not the security story, and provided its convenience is not
allowed to calcify into the architecture.

## 13. What would change this

- **If T1 accounts cannot be obtained in practice** (§5.7), the coverage is whatever
  fraction of programs publish or provision test accounts, and the honest response is to
  report that number rather than to relax the tier rule. Relaxing the tier rule is the
  one change that turns this design into a liability.
- **If host sprawl makes a single-host allowlist unusable** — real pages pull from CDNs,
  analytics, and font hosts. Three options, in preference order: strict single-host with
  degraded rendering (correct for validation, where the assertion matters and the pixels
  are secondary); gate on each new host (an escalation storm, measurable against §7.4
  instrumentation before committing); wildcards (refuse — §5.6 explains what the
  single-host rule is actually buying, and it is not bandwidth).
- **If HSTS-pinned targets are common**, MITM termination fails on them and no amount of
  design fixes it. Measure what fraction of real targets this excludes before building.
- **If state-changing steps cannot be bounded**, this stays non-production-only.
  `allow_state_changes: false` is doing more work than it can: authenticating is itself
  a state change, so the policy has to distinguish "logs in the synthetic user" from
  "destroys data." That is semantic scope, a named unsolved residual in
  `THREAT-MODEL.md`. Until it is solved the constraint is non-production environments
  and synthetic accounts only, enforced by the runner rather than chosen per engagement.
- **If authenticated screenshots cannot be cleared for upload.** An authenticated view
  of a real application may show other users' data, tokens in a debug panel, or PII
  incidental to the finding. If review cannot be made cheap, the default artifact set
  shrinks to assertion traces and the screenshots stay local.

## 14. Open questions

- Does the render vertex share `keel-isolate`'s backend abstraction, or is a disk-image
  vertex different enough to warrant its own launcher?
- Is the artifact channel a fifth vsock port, or a job type on the existing MCP port with
  the host brokering between two vertices?
- Where does the session store live relative to `keel-secrets`? It is credential custody,
  which argues for inside the TCB; it is also durable multi-run state with expiry and
  capture logic, which argues for outside. The budget says outside, and then the boundary
  has to be drawn so that the untrusted half never holds plaintext.
- Who owns the render image's build and pinning? The `apk add` in
  `spikes/build-phase1-image.sh` is currently the one unpinned input in an otherwise
  hash-pinned build; a 673 MB browser image makes that gap considerably more expensive.
- Does a second concurrent vertex break any single-writer assumption in `keel-audit` or
  the session fact set? The audit log has exactly one writer by design; two vertices in
  one run may or may not be one session.
- Is a captured session with a 30-minute expiry a *credential* or *state*? It behaves
  like both, and `PLAN.md` has no rank for it.
