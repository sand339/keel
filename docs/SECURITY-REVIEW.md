# Security review results

Date: 2026-09-25

Scope: the complete working tree, including uncommitted and untracked files.

Method: two read-only passes with the built-in Codex CLI, followed by manual
call-path validation and regression testing. This document tracks remediation
work performed after the review.

## Second review (2026-10-15)

Scope: every trusted crate and the untrusted code that trusted code relies on,
at `9141e4b`. About 44,000 lines had changed since the first review: the Linux
backend and bubblewrap confinement, verified teardown and crash recovery,
release packaging, provenance floors and payload verdicts, the policy compiler,
and credential zeroization.

Method: seven read-only reviewers, one per trust boundary (kernel and policy;
provenance and admission; credentials and TLS; isolation and confinement; the
trusted terminal; Git, audit, and recovery; supply chain and the CLI). Each
finding had to name a concrete failure path and was then checked by a separate
verifier told to refute it. All thirty survived. `cargo deny` also reported
RUSTSEC-2026-0346 through 0349 against rustls 0.23.45.

| ID | Severity | Finding | Status |
| --- | --- | --- | --- |
| KSR-033 | P0 | Confined host children share the operator's controlling terminal: TIOCSTI can inject the approval keystrokes (no setsid / --new-session) | Fixed and verified |
| KSR-034 | P0 | Trusted admission runs `git status` on the live workspace, so a filter driver in repo config runs on the host | Fixed and verified |
| KSR-035 | P1 | macOS Seatbelt profiles for the runtime and renderer allow almost all mach-lookup, an egress and clipboard path that bypasses the broker | Fixed and verified; residual: denylist |
| KSR-036 | P1 | Floor lift applies to a floor the operator never saw: content read while the lift challenge is pending is silently vouched for | Fixed; unit-tested only |
| KSR-037 | P1 | Kernel push derivation falls back to relay-claimed refs and default-branch flag when any ref name in the body fails validation | Fixed and verified |
| KSR-038 | P1 | is_force (force-push and ref deletion) is never derived by the kernel; it comes only from the relay | Fixed and verified |
| KSR-039 | P1 | Trailing slash on POST /repos/o/r/pulls/ skips the one-use PR effect permit, but the GitHub credential is still injected | Fixed and verified |
| KSR-040 | P1 | Trusted approval screen can be spoofed by guest-supplied multi-line target text that scrolls the real header off-screen | Fixed and verified |
| KSR-041 | P2 | Linux: reinstalling Keel during a live session makes recovery treat the live run as crashed and delete its broker dir, scratch and images | Fixed and verified |
| KSR-042 | P2 | gitd's protected diff for a new ref covers only the tip commit against its first parent, so the operator gate shows an incomplete or '(none)' diff | Fixed and verified |
| KSR-043 | P2 | A torn final record aborts the whole recovery pass and the session can never be recovered | Fixed and verified |
| KSR-044 | P2 | Guest attribution misses git hooks, Makefile/npm scripts, suffix-less interpreters and reparented processes, so the documented 'workspace-code push reaches the gate' rule is bypassable | Fixed and verified |
| KSR-045 | P2 | Trusted push derivation misses deletions, copies of admitted blobs, and force/delete, leaving the protected flags to untrusted gitd | Fixed and verified |
| KSR-046 | P2 | `keel policy accept` does not confirm, and does not bind to the draft the operator reviewed | Fixed and verified |
| KSR-047 | P2 | Absolute-form request targets inside terminated TLS are authorized and forwarded verbatim | Fixed and verified |
| KSR-048 | P2 | Linux liveness check treats a live session as crashed once `keel setup` replaces keel-input-runtime, and auto-recovery then deletes its live resources and attach socket | Fixed and verified |
| KSR-049 | P2 | `keel setup` builds and installs the trusted runtime from whatever checkout-looking directory is above the current directory | Fixed and verified |
| KSR-050 | P2 | macOS build path omits `cargo build --locked`, so release binaries can silently resolve dependencies outside Cargo.lock | Fixed and verified |
| KSR-051 | P2 | Release verification proves integrity, not authenticity: the verifier, the SHA256SUMS and install.sh all ship in the tarball they check, and the only outside check is a co-hosted unsigned .sha256 | Fixed: keyless signing; first signed release pending |
| KSR-052 | P2 | Operator Ctrl-G is eaten as a control prefix; Ctrl-G q shuts the run down and Ctrl-G s + 4 keys kills the renderer | Fixed and verified |
| KSR-053 | P3 | Recovery's temp-root assumptions differ from where the run created its resources (Linux broker dir under TMPDIR, reaper's TMPDIR) | Fixed and verified |
| KSR-054 | P3 | The backend group is recorded only after spawn, so a crash in that window leaves an orphaned VM that recovery reports as clean | Fixed and verified |
| KSR-055 | P3 | Guest TCP relay exits permanently on a transient accept() error; the workload can kill egress/Git/MCP relays by exhausting their descriptors | Fixed and verified |
| KSR-056 | P3 | No test or preflight probe covers the x86_64 x32/i386 kill path or the seccomp BPF jump offsets | Fixed and verified |
| KSR-057 | P3 | Long-lived egress bridges count against MAX_BROKER_CLIENTS, so busy workloads lock out Git, PR, and extraction requests | Fixed and verified |
| KSR-058 | P3 | SigV4 secret key and session token are never registered with the audit Redactor | Fixed and verified |
| KSR-059 | P3 | credential_process refresh runs with no timeout while holding the signer mutex | Fixed and verified |
| KSR-060 | P3 | Credential copies are dropped without zeroization despite the 'every buffer is wiped' contract | Fixed and verified |
| KSR-061 | P3 | package-release.sh ships whatever is installed under ~/.local/share/keel, labeled with the checkout's current HEAD | Fixed and verified |
| KSR-062 | P3 | Pre-push public-repo guard is bypassed by URL case or a trailing slash | Fixed and verified |

### KSR-033: confined children and the operator's terminal

The runtime, renderer, extraction helper, and launcher renderer were spawned
into their own process groups but stayed in the operator's session, so each
kept the operator's terminal as its controlling terminal. Every one of them can
read `/dev`, so a compromised child could open `/dev/tty` and use `TIOCSTI` to
place the secure-attention key followed by `a` or `g` in the input queue, which
the trusted runtime then reads as the operator approving. Where `TIOCSTI` is
disabled it could still paint over the trusted screen. Challenge prompts were
not affected; single-key approvals and grants were.

On Linux every bubblewrap child now runs with `--new-session`, so it has no
controlling terminal. On macOS a sandbox profile cannot change sessions, so
every profile denies opening `/dev/tty`, the console, and the `tty*` and `pty*`
devices; each child's standard streams are pipes, so it holds no terminal
descriptor to begin with. A sandbox test opens a real pseudo-terminal and
asserts that the runtime and renderer profiles cannot open it or `/dev/tty`,
with an unconfined control that can; it fails with the deny removed.

### KSR-034: content filters during admission

Admission recorded whether the workspace was dirty by running `git status` on
the operator's live directory. Status re-hashes a file whose stat data changed,
and hashing runs any `filter.<driver>.clean` or `process` command that the
repository configures and that `.gitattributes` or `.git/info/attributes` names.
The guest can write all three, so a run could leave a command that executed on
the host, unconfined, at the start of the next run, and a malicious repository
could ship one. This is the KSR-010 class through a call path the hardened Git
constructor did not cover: fixed `-c` overrides cannot name every driver.

`content_filter_overrides` reads the repository's configuration, which runs
nothing, and empties the clean, smudge, and process commands of every driver it
defines, including ones reached through `include.path`. A driver name that
cannot be overridden on the command line refuses the status check rather than
running it. Admission's status also no longer descends into submodules, which
carry their own configuration. The regression test configures filters through
`.git/config`, an include, `.gitattributes`, and `.git/info/attributes`, and
asserts none run, with a control showing the same status without the overrides
does run them.

### KSR-035: host services from the macOS sandboxes

The runtime, extraction helper, renderer, and launcher profiles allowed every
mach-lookup except the security daemons, so a confined child could read the
clipboard, open a URL or application, send Apple Events, reach the window
server, or resolve names through mDNSResponder, a DNS channel even with IP
denied. Every profile now also denies the pasteboard, Launch Services and lsd,
Apple Events, the window server and dock, mDNSResponder and dnssd,
nsurlsessiond, sharingd, and FileProvider. Residual: this is a denylist; an
allowlist derived by tracing what Virtualization.framework and Deno need would
be stronger.

### KSR-036: a floor lift and the read-set it showed

A lift's reasons do not depend on the read history, so a source read while the
challenge was pending was vouched for without being shown. `conclude_gate` now
denies the lift when the floor or the floor history differs from what the
screen displayed. The kernel unit test reads a source between the two halves of
the lift; the manual harness does not drive lifts.

### KSR-037, KSR-038, KSR-045: what a push is, from its own bytes

When any ref name in the body failed validation, the kernel kept the relay's
refs and default-branch flag, and it never derived force or deletion at all.
Now the relay's refs are always replaced by the body's, and a body whose
commands cannot all be read is uninspectable and treated as force,
default-branch, and manifest at once. `derive_push` derives rewrites and
protected changes itself: a deletion is a rewrite; an old commit in admitted
history must be an ancestor of the new one; a request with no pack is compared
against the base as well; and an old commit outside admitted history, such as
the run's own earlier push, must be reached through commits the push adds.
Protected paths deleted, or given admitted content, count as protected
changes, not only added blobs.

### KSR-039: one spelling of the pull-request effect

The kernel required its one-use permit only for `.../pulls` exactly, while
keel-secrets trimmed slashes before deciding to inject the GitHub credential,
so `.../pulls/` got the credential without the permit. The kernel now treats a
trailing slash as the same effect, and keel-secrets injects only for the exact
spelling: no empty segments and no percent-encoding.

### KSR-040: untrusted text on the trusted screen

A guest-supplied diff or detail could print lines that read as the screen's
own and scroll the real header away. Untrusted blocks are now shown in a
gutter, bounded to 80 lines of 240 characters; `safe_text` escapes bidi and
other invisible format characters; the guest-reported origin is escaped; and a
line beside the prompt restates the action: remote, refs, force, default
branch, and manifest, or service, operation, and recipient.

### KSR-041, KSR-048: a runtime replaced while it runs

`keel setup` renames new binaries over running ones, and Linux then reports the
executable as `keel-input-runtime (deleted)`, so recovery and `keel status`
treated a live session as crashed and deleted its resources. Both now strip
that suffix. A Linux test renames a copy over a running process.

### KSR-042: the protected diff a new branch shows

gitd diffed only a new ref's tip against its first parent, so an earlier
commit's workflow file did not appear on the gate. The kernel now builds the
gate's protected view itself from the derived push: every protected path it
changes, comparing a new ref with the admitted `HEAD`, and the content of every
protected file it adds. The relay's diff is no longer shown when the kernel
derived one.

### KSR-043: a torn final record

A crash mid-record left a partial last line, and recovery failed on it every
time, stopping every later chain in the directory too. A partial last line
without its newline now ends the authenticated prefix and is reported as
truncated; a malformed complete line still fails. One chain that cannot be read
no longer stops recovery of the others.

### KSR-044: which code a push comes from

Attribution counted only executables under writable roots and arguments with a
script suffix. It now also counts any argument naming an existing file under a
writable root, which covers Git hooks and scripts without a suffix; build and
package runners (make, npm, cargo, and others) started in a writable directory;
and an ancestry cut off by reparenting to PID 1, except Keel's own tmux server.
A process found to run workspace code when it execs keeps that mark, keyed by
process id and start time, however it rewrites its argv afterwards; and a
command in a tmux pane other than Keel's own, which is the server's first
child, is workspace code. Residual: attribution remains the guest's own claim,
the exec-time mark is read from a lossy event stream shortly after the exec,
and a process that rewrites its argv before that read is judged by the
rewrite.

### KSR-046: accepting the reviewed policy

`keel policy accept` now requires `--hash`, the hash in the review the operator
read, and refuses a draft whose hash differs; `keel policy compile` prints the
command with it. A pinned policy bundle is also named on the admission screen
whenever that screen is shown.

### KSR-047: request targets inside terminated TLS

An absolute-form target such as `POST https://other.example/upload` was
authorized as a path and forwarded verbatim, and some upstreams route by it.
Only an origin-form target is now read: it must start with `/`, not `//`, and
carry no fragment.

### KSR-049, KSR-050, KSR-061: what setup builds and a release ships

`keel setup` built from any checkout-looking directory above the working
directory. It now builds only from the checkout the running `keel` was built
from, or `KEEL_SOURCE_DIR`, and prints which. The macOS build uses `--locked`.
`package-release.sh` refuses a dirty checkout and builds the release from HEAD
into a fresh install directory, so nothing installed earlier ships.

### KSR-051: release authenticity

The tarball's `.sha256` and the bundled `SHA256SUMS` come from the same place as
the release, so they detect damage, not tampering. The README, the release
script, and `install.sh` now say so. `KEEL_RELEASE_SIGN=1 package-release.sh`
signs the tarball with Sigstore's keyless flow: a short-lived certificate bound
to the maintainer's GitHub login, a public transparency-log entry, and no key
kept anywhere. The README verifies the bundle with `cosign verify-blob`,
installed from outside the tarball, before unpacking. The first signed release
needs the maintainer's interactive login, so it is pending.

### KSR-052: the operator's Ctrl-G

The supervisor decoded the attach client's escaped Ctrl-G and wrote it raw to
the runtime, which decoded it again, so Ctrl-G q stopped the run and Ctrl-G s
took four keys as a size. The supervisor now re-escapes keystrokes, a direct
run decodes no control messages, and a size outside 1..1000 is dropped.

### KSR-053: where a run's directories are

Recovery required the broker directory under `/tmp` and scratch under its own
`TMPDIR`. It now accepts the canonical path the chain recorded when it has the
run's naming and is a private directory of this user, or is already gone.

### KSR-054: the backend before it is recorded

A runtime killed between spawning the backend and recording its process group
left a VM that recovery could not find. The backend now starts behind a shell
gate that waits on a pipe; the runtime opens it only once the group is durable
in the chain, and a runtime that dies first leaves the gate to exit unrun.

### KSR-055: the guest relays and descriptor exhaustion

A failed accept ended a guest relay for the rest of the run. It now logs and
retries, at most 256 connections are bridged at once, and a bridge whose host
side has ended releases its guest side.

### KSR-056: testing the seccomp filter

A unit test now interprets the filter as built, for every denied call, the
clone, prctl, and socket argument cases, x32 numbers, and a foreign
architecture, and fails on any jump out of the program. The guest's preflight
also forks two children that issue an x32 call and an `int 0x80` compat call;
the host refuses an `x86_64` guest unless both were killed by `SIGSYS`.

### KSR-057: bridges and the broker's slots

Long-lived egress bridges counted against the 64 broker slots, so they could
lock out Git, pull-request, and extraction requests. Only connections still
being decided count against those slots now; established bridges have their
own bound of 512. A request frame must also arrive whole within ten seconds,
not only each read within half a second, so a client that drips one byte at a
time cannot hold a slot.

### KSR-058, KSR-059, KSR-060: AWS and credential custody

The SigV4 signer's secret key and session token are now registered with the
audit redactor, and a refresh mid-run keeps the credential command's output out
of its error. The credential command has a one-minute deadline and is killed at
it. Every per-request copy of an injected credential is wiped, and the buffer it
is written into is sized so it never reallocates. The redactor is now one
shared set, and credentials obtained by a later refresh join it before they
are used. Its `Debug` output, which listed every secret it held, now shows
only a count.

### KSR-062: the pre-push guard

The guard now lowercases the remote URL and strips trailing slashes and `.git`
before matching, and `ci/test-pre-push-guard.sh` checks each spelling GitHub
accepts.

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
