# Run admission and verified teardown

**Status: implemented.** Admission manifests (D57), in-chain teardown
(D73), the supervisor receipt and two-stage stop (D74), crash recovery (D75),
the idle timeout and recovery on use (D76), and fault injection (D77) are
described in the slices below. Roadmap R1 then finished the rest, in the
[R1 slice](#r1-slice-every-run-receipted-and-bound): receipts for every run,
relay and approval checks, credential wiping, booting the hashed image
copies, and the opt-in reaper. What it does not claim is listed there.

This hardening phase gives every VM boot a complete, immutable identity and
makes `keel stop` return only after Keel has checked the observable teardown
postconditions. It strengthens lifecycle evidence without claiming hardware
measured boot or proof that physical memory has been erased.

## Goals

1. Bind every authority-bearing input before VM creation.
2. Refuse a run when any admitted input changes or cannot be verified.
3. Shut down the complete run process group and trusted broker.
4. Return a durable teardown receipt describing every checked postcondition.
5. Preserve intended evidence, such as audit and provenance history, while
   deleting transient control and credential material.

## Run admission

Keel will construct a versioned admission manifest containing:

- run ID and continuation parent, when applicable;
- SHA-256 digests of the Linux kernel and guest initramfs;
- accepted policy artifact and materialized policy-bundle digests;
- canonical GitHub repository identity and canonical worktree root;
- the normalized capability set;
- the selected isolation profile and its pinned VM image or V8 engine digest;
- credential provider and exact host, method, and path scope, without secrets;
- harness, model provider, provenance mode, CPU count, and connection-reuse mode;
- exact cumulative model token and micro-US-dollar ceilings.

The trusted runtime will validate and canonicalize these fields, hash the
canonical manifest, and write `kernel.run-admitted` to the authenticated audit
chain before spawning the runtime backend. Admission fails closed if a field is
missing, disagrees with trusted configuration, or changes between validation
and handoff.

The implementation should open or copy boot artifacts into a private immutable
staging directory before hashing and retain those exact objects through VMM
startup. Hashing a path and reopening it later leaves a time-of-check/time-of-use
gap.

This provides a strong local admission claim: the trusted runtime authorized
specific bytes and specific authority for one run. It does not prove that a
malicious VMM booted those bytes. That stronger claim requires measured boot or
hardware-backed guest attestation and is a separate research project.

## v1 slice: admission manifest and session status

The first increment builds only the admission manifest and an untrusted
session status. The teardown receipt, two-stage stop, resource registry,
crash-recovery cleanup, and private staging of boot artifacts follow in later
slices.

**Why first.** The shadow reports (`keel report --axes` and `--context`) are
the evidence for promoting verdicts to enforcement. Without a manifest, an
audit chain does not say which guest image, kernel, policy, provider, price, or
capability set produced it, so sessions across those changes blend together.
The provenance design also places W2–W4 enforcement after this binding.

### Event

`kernel.run-admitted` follows only the broker's startup enforcement state and
precedes every action. It is written after trusted admission, including any
operator-admitted summary, and before `keel-input-runtime` spawns the
untrusted runtime, so no VM process exists before it is durable. It carries
`manifest`, canonical JSON (sorted keys, no whitespace, `"version": 1`), and
`manifest_sha256`. A hashing or write failure refuses the run.

### Fields

| Group | Field | Source |
|---|---|---|
| Identity | `run_id`, `keel_build` (crate version) | session id, compile time; a continued session keeps its id and starts a new chain |
| Components and boot artifacts (SHA-256) | `trusted_runtime`, `runtime`, `kernel`, `initramfs`, `rootfs` (D61), `vz_backend` or `v8_runtime` and `v8_sdk`, `renderer`; plus `kernel_release` | paths `keel-input-runtime` already selects; the Git relay is part of the VZ backend |
| Policy | `policy_artifact`, `policy_bundle` | accepted policy hash and `policy_bundle_hash` |
| Workspace | `root` (canonical), `head` (commit or `unborn`), `git_control` (existing digest), `origin` (credential host and path), `dirty` | worktree at admission |
| Authority | `capabilities` (normalized), `egress_hosts`, `credential_scopes` (host, methods, path prefix, sentinel name; never the secret) | runtime intent and credential vault |
| Model | `provider` (`anthropic`, `bedrock`, `openrouter`), `host`, `region`, `model`, `tariff` (input and output micro-USD per token, `source`: `reviewed-table` or `admitted-snapshot`), `token_ceiling`, `microusd_ceiling` | trusted provider selection and budget |
| Run shape | `harness`, `isolation`, `cpus`, `memory_gib`, `provenance_mode`, `starting_floor`, `connection_reuse`, `mux` | runtime request and intent |
| Admission | `admitted_by` (`trusted-terminal` or `not-required`), `summary_sha256` (SHA-256 of the exact summary admitted) | trusted input |

Excluded: secrets of any kind, the price list behind a snapshot, environment
dumps, and any guest state.

### Limits

- Boot-artifact digests are evidence, not enforcement. The untrusted VZ backend
  reads the files itself, and v1 hashes at admission without a private staging
  copy, because the threat model trusts the host OS.
- `head` and `dirty` describe the workspace at admission, not later changes.

### Untrusted consumers

- `keel status SESSION` reports `closed` (sealed), `active` (unsealed, its
  trusted runtime alive), or `interrupted` (unsealed, runtime gone), with a
  manifest summary. The v4 slice splits `interrupted` into `stale`,
  `recovered`, and `recovered-unclean`.
- `keel report --axes` and `--context` print the manifest summary (harness,
  model, provider, kernel release, policy bundle) for each session; totals
  are not yet split by group.

### Tests

- Canonical serialization is byte-stable.
- The existing redactor finds no configured credential in any manifest.
- Each provider fills `provider` and `tariff` correctly.
- In a real run, `kernel.run-admitted` precedes every other runtime record.
- A refused admission writes no manifest.
- Status classifies a sealed chain, a dead writer, and a live process that is
  not the trusted runtime.

### Cost

249 trusted lines (PLAN D57): input 184, secrets 34 (credential scopes and
tariff source), kernel 20, and audit 11. Status and report summaries are
untrusted.

## v2 slice: in-chain teardown for one run

The second increment makes one runtime process clean up everything it created,
verify each postcondition, and record the result as `kernel.run-teardown`
inside the authenticated chain, immediately before the seal. The serve-side
two-stage stop, crash recovery, and the fault-injection suite follow as later
slices.

### Defects it closes

- The untrusted backend runs in its own process group (`process_group(0)` in
  `keel-input-runtime`), so a forced stop that signals only the trusted
  runtime's group leaves `keel-runtime`, the VMM or `deno`, and Git running.
  The graceful path sends `SIGTERM` to the backend group but never escalates.
- An error between creating the run scratch directory and spawning the
  backend, including a refused admission, leaves the directory behind; an
  error after the spawn also leaves the backend running, because dropping a
  `Child` does not kill it.
- `floor.json` is saved after the seal, so the chain cannot attest it.

### Resource registry

One trusted guard, created at the start of `spawn_runtime`, registers each
resource as it is created: the backend process group, the renderer, the run
scratch directory (which contains the VM or V8 control directory, `ca.pem`,
`launch`, and the Git mirror), the kernel broker directory and socket, and the
V8 proxy listener. It is the only cleanup path. On the normal path and on drop
it signals the backend group with `SIGTERM`, escalates to `SIGKILL` after a
bounded deadline, reaps, removes paths, and checks:

- no group member remains (`killpg(pgid, 0)` reports `ESRCH`);
- each removed path is absent (`symlink_metadata` reports `NotFound`);
- the listener is closed.

### Event

`kernel.run-teardown` is written by the broker loop after the shutdown
enforcement state and before `audit.sealed`, carried in through
`shutdown_with_teardown` beside the Git-control boundary. It carries
`admission_sha256`; `stop_reason` (`exited`, `shutdown`, or `error`); whether
escalation was needed; one `check.N.KIND` field per resource, `ok` or the
unmet postcondition followed by a secret-free identifier; and an overall `ok`.
The broker adds a check for its own socket and directory, which it removes once
no client can connect. The run exits nonzero, naming the postcondition, when a
runtime-side check fails (PLAN D71–D73).

`floor.json` is still saved after the seal: moving it would mean reading
session facts before the broker has closed its pushes and reservations.

### Consumers

- `keel status` prints a `teardown:` line and adds `closed-unclean`: sealed,
  with a teardown `ok` of false. A chain without the record, such as one sealed
  by an early-error exit, reports `not recorded`; verification does not reject
  it, because that exit is not tampering.
- `keel report` prints the teardown outcome beside the manifest summary.

### Limits

- Facts established after the seal, including all serve-side cleanup (attach
  socket, pid file, request file, `attach.exit`), are outside this event. The
  [v3 slice](#v3-slice-supervisor-receipt-and-two-stage-stop) adds a receipt
  bound to the sealed chain tip.
- Virtualization.framework may host the guest in a launchd-managed XPC service
  outside every Keel process group. Until a spike confirms otherwise, the event
  reports the VM as stopped through the framework API, not as an absent
  process.

### Tests

- Normal VZ and V8 runs end with a passing teardown event that checks every
  registered resource.
- A backend that ignores `SIGTERM` records escalation and leaves no group
  member.
- A refusal after the scratch directory exists leaves no directory; an error
  injected after the spawn leaves no backend process.
- An unremovable path yields a nonzero exit, the named postcondition, and a
  failing event.
- The audit chain binds the record to the admission digest and places it
  before the seal; an unmet postcondition yields `ok` false.
- The redactor finds no configured credential in the event.

### Cost

Estimated 250–320 trusted lines: `keel-input` about 200 (registry and checks),
`keel-kernel` about 40 (event plumbing), and `keel-audit` about 20 (sink and
verification rule). Status and report changes are untrusted.

## v3 slice: supervisor receipt and two-stage stop

**Status: implemented (PLAN D74).** The persistent session supervisor
(`keel-input-runtime serve`) now owns the facts established after the seal and
records them in a signed receipt; `keel stop` returns only once that receipt is
durable.

### Key anchoring

The chain's run key never leaves the run process, so the supervisor cannot sign
with it. Instead `serve` generates its own Ed25519 key, held only in memory,
and passes the public half to the run it spawns. The run records it as
`supervisor_key` in `kernel.run-teardown`, inside the authenticated chain. A
receipt therefore verifies only under the key its own sealed chain names.

### Protocol

1. `STOP` makes `serve` send the cooperative shutdown control and reply
   `STOPPING`. It holds the connection and accepts no further clients.
2. When the run exits (or, after 5 s, is terminated), `serve` closes its
   listener, ends whatever remains of the runtime's process group (`SIGTERM`,
   then `SIGKILL`), removes the attach socket, pid file, and request file, and
   checks each is gone.
3. It locates the run's chain (named for the runtime pid and written after the
   spawn), requires it to be sealed with a teardown record naming this
   supervisor, and records the seal's record digest as `chain_tip`.
4. It records the SHA-256 of each file kept on purpose (`attach.exit`,
   `floor.json`), signs the receipt, writes `AUDIT.receipt.json` beside the
   chain with `fsync` of the file and directory, and replies
   `STOPPED AUDIT.receipt.json`.
5. `keel stop` reads the receipt, names every unmet check, and exits nonzero
   if any. Repeating it after the session has gone reports the latest receipt.

A run that exits on its own writes a receipt by the same path, with
`stop_reason` `exited`.

### Consumers

`keel status` verifies the receipt beside the chain against `supervisor_key`
and the verified seal, and prints a `receipt:` line. A receipt that does not
verify, or names another chain, is an error, as an edited chain is. A sealed
chain whose receipt has an unmet check, or whose `floor.json` or `attach.exit`
no longer matches the recorded digest, is `closed-unclean`. This gives
`floor.json` the attestation the v2 slice could not.

### Limits

- The receipt's trust is the chain's: local tamper evidence, not attestation.
  Anyone who can replace the chain, its key file, and the receipt together can
  forge all three.
- `KEEL_SUPERVISOR_KEY` is honoured only with `KEEL_INPUT_SOURCE` set to
  `trusted-supervisor`, but both are environment the untrusted CLI could set on
  a direct `run`; a forged key can only vouch for serve-side files.
- A supervisor that crashes or is killed writes no receipt; `keel stop`
  reports a stale socket as a supervisor gone without one. Crash recovery
  remains the next slice.
- Deny-pending-approval at stop, secret zeroization, and connection-pool
  checks are not yet recorded.

## v4 slice: in-chain resources and crash recovery

**Status: implemented (PLAN D75).**

### Registration

The run records each host resource in the authenticated chain as
`kernel.run-resource` (`kind`, `detail`) before the backend can act on it:
the broker's private directory, the run scratch directory, and the backend's
process group. Audit records are `fsync`ed as they are written, so the
records survive a `SIGKILL` of the run. A resource whose record cannot be
written makes the run refuse to continue, and the D71 guard releases it.

### Recovery

`keel recover SESSION` runs trusted `keel-input-runtime recover`. For each
chain in the session directory that is unsealed, whose writer (the pid in its
file name) is not a live `keel-input-runtime`, and that has no recovery record,
it reads the authenticated prefix and releases each recorded resource:

- a directory only if it is in the expected temporary root and named for that
  run's pid (`keel-runtime-PID-…`, `keel-kernel-PID-…`); otherwise it is
  reported, not removed;
- a process group only if every member is a Keel backend component
  (`sandbox-exec`, `keel-runtime`, `keel-vz-spike`, `deno`, `git`, `git-*`)
  and a live leader started before the run recorded it. A group whose leader
  is gone cannot have been reused while members remain. It is then ended
  `SIGTERM`, then `SIGKILL`, and checked empty. An unreadable process table
  refuses rather than signals.

It writes `AUDIT.recovery.json` (chain, authenticated record count, recovery
time, one check per resource, `ok`) with `fsync`, and never touches the chain.
If `attach.pid` names a supervisor that is gone, it also removes the attach
socket and pid file and records `attach-PID.recovery.json`.

### Consumers

`keel status` reports an unsealed chain whose writer is gone as `stale` until
recovery has run, then `recovered` or `recovered-unclean`, with a `recovery:`
line. `keel doctor` warns of stale sessions and names the command to run.

### Limits

- The recovery record is unsigned: no key the chain names outlives the crash.
  It describes what recovery observed and when, not the state at the crash.
- A backend spawned but killed before its record was written is not recorded;
  the window is one `spawn` return.
- Virtualization.framework may keep the VM in an XPC service outside the
  recorded group (see the v2 limits).
- Recovery runs only when invoked; `keel run` does not yet reconcile at start.
- Run request files are not removed: one may belong to a session starting
  concurrently.

## v5 slice: idle timeout and recovery on use

**Status: implemented (PLAN D76), except the opt-in reaper, which is
planned.** A session can be stale in two ways that need different answers: it
crashed and left resources behind, or it is alive but nobody is attending it.
The second holds a VM and live credentials, so it is the larger risk.

### Idle timeout

`serve` stops a session that is detached and has produced no output for its
idle limit, through the same cooperative shutdown as `STOP`, so the run seals
and the receipt records `stop_reason` `idle`. A pending approval with no one
attached counts as idle, since the agent is blocked on a person. The limit
defaults to 12 hours; `keel run --idle-timeout HOURS` (0 to 720, 0 disables)
reaches `serve` as `KEEL_IDLE_TIMEOUT_SECS`. A malformed value keeps the
default rather than disabling it. The setting is untrusted input but can only
end a session sooner.

### Recovery on use

There is no daemon. `keel run` and `keel attach` first recover every stale
session whose chain has not changed for a grace period (15 minutes,
`KEEL_RECOVERY_GRACE_MINUTES`; `KEEL_AUTO_RECOVER=off` disables it), report
one line, and never block the command. The grace exists only to keep a fresh
crash's scratch directory for inspection: recovery's own checks, not the
timer, make it safe. A cheap pre-filter skips chains that are recovered,
receipted, sealed (by their last line), or recently written, and only the rest
are authenticated in full; on 217 session directories a warm pass takes about
80 ms. `keel recover --all` runs the same pass with no grace. `keel status`
and `keel doctor` only report.

### Opt-in reaper (planned)

A host where Keel is not used for days would keep an orphaned backend until
the next command. `keel setup --install-reaper` would install a launchd agent
running `keel recover --all` hourly. It changes host configuration, so it is
opt-in and not part of this slice.

### Fault injection (PLAN D77)

`ci/faults.py` runs the trusted runtime in front of a fake backend that
misbehaves on purpose. Its first runs found three defects, all fixed in D77:

- **The supervisor's pty reached the backend.** `openpty` returns descriptors
  without close-on-exec, so the run, and through it the untrusted backend,
  inherited both ends of the persistent supervisor's terminal and could write
  to them from inside the sandbox: the master is the trusted operator-input
  path, the slave the operator's screen. `serve` now marks both close-on-exec,
  and the trusted runtime refuses to start holding any inherited
  terminal-class descriptor; trusted code cannot mark a raw inherited
  descriptor itself without `unsafe`.
- **A cooperative stop never escalated.** On the shutdown control or a
  forwarded signal the run sent `SIGTERM` to the backend group and waited for
  the backend indefinitely; a backend that ignored it outlived the run when
  `serve` killed the run's own group. Each stop request now escalates to
  `SIGKILL` after the same 2 s grace teardown uses, and the in-chain teardown
  records it. A forced stop in `serve` also runs recovery on the chain before
  writing its receipt.
- **A run outlived its supervisor.** With the master leaked, a dead `serve`
  never produced a hangup, so the run ran on unattended, reported `active`,
  and could be neither stopped nor recovered. With the master closed, the run
  now treats end-of-input on its terminal as a hangup and stops in order.

### Not done

Session directories are never deleted automatically: chains are evidence, and
pruning them is a retention decision for the operator.

## R1 slice: every run receipted and bound

- **Every run ends with a receipt.** A `RunSession` guard owns the broker and
  the run's resources from the broker's start. On every exit, early errors
  included, it releases the resources, seals the chain with a teardown record
  (stop reason `error` on an early error), and, for a run no `serve`
  supervises, signs its own receipt with a key held only in memory whose
  public half the teardown record names.
- **Relays, pools, and approvals.** The broker joins every client thread
  before sealing; each owns its guest relay and any upstream connection it
  reuses. The teardown record names how many were open at stop
  (`relay-sessions`) and whether a pending approval was denied
  (`pending-approval`).
- **Credentials are wiped.** Beyond `SecretBytes`, Keel wipes each forwarded
  request with its credential or session token injected, every intermediate
  buffer of the injection, the session token's copies in signing, the
  credential-process and `gh` output, and the redactor's copies.
- **The hashed images are the booted images.** The launcher copies the
  kernel, initramfs, and root disk into a private run directory, hashes the
  copies for the manifest, and boots those; the directory is a recorded
  resource that teardown removes and recovery releases.
- **Opt-in reaper.** `keel setup --install-reaper` runs `keel recover --all`
  hourly through launchd or a systemd user timer.

Limits:

- A process of the same user can race the private image copy; on ext4 the copy
  costs about 2 s and 700 MB per run, where copy-on-write makes it free.
- The process environment block and `ring`'s derived signing keys are not
  wiped: the first needs `unsafe`, the second lives inside `ring`'s types.
- A crashed supervisor still writes no receipt, and recovery records stay
  unsigned.
- The receipt is local tamper evidence, not attestation.

## Verified teardown

The two-stage protocol and receipt below are implemented for persistent
sessions by the v3 slice; the remaining supervisor duties (denying a pending
approval, relays and connection pools, zeroization) are not yet recorded.

`keel stop RUN` is a two-stage protocol:

1. `STOPPING` acknowledges that the trusted supervisor accepted the request.
2. `STOPPED` is returned only after teardown checks pass and the receipt is
   durable.

The supervisor must:

- deny any pending approval and stop accepting new actions;
- close the kernel broker and durably finish the audit chain;
- terminate the VM and its complete process group, escalating from `SIGTERM` to
  `SIGKILL` after a bounded deadline;
- verify that every recorded process has exited;
- remove and verify absence of attach, broker, relay, and temporary sockets;
- remove VM control directories, temporary CA files, request files, and
  credential-process output;
- drop proxy connection pools and verify that no run-owned process remains to
  hold a connection;
- zeroize Keel-owned secret buffers before their owners exit;
- retain only documented durable state: authenticated audits, audit keys,
  accepted policy metadata, provenance history, and the teardown receipt.

The receipt will identify the admission digest, run ID, stop reason, timestamps,
termination escalation, each checked resource, retained files, and final
success or failure. `keel stop` must exit nonzero if a required postcondition
cannot be established. Repeating the command should return the existing valid
receipt or complete interrupted cleanup.

## Crash recovery

The [v4 slice](#v4-slice-in-chain-resources-and-crash-recovery) implements
the first form of this section.

Normal shutdown is insufficient because the host or supervisor can crash.
Startup and `keel doctor` should detect session directories with no live
supervisor and no successful teardown receipt. A recovery command can remove
recorded transient resources and append a recovery receipt, but must never
rewrite the earlier audit chain or claim that unobserved cleanup happened at the
original crash time.

## Implementation stages

Stages 2, 3, and 5 are implemented (v2 and v3 slices), stage 4 by the v1 slice
for the audit event, and stage 6 in its operator-invoked form (v4 slice).

1. Define canonical admission and teardown receipt schemas.
2. Add an explicit run resource registry owned by the supervisor.
3. Move runtime control directories under that registry and make cleanup
   guard-based on every error path.
4. Add trusted admission validation and the pre-boot audit event.
5. Change the stop protocol to wait for verified completion.
6. Add stale-session detection and recovery.
7. Add fault-injection tests for backend hangs, leaked sockets, failed audit
   flushes, changed images, changed repositories, and mismatched credential
   scope.

## Acceptance criteria

- Mutating any admitted field before boot refuses the run.
- Changing a boot artifact after hashing cannot alter the object handed to the
  VMM.
- No VM process is created before `kernel.run-admitted` is durable.
- `keel stop` does not report success while a recorded process, socket,
  connection owner, or transient control directory remains.
- A failed cleanup produces a nonzero exit and names the unmet postcondition.
- Secrets never appear in either manifest or receipt.
- Admission and teardown events verify as part of the existing authenticated
  audit chain.
- The full lifecycle passes repeated start/stop, forced-kill, and host-crash
  recovery tests.

## Scope and TCB budget

The pragmatic implementation is expected to add roughly 700–1,200 first-party
lines across trusted validation, untrusted orchestration, schemas, and tests.
This proposal predated D39. Since D65 each trusted crate is held to a line
ratchet with no aggregate ceiling; trusted growth raises a ratchet with a stated
reason and must not move silently.
