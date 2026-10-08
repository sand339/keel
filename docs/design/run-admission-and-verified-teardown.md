# Run admission and verified teardown

**Status: partially implemented.** Trusted-terminal admission now binds the
declared task capabilities, egress hosts, and elevated model token/cost
ceilings before workload execution. The [v1 slice](#v1-slice-admission-manifest-and-session-status),
an audited admission manifest and session status, is implemented (D57); the
byte-bound staging of boot artifacts and the verified teardown receipt follow
with R2.

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
crash-recovery cleanup, and private staging of boot artifacts wait for R2.

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
  manifest summary.
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

## Verified teardown

`keel stop RUN` will become a two-stage protocol:

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

Normal shutdown is insufficient because the host or supervisor can crash.
Startup and `keel doctor` should detect session directories with no live
supervisor and no successful teardown receipt. A recovery command can remove
recorded transient resources and append a recovery receipt, but must never
rewrite the earlier audit chain or claim that unobserved cleanup happened at the
original crash time.

## Implementation stages

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
This proposal predated D39. D64 records the current 16,000-line hard ceiling
with 15,331 lines allocated and a 669-line reserve after regression-only code
was moved out of production `src` and the broker's atomic grant-liveness
guarantee was added. Future trusted growth requires an explicit
reallocation or a separately recorded change to the hard ceiling; it must not
move silently.
