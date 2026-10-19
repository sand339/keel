# Keel roadmap

Future work only. What is built is in [Architecture](ARCHITECTURE.md); its
history is in the decision log and Git. Order expresses dependency and security
priority, not a delivery date.

## R2 — Security evaluation and reproducible evidence

Turn the test suite into a publishable evaluation of Keel's claims:

- adversarial scenarios for prompt injection, credential theft, destination
  confusion, replay, parser differentials, terminal forgery, provenance
  laundering, and audit tampering;
- fuzzing for action parsers, relay framing, policy inputs, and audit
  verification;
- measurements of trusted-code size, dependency surface, startup time,
  overhead, approval latency, and relay throughput, on macOS and Linux;
- negative tests for what Keel intentionally does not prevent;
- published source revision, platform, artifact hashes, commands, and raw
  results.

Exit criteria:

- each threat-model objective has at least one positive and one negative test;
- results reproduce from a clean checkout;
- every claim states its environment and limitations.

## Enforce the action-centric verdicts

Task intent outside branch scopes and the action-centric decision table are
recorded in shadow and do not decide yet. Promote them once real sessions show
they help, measured with `keel report --axes`:

- a run of real sessions, on both platforms, where the action-centric rules
  remove more prompts than they add;
- no added denial of an action the operator would have approved;
- each verdict switched on separately, with the rule it replaces retired.

Exit criteria:

- the README no longer lists shadow verdicts as a limitation;
- `keel report --axes` shows the measured prompt change for each switch.

## Linux and VM tests in CI

Linux end-to-end runs are manual today, and CI boots no VM on either platform.
Run them on every push:

- Linux runners with KVM: `keel setup`, `keel doctor`, a `vm-v8` run, and the
  fault suite;
- release tarballs built in CI, installed by a user with no toolchain, and
  smoke-tested;
- live model cases on a schedule, behind a credential the repository holds.

Exit criteria:

- a change that breaks Linux setup, boot, confinement, or teardown fails CI;
- every published tarball comes from CI, not a workstation.

## Guest patch cadence

The guest's Chromium, Node, toolchains, and kernel are pinned, so they are
patched only when the lock is refreshed by hand, and Alpine removes superseded
versions from its CDN.

- a scheduled lock refresh for both architectures, rebuilt and run through
  the E2E suite;
- security advisories watched for every pinned guest package and VMM binary;
- the guest kernel and images published with each release, so installs never
  depend on Alpine keeping an old version.

Exit criteria:

- a published advisory for a pinned component reaches a rebuilt release within
  a stated window;
- a fresh setup from any release tag still succeeds after Alpine moves on.

## Guided setup (`keel init`)

First use stalls on credentials, not on installing: model keys are environment
variables in every shell, and authenticated push needs three hand-built
variables per repository. `keel init` records where each credential comes from
(Keychain, a credential process, `gh`) without storing any secret, derives the
push scope from the workspace's `origin` at admission, and ends with a short
first session on the real trusted screen.

Exit criteria:

- a clean macOS account and a clean Ubuntu user go from a release download to a
  gated push in about ten minutes with no environment variables;
- the admission screen names every credential source and derived scope a run
  uses;
- a sources file inside the workspace, or writable by others, is refused.

## More harnesses

Only Claude Code runs in the guest. The boundary is meant to be agent-agnostic;
a second harness tests that claim.

- one more coding agent, such as Codex CLI or Gemini CLI, with its provider
  brokered by the trusted proxy like the existing ones;
- the same credential, egress, provenance, and audit guarantees, shown by the
  same E2E cases.

Exit criteria:

- a second harness passes the E2E suite with no harness-specific trusted code;
- the README states which guarantees depend on the harness, if any.

## Proxy protocol coverage

The trusted proxy speaks HTTP/1.1 only and relays no WebSockets, so some tools
and pages do not work.

- WebSocket relay after the HTTP upgrade is judged, with the frames counted
  against the same budgets;
- HTTP/2 where a required endpoint needs it.

Exit criteria:

- the payload checks and audit records cover upgraded connections;
- the README limitation is removed or narrowed.

## Host V8 on Linux

The lower-assurance `v8-sandboxed` profile is macOS-only; Linux refuses it.
Supporting it needs a bubblewrap adapter for the Deno process, the same
explicit `isolation:v8-sandboxed` grant, and the same conformance tests. Low
priority while `vm-v8` works on both platforms.

## Per-turn content provenance (conditional)

Replace the session floor with one derived from the exact content of each model
request, but only if it beats the current baseline on real sessions: a declared
workspace rank, payload checks, restart in place of taint decay, schema-bounded
extraction, and lockfile inheritance. Measure with `keel report --axes`, whose
floor-only gates are the most this could remove. Dropping it is an acceptable
outcome. See the
[design note](design/guest-confinement-attribution-and-turn-provenance.md#80-w4a-and-w4b-a-declared-rank-floor-d79).

If built, it must fail closed: unmatched content ranks 0, a floor lift vouches
for specific content rather than a session number, and direct workspace reads
get their own reviewed attestation design.

## Cross-cutting

- the first signed release (keyless signing is built), and notarized macOS
  binaries;
- a software bill of materials and dependency provenance;
- ARM64 Linux on real hardware (it is tested only in a nested VM);
- external audit witnessing and optional hardware-backed keys;
- clearer policy-authoring diagnostics;
- compatibility and migration rules for policy, audit, and admission formats.

## Non-goals

- judging whether an action is semantically or morally safe;
- preventing all leakage through permitted output;
- containers as a substitute for a VM boundary;
- silently falling back to a weaker isolation mode;
- natural-language interpretation in the live authorization path;
- a plugin system inside the trusted computing base;
- multi-tenant or fleet operation: Keel is a local, single-operator boundary.

## Proposing work

A design note may explore an idea without committing to it. To become roadmap
work, a proposal states the problem, its effect on the trust boundary, its
dependencies and cost, testable exit criteria, its trusted-code impact, and its
failure and rollback behavior.
