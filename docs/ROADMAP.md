# Keel roadmap

This roadmap contains future work only. Completed milestones and implementation history belong in the decision log and Git history.

Roadmap ordering expresses dependency and security priority, not a delivery date.

## Current baseline

Keel already has working macOS microVM execution for Claude and V8 workloads, a lower-assurance opt-in host V8 sandbox, policy and provenance enforcement, trusted approvals, brokered credentials and network access, resource budgets, persistent sessions, and authenticated audit logs.

Those features are documented in [Architecture](ARCHITECTURE.md). They are not roadmap items.

## R0 — Remaining public-source release readiness

Finish preparing the repository so a new user can understand, build, and evaluate it without private context. The repository has an explicit license, contribution guide, private-reporting policy, [pinned-artifact record](ARTIFACTS.md), [release checklist](RELEASE.md), and a known-limitations section in the README.

Remaining deliverables:

- decide the published history and authorship; the release tree itself has been scrubbed of personal and employer references;
- make setup and doctor output actionable on a clean Apple silicon machine;
- pin the guest's Alpine package set so the guest image is reproducible;
- run the complete CI suite on the release commit, and repeat the secret, dependency, and license review there;
- add a minimal end-to-end demonstration that produces verifiable audit evidence.

Exit criteria:

- a clean clone can follow the public README without undocumented steps;
- every public security claim points to implementation or test evidence;
- no historical plan is presented as current behavior.

## R1 — Canonical run admission and verified teardown

Implement [run admission and verified teardown](design/run-admission-and-verified-teardown.md).

The admission record will bind the authority-bearing inputs before a workload starts, including:

- run and continuation identity;
- kernel, initramfs, runtime, relay, and policy artifact digests;
- repository and workspace identity;
- isolation profile and requested capabilities;
- provider, credential handle, destinations, and budgets;
- provenance mode and starting floor.

The teardown path will terminate the full run process group, close relays, reconcile stale sessions, preserve intended evidence, remove transient control material, and emit a durable receipt describing verified postconditions.

Exit criteria:

- a run refuses to start when an admitted input changes;
- status can distinguish active, cleanly closed, interrupted, and stale sessions;
- stop returns only after observable teardown checks complete;
- crash-recovery tests cover host, guest, relay, and CLI interruption points;
- audit verification links admission, runtime events, and teardown.

## R2 — Security evaluation and reproducible evidence

Turn the current test suite into a publishable evaluation of Keel's claims.

Work:

- define adversarial scenarios for prompt injection, credential theft, destination confusion, replay, parser differentials, terminal forgery, provenance laundering, and audit tampering;
- run the same V8 workloads through both isolation profiles and document the expected boundary difference;
- add fuzzing for action parsers, relay framing, policy inputs, and audit verification;
- measure trusted-code size, dependency surface, startup time, steady-state overhead, approval latency, and relay throughput;
- publish exact source revision, platform, artifact hashes, commands, and raw results;
- add negative tests demonstrating what Keel intentionally does not prevent;
- validate Bedrock behavior against a live endpoint and capture protocol fixtures that contain no secrets.

Exit criteria:

- each threat-model objective has at least one positive and one negative test;
- published results are reproducible from a clean checkout;
- benchmark and security claims state their environment and limitations;
- known failures become tracked issues or explicit residual risks.

## R3 — Linux isolation backend

Implement [Linux platform support](design/linux-platform-support.md) with KVM and Cloud Hypervisor.

The goal is security-property parity, not merely successful boot. Linux should reuse the trusted policy, provenance, approval, audit, and relay semantics while replacing platform-specific VM lifecycle code.

Initial target:

- Ubuntu 24.04 LTS on x86_64;
- KVM with Cloud Hypervisor;
- pinned kernel, initramfs, and virtiofsd;
- interactive and noninteractive Claude sessions;
- V8 microVM workloads;
- equivalent no-normal-NIC posture and host-brokered effects.

Exit criteria:

- the same boundary and adversarial suites pass on macOS and Linux;
- platform differences are explicit in status and audit evidence;
- no container runtime is treated as the primary isolation boundary;
- Linux artifact admission and teardown meet R1 requirements;
- setup, doctor, and failure recovery work on a clean supported host.

## R4 — Distributed evaluation and RL substrate

Implement the [distributed evaluation and RL substrate](design/distributed-eval-rl-substrate.md) only after R1 through R3.

The fleet control plane must schedule work without becoming the authority oracle. Each worker continues to make sensitive decisions locally through Keel's trusted kernel.

Work:

- signed image, policy, workload, and evaluation bundles;
- worker identity, admission, lease, and revocation;
- deterministic noninteractive runs with durable closure;
- content-addressed evidence upload and verification;
- resource quotas and tenant separation;
- resumable scheduling and idempotent result collection;
- environment reset suitable for evaluation and RL rollouts;
- aggregation that preserves per-run provenance and audit identity.

Exit criteria:

- a compromised scheduler cannot grant an action that the worker's accepted policy denies;
- stale or replayed leases cannot start new work;
- every result is traceable to admitted artifacts and a verified teardown receipt;
- tenant-isolation and failure-recovery tests run under adversarial scheduling;
- local single-node operation remains supported and understandable.

## R5 — Optional render vertex

Evaluate the [render vertex](design/render-vertex.md) as a separate, narrowly scoped capability for browser-based validation.

This is exploratory and should not be added to the primary workload guest. A browser creates a large, frequently changing attack surface and conflicts with Keel's small-vertex assumptions.

Before implementation:

- define the exact validation use cases and outputs;
- place the browser in a separate isolation boundary;
- authenticate every request between the workload, broker, and render vertex;
- prevent the renderer from inheriting model or repository credentials;
- define provenance for pages, screenshots, downloads, and browser-produced evidence;
- establish artifact pinning, patch cadence, and teardown requirements.

Exit criteria:

- the render vertex can be disabled without changing core authorization semantics;
- browser compromise does not expose workload or host credentials;
- browser evidence is provenance-labeled and audit-linked;
- its maintenance cost and attack surface are justified by measured use.

## Cross-cutting future work

These items support multiple roadmap stages:

- reproducible and signed release artifacts;
- software bills of materials and dependency provenance;
- external audit witnessing and optional hardware-backed key protection;
- clearer policy-authoring diagnostics and smaller accepted policies;
- accessible trusted-approval UI and robust terminal repainting;
- documented compatibility and migration rules for policy, audit, and admission formats.

### Per-turn content provenance

Replace the conservative session scalar as an authorization input with a floor
derived from the exact content in each model request. This work must not infer
meaning or trust a harness assertion. Its exit criteria are:

- the broker records a content digest, rank, and source for every mediated
  result it delivers;
- each model request is walked at the trusted termination point, known content
  inherits its recorded rank, and unmatched content fails closed at rank 0;
- assistant blocks carry the floor of the turn that produced them, so summaries
  retain influence while content removed by compaction can leave the read set;
- subagent and model-mediated fetch results propagate through the same digest
  rule;
- a floor lift vouches for specific source/content references rather than a
  fungible session number;
- direct workspace reads have a separately reviewed attestation design, such as
  admission-time clean-tree blob commitments plus untrusted normalization with
  only digests crossing into the kernel;
- replay, compaction, collision-boundary, unmatched-content, and cross-session
  tests demonstrate fail-closed behavior.

The first increment, a shadow per-block digest log of every model request and
response with `keel report --context` (D54), is implemented. It measures
whether per-turn ranks would differ from the session floor before the larger
trusted spend.

## Explicit non-goals

The roadmap does not promise:

- autonomous interpretation of whether an action is morally or semantically safe;
- perfect prevention of data leakage through allowed output;
- container-only isolation as a substitute for a VM boundary;
- silent fallback from a failed strong isolation mode to a weaker one;
- moving natural-language interpretation into the live authorization path;
- an unbounded plugin system inside the trusted computing base;
- production multi-tenancy before admission, teardown, evaluation, and Linux parity are complete.

## How proposals enter the roadmap

A design note may explore an idea without making it a commitment. To become roadmap work, a proposal should state:

1. the user or security problem;
2. the trust-boundary effect;
3. dependencies and migration cost;
4. testable exit criteria;
5. impact on trusted code and dependencies;
6. failure and rollback behavior.

Implemented design notes such as the [policy compiler](design/policy-compiler.md), [V8 isolation](design/v8-isolation.md), and [Bedrock SigV4 relay](design/bedrock-sigv4.md) remain design references rather than future roadmap entries.
