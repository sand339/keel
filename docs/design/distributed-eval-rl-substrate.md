# Extending Keel into a distributed evaluation and RL execution substrate

**Status: future platform work; not implemented.**

This document describes how Keel could evolve from a local, single-operator
runtime into a fleet execution substrate for agent evaluations and
reinforcement-learning environments.

The goal is not to turn the central scheduler into a security kernel. Each
worker must continue making authority decisions locally through Keel's small
trusted kernel.

## Prerequisites

Fleet work should begin only after:

1. the Linux/KVM runtime in [linux-platform-support.md](linux-platform-support.md)
   reaches security parity;
2. [run admission and verified teardown](run-admission-and-verified-teardown.md)
   are implemented;
3. noninteractive runs have deterministic exit status and durable audit
   closure;
4. image and policy artifacts can be signed, distributed, and verified.

Without those properties, a fleet amplifies lifecycle leaks and ambiguous run
identity rather than solving them.

## Objectives

- Execute isolated evaluation and rollout jobs across Linux workers.
- Bind each episode to an immutable task, image, policy, repository, model,
  credential scope, budget, and run identity.
- Preserve local policy enforcement when the control plane is unavailable.
- Collect authenticated trajectories, audit chains, outputs, and metrics.
- Support deterministic reset, replay, checkpoint, and fork where the
  environment permits it.
- Prevent one tenant, task, rollout, or evaluator from affecting another.
- Reconcile and clean every run even after worker or control-plane failures.

## Non-goals for the first version

- Training or serving foundation models inside Keel VMs.
- Arbitrary long-lived user desktops.
- Cross-tenant shared mutable workspaces.
- A model deciding runtime authorization.
- Treating Kubernetes policy, cloud IAM, or a scheduler allowlist as a
  replacement for Keel's local broker.
- Perfect determinism for remote model providers.

## Proposed architecture

```text
                         CONTROL PLANE
  API / SDK -> job service -> scheduler -> placement and quotas
                    |             |
          artifact registry    worker registry
                    |             |
                    +------ signed run envelope ------+
                                                       |
                         LINUX WORKER                   |
       worker agent -> local admission verifier <------+
            |              |                |
       image cache     credential lease   policy cache
            |
       Keel supervisor and resource registry
            |
      +-----+---------------------+
      |                           |
   microVM                     microVM
  episode A                   episode B
      |                           |
      +---- trajectories, audits, results ----> DATA PLANE
```

The platform consists of three planes:

- **Control plane:** accepts jobs, validates references, schedules capacity,
  issues signed run envelopes, and tracks desired state.
- **Worker plane:** verifies admission, owns local resources, runs Keel VMs,
  enforces lifecycle, and reconciles actual state.
- **Data plane:** stores immutable artifacts, trajectories, audit chains,
  checkpoints, metrics, and evaluation results.

## Trust model

The control plane may select work, but it does not authorize individual agent
actions. A worker accepts only a signed, bounded run envelope. The local Keel
kernel derives its runtime state from that envelope and decides every MCP,
egress, Git, credential, and approval action.

New trusted or trust-sensitive components are:

- run-envelope signer authority;
- worker admission verifier;
- workload identity and credential-lease verifier;
- local resource registry and teardown verifier;
- artifact signature and digest verifier.

The scheduler, UI, queue, metrics pipeline, and artifact transport remain
outside the action-decision TCB.

## Signed run envelope

Every scheduled run should carry a canonical signed envelope containing:

- globally unique run and episode IDs;
- tenant, project, experiment, and task IDs;
- parent run or checkpoint for forks;
- worker eligibility constraints;
- kernel, initramfs, root filesystem, and tool-bundle digests;
- policy artifact and runtime-bundle digests;
- repository identity, commit, patch, and workspace-image digest;
- harness and model configuration;
- isolation profile and the selected VM image or V8 engine digest;
- normalized capabilities and network destinations;
- credential lease identities and exact scopes, without secrets;
- CPU, memory, disk, process, token, cost, and wall-clock budgets;
- provenance mode and initial source facts;
- evaluator and reward-function artifact digests;
- determinism seed and declared nondeterministic dependencies;
- issue time, expiry, signer, and signature.

The worker verifies the envelope and local artifacts before creating the VM.
The admission digest becomes the root identifier for audit, trajectory,
checkpoint, and teardown records.

## Worker agent

Each Linux machine runs a small worker agent responsible for:

- registering capacity and supported backend versions;
- leasing jobs from the scheduler;
- downloading and verifying content-addressed artifacts;
- invoking the local Keel admission path;
- maintaining a resource registry for VMs, helper processes, sockets, mounts,
  cgroups, and temporary files;
- reporting heartbeats and state transitions;
- uploading results and authenticated audit artifacts;
- enforcing cancellation and deadlines;
- recovering or quarantining stale runs after restart;
- refusing new work when local invariants fail.

The worker agent must not bypass the Keel broker to improve throughput.

## Evaluation execution contract

An evaluation task needs a machine-readable contract:

```text
prepare -> reset -> run agent -> observe -> evaluate -> finalize
```

It should define:

- repository or environment initial state;
- task prompt and trusted-input provenance;
- available tools and network fixtures;
- completion and timeout conditions;
- expected output schema;
- evaluator artifacts and version;
- pass/fail and partial-credit rules;
- retained and redacted artifacts;
- retry semantics.

Evaluators should run in a separate sandbox from the agent. An agent must not
modify its evaluator, reward function, reference answer, or hidden tests.

## RL environment contract

RL workloads additionally require:

```text
create(seed) -> reset(checkpoint) -> step(action) -> observation/reward/done
```

The contract must make explicit:

- action and observation schemas;
- reward components and provenance;
- episode horizon and termination reasons;
- deterministic seed handling;
- checkpoint and fork semantics;
- environment-side tool results;
- model request accounting;
- whether network fixtures are replayed or live;
- which state is excluded from the agent's observation.

Keel's existing MCP boundary is a natural action transport, but coding-agent
episodes may also need a higher-level task protocol for shell, file, test, and
Git observations.

## Determinism and replay

Exact replay requires control over:

- initial filesystem and repository bytes;
- clock and timezone;
- randomness and entropy exposed to the guest;
- process scheduling where outcomes depend on races;
- package and network responses;
- model and evaluator versions;
- tool output ordering;
- CPU architecture and guest kernel;
- checkpoint format.

Remote model APIs prevent complete bit-for-bit determinism. The platform should
therefore distinguish:

- **artifact deterministic:** identical initial environment and tools;
- **fixture deterministic:** network and external services are replayed;
- **model best effort:** model provider and parameters are pinned but outputs
  may vary;
- **fully replayed:** prior model and tool responses are injected from a
  trajectory.

Never label a run deterministic without naming the level.

## Checkpoints, forks, and warm pools

RL throughput may require:

- content-addressed workspace snapshots;
- copy-on-write block images;
- VM memory snapshots;
- prebooted, credential-free warm guests;
- checkpoint trees linking parent and child admission digests.

Secrets, live proxy connections, approval tokens, and credential leases must
not be captured in reusable snapshots. A restored guest receives a fresh run
identity, broker, audit chain, credentials, and budgets.

Warm pools improve latency but enlarge the lifecycle and cross-run leakage
surface. They should follow a correct cold-boot implementation and use periodic
destruction rather than indefinite recycling.

## Networking and external services

Fleet guests still receive no NIC. All external traffic crosses local vsock to
the Keel broker.

At fleet scale, the broker may connect to:

- model gateways;
- recorded HTTP fixtures;
- package mirrors;
- Git mirrors;
- task-specific mock services;
- explicitly approved public endpoints.

Destination policy remains local and exact. A central egress gateway may
provide accounting and organizational controls, but it cannot widen the
run envelope or replace the local decision.

## Identity, secrets, and credentials

Use short-lived workload identity:

- worker identity through mTLS or SPIFFE-compatible certificates;
- one credential lease per run and capability;
- cloud KMS or secret manager for envelope-authorized retrieval;
- exact host, method, repository, path, and expiry scope;
- no reusable tenant credential in an image, checkpoint, queue message, or
  trajectory;
- immediate lease revocation on cancellation or teardown.

The worker should receive only the credentials required to construct the local
trusted broker. The guest continues to receive inert sentinels.

## Multi-tenancy

Multi-tenancy changes Keel's threat model. Required controls include:

- dedicated microVM per episode;
- cgroup CPU, memory, process, and I/O limits;
- per-run workspace images;
- no writable host-directory sharing between tenants;
- authenticated artifact ownership and access control;
- tenant-separated encryption keys and storage prefixes;
- scheduler quotas and admission rate limits;
- node quarantine after failed teardown;
- protection against disk, PID, CID, socket, and cache namespace collisions;
- explicit policy for same-host placement of mutually untrusted tenants.

High-risk tenants may require dedicated workers or hardware-backed attestation.

## Scheduling and capacity

The scheduler needs:

- CPU, memory, disk, architecture, backend, and locality constraints;
- queue priority and fairness;
- tenant and experiment quotas;
- cancellation and preemption policy;
- checkpoint-aware placement;
- image-cache locality;
- retry classification;
- worker draining and maintenance;
- admission backpressure when audit or artifact storage is unavailable.

Model token capacity and API cost are separate resources from VM CPU. Both must
participate in admission and quota accounting.

## Results, trajectories, and audit

Store immutable, content-addressed run outputs:

- admission envelope and digest;
- lifecycle and teardown receipts;
- Keel authenticated audit chain and verification key envelope;
- normalized trajectory events;
- prompts and model responses under configured retention policy;
- tool calls and observations;
- filesystem patch or final workspace snapshot;
- evaluator inputs, outputs, and reward components;
- resource, token, latency, and cost metrics;
- failure and retry classification.

Central ingestion must verify each run's audit chain before indexing it.
Searchable metadata may be rebuilt; immutable source artifacts remain the
evidence.

## Human approval

Interactive `Ctrl-]` approval does not scale to unattended rollouts. Fleet runs
should use reviewed deterministic policy:

- allowed routine operations proceed within the signed envelope;
- forbidden operations fail;
- escalations terminate or pause the episode according to experiment policy;
- optional human review occurs through an authenticated queue for a small
  subset of evaluations.

No model should convert an escalation into approval during execution.

## Observability and operations

Required fleet signals include:

- queue delay, boot time, reset time, and episode duration;
- active VMs and helper processes per worker;
- admission failures by reason;
- policy denials and escalations by rule;
- model tokens, cost, latency, and connection failures;
- checkpoint and cache hit rates;
- teardown duration and failed postconditions;
- stale resources and quarantined workers;
- audit ingestion and verification failures;
- tenant quota and storage consumption.

Operator tooling needs run inspection, audit verification, cancellation,
worker drain, quarantine, artifact lookup, and controlled terminal attachment
for debugging.

## Failure semantics

Every state transition must be idempotent. At minimum:

```text
queued
leased
admitted
starting
running
finalizing
stopping
stopped
failed
quarantined
```

A worker restart reconciles its resource registry with actual processes,
sockets, mounts, cgroups, and receipts. A scheduler timeout never assumes that
the VM disappeared; it marks the run uncertain until a worker proves teardown
or the worker is quarantined.

## Security invariants

- No VM starts without a valid signed run envelope.
- No guest receives a real credential.
- No action bypasses the local Keel kernel.
- Control-plane outage cannot widen authority.
- A checkpoint cannot carry authority into another run.
- Evaluator and hidden-test artifacts are inaccessible to the agent.
- Tenant workspaces and storage keys never overlap.
- Teardown failure prevents worker reuse for another tenant.
- Every terminal result links to admission, trajectory, audit, and teardown
  evidence.
- Scheduler metadata is never treated as proof of local enforcement.

## Implementation phases

### Phase F0: single-worker batch runner

- Linux Keel runtime;
- signed local run envelope;
- noninteractive task contract;
- one worker process;
- local artifact directory;
- verified teardown;
- sequential evaluations.

### Phase F1: internal evaluation fleet

- API, queue, scheduler, and worker registration;
- content-addressed artifact store;
- short-lived credential leases;
- centralized results and audit verification;
- hundreds of concurrent single-tenant jobs;
- cancellation, retries, and stale-run recovery.

### Phase F2: reproducible environments

- immutable workspace images;
- network fixtures;
- deterministic reset levels;
- checkpoint and fork lineage;
- evaluator isolation;
- trajectory replay.

### Phase F3: RL throughput

- step/reset API;
- copy-on-write snapshots and safe warm pools;
- batched rollout submission;
- reward-component pipeline;
- model and token-capacity scheduling;
- thousands of concurrent episodes.

### Phase F4: multi-tenant hardening

- tenant isolation and encryption domains;
- quotas, fairness, and abuse controls;
- worker quarantine and dedicated-node placement;
- disaster recovery and regional operation;
- independent security review and adversarial testing.

## Acceptance criteria

### Internal evaluation fleet

- A submitted job is either rejected before admission or produces complete
  admission, audit, result, and teardown artifacts.
- Worker or scheduler restart does not duplicate authority or lose lifecycle
  ownership.
- Cancellation proves VM and resource teardown.
- Hidden evaluator data cannot be read by the agent.
- A compromised guest cannot contact another run, worker service, metadata
  endpoint, or unlisted destination.
- Central audit ingestion detects tampering and missing terminal records.

### RL substrate

- Reset restores the declared environment state without carrying credentials,
  grants, budgets, or connections.
- Forked episodes have explicit parent lineage and fresh run authority.
- Reward components name their evaluator versions and source artifacts.
- Determinism level is recorded and verified by replay tests.
- Snapshot and warm-pool use produces no detectable cross-episode state.
- Capacity limits remain enforced under load and partial failure.

## Expected effort

| Target | Typical team | Estimated time |
|---|---:|---:|
| Single-worker batch prototype | 2–3 engineers | 2–3 months |
| Internal single-tenant evaluation fleet | 2–4 engineers | 3–5 months |
| Reliable multi-tenant evaluation platform | 5–8 engineers | 6–12 months |
| Large RL fleet with snapshot-based rollouts | 8–15 engineers | 9–18 months |

These estimates assume Linux platform support and verified lifecycle work are
already complete. Operating multiple regions, regulated data, or adversarial
external tenants increases the scope materially.

## Principal risks

- Snapshot optimization can silently preserve credentials or state across
  episodes.
- Central orchestration can become an accidental second authorization system.
- Remote model nondeterminism can be mistaken for environment nondeterminism.
- Reward evaluators can become a privileged code-execution path.
- Audit and trajectory volume can exceed VM compute cost.
- Aggressive retries can duplicate expensive or externally visible actions.
- Multi-tenant worker reuse is unsafe unless teardown failure causes
  quarantine.
- Throughput pressure can erode the per-action mediation boundary that gives
  Keel its security value.

## Decisions required before implementation

1. Cloud Hypervisor, Firecracker, or different backends for interactive
   evaluation and high-throughput rollouts.
2. Kubernetes integration versus a purpose-built worker scheduler.
3. Workspace block images versus object-backed filesystem snapshots.
4. Cold boot, memory snapshots, or credential-free warm pools.
5. SPIFFE-compatible identity versus cloud-specific workload identity.
6. Paused escalation versus deterministic episode termination.
7. Required determinism levels for each evaluation family.
8. Single-tenant first release versus multi-tenant design from the beginning.
