# Keel documentation

This directory contains the public documentation for Keel. The five documents below are the normative starting point for users and reviewers.

## Start here

1. [Project overview](../README.md) — what Keel is, its current status, and a minimal quick start.
2. [Usage](USAGE.md) — install, configure, run, approve, inspect, and troubleshoot sessions.
3. [Architecture](ARCHITECTURE.md) — trusted and untrusted components, isolation profiles, and the action path.
4. [Threat model](THREAT-MODEL.md) — assets, adversaries, security objectives, assumptions, and residual risks.
5. [Roadmap](ROADMAP.md) — future work and the conditions required to call each item complete.

When documents disagree, current source and tests take precedence. Architecture and threat-model claims describe implemented behavior unless they are explicitly labeled planned.

## Repository policies

- [Security policy](../SECURITY.md) — report vulnerabilities privately and understand current support.
- [Contributing](../CONTRIBUTING.md) — development workflow, trust-boundary rules, tests, and review expectations.
- [Apache License 2.0](../LICENSE) — terms for use, modification, and distribution.
- [Third-party notices](../THIRD_PARTY_NOTICES.md) — attribution for embedded
  renderer dependencies and the components setup downloads.
- [Pinned artifacts](ARTIFACTS.md) — every downloaded artifact, its source and
  pin, and how to update it.
- [Release checklist](RELEASE.md) — what a release must pass, and the release
  notes.
- [End-to-end acceptance](E2E.md) — the headless suite and the manual runbook
  for operator decisions.

## Design notes

Design notes explain individual mechanisms in more detail. They are useful to contributors and security reviewers, but they are not substitutes for the architecture or threat model.

### Implemented foundations

- [Natural-language policy compiler](design/policy-compiler.md)
- [V8 isolation modes](design/v8-isolation.md)
- [Amazon Bedrock SigV4 relay](design/bedrock-sigv4.md)

### Planned or exploratory work

- [Canonical run admission and verified teardown](design/run-admission-and-verified-teardown.md)
- [Linux KVM and Cloud Hypervisor backend](design/linux-platform-support.md)
- [Action-centric provenance, guest confinement, and process attribution](design/guest-confinement-attribution-and-turn-provenance.md)
- [Distributed evaluation and RL substrate](design/distributed-eval-rl-substrate.md)
- [Triage reproduction profile](design/triage-reproduction.md)
- [Run profiles](design/run-profiles.md)
- [Render vertex concept](design/render-vertex.md)

The status stated inside a design note can lag the implementation. The [roadmap](ROADMAP.md) is the public list of unfinished commitments.

## Examples

- [V8 smoke workload](examples/v8-smoke.mjs)

The smoke workload is intentionally portable across Keel's Node-based microVM path and Deno-based host sandbox path.

## Deeper background

- [Learning guide](LEARNING_GUIDE.md) — a longer conceptual walkthrough.

## Project history and maintainer material

The following files preserve design history and implementation context. They are public for transparency, but they are not current user documentation and should not be read as promises:

- [Project brief](PROJECT-BRIEF.md)
- [Implementation plan](PLAN.md)
- [Decision log](DECISIONS.md)

Historical milestone language may describe an earlier repository state. Use the primary documents above for current behavior and the roadmap for future work.
