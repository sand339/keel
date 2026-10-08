# Contributing to Keel

Thank you for helping improve Keel. Because Keel is a security-boundary project, a locally correct change can still be architecturally unsafe. Contributions should preserve the distinction between untrusted execution and trusted authorization.

Start with the [architecture](docs/ARCHITECTURE.md), [threat model](docs/THREAT-MODEL.md), and [usage guide](docs/USAGE.md).

## Before opening a change

For a small bug fix, documentation correction, or test improvement, a pull request is welcome directly.

Open an issue or design discussion first when a proposal:

- adds authority, credentials, networking, host access, or a new action class;
- changes the trusted/untrusted crate boundary;
- adds a dependency to a trusted crate;
- increases a trusted crate's line budget;
- changes policy, provenance, approval, audit, or secret semantics;
- adds an isolation backend or weakens an existing boundary;
- changes a persistent policy, audit, admission, or session format;
- implements a roadmap design with migration or compatibility consequences.

Do not file public issues for suspected vulnerabilities. Follow [SECURITY.md](SECURITY.md).

## Development environment

Keel currently targets Apple silicon macOS.

Install:

- Xcode Command Line Tools;
- Docker Desktop for guest-image setup;
- cpio, gzip, and shasum;
- the Rust toolchain pinned by rust-toolchain.toml.

From the repository root:

~~~sh
cargo run -p keel-cli --bin keel -- setup
keel doctor
~~~

See [Using Keel](docs/USAGE.md) for provider credentials and runtime details. Never place real credentials in source, fixtures, screenshots, audit logs, or pull requests.

## Repository boundary

The source tree deliberately separates trusted and untrusted crates:

~~~text
crates/
  trusted/
    keel-audit
    keel-input
    keel-kernel
    keel-policy
    keel-provenance
    keel-secrets
  untrusted/
    keel-cli
    keel-compile
    keel-conn
    keel-gitd
    keel-isolate
    keel-mcp
    keel-render
~~~

“Untrusted” does not mean low quality. It means the component must not be able to grant itself a protected effect if it is buggy or compromised.

## Security architecture rules

Contributions must preserve these rules:

1. **Only trusted code grants authority.** Launchers, renderers, relays, harnesses, guests, and policy translators may request or transport an action but do not decide it.
2. **Untrusted facts are asserted, not trusted.** The kernel reconstructs principal, provenance, session, budget, and other authority-bearing facts.
3. **Structural denials run before discretionary authorization.** Policy or operator approval must not override malformed or categorically forbidden actions.
4. **The live authorization path does not call a model.** Model-assisted policy translation remains outside the trusted computing base.
5. **Credentials remain host-owned.** Workloads receive handles or sentinels; trusted code binds secret use to the authorized destination and operation.
6. **Normal terminal output is not trusted input.** Approval authority remains behind secure attention and an action-bound, single-use decision.
7. **A live provenance floor rises only through an explicit operator lift.** Compaction and relay behavior must not silently reset influence. A new or continued broker currently starts fail closed at rank 0 and must never import authority from unsigned continuation state.
8. **No silent isolation downgrade.** Failure to start a microVM cannot fall back to the host sandbox.
9. **Fail closed on ambiguity and partial state.** Unknown actions, fields, versions, outcomes, and missing enforcement state must not create authority.
10. **Security-relevant decisions are auditable.** New protected effects need structured events and verification coverage.

Explain any proposed exception in the pull request and update the architecture and threat model. An exception that changes the security thesis should be discussed before implementation.

## Trusted computing base budget

CI enforces a 16,000-line ceiling across the six trusted crates, together with per-crate allocations and dependency-direction checks. Per-crate allocations total 14,567 lines (D52); the remaining 1,433 lines are unallocated reserve, not incidental headroom.

When changing trusted code:

- keep the change as small and explicit as possible;
- avoid moving convenience or protocol code into the trusted boundary;
- prefer closed enums and bounded inputs over extensible strings;
- document new authority and failure states;
- add negative tests for bypass, replay, malformed input, and partial failure;
- justify any budget reallocation or total increase in the decision log.

The line ceiling is a reviewability constraint, not a security proof.

## Coding expectations

- Keep unsafe Rust forbidden in trusted crates.
- Pin dependencies consistently with the workspace policy.
- Avoid hidden network access, dynamic code loading, or ambient credentials.
- Keep platform-specific behavior explicit.
- Preserve deterministic, bounded parsing at security boundaries.
- Use typed errors and fail-closed defaults.
- Keep unrelated refactors out of security-sensitive pull requests.
- Add comments for invariants and non-obvious security reasoning, not for syntax.

Use cargo fmt for formatting and address relevant Clippy warnings.

## Tests

Run the standard checks before opening a pull request:

~~~sh
cargo fmt --all -- --check
cargo check --workspace
cargo test --workspace
./ci/check.sh
~~~

Add focused tests appropriate to the change:

- unit tests for normal and malformed inputs;
- integration tests across the trusted/untrusted boundary;
- negative tests proving a denied action remains denied;
- replay and state-transition tests for approvals or sessions;
- audit verification tests for new security events;
- xterm-headless renderer tests for split sequences, canonical snapshots,
  terminal replies, approval overlays, modes, and resizing;
- both V8 profiles when behavior should be portable.

Tests that require live providers must be opt-in, must not expose credentials, and should record enough environment information to interpret the result.

## Documentation

Update documentation in the same pull request when behavior changes:

- README.md for the public product surface or quick start;
- docs/USAGE.md for operator-visible commands and troubleshooting;
- docs/ARCHITECTURE.md for components, trust boundaries, and implemented behavior;
- docs/THREAT-MODEL.md for assumptions, guarantees, attacks, and residual risk;
- docs/ROADMAP.md only for unfinished work;
- docs/design/ for detailed proposals and design reasoning.

Mark design notes as implemented, planned, or exploratory. Do not describe planned behavior as a current guarantee.

## Pull requests

A useful pull request includes:

- the problem and intended outcome;
- the affected trust boundary;
- implementation summary;
- tests run and their results;
- new dependencies or trusted-code growth;
- compatibility or migration impact;
- documentation changes;
- known limitations and follow-up work.

Keep commits reviewable and do not mix generated artifacts, unrelated formatting, or local runtime state into the change.

## Review priorities

Reviewers will prioritize:

1. authority and trust-boundary changes;
2. fail-closed behavior and state transitions;
3. credential and destination binding;
4. policy and provenance consequences;
5. audit completeness;
6. negative and adversarial tests;
7. compatibility and operator clarity;
8. code quality and performance.

Security-critical changes may require additional review even when the test suite passes.

## License

By submitting a contribution, you agree that it is licensed under the repository's [Apache License 2.0](LICENSE), unless you explicitly mark material that you are not authorized to contribute.
