# Policy compiler

## Security boundary

The policy compiler is untrusted. A host model may propose a translation,
but no model runs in the live authorization path. Claude runs in `--bare` mode
with tools disabled, so project instructions, plugins, hooks, MCP servers, and
memory do not enter the translation context. The compiler accepts only a closed
intermediate representation and produces a complete Cedar bundle plus a
separate Rego oracle.

```text
policy text
  → tool-disabled model proposal
  → closed-IR validation
  → Cedar + Rego generation
  → generated scenarios
  → Cedar/Rego/Rust differential check
  → reviewable draft
  → explicit acceptance
  → independently pinned runtime bundle
```

Generated rules can only restrict behavior. `escalate` and `deny` both compile to
Cedar `forbid`; a `deny:` rule ID tells the kernel that approval cannot override
it. Protected state and forbidden network ranges remain hardcoded outside
policy.

## Closed intermediate representation

A policy can select existing capabilities and define up to 64 stateful
rules. Each rule selects one action, one effect, and predicates combined with
logical AND.

The closed capability vocabulary is ordinary branch push, pull-request
creation, exact-host egress, force-push denial, and
`isolation:v8-sandboxed`. The isolation capability is an explicit acceptance
of the lower-assurance host V8 boundary; it never causes a fallback or weakens
the VM profiles.

Actions are `read`, `write`, `push`, `run`, `commit`, `egress`,
`pull_request`, `publish`, `delete`, and `lift_floor`.

Predicates are:

- always;
- provenance floor below a rank;
- recent writes or distinct files at a threshold;
- denials or escalations at a threshold;
- registry contacted;
- write target not created by this vertex;
- source host outside operator-owned domains;
- raw Git force update.

The compiler also validates exact executable and argument-role annotations.
Those annotations are preserved for review and for a mediated command channel.
The current guest shell is not host-mediated, so an annotation does not claim
that arbitrary in-guest process execution is intercepted.

## Verification

The compiler emits:

- the complete default schema;
- the default Cedar policies plus generated restrictions;
- a Rego implementation of generated restrictions;
- safe baselines for all action classes;
- a triggering scenario for every rule;
- one near-miss scenario for every non-`always` condition;
- independently computed expected violation IDs;
- a verification report;
- a runtime bundle hash and an outer artifact hash.

Acceptance regenerates and reverifies every derived field. It refuses blockers,
hash changes, Cedar warnings, Rego errors, missing rule coverage, generated
permits, or any Cedar/Rego/Rust disagreement.

This catches compiler and engine disagreement over the closed IR. It does not
prove that natural-language intent was interpreted correctly; the exact
translation remains an operator review step.

## Runtime loading

`keel mux --policy ACCEPTED.json` verifies the artifact and current HTTPS GitHub
origin, materializes the exact bundle in the private session directory, and
places its digest independently in the run request. Trusted `keel-input` loads
the bundle through `keel-policy`, which recomputes the digest and performs strict
Cedar validation before starting the broker.

The bundle is immutable for that runtime. Continuing a session must select the
accepted policy again so the expected digest is supplied again.
