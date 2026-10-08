# Keel — project brief

**A secure local runtime for coding and research agents. One agent, one boundary, in Rust.**

| | |
|---|---|
| Status | Research prototype through Phase 3 (2026-09-22); evaluation and packaging remain |
| Scope | Single vertex. Personal, local, single-operator. |
| Hosts | Claude Code, Codex, Goose, or any harness that speaks MCP and can live in a guest |
| Relationship to prior work | Implements Part I of *Containing Autonomous Principals* (`../paper/`). Same problem space as IronCurtain (Provos), which is ahead on the node contract and honestly cited as such. |
| Explicit non-goal | The collective. No envelopes-over-a-wire, no delegation chains, no topology policy, no tree ledger. See "Why no crew." |
| Name | Working title. Alternatives: `Warden`, `Girder`, `Plinth`. |

---

## The problem, stated for one agent

You run Claude Code on your own machine, against your own repositories, with your
own credentials. It reads a GitHub issue. It reads a dependency's README. It
fetches a documentation page. Any of those can carry text the model obeys as an
instruction, because the boundary between data and instructions dissolves inside
a context window.

Then it force-pushes, merges a PR, installs a package, or sends something.

That is the whole threat. Not a rogue crew — **one credulous agent that read the
wrong page and then used your real authority.** Everything in this project points
at that sentence.

The current answers are both unsatisfying. Restrict the agent to a narrow sandbox
and it stops being useful. Approve every action and you stop reading the prompts
by Thursday. The interesting design space is in between, and it is mostly
unexplored because it requires the runtime to know something the model doesn't
tell it.

---

## Thesis

Two claims, in order of confidence.

**1. A runtime is a security kernel wearing an SDK costume.** Everything valuable
about it — policy decisions, credential custody, budget accounting, audit
integrity — is a small amount of code that must be correct, and everything else is
convenience that must be *outside* the boundary. Existing runtimes invert this:
the enforcement point shares a process with orchestration, prompt assembly, the
transcript store, and a web UI, so the trusted computing base is whatever the
repository happens to contain. Keel declares a size-capped, statically linked,
CI-enforced TCB and puts everything else outside it, untrusted by construction.

**2. The runtime should track what entered the agent's context, and let policy
read it.** A tool call is not just `(tool, args)`; it is `(tool, args, everything
this agent has read since it started)`. No shipping runtime evaluates the second
half. Once the kernel accounts for it, a control that currently cannot be
expressed becomes trivial: *you fetched a web page, so pushing to the default
branch now requires me to ask.*

Claim 1 is engineering with a known right answer. Claim 2 is the research
content, and it may turn out to be too conservative to use — which is a result
worth having either way.

---

## Why no crew

The collective machinery from Part II of the paper is dropped, and not merely
because you run one agent at a time.

**Edge mediation cannot see the interactions that actually happen.** When Claude
Code spawns a subagent, that occurs inside the harness, inside one guest. No
message crosses a boundary the kernel could stamp. An envelope schema, a
delegation chain, a declared-edge topology, and a tree-scoped ledger all exist to
police a wire that does not exist in this deployment. Building them means
watching every interesting interaction happen underneath the mediation layer.

One thing is kept, because it costs a day and buys the seam back later: **the
`Asserted` / `Stamped` type split.** Sender-supplied fields and kernel-written
fields are distinct types, and the kernel-written half has no public constructor
outside the kernel. That is what makes "the agent cannot raise its own trust
label" a compile error rather than a code-review convention. The chain,
intersection, and topology machinery can be added on top of that shape without a
redesign, if the deployment ever grows a real wire.

---

## What Keel is

A single binary (`keel`) that:

1. **Boots one vertex per task** — an isolation boundary below the language
   runtime, a microVM or user-space kernel, never a bare container. Keel drives a
   backend; it never becomes one.
   JavaScript evaluators may explicitly choose the lower-assurance
   `v8-sandboxed` profile, which is labeled separately and cannot satisfy this
   criterion.
2. **Owns the only route out.** The vertex has no network route, no DNS resolver,
   and no credentials. Its sole channel is a vsock/UDS transport to the kernel.
3. **Runs your real harness, interactively.** Claude Code's TUI, bridged over a
   PTY, feels local. A runtime you resent using is a runtime you turn off.
4. **Mediates every consequential action** — tool calls *and* raw egress —
   through one deterministic policy decision point. Egress is not a separate
   allowlist with its own logic; it asks the same PDP.
5. **Brokers credentials.** Real API keys and OAuth tokens never enter the guest.
   Sentinels are swapped for real values after the policy check, outside the
   model's view.
6. **Accounts for provenance.** Every result crossing into the guest is labelled
   by source class; the vertex's trust floor is the running minimum; capabilities
   declare a minimum rank they require.
7. **Keeps state that policy can read.** What files did this agent create? Has it
   fetched from a registry? How many writes in the last minute? Rules can ask.
8. **Gates what is irreversible** and hash-chains every decision into a log the
   agent cannot reach.

## What Keel is not

- Not an agent framework. No prompts, no planner, no model opinion.
- Not a virtualization layer.
- Not multi-tenant, not hosted, not remote. Co-located trust model: the kernel,
  the proxies, and the secrets are on the machine you own. Multi-tenancy is a
  different threat model, not a scaling exercise.
- Not a replacement for review. Submission authority, not merge authority.

---

## Contributions

| # | Contribution | Why it isn't already done |
|---|---|---|
| 1 | **Declared TCB budget.** A 16k hard ceiling across six trusted crates, with 15,331 lines currently allocated and 669 explicitly reserved; CI-enforced, `forbid(unsafe_code)`, no runtime code loading. Everything else outside the boundary. | Existing runtimes have no boundary to declare. You cannot refactor toward this; it is a founding constraint or it is nothing. |
| 2 | **Tool-boundary provenance accounting.** Source-class labels assigned where data crosses into the guest; monotonic floor in kernel state; per-capability minimum rank. | In-model taint tracking is unsolved, so the field skipped the problem. Moving the accounting to the boundary makes it deterministic at a utility cost nobody has measured. |
| 3 | **Stateful policy.** Rules read session history — files this agent created, registries it contacted, recent write volume — not just the current call's arguments. | Policy engines in this space evaluate one call in isolation. "Escalate writes to files the agent didn't create" is inexpressible today, and it is the single most useful rule a developer wants. |
| 4 | **Egress under the same engine as tools.** Raw HTTP/S egress is policy-evaluated by the same PDP, with no allow-all escape hatch. | Proxies in this space do TLS termination, host allowlisting, and credential swap, but do not evaluate egress as policy — so the two halves of the action space have different semantics and different bugs. |
| 5 | **Differential policy verification.** Natural-language intent compiles to a closed IR and complete Cedar bundle; every generated scenario also runs against a separate Rego program and an independent Rust expectation. Disagreement refuses the artifact. | Compiled-policy fidelity is the top named limitation of this approach, and the usual check is an LLM judge reviewing an LLM compiler — which shares the failure mode. |
| 6 | **macOS-native isolation.** Virtualization.framework / libkrun directly, with the host-side kernel confined by seatbelt. | The mature path on this platform runs your agent in a Linux VM via Docker regardless. Native is a real engineering contribution on the machine most solo developers actually use. |
| 7 | **Escalation load as a measured property.** Escalations per task, time-to-decision, and the fraction approved in under two seconds — an honest instrument for rubber-stamping. | Escalation fatigue is universally acknowledged as *the* practical failure mode and universally unmeasured. You cannot tune what you do not count. |

Contributions 1, 4, and 6 are engineering. 2, 3, 5, and 7 are the research
content, and 2 is carrying the project.

---

## Running examples

Both are things you would actually do, chosen because between them they cover
every cell of the reversibility × blast-radius matrix.

**A — coding session.** Claude Code on one of your repositories. Reads code, runs
tests, edits files, commits, pushes a branch, opens a PR. Untrusted inputs arrive
via issue text, dependency READMEs, CI output, and fetched documentation.
Irreversible high-blast actions: force-push, push to default branch, PR merge,
adding a dependency, publishing a release.

**B — research and drafting session.** Fetches web pages, reads a local document
store, drafts, and sends or publishes. Untrusted input is the entire point of the
task, which makes it the honest stress test for provenance flooring.
Irreversible high-blast actions: send external mail, publish, share a file.

Example B is where contribution 2 either works or dies: an injected instruction in
a fetched page attempting to drive a `send` is the canonical laundering hop, and
the floor is the only control that sees it. But B is also the case where a
conservative floor is most likely to block work you wanted — the task *is* reading
untrusted content. If flooring survives B, it survives.

---

## Success criteria

Ordered; each gates the next.

1. **The boundary is real.** Trusted crates within budget, zero `unsafe`, CI fails
   if an untrusted crate links into the kernel. Two-sided preflight proves no
   route, no DNS, no metadata, no internal ranges — asserted from inside the guest
   *and* verified from the host, because a compromised image can ship a lying
   preflight.
2. **You use it voluntarily.** Claude Code's TUI in a vertex is close enough to
   local that you stop reaching for the unwrapped binary. This is a real
   criterion, not a nicety: an unused runtime has no security properties.
3. **A real laundering hop is denied.** A live agent reads a poisoned issue in
   Example A, attempts a force-push, and is stopped — with the audit log showing
   what it read, when the floor dropped, and which rule fired.
4. **Utility survives.** Both suites complete with an escalation count you
   tolerate for a week without degrading into reflex approval, measured by
   contribution 7's instrument rather than by vibe.
5. **The numbers exist.** Provenance false-positive rate, reset-frequency curve,
   and escalation-load comparison, reproducible with one command.
6. **The write-up lands.** An addendum to the paper — Part I with running code —
   or a standalone systems note, with Keel as the artifact.

## Risks

- **The isolation seam on macOS.** If Virtualization.framework / libkrun cannot
  give a real VM-per-vertex with a workable vsock story, everything downstream
  decorates a bare container. Phase 0 exists to find out cheaply.
- **Provenance flooring may lose.** A monotonic floor over everything read since
  reset may block ordinary work badly enough that the brute-force alternative — a
  fresh vertex per untrusted read — simply wins. Planned as a publishable negative
  result, not a hidden failure.
- **The PTY bridge is deceptively expensive.** Interactive TUI into a guest, with
  escalation prompts overlaid, is where the engineering hours actually go. It is
  also non-negotiable per criterion 2.
- **The model may misread the policy.** It proposes only a closed IR with
  tools disabled. Deterministic validation, differential verification, explicit
  review, and content-hash acceptance prevent it from joining the live decision
  path, but they cannot prove that ambiguous prose was interpreted as intended.
- **Scope gravity.** Every runtime here grows a scheduler, a memory system, and a
  web UI, and the boundary erodes. The TCB budget is the immune system: anything
  that wants inside must displace something.
- **The overlap is real.** IronCurtain already does the node contract, shipped and
  tested. Only claims 1 and 6 justify building rather than contributing upstream,
  and they should be defended on those terms or not at all.
