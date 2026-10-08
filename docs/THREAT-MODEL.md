# Keel threat model

This document defines the security problem Keel currently attempts to solve. It is written for a research prototype, not as a certification or production-security claim.

## 1. Scope

Keel runs an AI coding or research workload on a developer machine. The workload may read attacker-controlled repository content, model output, web content, MCP results, dependency metadata, and tool output. It may then attempt to use the operator's authority.

Keel's objective is to keep protected effects behind a small trusted decision path even if the workload is compromised.

Protected effects include:

- disclosing model, cloud, Git, or service credentials;
- making network requests outside declared intent;
- performing sensitive Git or MCP operations;
- writing data across a provenance boundary;
- exceeding declared cost, request, byte, rate, or loop budgets;
- obtaining operator approval through a forged interface;
- altering security evidence without detection by the local verifier.

Keel does not attempt to make arbitrary agent behavior safe or correct.

## 2. Assets

| Asset | Why it matters |
| --- | --- |
| Host credentials | Can authorize model use, cloud actions, source control, or external services |
| Source and workspace data | May be confidential, integrity-sensitive, or executable |
| Host filesystem and processes | Represent authority outside the selected workspace |
| Network identity and destinations | Determine where information and requests can flow |
| Policy and accepted artifacts | Define the operator's intended authority |
| Provenance state | Records which sources influenced an effect |
| Budgets and session grants | Bound resource use and repeated authority |
| Approval decisions | Carry direct operator authorization |
| Audit records and keys | Provide local evidence of decisions and effects |
| Runtime artifacts | Establish the code that runs in the guest or V8 profile |

## 3. Adversary

Assume an attacker can control or influence:

- prompts and model output;
- the agent or harness;
- repository files, branches, commits, generated code, and build output;
- network responses and remote content;
- MCP servers and tool responses;
- the guest operating system and guest processes;
- JavaScript executed in either V8 profile;
- ordinary terminal output and the untrusted renderer;
- asserted action fields sent by an untrusted component;
- malformed, oversized, reordered, duplicated, or replayed requests.

The adversary may know Keel's source and policy. Security must not rely on obscurity.

## 4. Trust assumptions

Keel assumes:

- the local operator is not malicious and can review accurately rendered approvals;
- the host OS, kernel, process isolation, filesystem permissions, and randomness work as intended;
- Apple Virtualization.framework provides the expected VM boundary;
- the trusted Keel crates and their pinned dependencies behave correctly;
- configured runtime artifacts are the artifacts the operator intended to admit;
- the secure-attention key reaches the trusted input path;
- host processes running as the operator's user outside Keel's sandboxes act
  for the operator: such a process can start the trusted runtime or attach to
  a session from a pseudo-terminal it creates and answer its prompts, so the
  foreground-terminal and input-source checks distinguish Keel's own launch
  paths from mistakes, not from same-user code (the guest and both sandboxed
  host profiles cannot reach those paths);
- the audit key remains available to the intended verifier and is not replaced by a compromised host;
- external providers enforce their own credentials and protocols correctly.

Compromise of these assumptions can invalidate Keel's guarantees.

## 5. Security objectives

Keel is designed so that:

1. The workload cannot obtain real service credentials through the normal execution path.
2. A microVM workload cannot use an ordinary guest NIC or DNS path.
3. Protected actions require a trusted, typed decision rather than an untrusted boolean or string.
4. Structurally forbidden actions are rejected before policy or approval.
5. Policy, provenance, budgets, and approval requirements all constrain authority.
6. A terminal-controlled prompt cannot itself capture trusted approval.
7. `A` applies to one exact action and cannot be replayed as general authority;
   `G`, when offered, creates only the displayed bounded host, port, and method
   grant, which never waives a reason or a lower floor the operator did not see.
8. Security-relevant decisions are recorded in an authenticated, ordered audit chain.
9. The trusted first-party Rust surface and its dependencies remain reviewable and mechanically constrained.

These are design and implementation objectives under the assumptions above. They are not claims against a compromised host or trusted computing base.

## 6. Control map

| Threat | Primary controls | Important limit |
| --- | --- | --- |
| Prompt injection proposes data exfiltration | Provenance floors, destination policy, explicit grants, budgets, approval | Lawful output to an allowed destination may still reveal information |
| Workload reads a model or cloud credential | Host-owned secret store, sentinel credential, trusted substitution or SigV4 logic | A compromised host or trusted credential path can access host-held material |
| Guest opens an arbitrary socket | No normal guest NIC or DNS; brokered host relay | Hypervisor or host-kernel compromise is out of scope |
| Guest uses an approved CONNECT as a DNS or port oracle | CONNECT/front TLS remain local; exact decrypted request authorization precedes external resolution and connection | Trusted HTTP/TLS parsing remains in the TCB |
| Workload lies about its requested action | Asserted/stamped split, reconstruction, structural validation | Trusted parsers and reconstruction must be correct |
| Policy translator emits a permissive rule | Closed IR, multiple generated representations, differential checks, explicit acceptance, hash binding | Agreement does not prove the original sentence was unambiguous |
| Agent fabricates an approval prompt | Secure-attention key and trusted approval rendering | Operator can still approve a dangerous action |
| Approval is applied to another action | The synchronous trusted gate receives the exact kernel-owned action; no bearer approval token exists | Bugs in action rendering or binding remain TCB risks |
| A human approval outlives the relay or broker that requested it | V2 emits `P` only after acquiring the adjudication slot; peer hangup and broker shutdown cancel the gate; the bounded decision wait rejects late input | Host suspension or failure can still interrupt an active session |
| Repeated allowed calls cause cost or denial of service | Request, byte, cost, rate, and loop limits | Availability is not a full security guarantee |
| A provider disconnect makes model accounting ambiguous | Send-attempt marker and conservative terminal reservation charge | Conservative charging may exhaust a run budget without a usable response |
| Renderer corrupts or forges ordinary output | Renderer excluded from authorization; trusted view for approvals | Ordinary terminal content remains untrusted |
| Audit log is edited or truncated after the run | Authenticated hash chain, signed terminal seal, public-key verification | A crash leaves an intentionally unsealed/incomplete stream; host compromise during the run remains out of scope |
| Host V8 script escapes Deno permissions | Explicit lower-assurance grant, cleaned environment, narrow permissions, one preselected loopback proxy port | A runtime escape reaches a sandboxed host process, not a VM |
| Malicious write launders untrusted input | Read-set joins and write-label inheritance | Provenance is coarse and depends on correct labeling |

## 7. Decision boundary

An action does not become permitted merely because one check succeeds.

~~~text
untrusted request
  |
  v
bounded parse and trusted reconstruction
  |
  v
structural denials and loop constraints
  |
  v
accepted policy
  |
  v
provenance constraints (minimum rank depends on the policy verdict)
  |
  v
budgets and rates
  |
  v
trusted approval when required
  |
  v
narrow effect backend and audit
~~~

Examples of structural denials include malformed targets, unsupported schemes or operations, authority outside the selected isolation profile, and incomplete credential scoping. These checks are not overrideable by a permissive policy or approval.

## 8. Isolation-specific analysis

### MicroVM profiles

The Claude and V8 microVM profiles rely on Virtualization.framework to separate the workload from the host. The guest does not receive a normal network interface. Brokered channels expose selected operations, so their parsers and authorization bindings remain security-critical.

Inside the guest, the workload runs as UID 0 with no capabilities, under
Landlock, seccomp, and a bounded cgroup, while guest relays run under a
separate service UID. This second layer removes direct vsock access, kernel
attack surface such as `io_uring` and `bpf`, and the ability to tamper with
guest services; Landlock scoping also stops the workload from signalling
processes outside its domain. It is self-reported: the host validates a confined child's
own preflight, which a compromised guest kernel could forge. A guest kernel
exploit defeats the layer, and the VM boundary remains the outer wall.

Process origins reported by the guest's PID 1 supervisor are claims, not
evidence. A compromised guest kernel or supervisor can report any origin, so
Keel uses an origin only to add a violation. A Git push or pull request whose
ancestry includes workspace code reaches the gate; an origin can never remove
a violation or raise a rank. Attribution can miss a process that exits before
its connection is examined; such connections are reported as unknown.

The boundary does not defend against:

- a host-kernel or hypervisor exploit;
- a vulnerability in a trusted host relay;
- a malicious runtime artifact admitted by the operator;
- host data deliberately mounted or exposed to the guest.

### Host V8 sandbox

The host V8 profile relies on a pinned Deno process and OS process isolation. Keel removes most environment state, restricts workspace access, uses cached-only module behavior, denies general network permission, and exposes a loopback broker.

This profile is useful for fast evaluation but is explicitly lower assurance:

- the JavaScript engine and Deno permission implementation are part of the practical boundary;
- a sandbox escape occurs on the host side of the VM boundary;
- host-local side channels and kernel attack surface are broader;
- accidental permission expansion can weaken the profile.

For those reasons, selecting it requires the explicit isolation:v8-sandboxed
grant and a foreground-terminal `HOST V8` confirmation. A request file,
background process, or unauthenticated attach stream cannot provide that
confirmation.

## 9. Credentials and network

Credentials are intended to remain in trusted host memory and never appear as plaintext in the workload. The workload sends a sentinel value. The untrusted relay carries the request, while the trusted authorization and secret path replaces or applies the credential only for an allowed endpoint and operation.

For Bedrock, the host obtains AWS credentials and signs an allowed request with SigV4. For Anthropic and OpenRouter, the host relay applies the API credential at the provider boundary. OpenRouter adds a party that receives the full model context, and its run budget is charged at a launcher-fetched price snapshot that the operator admits; the trusted proxy strips OpenRouter's routing and plugin fields so requests cannot leave the admitted model.

Keel must reject:

- a sentinel sent to an unapproved destination;
- credential use with an unbound or mismatched host and path;
- unsupported redirection or protocol changes;
- attempts to smuggle authority through ambiguous parsing;
- traffic beyond the active policy, provenance, or budget context.

Model budget values arrive in an untrusted run request. Values at or below the
trusted defaults only narrow authority. Raising either the token or cost
ceiling requires foreground trusted-terminal admission, and the admitted
values—not ambient environment variables—are passed to the broker and recorded
as enforcement state.

The egress transport does not use one five-second timeout for both parsing and
human review. Protocol V2 requires the trusted broker to acknowledge a complete
request with a non-authorizing `P` only after it owns the serialized
adjudication slot. A queued request has no `P` and no active review timer. The
relay then waits up to five minutes for terminal `A`, `D`, or `E`; the kernel
expires its approval at 4 minutes 45 seconds so denial can reach the relay
first. Peer hangup cancels a still-pending decision, and cancellation is
checked again around execution so no reusable grant survives a disconnected
caller. An effect that already began cannot be rolled back. An acknowledgement
cannot be used as network authority.

CONNECT and the guest-facing TLS handshake likewise grant no external network
authority. They terminate locally so Keel can recover the exact HTTP method,
path, and body digest. Only after that request is authorized may the trusted
connector perform DNS, reject forbidden address classes, establish upstream
TCP/TLS, or substitute a credential. A denied exact request therefore makes no
resolver or connector call.

Model budget reservations move from `authorized-unsent` to `send-attempted`
immediately before trusted TLS custody writes the first upstream application
byte. Only a definitely unsent request is refunded. Trusted complete usage
settles actual cost; non-success responses (even if their body resembles a
usage record), missing or malformed usage,
disconnects, timeouts, and other post-send ambiguity retain the conservative
charge. Terminal outcomes are audited before accounting state is changed. This
chooses possible overcharging over an attacker turning a reset into free model
use.

The one narrowing is a successful stream that ended after the provider's
opening usage event. It is charged that exact input, plus the bytes of output
already delivered, plus a 4,096-token margin, capped at the reservation. A
workload that cuts a stream short therefore pays for everything it received,
plus the margin. The residual is a provider that keeps generating more than
the margin after it sees the disconnect: Keel's ledger would then undercount
real spend.

TLS termination at the host credential boundary protects the secret from the workload but increases the security importance of trusted parsing, substitution, and protocol logic.

## 10. Provenance threats

Keel uses provenance to track influence, not truth.

The main defended scenario is:

1. low-trust data enters through a repository, tool, or network source;
2. the workload reads that data;
3. the workload proposes a higher-trust write or external effect;
4. the joined provenance label violates the active floor;
5. Keel escalates the exact effect for trusted operator approval.

That approval authorizes only the displayed action and does not raise the
floor. A floor lift is a separate, high-risk attestation against the live
broker's displayed read history. It must pass through secure attention and the
kernel's operator channel, and it is recorded in the same audit chain. A later
low-rank observation can lower the floor again.

`gate-context` is deliberately weaker: it renders provenance at gates but does
not add a minimum-rank violation. New and continued runs start with a rank-0
direct-workspace observation. The shutdown `floor.json` is unsigned status
metadata and is never accepted as authorization for another broker.

Residual provenance risks include:

- a source assigned the wrong initial rank;
- an influence that is not represented in the read set;
- a session-wide scalar remaining low after content leaves the model context;
- ranks too coarse to express the real policy;
- data summarized through an allowed high-trust channel;
- an operator lifting a floor without understanding the influence;
- semantic leakage through a permitted output.

Keel does not solve information-flow control for every byte or infer the meaning of data.

## 11. Approval threats

The workload can draw any terminal text, including a perfect imitation of Keel. Therefore:

- the ordinary terminal never receives approval authority;
- the white mux footer and approval-pending terminal title are discoverability aids that the workload can imitate, not proof of a trusted prompt;
- Ctrl-] enters the trusted path; authenticated mux attachments also expose the equivalent `Ctrl-A` then `/approve` fallback;
- the trusted view reconstructs the action from trusted state;
- high-risk actions can require a challenge;
- `A` is action-bound, expiring, and single use;
- `G`, when offered, creates only the displayed host, port, and method grant,
  expiring after 15 minutes, 64 actions, or a drop in the floor;
  credential-bearing and high-impact effects are ineligible.

Approval expiry is active state, not merely a socket timeout. When the bounded
kernel deadline passes, trusted input clears the pending UI and rejects a late
decision. The outer relay deadline is intentionally longer so it receives the
terminal denial instead of reporting a connection reset.

The trusted UI establishes authenticity and action binding. It does not establish that the action is wise. Review fatigue, misunderstanding, coercion, and careless approval remain human risks.

## 12. Policy threats

Natural-language policy translation is untrusted because language is ambiguous and model output is fallible. The compiler reduces risk by generating a closed intermediate representation and independent Cedar, Rego, and Rust expectation artifacts, then checking them for disagreement.

The operator must accept the exact artifact used for a run.

This protects against unreviewed mutation and some translation errors. It does not prove equivalence between human intent and generated policy. Security-sensitive deployments should prefer narrow, explicit policies and inspect the accepted artifact.

The repeated-denial rule uses a 15-minute trailing window for one canonical
action scope at a time, rather than the cumulative session denial total.
Provider, transport, quota, and budget failures are classified as resource
outcomes and do not contribute. A successful operator review clears only the
exact scope that triggered `repeated-denials-same-scope`; unrelated targets and
the cumulative audit total are unchanged.

## 13. Audit threats

Audit events are ordered, hash-chained, and authenticated. Verification detects modification, deletion, insertion, or reordering relative to the verifier's key and expected chain.

Denials carry a trusted origin, an opaque digest of their canonical action
scope, whether they count toward repeated-behavior review, and the current
same-scope window count. Model-budget reservations carry a run-local identifier
and one terminal outcome. These fields make approval fatigue and conservative
charges attributable without logging provider response bodies.

The current audit system does not provide:

- remote hardware-backed attestation;
- an external append-only witness;
- proof that a compromised trusted kernel emitted truthful events;
- complete verified teardown after every crash;
- guaranteed delivery of the final event under host failure.

Keep audit material and its key according to the sensitivity of the run.

## 14. Residual risks

The most important risks that remain even when Keel works as designed are:

- **Lawful-output exfiltration.** Sensitive content can be encoded in an output the active policy permits. Keel now records, in shadow, when a request carries verbatim fragments of the committed repository to a destination not cleared for them, but it does not block, and paraphrased or re-encoded content is not detected.
- **Semantic task failure.** Keel cannot decide whether a code change, command, or message actually serves the user's goal.
- **Incorrect provenance classification.** A trusted label can be too generous, or an influence can be missed.
- **Invisible agent structure.** Subagents inside a harness may not correspond to separately visible or separately authorized principals.
- **Policy ambiguity.** Differential compilation checks representations, not the meaning the operator had in mind.
- **Trusted-code defects.** Memory safety reduces but does not eliminate logic, parsing, cryptographic-use, or state-machine bugs.
- **Dependency and artifact compromise.** Pinned software can still be malicious or vulnerable.
- **Host V8 escape.** The lower-assurance profile has a materially weaker containment boundary.
- **Host or hypervisor compromise.** Keel has no defense once its trusted platform is controlled.
- **Availability attacks.** A workload can consume time and permitted resources up to configured limits.
- **Expected workspace mutation.** Keel is designed to let authorized agents edit the selected workspace; it is not a backup system.

## 15. Out of scope

Keel does not currently claim:

- protection from a malicious local operator;
- protection from physical attacks;
- protection from a compromised macOS host or hardware;
- formal noninterference or complete data-loss prevention;
- correctness of model output or generated code;
- safe execution of arbitrary kernel modules or privileged guest devices;
- production multi-tenant isolation;
- Linux-host parity;
- remote attestation;
- automatic recovery of every interrupted session;
- guaranteed service availability.

## 16. Validation

Security claims should be tested at three levels:

1. **Repository invariants** check crate boundaries, trusted-code size, dependencies, and forbidden patterns.
2. **Unit and integration tests** exercise action validation, policy, provenance, approvals, relays, budgets, and audit verification.
3. **Adversarial scenarios** attempt prompt injection, credential theft, destination confusion, replay, malformed requests, terminal forgery, provenance laundering, policy disagreement, and audit tampering.

Run the local suite:

~~~sh
cargo fmt --all -- --check
cargo check --workspace
cargo test --workspace
./ci/check.sh
~~~

A passing suite is evidence for a particular source revision and environment. It is not a general proof of security.

## 17. Planned security work

The following are not current guarantees:

- a canonical admission manifest that binds image, policy, repository state, capabilities, credentials, and run identity before boot;
- verified teardown receipts and crash reconciliation;
- a Linux KVM or Cloud Hypervisor backend;
- distributed evaluation and reinforcement-learning infrastructure;
- external audit witnessing or hardware-backed attestation.
- per-turn provenance reconstructed from the exact content in each model
  request; current direct-workspace exposure fails closed at rank zero.

See the [roadmap](ROADMAP.md) for sequencing and the linked design notes for proposals.

## 18. Reporting security issues

Follow the repository [security policy](../SECURITY.md). Use GitHub private vulnerability reporting and do not publish an unpatched vulnerability in an issue, pull request, discussion, commit message, or shared audit log.
