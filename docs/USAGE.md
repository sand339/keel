# Using Keel

This guide covers the supported local workflow: install Keel, configure one model provider, start a session, respond to trusted approval prompts, and inspect the resulting evidence.

Keel is currently a research prototype for Apple silicon macOS.

## 1. Prerequisites

Install or provide:

- an Apple silicon Mac;
- Xcode Command Line Tools;
- Docker Desktop, running during guest-image setup;
- cpio, curl, gzip, Python 3, shasum, and tar;
- the Rust toolchain selected by rust-toolchain.toml;
- either an Anthropic API key or usable Amazon Bedrock credentials.

GitHub CLI is optional and is used only when a GitHub MCP or GitHub authentication flow needs it.

## 2. Build and install

From the repository root:

~~~sh
cargo run -p keel-cli --bin keel -- setup
keel doctor
~~~

Setup builds Keel, prepares the pinned runtime artifacts—including the
xterm-headless renderer—and installs a launcher at ~/.local/bin/keel by
default. It also downloads the pinned Alpine `linux-virt` 6.12 guest kernel,
checks its digest, and extracts the raw ARM64 image and modules. Doctor checks that the configured kernel, initramfs, guest root disk, V8 runtime,
terminal renderer, relay binaries, policy artifacts, and local platform
requirements are usable.

If ~/.local/bin is not already on PATH:

~~~sh
export PATH="$HOME/.local/bin:$PATH"
~~~

Useful setup overrides:

~~~sh
export KEEL_INSTALL_DIR="$HOME/sandboxes/keel"
export KEEL_BIN_DIR="$HOME/bin"
export KEEL_CONFIG="$HOME/.keel/config.json"
~~~

When an already-installed Keel binary is used from outside the checkout, KEEL_SOURCE_DIR can point setup at the source tree.

Re-run setup after changing guest components, trusted relays, the V8 runtime,
the launcher, or the terminal renderer. Already-running sessions retain the
renderer executable with which they started; start a new session after setup.

## 3. Configure model access

Keel supports one model provider per run. Credentials stay on the host and are used by the trusted connection relay; the workload receives only a sentinel credential.

### Anthropic API

~~~sh
export ANTHROPIC_API_KEY='...'
~~~

Host Claude Code SSO is not currently imported into Keel. Being logged in to Claude Code on macOS therefore does not satisfy Keel's model credential check.

### Amazon Bedrock with AWS SSO

First refresh the selected AWS profile:

~~~sh
aws sso login --profile PROFILE
~~~

Then tell Keel how to obtain short-lived credentials:

~~~sh
export KEEL_MODEL_PROVIDER=bedrock
export AWS_REGION=us-west-2
export KEEL_AWS_CREDENTIAL_PROCESS='aws configure export-credentials --profile PROFILE --format process'
~~~

KEEL_AWS_CREDENTIAL_PROCESS may be any local command that prints the standard AWS credential-process JSON. Keel executes it on the host and uses the returned credentials for SigV4 signing. Do not place AWS credentials inside the workspace or guest.

The currently tariffed Bedrock regions are us-east-1, us-east-2, and us-west-2.
Base (`anthropic.*`), US cross-region (`us.anthropic.*`), and global
(`global.anthropic.*`) Anthropic inference-profile IDs are recognized; unknown
families still fail closed before the guest starts, with the unsupported model
and provider named in the error.

### OpenRouter

~~~sh
export OPENROUTER_API_KEY='sk-or-...'
keel mux --auth openrouter --model anthropic/claude-sonnet-4.6
~~~

`--model` takes an OpenRouter model id (`PROVIDER/MODEL`); non-Anthropic
models work but are best-effort with Claude Code. Before the run starts, the
launcher fetches the model's prices from OpenRouter and takes the worst case
across every provider and long-context tier, rounded up to whole micro-USD per
token. The admission screen shows that snapshot, and you must admit it: the
run's budget is charged at it. Every harness model slot, including background
and subagent requests, is pinned to that model, and OpenRouter's routing,
fallback, and plugin fields are stripped. Auto-routing models, `:online`
variants, and models with a per-request fee are refused. Only the Claude
harness is supported.

Select a provider explicitly when both are configured:

~~~sh
keel run --auth bedrock --provenance floor claude
keel run --auth api-key --provenance floor claude
~~~

Run keel doctor after configuring credentials. A warning that no model credential is set means live Claude requests will fail even if the runtime itself can start.

### GitHub MCP

Authenticate the GitHub CLI on the host:

~~~sh
gh auth login
~~~

Alternatively provide GH_TOKEN in the host environment. The trusted relay owns the real token; it is not copied into the workload.

### Authenticated Git push

Provide all three variables or none of them:

~~~sh
export KEEL_GIT_AUTHORIZATION='Basic ...'
export KEEL_GIT_CREDENTIAL_HOST='github.com'
export KEEL_GIT_CREDENTIAL_PATH='/OWNER/REPOSITORY.git'
~~~

The host and path restrict where the credential may be attached. It is attached
only to the selected repository's `git-receive-pack` advertisement GET and the
later authorized `git-receive-pack` POST; upload-pack and every other repository
path remain unauthenticated. The advertisement GET is a smart-HTTP protocol
preflight, not a typed push authorization: its exact method, repository path,
and host are admitted and audited through inspected egress, while the later
POST still requires the separately authorized push action.

Authenticated private issue reads require their own visible authority:

~~~sh
keel mux --allow github:read-private-issues
~~~

When that capability is admitted and the credential scope is a GitHub
repository, its exact `owner/repository` scopes authenticated `gh_issue_read`
requests. `pr:create` does not imply private issue-read authority, and the
private-issue capability does not imply PR creation. Reads of other
repositories remain anonymous.
Prefer short-lived, narrowly scoped credentials.

## 4. Start a session

The normal entry point is:

~~~sh
keel mux
~~~

The launcher presents three profiles:

| Launcher choice | What it runs | Workspace rule |
| --- | --- | --- |
| Claude Code — microVM | Claude Code in the VZ guest | New or existing workspace |
| V8 script — microVM | Node/V8 in the VZ guest | Existing workspace and entry file |
| V8 script — host sandbox | Pinned Deno on the host | Existing workspace and entry file |

For an existing directory, navigate to the directory and choose **Use this directory**. For a V8 profile, enter a JavaScript path relative to that directory, such as:

~~~text
docs/examples/v8-smoke.mjs
~~~

Start in a particular workspace:

~~~sh
keel mux --workspace /path/to/project
~~~

Pass Keel run options before a double dash and harness arguments after it:

~~~sh
keel mux --cpus 4 --provenance floor -- --verbose
~~~

Set cumulative model ceilings for one run with exact token and US-dollar
values:

~~~sh
keel mux --model-token-budget 250000 --model-cost-budget 5.00
~~~

The defaults are 1,000,000 total tokens and USD 20.00. The cost value accepts
at most six decimal places and is converted to integer micro-US-dollars; no
floating-point value enters enforcement. A ceiling above either trusted
default expands authority and therefore appears on the trusted task-admission
screen for explicit approval. Lower ceilings are safe narrowing. Every task
admission screen shows the exact token and cost ceilings that the broker will
enforce.

Before each model request, Keel conservatively reserves the request-body upper
bound plus the provider request's `max_tokens` at its pinned tariff. Trusted
response usage settles that reservation against the cumulative ceilings. The
reservation is refundable only while the request is provably
`authorized-unsent`. Immediately before the first upstream application byte,
Keel marks it `send-attempted`. A complete usage record from a successful
response settles actual usage;
an ambiguous post-send timeout, disconnect, malformed or missing usage record,
or non-success provider response commits the conservative reservation instead
of treating the request as free. A usage-shaped body does not turn a non-success
response into a refund. The authenticated audit records each terminal
reservation outcome.

### Direct Claude run

~~~sh
keel run --provenance floor claude
~~~

### V8 in the microVM

This is the recommended V8 mode:

~~~sh
keel run --isolation vm-v8 v8 docs/examples/v8-smoke.mjs
~~~

The entry file must be a .js, .mjs, or .cjs file within the selected workspace.

### V8 in the host sandbox

The host mode is deliberately lower assurance and is never silently selected. Grant it explicitly:

~~~sh
keel mux --allow isolation:v8-sandboxed
~~~

Or run it directly:

~~~sh
keel run --isolation v8-sandboxed --allow isolation:v8-sandboxed v8 docs/examples/v8-smoke.mjs
~~~

The pinned Deno process starts with a cleaned environment, restricted file access, no general network access, and only the Keel loopback proxy made available. A Deno NotCapable error is an expected denial when a script attempts an undeclared read, write, environment, subprocess, or network operation.

The trusted terminal also asks you to type `HOST V8` before launch. The flag in
the request is not sufficient by itself. In a persistent mux, the confirmation
must come from the foreground terminal attachment accepted by the trusted
supervisor.

Do not add a broad Deno permission merely to make an untrusted script pass. Decide whether the operation belongs in the workspace, behind the trusted broker, or outside the workload.

## 5. Grant capabilities

Capabilities are explicit run intent. A capability does not bypass structural checks, provenance constraints, budgets, policy, or required approval.

Example:

~~~sh
keel run --allow egress:api.anthropic.com --allow push:branch --provenance floor claude
~~~

The lower-assurance host V8 profile additionally requires:

~~~text
isolation:v8-sandboxed
~~~

Prefer the narrowest host, path, operation, and duration that the task requires.

Branch scopes narrow Git and pull-request authority:

~~~sh
keel run --allow push:ref:refs/heads/feature/* \
  --allow pr:create --allow pr:target:main claude
~~~

- `push:ref:refs/heads/PATTERN` admits pushes only to matching branches. A
  trailing `*` matches any suffix. It implies push authority, and naming the
  default branch exactly is the only way to place a default-branch push inside
  the task envelope; such a push still needs its usual challenge.
- `pr:target:BRANCH` limits pull requests to that base branch and requires
  `pr:create`.

Declare a public repository so its committed content is not treated as
confidential:

~~~sh
keel run --allow workspace:public claude
~~~

A push or pull request outside its declared scope is not refused outright: it
reaches the trusted gate as an exact action the operator can approve. Every
action's audit record carries an `intent` field: `inside`, `not-applicable`,
or the reason it falls outside the admitted task, such as `default-branch`,
`force-or-delete`, `registry-write`, or `egress-host`. Apart from the two
branch scopes, that field is recorded for measurement and does not yet change
any decision.

Requests from the microVM also carry an `origin` field. It names the guest
process that opened the connection and its ancestry, for example
`curl -s ... <- bash -c ... <- claude`. A `workspace-code:` prefix and a `*`
mark code the workload could have written, such as a script in the workspace
or a package's install hook. The trusted gate shows the same line as "issued
by (guest-reported)". A Git push or pull request from workspace code always
reaches the gate. The origin comes from guest code, so Keel uses it only to
add prompts, never to skip one.

A push that adds lines to a protected place carries an `integrity` field.
Protected places are dependency manifests, CI configuration such as
`.github/workflows/`, and every file of a default-branch push. The field is
`accounted:N` when the model wrote every added line in this session,
`unaccounted:U/N` when `U` lines came from somewhere else (a build, an install
hook, a download), or `uninspectable` when the diff was too large or binary.
The trusted gate shows the unaccounted count. Like `flow`, it is recorded and
shown but decides nothing yet.

Each decrypted non-model request also carries a `flow` field: `clean`,
`cleared:N`, or a leak such as `private-to-public:N`, where `N` counts
fingerprints of the repository's committed content found in the request
target or body. At admission Keel indexes the `HEAD` tree as private, and
credential-shaped files such as `.env*` and `*.pem` as secret. The workspace's
own GitHub origin is cleared for private content and the model endpoint for
everything. The field is recorded in shadow and blocks nothing; it detects
verbatim copies, not paraphrased or re-encoded content.

## 6. Use a policy

Keel can compile a constrained natural-language policy outside the trusted computing base. Compilation produces a draft; drafts cannot authorize a run until accepted.

Compile from a file:

~~~sh
keel policy compile POLICY.md --output .keel/policy.draft.json
~~~

Or compile a short policy:

~~~sh
keel policy compile --text "Allow HTTPS to api.anthropic.com and require approval for Git push." --output .keel/policy.draft.json
~~~

Inspect and compare the generated policy:

~~~sh
keel policy show .keel/policy.draft.json
keel policy diff .keel/old-policy.json .keel/policy.draft.json
~~~

Accept the exact reviewed artifact:

~~~sh
keel policy accept .keel/policy.draft.json --output .keel/policy.json
~~~

Use it:

~~~sh
keel mux --policy .keel/policy.json
~~~

Acceptance also records the artifact's content hash in a host ledger under
`~/.keel/accepted-policies/` (or `$KEEL_STATE_DIR/accepted-policies/`). A run
refuses any artifact whose hash is not in that ledger, because the artifact
usually lives in the guest-writable workspace and its own status and hash can
be recomputed by anything that can edit it. An artifact accepted before the
ledger existed, or on another host, is recorded by running `keel policy accept`
on it again after review.

The compiler emits a closed intermediate representation and differential policy artifacts. Acceptance binds the reviewed artifact by hash; it does not prove that ambiguous natural language expressed the operator's intent.
Its repository-scoped grants include `push:branch`, `pr:create`, the
branch scopes `push:ref:refs/heads/PATTERN` and `pr:target:BRANCH`, and the
independent `github:read-private-issues`; each requires an exact GitHub
`owner/name` repository in the accepted artifact. Branch scopes keep their
case, because Git ref names are case sensitive.

## 7. Respond to an approval

When an action needs approval, the untrusted terminal shows a notice:

~~~text
KEEL APPROVAL PENDING - Ctrl-] or Ctrl-A /approve
~~~

Press Ctrl-] to enter the trusted approval view. In mux sessions, `Ctrl-A`, `/approve`, Enter is an equivalent fallback if the terminal intercepts Ctrl-]. Review the action, destination, provenance, budget impact, and reason.

- Press A to approve only the exact displayed action once.
- When the trusted screen offers it, press G to create the displayed grant for
  that exact host and port. The grant expires after 15 minutes or 64 actions.
- Complete the displayed challenge for a high-risk approval.
- Press Escape to deny or leave trusted mode.

An `A` approval is bound to the displayed action and is consumed once. `G` is
available only for eligible routine egress: credential-bearing and high-impact
effects cannot create or use a reusable grant. Text drawn inside the ordinary
workload terminal is not a trusted approval prompt.

For HTTPS, Keel does not ask you to approve a generic CONNECT and then ask
again for the useful request. CONNECT and the front-side TLS handshake stay
local to Keel. The trusted screen shows the decrypted HTTP method and path, and
no external DNS lookup or TCP connection occurs until that exact request has
been allowed.

The broker acknowledgement and the human decision have separate deadlines. A
complete egress request must receive a non-authorizing pending acknowledgement
within the client's five-second machine window, and the broker emits that `P`
only after acquiring its serialized adjudication slot. A queued request has no
`P` and no active human-decision clock. After `P`, the relay waits up to five
minutes for the trusted decision. Keel
expires the trusted gate slightly earlier (4 minutes 45 seconds), clears the
pending UI, rejects late approval input, and returns a denial before the relay's
outer deadline. If the relay disconnects, Keel cancels its pending gate and
cannot execute the action or leave behind a grant. If a prompt expires, ask the
agent to retry the action instead of approving the stale screen.

Repeated-denial prompts are scoped to the same canonical action target within
a 15-minute window. Provider disconnects and budget or quota failures are
resource outcomes and do not contribute. Approving a repeated-denial review
clears only that exact scope; it does not reset cumulative audit statistics or
approve unrelated destinations.

## 8. Use the persistent mux

Keel mux keeps sessions available across terminal detachment. Press Ctrl-A to enter mux command mode, then use:

Claude Code owns the normal full-screen display. Keel's sandboxed renderer
feeds its PTY bytes through a pinned xterm-headless model and emits complete
snapshots. The guest mux reserves one white footer row that keeps the available
`Ctrl-A` commands visible. That footer is display-only and is not a trusted
approval surface. While an approval is pending, the untrusted renderer replaces
the bottom row with the notice above; use Ctrl-] or `Ctrl-A`, `/approve`, Enter
to open the actual trusted approval view.

| Command | Effect |
| --- | --- |
| /approve | Enter the trusted approval view when an action is pending |
| /floor-lift [rank] | Request a gated lift of the live provenance floor; defaults to 3 |
| /new | Start another session tab |
| /tab | Switch tabs |
| /close | Close the current tab |
| /resume | Resume a known session |
| /detach | Leave the mux without stopping sessions |
| /redraw | Repaint the display |

Press Ctrl-A again or Escape to leave command mode.

For the raw terminal path, keep a session alive explicitly:

~~~sh
keel run --keep-alive --cpus 4 --provenance floor claude
~~~

Then attach or stop it:

~~~sh
keel attach SESSION
keel stop SESSION
~~~

Persistent attachment accepts approvals only from a foreground terminal peer
authenticated by the trusted supervisor. Background, terminal-less, and raw
socket clients are rejected before their input reaches the session.
`keel stop` requests cooperative shutdown and waits for the broker to write its
terminal audit seal. A forced-timeout fallback is reported as an error rather
than pretending the session stopped cleanly.

## 9. Provenance modes and floors

The default provenance floor records the lowest-ranked classified influence in
the live broker. Because the guest can read the workspace directly, a
production run starts conservatively at rank 0. An action that requires a
higher rank opens the trusted gate; approving that action does not raise the
floor.

Run with the floor model:

~~~sh
keel run --provenance floor claude
~~~

The compatibility mode still records and displays provenance at gates, but it
does not enforce minimum ranks:

~~~sh
keel run --provenance gate-context claude
~~~

Inspect the last floor snapshot written when a session shut down:

~~~sh
keel floor show SESSION
~~~

To raise the floor of a running session, keep that session attached, press
`Ctrl-A`, enter `/floor-lift 2`, and press Enter. Keel then opens the trusted
challenge showing the read history being vouched for. Omitting the rank requests
rank 3.

You can submit the same request from another foreground terminal:

~~~sh
keel floor lift SESSION
keel floor lift SESSION 2
~~~

The trusted challenge still appears in the terminal attached to `SESSION`; a
detached session refuses the request. The requested rank must be from 1 through
3 and higher than the current live floor. A lift changes only that broker's
live trust epoch, is recorded in its audit chain, and can be lowered again by a
later classified observation.

`floor.json` is a non-authoritative status snapshot. Editing it cannot authorize
a run, and `floor lift` no longer edits it directly.

## 10. Reproduce a report (triage profile)

Run a reproduction confined to the hosts you declare:

~~~sh
keel mux --profile triage --scope '*.target.example' --scope api.target.example:8443 \
    --exclude admin.target.example
keel mux --profile triage --scope-file target-scope.txt
keel mux --profile triage --report report.md     # proposes the report's URL hosts
~~~

Rules:

- `*.host` matches subdomains only; list the apex `host` on its own;
- a rule without a port matches 443 and 80;
- `--exclude` always wins;
- a scope file has one rule per line, `!rule` for exclusions, `#` for
  comments.

The admission screen lists the normalized rules, and the run starts only after
you admit them. Check a proposed scope carefully: it includes every host the
report links to, including documentation links. Everything outside the scope
and the run's own hosts (the model endpoint, for example) is refused without a
prompt, and the audit records each refusal as `kernel:out-of-scope`.

Triage runs use only approved model providers, by default Anthropic and
Bedrock. Set `KEEL_TRIAGE_PROVIDERS=bedrock` to narrow the list.

### The guest browser

Every Claude session has a headless Chromium driven by `agent-browser`. The
agent uses it as the `browser` MCP server; ask Claude, for example, to "open
https://app.target.example and screenshot the login page", or allow it ahead
of time with `--allowedTools mcp__browser`.

You can drive the same browser yourself from a guest shell, for example in a
new mux tab (`Ctrl-A /tab`), without the agent:

~~~sh
agent-browser open https://app.target.example/login
agent-browser snapshot -i              # interactive elements, with @refs
agent-browser fill @e2 'test-user'     # fill a field by ref
agent-browser click @e4
agent-browser screenshot               # saved under .keel-browser/screenshots
agent-browser network har start .keel-browser/har/repro.har
agent-browser network requests         # requests with status codes
agent-browser network har stop
agent-browser console                  # page console output
~~~

The agent and the CLI share one browser, so you can log in and then hand the
page to the agent, or the reverse. Screenshots, downloads, and HAR files land
in `.keel-browser/` in your workspace, visible on the Mac immediately; the
directory ignores itself, so Git never sees it. It is created only when the
browser is first used.
- **Traffic and scope.** Its traffic goes through Keel like everything else,
  so a triage scope applies to it.
- **Background traffic.** Chromium's own background calls to Google are turned
  off, so they cause no prompts.
- **Protocols.** The proxy speaks HTTP/1.1 and does not yet relay WebSockets,
  so pages that depend on WebSockets will not work fully.
- **Disabled features.** `agent-browser chat`, its cloud providers, and WebMCP
  are not usable: the first two need credentials the guest never holds, and
  WebMCP is switched off because it would surface tools defined by the page.
  Downloaded files land in `.keel-browser/downloads` on your Mac; treat them
  as hostile.

### Building software in the guest

The guest has `gcc`, `make`, `npm`, `pip`, Rust (`rustc`, `cargo`), and Go.
They run inside the guest's confinement:

- **Where builds write.** Writes are allowed only to the workspace, `/tmp`,
  `/var/tmp`, and `/root`. Build outputs in the workspace persist, and the
  host sees them; anything else is gone when the VM stops. Cargo and Go keep
  their caches under `/root`.
- **Python packages.** System site-packages are read-only, so use a virtual
  environment, for example `python3 -m venv .venv`.
- **Fetching dependencies.** Package registries are reached through Keel like
  any other host: approve them when prompted, or admit them up front, for
  example `--allow egress:registry.npmjs.org --allow egress:crates.io
  --allow egress:static.crates.io --allow egress:proxy.golang.org
  --allow egress:sum.golang.org --allow egress:pypi.org
  --allow egress:files.pythonhosted.org`. The tools already trust the run's
  certificate.
- **Memory.** Workspace VMs get 2 GiB. Heavy builds can ask for more with
  `--memory 8` (GiB), alongside `--cpus N`.

## 11. Inspect a session

Show the session's state, admission manifest, and recorded boundary state:

~~~sh
keel status SESSION
~~~

`state` is `active` while the trusted runtime is still writing the chain,
`closed` once it is sealed, and `interrupted` when the chain is unsealed and
its runtime is gone. `admitted` summarizes the run's admission manifest:
harness, model, provider, guest kernel, policy bundle, and manifest digest.
The full manifest is the `kernel.run-admitted` record at the start of the
audit chain.

Check against a particular audit file:

~~~sh
keel status SESSION --audit /path/to/audit.ndjson
~~~

Verify an audit chain directly:

~~~sh
keel audit verify /path/to/audit.ndjson /path/to/audit.key
~~~

A successful completed run prints `VERIFIED AND SEALED`. A live or crashed
stream whose available prefix authenticates prints `VERIFIED PREFIX — SESSION
UNSEALED` and exits nonzero. Retired 32-byte MAC streams are reported as legacy,
not as current Ed25519 evidence.

Generate a report:

~~~sh
keel report /path/to/audit.ndjson /path/to/audit.key
~~~

Compare today's prompts with the action-centric rules:

~~~sh
keel report --axes            # every finished session
keel report --axes SESSION    # selected sessions
~~~

For each finished, sealed session, it reports how many effects Keel judged,
how many prompted you, and what the action-centric rules would have done
from the recorded `intent` and `flow` verdicts:

- **allow:** inside intent, clean flow;
- **prompt:** outside intent, private content leaving, or another policy rule;
- **deny:** secret content leaving.

It lists each prompt the new rules would have avoided or added. Budget
refusals and connection-setup legs are not counted, and running sessions are
skipped until they seal. Use it to decide whether the shadow verdicts should
start deciding.

Summarize what model requests carried, from the shadow context digest log:

~~~sh
keel report --context            # every finished session
keel report --context SESSION    # selected sessions
~~~

For each finished, sealed session, it counts:

- model requests and logged responses;
- assistant blocks the model emitted, and those it did not;
- tool results bound to a model tool call;
- requests with no tool output in context;
- distinct system prompts and tool sets.

Keel records only digests, sizes, and positions, never block content. The log
changes no decision; it measures whether per-turn context ranks would ever
differ from the session floor.

The report separates gate decisions from prompts a human could actually see.
It also shows automatic deny-only decisions, prompt share by rule, decision
latency, and how many older records required a conservative legacy inference.

Runs that request extra egress or Git authority first show `KEEL TASK
ADMISSION`. Review the listed capabilities and hosts and type `APPROVE` once.
During a later off-manifest egress prompt, press `A` for this action only or `G`
for the reusable scope printed on the trusted screen.

Keel prints the audit and key paths when a run exits. Treat the key as sensitive evidence material. Verification establishes that the local chain matches its key; it is not remote attestation and does not prove the host was uncompromised.

## 12. Reuse connections and continue work

Connection reuse can reduce setup overhead:

~~~sh
keel run --provenance floor --reuse-connections claude
~~~

Continue from a prior Keel session when the selected harness supports it:

~~~sh
keel run --continue SESSION --provenance floor claude
~~~

Continuation restores harness context, but it does not import authority from
unsigned `floor.json`. The new broker starts at rank 0 because the workspace is
directly exposed. Old approvals, grants, and lifts are not reusable
authorizations; the stored history remains evidence for inspection only.

## 13. Common errors

### No model credential is set

Configure ANTHROPIC_API_KEY or the Bedrock variables in section 3. Host Claude Code SSO is not currently consumed by Keel.

### V8 workloads require an existing workspace with an entry file

Choose **Existing directory**, select **Use this directory**, and provide a relative .js, .mjs, or .cjs entry path.

### v8-sandboxed isolation requires an explicit grant

Start the launcher with:

~~~sh
keel mux --allow isolation:v8-sandboxed
~~~

Or add the same grant to a direct run.

### Deno reports NotCapable

The host sandbox blocked an operation. For example, reading /etc/shadow should fail. Keep the denial unless that exact access is part of the intended design; do not respond by granting broad host access.

### The guest workload confinement preflight failed

The guest kernel or image did not apply every confinement layer: capability
removal, Landlock, seccomp, or the workload cgroup. Rerun keel setup to
rebuild the guest image; doctor reports whether the installed guest kernel
supports Landlock scoping. Keel refuses to start an unconfined workload rather
than falling back.

### A tool fails inside the guest with "Operation not permitted"

The guest workload has no capabilities and a seccomp filter. Tools that need
namespaces, mounts, `ptrace`, `io_uring`, raw sockets, or kernel modules do not
work in the guest by design. Examples are container runtimes, `strace`, `gdb`,
and `ping`. Writes outside the workspace, `/tmp`, `/var/tmp`, and `/root` are
also refused.

### KEEL_KERNEL or KEEL_INITRAMFS is not set

Run keel setup, then keel doctor. Use the installed launcher so it can load the generated configuration.

### The guest kernel download fails with 404

Alpine removes superseded kernel packages from its CDN. Bump the version,
release, and digest together in spikes/fetch-guest-kernel.sh after checking
the new kernel's configuration and booting it, then rerun keel setup.

### Linking fails with "tapi error: malformed file ... unknown architecture"

The newest macOS SDK on the machine lists link targets the installed Command
Line Tools linker does not recognise, which happens when a beta SDK sits beside
older tools. `xcrun` picks the newest SDK. Point builds at an SDK that matches
the linker, for example:

~~~sh
export SDKROOT=$(xcrun --sdk macosx26.5 --show-sdk-path)
~~~

Or update the Command Line Tools to the release that ships the newer SDK.

### The first session after setup is slow

The first VM run of a fresh install can take a few minutes; later runs boot in
seconds. In the clean-clone walkthrough the first run took about five minutes
while the machine was also compiling, and every later run took two to three
seconds. Let the first run finish rather than interrupting it.

### Docker is unavailable during setup

Start Docker Desktop and rerun keel setup. Docker is used to build the guest artifacts, not as the runtime isolation boundary.

### Git credential configuration is incomplete

Set all three KEEL_GIT_* variables or unset all three.

### Terminal output contains literal escape sequences or diagonal spacing

Rerun setup so ~/.local/bin/keel uses the current renderer, then start a new
session. In a current session, press Ctrl-A and run /redraw to request a fresh
canonical snapshot. Ctrl-L remains a guest-application redraw command, but it
is not part of Keel's normal repair path. Current builds terminate incremental
guest output in the sandboxed xterm-headless model and paint replayable complete
snapshots instead of forwarding guest cursor deltas directly.

### Connection dropped while an approval is pending

Start a new session from a current build. Egress broker V2 acknowledges the
parsed request only after acquiring its serialized adjudication slot, then
keeps the relay open for the bounded human-decision window; older V1 clients
treated the short machine timeout as the whole authorization timeout. Enter
the trusted view with Ctrl-] or `Ctrl-A`, `/approve`, Enter. If the
4-minute-45-second trusted gate
has expired, its UI is cleared and a late decision is rejected; retry the
original action. If the requesting relay disconnects during review, Keel
cancels that prompt without executing the action or creating a grant. A
disconnect after provider transmission is different, because the provider may
already have done billable work:

- **After the opening usage event:** if the stream had already reported its
  input, Keel charges that input plus the output streamed so far and a
  4,096-token margin, recorded as `committed-observed`.
- **Before it:** Keel keeps the full reservation, recorded as
  `committed-conservative`.

### Model requests are refused with "403 Keel refused this request"

The run's model token or cost ceiling is exhausted; the audit shows
`kernel:model-budget` denials. Each request reserves its worst case: every
byte of the request counted as an input token, plus its full `max_tokens` of
output at the pinned tariff. With Opus and a large `max_tokens`, that can be
more than half of the USD 20 default for a single request, even though the
actual charge settles far lower. A request that would fit once in-flight
requests settle waits up to 30 seconds for them, instead of being refused. Start the session with a higher ceiling, which you
approve at task admission, for example `--model-cost-budget 100`.

## 14. Contributor checks

Before publishing a change:

~~~sh
cargo fmt --all -- --check
cargo check --workspace
cargo test --workspace
./ci/check.sh
~~~

The CI script also enforces trusted-code size and dependency constraints. See [Architecture](ARCHITECTURE.md) for the crate boundary and [Threat model](THREAT-MODEL.md) for what those checks do and do not establish.
