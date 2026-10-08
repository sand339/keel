# End-to-end acceptance

Keel's end-to-end acceptance has two parts:

1. **The headless suite** (`ci/e2e.py`) runs every workflow that needs no
   operator decision, checks its output and audit records, verifies every audit
   chain, and runs the reports.
2. **The manual runbook** below covers every workflow that needs an operator
   decision at the trusted terminal: approvals, grants, challenges, and
   admission screens. Those decisions are, by design, something only a person
   at the terminal can make, so they are exercised by a person.

A release needs both to pass (see the [release checklist](RELEASE.md)).

## 1. Headless suite

```sh
aws sso login --profile PROFILE        # or export another provider's credential
python3 ci/e2e.py                      # all cases whose credentials are present
python3 ci/e2e.py --list               # case names
python3 ci/e2e.py --case build-offline # one case
```

The suite uses the installed `~/.local/bin/keel` and an isolated
`KEEL_STATE_DIR`, so it does not mix with your own sessions. Each case's input
is `/dev/null`: a case that raised an approval or admission screen could not
proceed, and the suite counts any such screen as a failure.

| Case | What it proves |
|---|---|
| `doctor` | The installation is complete: root disk, guest kernel with Landlock scoping, signed VZ backend |
| `v8-vm` | V8 runs inside the microVM; the manifest records the isolation and root disk digest |
| `claude-reply` | Claude Code reaches the model through the trusted proxy; usage is settled from trusted usage; the context digest log records requests |
| `guest-confinement` | The guest runs the 6.12 kernel with Landlock ABI 6, and the workload cannot signal PID 1 |
| `browser-mcp` | The agent drives the guest browser over MCP; the screenshot lands in the workspace, and Git ignores it |
| `browser-cli` | The `agent-browser` CLI drives the same browser from a guest shell |
| `build-offline` | gcc, Rust, Go, pip, and npm work in the guest; `--memory 4` reaches the guest and the manifest |
| `refusals` | Invalid configurations are refused before any VM boots: unknown profile, malformed scope, unapproved triage provider, invalid memory and auth |
| `interrupted` | A session whose trusted runtime dies is reported as `interrupted`, and its chain verifies as an unsealed prefix |
| `provider-anthropic` | The Anthropic API key path works (needs `ANTHROPIC_API_KEY`) |

Every session must also record an admission manifest, present no operator
prompt, and verify as `VERIFIED AND SEALED`, except the interrupted one,
which must verify as `VERIFIED PREFIX`.

Results go to `~/.keel/e2e-results/<UTC time>/`:
- `summary.md`, the human-readable summary;
- `summary.json`, the same results as data;
- `transcripts/`, one transcript per case;
- `report-axes.txt` and `report-context.txt`, the reports;
- `state/`, every session and audit chain.

## 2. Manual runbook

Run each case from an interactive terminal in a throwaway Git workspace.
- **Keys.** When an approval is pending, the terminal title reads "Keel
  approval". Press `Ctrl-]` to open the trusted screen, then:
  - `A` approves once;
  - `G` grants for the displayed host, port, and method;
  - `Escape` denies;
  - for a challenge, type the shown code and press Enter.
- **Admission screens.** Type `APPROVE`, or `HOST V8` for the host sandbox.
- **Recording.** For each case, note the session id from the `Keel audit:`
  line printed at exit, then run `keel audit verify AUDIT KEY` and expect
  `VERIFIED AND SEALED`.

| # | Workflow | Command | Operator action | Expected |
|---|---|---|---|---|
| M1 | Approve once | `keel run claude -p 'Run curl -sI https://example.com twice with Bash and show the status lines.' --allowedTools Bash` | `A` at each prompt | Two separate prompts, two `HTTP/2 200` or `HTTP/1.1 200`; `A` is not reused |
| M2 | Reusable grant | Same command | `G` at the first prompt | One prompt; the second request runs without one |
| M3 | Deny | Same command, one request | `Escape` | The request fails; `keel report AUDIT KEY` counts one denial |
| M4 | Task admission, dependency fetch | `keel run --allow egress:registry.npmjs.org claude -p 'Run npm init -y and npm install is-number with Bash.' --allowedTools Bash` | `APPROVE` on the admission screen | The admission screen lists `egress:registry.npmjs.org`; the install completes with no further prompt |
| M5 | Triage scope | `keel run --profile triage --scope example.com claude -p 'Run curl -sI https://example.com and curl -sI https://www.google.com with Bash.' --allowedTools Bash` | `APPROVE` | The admission screen shows the triage scope line; example.com succeeds with no prompt; google.com is refused at once; the audit shows `kernel:out-of-scope` |
| M6 | Browser on a real site | `keel run claude -p 'Open https://example.com in the browser, take a screenshot, and tell me the title.' --allowedTools mcp__browser` | `A` for example.com | Title "Example Domain"; screenshot in `.keel-browser/screenshots/`; no prompt for any Google host |
| M7 | MCP issue read and attribution | `keel run claude -p 'Use the keel gh_issue_read tool to read issue 1 of octocat/Hello-World.' --allowedTools mcp__keel` | `A` for api.github.com | The issue is returned; the action's `origin` in the audit names `keel-mcp-guest` |
| M8 | Host V8 sandbox | `keel run --isolation v8-sandboxed --allow isolation:v8-sandboxed v8 docs/examples/v8-smoke.mjs` (from the repository) | Type `HOST V8` | The smoke script runs; the manifest records `v8-sandboxed` |
| M9 | Elevated budget | `keel run --model-cost-budget 25 claude -p 'Reply OK.'` | `APPROVE` | The admission screen shows the USD 25 ceiling; the manifest records it |
| M10 | OpenRouter | `keel run --auth openrouter --model anthropic/claude-sonnet-4.6 claude -p 'Reply OK.'` | `APPROVE` | The admission screen shows the price snapshot. Its `kernel.model-reservation` records end in `settled-actual` with an actual cost below the reserved cost, which confirms OpenRouter usage parsing; `committed-conservative` would mean usage was not parsed |
| M11 | Persistent mux | `keel mux`, then `Ctrl-A /detach`, `keel attach SESSION`, `keel stop SESSION` | Launcher choices | The session survives detach, reattaches with its screen, and stops cleanly; `keel status` shows `closed` |
| M12 | Git push, default branch, force | In a disposable private GitHub repository you own: `--allow push:branch` and a feature-branch push, then a default-branch push, then a force push | `APPROVE`, then `A`, then the challenge | The feature push succeeds; the default-branch push asks for a challenge; with `--allow deny:force-push` the force push is denied with no prompt |

M12 writes to a real GitHub repository; use one created for this purpose.

After the manual cases, run `keel report --axes` and `keel report --context`
over all of the sessions.
