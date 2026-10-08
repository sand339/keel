# Triage reproduction profile

**Status: stage 1, trimmed, is implemented (D58):** the triage profile,
analyst-declared scope enforced without prompts, scope proposed from the
report, and approved model providers. **Stage 2, the headless browser, is
implemented (D59)** for every Claude session, not only triage. Test-credential
injection, request limits, enforced report flow, the interactive window, and
WebSockets remain planned. §5 lists proxy
gaps found in the current code.

## 1. Decision

Keel should offer a **triage profile**: a run shape for reproducing a
reported vulnerability against an in-scope target, by an analyst or an agent,
inside the VM. The profile adds four things:

- scope admitted up front;
- test-account credentials injected per host;
- per-target request limits;
- enforced payload flow for report content.

A browser runs **inside the guest**, headless, and all its traffic goes
through Keel's proxy. The analyst's own browser is never connected to the
guest.

The audit chain and admission manifest then become a signed record that the
reproduction stayed inside the authorized scope. That record is the main
reason to do this in Keel rather than on an analyst's laptop.

## 2. Problem and analyst context

Triage means reproducing someone else's claim, usually with their code:

- a PoC script;
- a crafted request sequence;
- a malicious page;
- occasionally a binary.

The target is a customer's system, often in production. An analyst does this
many times a day, under time pressure, on their own workstation.

What goes wrong today:

1. **The PoC attacks the analyst.** A report can carry a payload aimed at
   whoever opens it: a script that reads `~/.aws` or browser cookies, or a page
   that exploits the analyst's browser. Analysts handle more hostile input than
   almost anyone, on machines that hold their most sensitive sessions.
2. **The repro leaves scope.** A PoC that follows redirects, loads third-party
   scripts, or was written against a different host can touch assets outside
   the program's authorization. Nobody can later show that it did not.
3. **Test credentials leak.** Test-account cookies and tokens get pasted into
   PoCs and terminals and end up in shell history, screenshots, and model
   context.
4. **Report data leaks.** Unfixed vulnerability details are among the most
   sensitive data a security team handles. A repro, or an agent helping with
   one, can send report fragments to hosts that should never see them.
5. **Agents make all of this faster.** Agent-driven reproduction runs
   unvalidated exploits automatically, which are just as sensitive, so it
   needs containment by construction rather than by analyst discipline.

What analysts need from a reproduction environment:

- one command to start, from the report;
- a real browser for web findings;
- confidence that nothing outside scope was touched;
- evidence to attach to the report;
- no setup per target.

## 3. What Keel already provides

| Triage risk | Existing control |
|---|---|
| PoC compromises the analyst | VM boundary with no host mounts except the workspace, plus the second guest confinement layer (D46, D53) |
| PoC steals host credentials | Credentials never enter the guest; the guest presents sentinels that the trusted proxy swaps per scope |
| Repro leaves scope | Egress allowlist from admission; every request is authorized after TLS termination |
| Report content leaves | Payload-flow fingerprints of admitted content (W2, D47); shadow mode today |
| "What exactly happened?" | Signed hash-chained audit, per-request actions, admission manifest (D57) |

## 4. Design

### 4.1 Triage profile

`keel mux --profile triage --scope PATTERN …` (or `keel run`, with the
same options) admits:

- **Scope, declared by the analyst.** Keel is local and operator-driven, so
  the analyst declares scope as arguments, the same way every other run
  authority is declared:

  ```sh
  --scope '*.target.example' --scope api.target.example:8443 \
  --exclude admin.target.example
  ```

  Long scopes use `--scope-file FILE`, with one rule per line, kept per
  program and reused. Matching is strict to avoid the usual scope mistakes:
  - `*.x` matches subdomains only, never the apex `x`, which must be listed on
    its own;
  - ports default to 443 and 80;
  - an exclusion beats any match.

  The untrusted CLI may extract target hosts from the report and propose them
  as the scope. The admission screen lists the parsed rules exactly, and the
  run starts only after the analyst admits them, which is the guard against a
  typo widening scope.

  Everything outside scope is denied without a prompt. A browser loads dozens
  of hosts per page, so per-request prompting cannot work.

  The analyst's declaration is trusted: the analyst is the operator. The
  manifest records the admitted rules. The evidence therefore shows that the
  repro stayed within what the analyst declared, which equals the program's
  authorization only if the declaration was right. Checking declarations
  against program scope data is deferred until the profile is adopted.
- **Approved model providers only.** The model endpoint receives the full
  context, including report content. The profile refuses any provider not on an
  operator-configured approved list, for example Bedrock in the company's
  account. OpenRouter and other aggregators are refused.
- **Test-account credentials, for scripted repro.** Each in-scope host can
  bind one header or cookie through the existing vault: the guest sees a
  sentinel, and the trusted proxy substitutes the real value only on that host.
  The credential never reaches the guest, the model context, or a PoC file.
  The analyst logs in on the host and supplies the session token or API key
  through an environment variable named by a flag, for example
  `--target-credential app.target.example:Cookie=TARGET_COOKIE`, so the value
  never appears in arguments or shell history;
  username-and-password logins happen in the interactive browser (§4.2)
  instead. Form-login body substitution and a trusted cookie jar are not
  built: the returned session reaches the guest anyway, and a proxy-held jar
  breaks pages whose scripts read cookies.
- **Request limits.** Per-host request and byte budgets, enforced like the
  model budget, so a looping PoC or agent cannot load a customer's production
  system.
- **Payload flow, enforced.** The report text is admitted as `secret` content.
  Fragments of it leaving to any host other than the approved model endpoint
  are denied, not just audited.
- **OOB callbacks.** An optional, explicitly admitted interaction host
  (interactsh or Collaborator style) for blind SSRF and blind XSS. Egress to it
  is easy. Receiving callbacks inside the guest is not, so v1 has the analyst
  read results from the interaction service directly.

### 4.2 Browser in the guest

- **Engine.** Chromium in the guest image, driven by `agent-browser`: by the
  agent through its MCP tools, and by the analyst directly through its CLI,
  sharing one browser (§4.3).
- **Logins.** The analyst logs in inside the guest browser, which handles form
  logins, SSO redirects, MFA, and CAPTCHAs that injection cannot. The password
  and session then live in the guest, where the PoC and agent could read them;
  for test accounts that is accepted, and scope still bounds where they can be
  sent. SSO identity-provider hosts must be declared in scope.
- **Traffic.** Everything uses the guest's proxy and the run CA. QUIC is
  disabled, so all traffic is TCP through Keel. Service workers and HTTP
  caches start empty for each run.
- **Chromium's own sandbox.** It needs user namespaces, and the guest
  confinement denies them. The browser therefore runs with `--no-sandbox` and
  relies on the VM. This should be a recorded decision rather than a quiet
  flag. The workload's Landlock, seccomp, and cgroup layers still apply.
- **Never the analyst's browser.** Bridging the host browser, its profile, or
  its SSO sessions into the guest hands them to a hostile PoC. This is a
  non-goal, not deferred work.

**As built (D59).**
- **Guest base and packages.** The guest moved from Alpine 3.20 to 3.23 for
  Chromium 149; 3.20 shipped Chromium 131.
- **Driver (D60).** `agent-browser` 0.38.2 (vercel-labs), pinned by checksum,
  replaced Playwright's MCP server: one static musl binary instead of a Node
  dependency tree, with a CLI the analyst uses directly, HAR capture, request
  and console listing, and an MCP mode registered as the `browser` server.
  The CLI and MCP share one browser through its daemon.
- **Launch.** It launches Chromium through `keel-chromium`, which appends
  Keel's flags (`--no-sandbox`, QUIC off, the background-traffic switches) and
  merges `--disable-features` lists, because Chromium honors only the last
  one. The egress relay is its proxy.
- **CA trust.** The run CA is added to Chromium's NSS store at launch.
- **No background traffic.** Chromium calls Google services on its own:
  sign-in, push messaging, variations, and search. A managed policy disables
  those features, and endpoint switches send the remainder to a closed
  loopback port, so a run sees no browser background traffic: no prompts, and
  no scope refusals.
- **Image cost.**
  - The root filesystem grows to about 875 MB, after removing Mesa's LLVM and
    Gallium libraries, which headless Chromium with the GPU off never loads.
  - It is compressed with zstd: 353 MB.
  - Since D61 it is a read-only squashfs disk read on demand, not unpacked
    into RAM: idle guest memory is about 150 MiB and workspace VMs are back
    to 2 GB.
- **Attribution.** Code under `node_modules` now counts as workspace code
  only under a writable root, so the bundled browser server is not flagged.

### 4.3 Evidence and visibility

- **Evidence bundle.** `keel triage export RUN` writes:
  - the sealed audit chain and its verification key;
  - the admission manifest, including scope;
  - HAR from the proxy's view of each request;
  - browser screenshots.

  It is a defensible record of what the repro did and did not touch.
- **Interactive browser window (deferred).** The analyst drives the browser
  and takes screenshots through the `agent-browser` CLI and finds the files
  in the workspace (D60), which covers most of what the window was for. A
  live view remains future work.
  The original design was this: a host window shows the guest's Chromium
  through a CDP screencast and forwards the analyst's clicks and keystrokes to
  it, so the agent and the analyst share one browser. It is untrusted code:
  Keel's approvals happen only through the secure-attention key in the trusted
  terminal, so nothing drawn in the window can approve an action. A native VM
  display was considered and rejected for the much heavier guest image, as was
  rendering the browser into the terminal, which would need guest-controlled
  graphics escape sequences passed to the host terminal.

## 5. Proxy gaps found in the current code

A browser exercises the trusted proxy far harder than a coding harness does.

| Gap | Current behavior | Needed |
|---|---|---|
| HTTP/2 | No ALPN is offered, so clients fall back to HTTP/1.1 | Acceptable for v1; measure page-load cost |
| WebSockets | No `Upgrade` handling | Authorize the upgrade request, then relay frames as a bounded, audited stream |
| Connection reuse | A new upstream connection per request, except the Anthropic API | Bounded reuse for in-scope hosts |
| Buffering | Whole request and response bodies are buffered | Streaming for large downloads, with the same inspection |
| Audit volume | One action per request | Group subresource loads per page, or summarize per host, without losing exact targets |
| Non-HTTP protocols | Not mediated | Out of scope for v1: SMTP, database ports, raw DNS |

WebSockets is the main risk to commit to. Modern applications, including many
targets, use them for core features.

## 6. Data handling

- Report content and agent-found exploits are treated as the most sensitive
  data the run holds. The profile admits them only to the approved model
  endpoint and the workspace.
- Evidence bundles contain target responses, which can include customer data.
  Export is explicit, written as owner-only files, and never uploaded by Keel.
- Test-account credentials are never written to the audit, the manifest, HAR,
  or the bundle; the existing redactor covers them.

## 7. Trusted-code budget

866 lines remain. The trusted additions are:

| Item | Crate | Estimate |
|---|---|---:|
| Scope patterns and exclusions in admission and egress | keel-input, keel-kernel | 80 |
| Per-host test-credential bindings | keel-secrets | 40 |
| Per-host request and byte budgets | keel-kernel | 60 |
| Enforcing payload flow for admitted report content | keel-kernel | 30 |
| Approved-provider rule | keel-input | 15 |
| WebSocket upgrade and bounded frame relay | keel-secrets | 120 |
| **Total** | | **~345** |

Everything else is untrusted:

- the browser image and `agent-browser`;
- the MCP browser tool;
- the interactive browser window;
- the HAR writer;
- the evidence export;
- the `keel triage` command.

The trusted total is affordable, but it would leave about 500 lines, which W4
enforcement and the trusted push diff also need. Prioritizing is a product
decision.

As built, the trimmed stage 1 (scope and approved providers) used 176 lines
(D58), against an estimate of 95: strict rule parsing, matching, and
normalized display for admission and the manifest cost more than the table
assumed. 690 lines remain.

## 8. Sequencing

1. **Triage profile without a browser.**
   - Contents: scope, approved providers, test credentials, request limits,
     enforced report flow, evidence export without HAR.
   - Useful as is: much reproduction is scripted `curl`-style requests.
2. **Headless Chromium.** In the guest, over HTTP/1.1, with an MCP browser tool
   and screenshots. It ships without WebSockets, and targets that need them are
   called out.
3. **Interactive browser window**, so analysts log in themselves.
4. **WebSocket relay**, then HAR.

Each stage is measured on real reproductions before the next: time to
reproduce, prompts, out-of-scope denials, and analyst feedback.

## 9. Open questions

1. If the profile is adopted, should declared scope later be checked against
   program scope data, and should a mismatch warn or refuse?
2. Should `--no-sandbox` Chromium need its own admission flag, or is it
   implied by the profile?
3. Should the browser keep cookies across navigations within a run? Yes by
   default; does any finding class need isolation between steps? Logins in
   the interactive window depend on keeping them.
4. How should HAR treat response bodies containing customer data: always
   included, truncated, or opt-in?
5. Is there demand for raw TCP targets (SMTP, Redis, databases) large enough to
   justify a mediated TCP relay with its own scope rules?

## 10. Limits

- A guest kernel exploit from a hostile PoC defeats the inner confinement; the
  VM remains the boundary. Browser exploits that also escape the VM are out of
  scope, as they are for Keel generally.
- Scope enforcement covers what crosses Keel's proxy. A target that redirects
  through an out-of-scope host is denied there, which can break a legitimate
  reproduction; the analyst then widens scope deliberately.
- The evidence is tamper-evident relative to the run key. It is not
  attestation and cannot prove the host recorded reality.
