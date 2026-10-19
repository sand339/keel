# Design note — `keel init`: guided setup without stored secrets

> **Status: proposed (2026-10-17). Nothing is built.** Decided 2026-10-18:
> one credential source per provider, chosen with `--auth` (§4); keyring-less
> Linux uses `process` sources, which never prompt on the terminal (§4.1, §4.2);
> with `gh` absent, `init` prints how to install it and continues (§3); the
> first session runs offline-safe in the V8 microVM (§3). Scope follows the
> 2026-10-16 decision that Keel stays a local boundary for one operator on
> their own laptop or workstation. Cost estimates are from reading the code,
> not from a prototype.

---

## 1. The problem

Installing Keel works. Using it the first time does not go smoothly, and the
friction falls on the features that make Keel worth running:

- **Model access is environment variables, per shell.** `ANTHROPIC_API_KEY`,
  four variables for Bedrock, or `OPENROUTER_API_KEY` must be exported before
  every run, and two configured providers make the run ask which to use.
- **Authenticated Git push is three hand-built variables.**
  `KEEL_GIT_AUTHORIZATION='Basic …'`, `KEEL_GIT_CREDENTIAL_HOST`, and
  `KEEL_GIT_CREDENTIAL_PATH`, redone for every repository. Push gating is
  Keel's sharpest feature and this is the hardest step to get right.
- **The trusted path is learned by surprise.** The first time most users see
  `Ctrl-]`, `A`, `G`, a challenge, or the admission screen is during real work.
- **Doctor diagnoses but does not fix.** A stale install, the `kvm` group, the
  Ubuntu AppArmor profile, and the macOS SDK linker issue are each a line of
  advice the user must act on.

Two of these cost the maintainer during the second security review: a droplet
run that failed every case because the model key lived in an env file a
non-login shell did not read, and an E2E run against a six-day-old install.

## 2. Goals and non-goals

Goals:

- From a downloaded release to a gated push in about ten minutes, with no
  environment variables and no reading beyond what `keel init` prints.
- No secret at rest that Keel did not already have. Keel today reads
  credentials at launch and never writes them; `init` keeps that.
- Every change `init` makes to the host is shown first and confirmed.
- Rerunnable: `keel init` on a configured machine reports what is set, what
  is stale, and offers only the missing steps.

Non-goals:

- Storing API keys or tokens in a Keel file.
- Editing shell profiles, or setting environment variables for the user.
- Applying any fix without confirmation, or using `sudo` itself.
- Remote, fleet, or service operation.

## 3. The flow

`keel init` runs in the operator's terminal, outside any VM. It is untrusted
code: it writes configuration the trusted runtime later checks, and it runs
the same commands a user would.

1. **Preflight.** Run doctor's checks. For each failure, show the exact command
   that fixes it; run it only when the user confirms and it needs no
   privilege. Privileged fixes (the AppArmor profile, `usermod -aG kvm`) are
   printed, not run.
2. **Install.** If the runtime is missing, or its build does not match this
   `keel`, offer `keel setup` (from source) or `keel setup --prebuilt DIR`.
3. **Model providers.** Configure one or more of Anthropic, Bedrock, and
   OpenRouter, each with its own *source* (§4), and optionally mark one the
   default. Verify each with one minimal model request through the trusted
   proxy, the same path a run uses, and report the model and region that
   answered.
4. **Git and GitHub.** If `gh` is signed in, offer it as the source for both
   the GitHub tools and authenticated push (§5). If `gh` is installed but
   signed out, offer `gh auth login`. If it is absent, which is common on a
   release install with no developer tooling, print how to install it for
   this platform (`brew install gh` on macOS; GitHub's apt repository on
   Ubuntu, with its signing-key steps) and continue without it. Keel never
   installs `gh` itself. Until it is set up, pushes are refused and the GitHub
   tools read public data only; `keel init` can be rerun to finish this step.
5. **Optional.** Offer the crash-recovery reaper (`keel setup --install-reaper`).
6. **First session.** Run a short script in the V8 microVM
   (`--isolation vm-v8`), so the lesson needs no model call, costs nothing,
   and behaves the same every time; the trusted screen, gate, audit chain,
   and receipt are those of any run. The script, `share/keel/demo.mjs`, ships
   read-only with the release and runs in a throwaway workspace,
   `~/.keel/init-demo`. It never touches a real repository and never pushes.
   It makes two requests and explains each screen before it appears:
   1. `GET https://example.com/`: the user presses `Ctrl-]`, then `A`.
   2. `GET https://example.org/`: the user is asked to press `Escape`, and the
      script shows the refusal it got.

   The demo passes on the decisions, not on the network: the gate is decided
   before any connection is made, so success is one approval and one denial
   in the audit chain and `keel status` ending `closed` with a verified
   receipt. Offline, the approved request then fails to connect, and the demo
   says so instead of failing. Admission requires a model credential even for
   V8 runs; step 3 has configured one by now, and a skipped step 3 uses a
   placeholder for this run only, as the E2E harness does.

The flow ends by printing the commands for the user's next real run.

## 4. Credential sources, not credentials

A **source** says where the trusted runtime fetches a credential at launch.
Keel already works this way for one provider: `KEEL_AWS_CREDENTIAL_PROCESS`
names a command whose output the trusted runtime reads, wipes, and never
persists. `init` generalizes that, and the runtime keeps reading the existing
environment variables first, so nothing a user has today breaks.

Sources, stored in `~/.keel/sources.json` (new, beside the existing
`~/.keel/config.json`):

| Kind | Example | Notes |
|---|---|---|
| `keychain` (macOS) | service `keel-anthropic`, account `$USER` | Read with `/usr/bin/security find-generic-password -w`; `init` offers to add the item, prompting for the key once |
| `secret-tool` (Linux) | attribute `keel anthropic` | libsecret, where a desktop keyring exists |
| `process` | `aws configure export-credentials --profile P --format process` | The existing credential-process contract, with its one-minute deadline. Also how `systemd-creds`, `pass`, and password-manager CLIs are used (§4.2) |
| `gh` | `gh auth token --hostname github.com` | Already how `keel-secrets` gets the GitHub token for the MCP tools |
| `env` | `ANTHROPIC_API_KEY` | The current behavior, made explicit |

What the file holds: one source per configured provider, keyed by the same
names `--auth` takes (`api-key`, `bedrock`, `openrouter`), plus the GitHub
source, an optional default provider, and per-provider model and region.
Never a secret.

```json
{
  "version": 1,
  "providers": {
    "api-key": {"source": {"kind": "keychain", "service": "keel-anthropic"}},
    "bedrock": {
      "source": {"kind": "process", "command": "aws configure export-credentials --profile work --format process"},
      "region": "us-west-2"
    },
    "openrouter": {"source": {"kind": "env", "variable": "OPENROUTER_API_KEY"}, "model": "anthropic/claude-sonnet-4.6"}
  },
  "default": "api-key",
  "github": {"source": {"kind": "gh"}}
}
```

**Choosing a provider.** `--auth` keeps its meaning and selects the entry of
that name; a run resolves only the source it selected, so a Bedrock run never
reads the Anthropic Keychain item. Without `--auth`, a run uses the single
configured provider; with several, it uses `default` when set and otherwise
asks at the terminal, as it does today when two providers are configured in
the environment. An environment variable for a provider overrides that
provider's stored source, so existing setups keep working unchanged.

### 4.1 The file is trusted input

The trusted runtime runs the commands the file names. That makes the file as
sensitive as a shell profile, so the runtime refuses it unless:

- it is a regular file, not a symlink, owned by the operator, and not writable
  by group or others; the same holds for `~/.keel` itself;
- it lies outside every workspace. A run whose workspace contains the file's
  path is refused, so a repository cannot supply or shadow one;
- every `process` command is an absolute path or a bare name resolved against
  a fixed `PATH` the runtime sets (`/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin`),
  never the workspace's.

- every `process` command runs with no terminal: stdin is null, no
  `GPG_TTY` or `SSH_ASKPASS` is set, and its stdout and stderr are pipes. A
  source that would prompt therefore fails instead, and the run is refused
  with the source's own unlock hint (§4.2). A prompt drawn on the operator's
  terminal, reading keys Keel did not route, is what the trusted terminal
  exists to rule out. A GUI prompt outside the terminal, such as the macOS
  Keychain dialog or a desktop pinentry, is unaffected.

The admission screen names each source a run will use ("model: Keychain item
`keel-anthropic`"; "Git push: `gh` token, scope github.com/OWNER/REPO.git"),
and the admission manifest records the kinds and names. A source cannot widen
what a capability allows; it only says where the credential comes from.

### 4.2 Linux without a desktop keyring

No tool gets a kind of its own: each is a `process` source, so trusted code
knows how to run a command and read its stdout, as it already does for AWS,
and nothing about any one tool. `keel init` detects these on `PATH` and
offers a ready command line, in this order:

| Tool | Command `init` offers | Unlock before a run |
|---|---|---|
| `systemd-creds` | `systemd-creds decrypt ~/.keel/anthropic.cred -` | None: encrypted to the host key, or the TPM where present; suits unattended workstations |
| `pass` | `pass show keel/anthropic` | Unlock the gpg agent once per login (`pass show keel/anthropic >/dev/null`) and set its cache TTL as long as wanted |
| `op` (1Password) | `op read op://Private/keel-anthropic/credential` | `eval $(op signin)` or the desktop app's CLI integration |
| `bw` (Bitwarden) | `bw get password keel-anthropic` | `export BW_SESSION=$(bw unlock --raw)` in the shell that starts Keel |
| none of these | `env` source | Today's behavior |

`init` stores the item only when the user confirms: `systemd-creds encrypt`
for the first, `pass insert` for the second; for the managers it names the
item to create and leaves creating it to their own tools. When a locked
source makes a run fail, the refusal names the unlock step from this table.

## 5. A Git push scope derived per run

Today the operator spells the push credential's host and path. With the `gh`
source, the trusted runtime derives both at admission from the workspace's
`origin`:

1. Read `remote.origin.url` with the hardened trusted Git command admission
   already uses (repository filters emptied, per KSR-034).
2. Accept only `https://HOST/OWNER/REPO(.git)` with `HOST` on a fixed list
   (`github.com` first; GitHub Enterprise hosts only when named in
   `sources.json`). SSH remotes, `insteadOf` rewrites, credentials embedded
   in the URL, and anything with a port, query, or fragment are refused, with
   a message saying how to set the push scope by hand.
3. Normalize it: lowercase host and owner, one `.git` suffix, no trailing
   slash. That is the scope `keel-secrets` binds, exactly as if the three
   variables had been set.
4. Build the `Basic` authorization from the `gh` token in trusted memory and
   wipe it with the other credential buffers.

If the stored GitHub source is `gh` but `gh` is missing or signed out when a
run starts, the run still starts: it binds no push credential, a push is
refused with the same install or `gh auth login` hint, and `keel doctor`
reports the source as unavailable. A missing tool narrows what a run can do;
it never stops a run that asked for no push.

The admission screen shows the derived scope beside the push capability, so a
repository whose `origin` points somewhere unexpected is visible before any
token is used. Derivation narrows: the token is the user's `gh` token, which
can already push wherever the user can; Keel binds it to one repository for
this run. The guest still never sees it.

## 6. Doctor fixes

Doctor's checks become structured results, each with an optional fix:

| Check | Fix offered |
|---|---|
| Runtime missing or stale | Run `keel setup` (or `--prebuilt`) |
| macOS: CLT linker cannot read the newest SDK | Print `export SDKROOT=…` for the newest SDK it can read; source builds only |
| Linux: not in `kvm` | Print `sudo usermod -aG kvm $USER` and "log in again" |
| Ubuntu: AppArmor blocks user namespaces | Print the one-line profile install |
| No model source | Go to step 3 |
| Git scope unset | Go to step 4 |

`keel doctor` keeps printing the same results; only `keel init` acts on them.

## 7. Threats this adds, and their answers

| Threat | Answer |
|---|---|
| A repository plants a sources file | The runtime reads only `~/.keel/sources.json`, refuses one inside the workspace, and refuses one not owned by the operator or writable by others (§4.1) |
| A `process` source is swapped for a command that exfiltrates | Only someone who can write the operator's `~/.keel` can do that, the same power as editing their shell profile; the admission screen names the command |
| `origin` is set to an attacker's repository to redirect the push token | Derivation is shown on the admission screen; only HTTPS to listed hosts; the token is bound to that one repository for that run (§5) |
| The demo session is used to train users to approve blindly | It teaches both answers, one approval and one denial, on clearly labeled requests; it never touches a real repository |
| A keychain prompt is spoofed by the guest | The prompt comes from macOS when the trusted runtime reads the item, outside the guest's terminal stream |

None of these touch the guest boundary: everything here happens on the host,
before or at admission.

## 8. Where the code goes

| Part | Side | Estimate |
|---|---|---|
| `keel init` flow, prompts, demo script | untrusted `keel-cli` | 400–600 lines |
| Structured doctor results with fixes | untrusted `keel-cli` | 100–150 lines |
| Source resolution: keychain, secret-tool, process, `gh`, env | trusted `keel-secrets` | 60–80 lines (process and `gh` exist) |
| `sources.json` ownership, mode, and workspace checks | trusted `keel-input` | 30–40 lines |
| Derived Git scope from `origin` | trusted `keel-input` (admission) | 40–60 lines |
| Sources and derived scope on the admission screen and manifest | trusted `keel-input` | 15–25 lines |

Trusted total: about 150–200 lines, with each crate's ratchet raised in the
commit that spends it.

## 9. Testing

- Unit: the ownership, mode, symlink, and inside-workspace refusals; `origin`
  parsing for every refused shape (SSH, `insteadOf`, embedded credentials,
  ports, case and trailing-slash variants); a `process` source sees no
  terminal and no `GPG_TTY` even when the operator's environment sets it (the
  credential process inherits the environment today, so this is new).
- Manual on Linux: a locked `pass` store refuses the run with the unlock hint
  and draws nothing on the terminal; `systemd-creds` works with no session.
- E2E: `init-noninteractive` (answers supplied by flag) followed by a run with
  no credential environment variables; a push whose credential comes from
  `gh` with a derived scope; a run refused because the sources file is
  group-writable.
- Manual: the full flow on a clean macOS account and a clean Ubuntu user,
  timed; the demo session's screens, online and with the network off; a
  repository whose `origin` was changed
  to another owner, checking the admission screen shows it.

## 10. Open questions

None remain. Decided 2026-10-18: one source per provider chosen with
`--auth` (§4); keyring-less Linux through `process` sources that never prompt
on the terminal (§4.1, §4.2); `gh` absent means printed install steps and a
run without push (§3, §5); the first session runs in the V8 microVM, teaches
one approval and one denial, and is judged by the audit, not the network (§3).

## 11. Rollout

1. Credential sources and the ownership checks, behind the existing
   environment variables, which keep priority. `keel doctor` reports sources.
2. The derived Git scope, with the admission screen change.
3. `keel init` itself, then the demo session.
4. README's quick start becomes `keel init`; the environment-variable
   instructions move to USAGE as the manual path.

Each step ships on its own and is useful without the next.
