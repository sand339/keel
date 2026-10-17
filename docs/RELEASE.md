# Release checklist

A release is cut only when every item below passes on the commit being tagged.
Record the outcome of each check in the release notes.

## 1. Tree and history

- [ ] **No personal, employer, or machine-specific content** in the tree:
  names, email addresses, account identifiers, private repository names,
  absolute home-directory paths.
- [ ] **Secret scan of the full history** finds nothing:
  `docker run --rm -v "$PWD:/repo:ro" zricethezav/gitleaks:latest git /repo --redact`.
- [ ] **No generated or local state** is tracked (`.phase0/`, `.phase1/`,
  `.keel/`, `target/`, session or audit files).
- [ ] **Commit authorship** uses the intended public identity.

## 2. Dependencies and licenses

- [ ] **Advisories, bans, licenses, and sources:** `cargo deny check` passes.
- [ ] **Pins are current.** Every artifact in [Pinned artifacts](ARTIFACTS.md)
  matches the scripts, and any update followed its procedure.
- [ ] **Notices are complete.** [Third-party notices](../THIRD_PARTY_NOTICES.md)
  list every embedded dependency and every component setup downloads.

## 3. Build and test

- [ ] **Formatting and lints:** `cargo fmt --all -- --check` and
  `cargo clippy --workspace --all-targets --locked -- -D warnings`.
- [ ] **Tests:** `cargo test --workspace --all-targets --locked`.
- [ ] **Invariants:** `python3 ci/check_invariants.py` passes I1–I12, and
  every trusted-line change has a PLAN decision.
- [ ] **CI is green** on the release commit. CI does not boot a VM, build the
  guest image, or run the browser; the checks in §4 cover those.

## 4. End-to-end, on an Apple silicon Mac

The [end-to-end acceptance](E2E.md) page has both parts: the headless suite
(`python3 ci/e2e.py`) and the manual runbook for operator decisions.

- [ ] **Fresh clone.** A fresh clone followed only the README:
  - `keel setup` and `keel doctor` succeeded with no undocumented step;
  - the clone used an empty `KEEL_STATE_DIR` and a fresh install directory.
- [ ] **Smoke runs:**
  - a VM V8 smoke run: `keel run --isolation vm-v8 v8 docs/examples/v8-smoke.mjs`;
  - a Claude session for each configured provider;
  - one browser task;
  - one build that fetches dependencies;
  - one scoped run with a declared scope, showing an out-of-scope refusal.
- [ ] **Lifecycle faults:** `python3 ci/faults.py` passes every case.
- [ ] **Audit evidence.** Each run's audit verifies with
  `keel audit verify AUDIT KEY` (`VERIFIED AND SEALED`). Its admission
  manifest names the expected kernel, root disk, provider, and model.
- [ ] **Reports.** `keel report --axes` and `keel report --context` run over
  the sessions above.

## 5. Documentation

- [ ] **README is current.** It describes current behavior only, and every
  security property it lists links to evidence.
- [ ] **Security claims link to evidence.** The THREAT-MODEL control map and
  the ARCHITECTURE implemented list name a test or invariant for every row, and
  each named test still exists.
- [ ] **Known limitations** in the README are up to date.
- [ ] **No historical plan reads as current behavior.** ROADMAP holds future
  work only; PLAN and DECISIONS are logs.

## 6. Tag

- [ ] **Clone URL.** The README's clone command names the published
  repository (`sand339/keel`).
- [ ] **Version.** Bump the workspace version, update the release notes below,
  tag `vX.Y.Z`, and push the tag.

## 7. Publishing

Development happens in the private repository (`private` remote, branch
`main`, full history). The public repository (`public` remote) receives only
release snapshots: commits on a local `public` branch that share no history
with `main` and carry each release's exact tree.

```sh
# Once per clone: install the guard that keeps main out of the public repo.
cp ci/pre-push-guard.sh .git/hooks/pre-push

# Each release, after this checklist passes on main:
snapshot=$(git commit-tree 'main^{tree}' -p refs/heads/public -m "Keel vX.Y.Z")
git branch -f public "$snapshot"
git push private main
git push public refs/heads/public:refs/heads/main
```

Release tarballs are built per platform, on that platform, from a clean
checkout of the release commit. The script refuses uncommitted changes and
runs `keel setup` itself into a fresh directory, so nothing installed earlier
ships:

```sh
./spikes/package-release.sh      # writes target/dist/keel-VERSION-PLATFORM.tar.gz and .sha256
```

The `.sha256` and the bundled `SHA256SUMS` detect a damaged download; they
are not signatures. Sign each tarball with Sigstore's keyless flow, which keeps
no signing key anywhere:

```sh
KEEL_RELEASE_SIGN=1 ./spikes/package-release.sh   # cosign opens a browser; log in with GitHub
```

Log in as the identity the README's `cosign verify-blob` names
(`sandeepsingh001@gmail.com`, issuer `https://github.com/login/oauth`); a
different login produces a signature users' verification rejects. Upload the
`.sigstore.json` bundle with the tarball and its `.sha256`, then run the
README's verification against the uploaded files before announcing the release.

Set `KEEL_RELEASE_VERSION` (for example `0.1.0`) for a tagged release; it
defaults to the workspace version and commit. Before publishing, install the
tarball as a user with no toolchain and run `keel doctor` and one session.
Upload each tarball, its `.sha256`, and its `.sigstore.json` to the release on
the public repository.

The first snapshot has no parent; later ones use `-p refs/heads/public` so
the public history is one commit per release. Spell the branch as
`refs/heads/public`: a bare `public` is ambiguous, since it names both the
branch and the remote.

---

# Release notes

## v0.1.0 (unreleased)

The first public research release. Apple silicon macOS, and Linux with KVM
(tested on Ubuntu 24.04 x86_64).

**Isolation**
- Claude Code and V8 workloads in a Virtualization.framework microVM with no
  ordinary network device, plus a lower-assurance host V8 sandbox behind an
  explicit grant.
- A second confinement layer inside the guest:
  - capabilities removed;
  - Landlock on the 6.12 guest kernel;
  - seccomp;
  - a bounded cgroup.
- The guest boots from a read-only root disk under a writable overlay.

**Authority**
- **Credentials.** They stay on the host. The guest presents sentinels, which
  the trusted proxy swaps for the real credential only on its exact host and
  path. Providers: Anthropic, Bedrock (SigV4 or bearer), and OpenRouter
  (priced from an admitted snapshot).
- **Approvals.** A trusted terminal handles them: single-use `A` approvals,
  scoped `G` grants, and secure-attention input.
- **Policy.** Policy, provenance floors, and model budgets.
- **Admission manifest.** Every run records its manifest before it starts.
- **Attribution.** Each guest request carries the process that made it.

**Workflows**
- A guest browser driven by `agent-browser`, for the agent and the operator.
- Build toolchains in the guest: gcc, make, npm, pip, Rust, and Go.
- A scoped profile that confines a run to a declared scope, or to no outside
  host with `--scope none`.

**Evidence**
- An authenticated, hash-chained audit chain with a terminal seal.
- `keel report` for prompt fatigue, the action-centric comparison, and the
  context digest log.

**Known limitations:** see the README.
