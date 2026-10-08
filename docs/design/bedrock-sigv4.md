# Design note — Bedrock and SigV4 model providers

> **Status: both tracks built, unverified against a live endpoint.**
> §5 steps 1–4 are implemented and D16 is taken (§6). Track B is implemented under
> D17, which raised the total cap 12,000 → 12,700 with no donor — the budget decision
> this note insisted on, decided the other way (§6.1). Identity Center arrived with it,
> through a `credential_process` command rather than any SSO code in the TCB.
> Every wire fact below — the eventstream framing, the usage field names, the tariffs,
> and now the canonical path encoding — is documentation-derived and has never met a
> real Bedrock response; the first live run is the test. The **one** exception is the
> `SigV4` key-derivation chain, which reproduces AWS's published `get-vanilla` vector
> exactly.

---

## 1. Why this is the one deferral that tightens the boundary

Every other entry under "Deliberately deferred" erodes something. This one does the
opposite. Today the guest holds a scoped sentinel: a non-secret string that only
works through `keel-secrets`, but still a credential-shaped object the guest can
present. A signing proxy removes even that — the guest holds nothing, because what
travels upstream is a signature over a payload the guest never sees in final form.
`PLAN.md` §8.2's swap becomes unnecessary rather than merely sufficient.

It waits because it is a project, and because the *reason* it is a project is
uncomfortable: it makes the request sanitizer load-bearing.

**The asymmetry to hold onto.** Under §8.2, if the swap scope is wrong the request
is refused at swap time — a scope mismatch is caught by a check that runs after
sanitization and independently of it. Under SigV4 there is no second check: the
signature is computed over the payload hash, so `keel-secrets` signs whatever the
sanitizer produced. A sanitizer bug that leaves `mcp_servers` in the body today
produces a request Anthropic rejects or a scope mismatch catches; tomorrow it
produces a *validly signed* request for exactly the wrong thing. The strip list
stops being defence in depth and becomes the boundary.

That is acceptable — but only with the sanitizer tested as a boundary rather than as
a filter, which is §5.

---

## 2. Two tracks, and they are not the same size

`ROADMAP.md` already says to try the bearer token first. Concretely:

| | Track A — `AWS_BEARER_TOKEN_BEDROCK` | Track B — SigV4 signing |
|---|---|---|
| Credential shape | `Authorization: Bearer …`, a plain header | derived signing key, four HMAC rounds |
| §8.2 swap | works verbatim | replaced entirely |
| Sanitizer role | unchanged (defence in depth) | **load-bearing** |
| New trusted deps | none | `ring` into `keel-secrets` |
| Guest holds | a sentinel | nothing |
| Est. net trusted LOC | 250–350 | 600–800 |
| Actual | ~294 | ~550 |

Two rows aged differently. "Guest holds: nothing" was an understatement of the good
news — signing does not substitute a secret, so the sentinel header is *discarded*, and
the guest ends up holding a string that authenticates nowhere rather than a scoped one
that works through the broker. "New trusted deps: `ring` into `keel-secrets`" read as a
cost and was nearly free: `keel-audit` and `keel-kernel` already carry the same pinned
version, so the allowlist gained a caller, not code.

Both tracks share the expensive half, and it is not the credential:

**Bedrock streams `application/vnd.amazon.eventstream`, not SSE.** §8.3 settles the
budget reservation from trusted parsing of the response `usage`. Point the original
machinery at an eventstream and it finds nothing to read, which historically failed
in the worst available direction: the guest got its tokens while the reservation
had no explicit terminal outcome. The current lifecycle closes that ambiguity with
a conservative charge, but a trusted
eventstream decoder is unavoidable, and Claude Code streams by default — this is
not an edge case reachable only by a flag.

So the shared work is the decoder, the second host, and the tariff table. Track A
buys a working second provider for that shared work alone. **Do Track A first, ship
it, and let it prove the decoder in production before Track B touches signing.**

---

## 3. Shared work (both tracks)

### 3.1 Second model host

`sanitize_model_request` today admits exactly `POST /v1/messages` on
`api.anthropic.com:443` (`crates/trusted/keel-secrets/src/lib.rs`). Bedrock is a
different shape in three ways at once:

- Host is regional: `bedrock-runtime.{region}.amazonaws.com`.
- Path carries the model: `/model/{modelId}/invoke` and
  `/model/{modelId}/invoke-with-response-stream`.
- Body carries `anthropic_version: bedrock-2023-05-31` and **no `model` field**.

Generalize the admitted set to a small closed table of `(host pattern, method,
path shape)` rather than growing an `if`. The region must come from trusted
configuration, never from the guest's request — a guest-chosen region is a
guest-chosen endpoint, and `{region}` is a wildcard in a hostname otherwise.
Everything outside the table denies before upstream application bytes, as now.

The strip list (`mcp_servers`, `container`, server-side `web_search`/`web_fetch`/
`computer`/`bash`/`text_editor` tool types) applies unchanged. Verify that the
Bedrock body shape does not reintroduce a stripped key under a different name; if
it does, the table entry says so explicitly.

### 3.2 Tariff table

§8.3's pinned tariffs are keyed on a model identifier read from the body. On Bedrock
the identifier is in the *path*, is region-qualified, and pricing is per region. The
table therefore doubles in the awkward direction: `(region, model)` rather than
`model`. Unknown identifiers must keep failing closed — an unpinned tariff is an
unbounded charge, and "unknown" arriving from a path segment is the likeliest new
failure, since path parsing is now the source of the key.

Cross-region and global inference profile ids (`us.anthropic.…` and
`global.anthropic.…`) are distinct keys from the base id. Treat the prefix as
part of the key, not as noise to strip, even while the current pinned table uses
the same conservative family tariff for all three forms.

### 3.3 Eventstream decoder (the expensive part)

Framing is fixed-width and self-describing: total length, headers length, prelude
CRC32, headers, payload, message CRC32.

**Do not verify the CRCs.** The stream arrives over TLS from an endpoint
`keel-secrets` itself authenticated; the CRCs defend against corruption, not against
an adversary, and there is no adversary positioned to benefit. Skipping them saves a
dependency (there is no CRC32 crate in the trusted allowlist and adding one for this
is not defensible) and the ~30 lines of table. **Do** fail closed on any framing
inconsistency — a declared length that overruns the buffer, a headers length larger
than the message, a payload that is not valid UTF-8 JSON where a JSON event is
expected. Inconsistent framing means the decoder's model of the stream is wrong, and
a settlement computed from a stream you are mis-parsing is worse than no settlement.

Usage lands in `amazon-bedrock-invocationMetrics` (`inputTokenCount`,
`outputTokenCount`) on the terminal message. Non-streaming `invoke` also returns
`X-Amzn-Bedrock-Input-Token-Count` / `-Output-Token-Count` response headers.
**Verify both against a live call before building the settlement path on either** —
this is the one fact in this note taken from documentation rather than from this
codebase, and the budget's correctness depends on it.

Settlement semantics are unchanged from §8.3: missing or malformed usage fails
closed and retains the conservative charge. A stream that ends early after the
send boundary never terminates as a release, because connection close is not
evidence that the provider performed no work. It terminates as
`committed-conservative`, unless complete event-stream frames already
included the opening usage event. In that case it is `committed-observed`,
charged at the stated input plus streamed output and a fixed margin (D48).

---

## 4. Track B only — signing

### 4.1 Credential custody

`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, optional `AWS_SESSION_TOKEN`, and a
configured region, taken from the trusted runtime's environment exactly as
`ANTHROPIC_API_KEY` is today and removed before any untrusted process starts.

**Do not implement the SSO credential chain.** Reading `~/.aws/sso/cache/*.json`,
exchanging for STS credentials, and refreshing is a second project inside this one,
and it puts trusted code in the business of parsing files the operator's other tools
write. The operator exports credentials (`aws configure export-credentials`) and
Keel treats them as opaque. Consequence, stated plainly: **temporary credentials
expire mid-run and Keel cannot refresh them.** The run must fail closed with an
error that names expiry as the cause — not a generic 403 surfaced from upstream —
and the operator refreshes and resumes with `--continue`. D5's "only the kernel
refreshes" is satisfied vacuously: nobody refreshes.

**As built (D17): the first sentence held and the consequence did not have to.** No SSO
code entered the TCB — no cache file is read, no portal is called, no STS exchange is
implemented. What changed is that `aws configure export-credentials --format process`
was treated as a *command Keel may re-run* rather than a thing the operator runs once by
hand. `KEEL_AWS_CREDENTIAL_PROCESS` names it; `keel-secrets` parses the four-field
`credential_process` JSON, notes the expiry, and re-runs the command when within 120s of
it. That is ~40 lines and it buys rotation across an Identity Center session's hourly
role credentials, because the AWS CLI is the thing that knows how to refresh and it was
already installed. The paragraph above was right that Keel should not learn SSO; it was
wrong that not learning SSO means not refreshing.

Static credentials remain exactly as described: the environment does not say when a
session token expires, so Keel cannot distinguish a long-lived key from a session
lapsing in five minutes, and that shape still fails mid-run. `keel doctor` names it and
points at the credential-process form. The error on expiry still needs to name expiry
rather than surface a 403 — for the static shape that is the open item in §7.

D5's "only the kernel refreshes" is now satisfied non-vacuously and in the stronger
sense: refresh happens in the trusted process, and the untrusted children have all five
`AWS_*`/`KEEL_AWS_*` variables scrubbed, so nothing else could refresh even if it knew how.

I7 applies to more than the secret key. AWS4 derivation is
`kSecret → kDate → kRegion → kService → kSigning`; every intermediate is key
material and every one must be opaque, non-serializable, and zeroized. The obvious
bug is a derived key held in a plain `Vec<u8>` for the duration of a session because
caching it by date seemed thrifty.

Audit redaction (§8.2) currently covers sentinel and real forms. Signatures are not
secret, but the `Authorization` header contains the key id in clear and must be
redacted with the same machinery.

### 4.2 Dependency

`ring` enters `keel-secrets`'s I4 allowlist for HMAC-SHA256 and SHA-256. Cheap
argument: `ring` is already a direct dependency of `keel-audit`, `keel-kernel`, and
`keel-policy`, so this adds a review edge, not a review surface. It is still a
review event and `ci/trusted-dependencies.toml` gets the comment explaining it.

### 4.3 Tests as a boundary, not a filter

Canonical-request construction is where SigV4 implementations go wrong, and AWS
publishes canonical vectors — use them, do not hand-roll expected strings.

The test that matters more is the one the asymmetry in §1 demands: **for every entry
on the strip list, assert that the signed payload hash is the hash of the sanitized
body and not of the body as received.** Prove it by construction — sign, then verify
the hash against an independently sanitized copy — rather than by asserting the
stripped key is absent from a request that was never signed. A sanitizer test that
passes on an unsigned path proves nothing about the signed one.

---

## 5. Sequencing

1. ~~**Eventstream decoder, standalone, against recorded frames.**~~ **Done.** No
   networking, no signing. Fails closed on truncation, overrun, and early end. This
   is the piece that carries the budget, so it landed first and alone — and it spent
   238 of the 294 lines §6 had to work with, which is why D16 came before step 4
   rather than after it.
2. ~~**Tariff table keyed on `(region, model)`**~~ **Done.** Path-derived keys;
   unknown region or model fails closed.
3. ~~**Admitted-endpoint table** generalized~~ **Done.** Anthropic's single entry
   unchanged and its existing tests untouched as a regression fence. One correction
   found while implementing: the endpoint table matches on *host only*. Folding the
   port and forbidden-IP checks into it would have turned a forbidden-IP
   `api.anthropic.com` request into "not a model host" — and forwarded it
   unsanitized. Those checks stay in the sanitizer.
4. ~~**Track A end to end**~~ **Done, unverified.** Bearer token, existing swap,
   `CLAUDE_CODE_USE_BEDROCK=1` in the guest. One provider per run: the selection is
   made in the trusted process, only the selected host joins the egress allowlist,
   the credential the run did not select is left unbound, and the four `AWS_*`
   variables are scrubbed from both untrusted children. Still to do: run it for a
   week, so the decoder gets real traffic.
5. ~~**D16**~~ **Taken** (§6), with a different donor than this note proposed.
6. ~~**Track B** — signing, credential custody, the hash-of-sanitized-body tests,
   sentinel removed from the guest for this provider.~~ **Done, partly unverified,
   funded by D17** (§6.1). Signing, `credential_process` refresh, and the discard of the
   guest's sentinel header are built; the key derivation is pinned to AWS's published
   vector; and §4.3's hash-of-sanitized-body test is written the way it asked for —
   recompute the signature over both bodies and require the sanitized one, so the test
   fails on a request that signs the original bytes *and* on one that sends them. The
   property holds by construction: signing happens inside `CredentialVault::inject`,
   which runs on the bytes `rebuild_http_request` produced from the sanitized body, so
   there is no ordering in which the signature could cover anything else. The guest's own
   `x-amz-content-sha256` is dropped rather than forwarded. Not done: canonical path
   encoding against a live endpoint.

Exit criterion for the whole thing: a live Bedrock streaming run whose audit chain
settles every reservation, verified with `keel audit verify`, plus a deliberate
mid-stream disconnect that records and retains a conservative terminal charge rather
than leaking or refunding its reservation.

---

## 6. D16 — the budget, which was the actual blocker

`keel-secrets` had **294 lines of headroom** (2,406 / 2,700). The decoder alone spent
238 of them, which settled the question this section was hedging: Track A does not fit
without a reallocation.

**What was proposed here:** take 200 from `keel-policy` (1,000 → 800, actual 750) and
100 from `keel-audit` (900 → 800, actual 673), on the grounds that the Rego
differential oracle is deferred to Phase 3 and the audit chain is complete.

**What was actually taken, and why it differs.** The proposed donors would have left
`keel-policy` with 50 lines of headroom and `keel-audit` with 63 — this note's own
text called that "effectively frozen." Freezing two crates to fund a third is not
displacement, it is accretion with extra steps. `keel-input` was the honest donor: 322
lines of surplus against a trusted input path that is *finished*, not merely quiet.

| Crate | Before | D16 | Actual | Argument |
|---|---|---|---|---|
| `keel-input` | 2,000 | 1,800 | 1,678 | Raw tty, gate, and approval channel are complete |
| `keel-secrets` | 2,700 | 2,900 | 2,781 | Second provider and the eventstream decoder |
| total | 12,000 | 12,000 | | unchanged, as D14 requires |

**The finding stands, and should be read as a result rather than an obstacle:** a
second model provider cost 200 lines of the trusted set's slack, and it bought utility
rather than safety. `keel-secrets` now has 119 lines of headroom. Track B's estimate of
600–800 does not fit behind that at any donor, so the choice it forces — raise the
12,000, which is a charter change against §2's claim that the cap forces displacement,
or do not support signing — is now the *only* remaining question, and it has to be
answered before any of Track B is written rather than halfway through it.

**Revisit trigger (from `ROADMAP.md`, unchanged):** a Bedrock-only account, or a
deployment that forbids first-party Anthropic keys.

### 6.1 D17 — the question above, answered "raise it"

The choice §6 framed was raise the 12,000 or do not support signing. The operator chose
signing. `keel-secrets` went 2,900 → 3,600 (3,581 actual) and the total 12,000 → 12,700,
**with no donor.**

| Crate | Before | D17 | Actual | Argument |
|---|---|---|---|---|
| `keel-secrets` | 2,900 | 3,600 | 3,581 | `SigV4` signing, credential refresh, canonicalization |
| total | 12,000 | 12,700 | 11,797 | raised; no crate could pay |

Two things worth keeping straight about what that cost.

**The estimate was good and the framing was not.** 600–800 predicted, ~550 spent. What
§6 got wrong was treating "does not fit" as a conclusion rather than a question for
whoever owns the thesis. It also proposed the wrong escape: freezing `keel-policy` and
`keel-audit` at their actuals to manufacture 300 lines would have produced the same total
growth with the extra property that two finished crates could no longer be touched. Its
own words for that were "accretion with extra steps," and they applied to itself.

**What the cap actually buys, restated honestly.** Not that the number never moves — it
moved. That moving it costs a written decision naming what was bought and why nothing
could pay. `ARCHITECTURE.md` §2 previously claimed the cap "forces displacement instead
of accretion"; that claim was true of the per-crate mechanism and false of the total, and
it has been corrected rather than left as the more flattering version.

The `ring` line item, priced here as a cost, was close to free: `keel-audit` and
`keel-kernel` already carry the same pinned version, so the I4 allowlist gained a caller
and the reviewable surface gained nothing.

---

## 7. Open questions

- Does `invoke-with-response-stream` ever omit `invocationMetrics` — on an error
  mid-stream, or on a throttle? If so, that path must commit the reservation
  conservatively and audit the terminal outcome; it must not infer a refund from
  the missing metrics.
- Does Claude Code's Bedrock mode call anything beyond `invoke` and
  `invoke-with-response-stream`? A control-plane probe here has the same shape as the
  auto-mode problem: refused by design, and the question is only whether the harness
  tolerates the refusal.
- ~~Bedrock's `anthropic_version` is a wire contract Keel would now assert. Where does
  a version mismatch surface?~~ **Answered by construction:** the sanitizer rejects any
  value other than `bedrock-2023-05-31`, so a mismatch is a local refusal naming the
  contract rather than an upstream 400 the harness reports as a network failure.
- The eventstream decoder does not check either CRC. The bytes arrived over a TLS
  session this crate authenticated, and no CRC implementation is on the I4 dependency
  allowlist. Every *framing* disagreement still fails closed. If a live run ever shows
  a corrupt frame that framing checks admit, that trade needs revisiting — and it is
  the one place a real Bedrock stream could prove this note wrong cheaply.
- Is `AWS_BEARER_TOKEN_BEDROCK` available in every deployment that would want this,
  or is Track A unavailable exactly where Bedrock is mandated?
- **Canonical path encoding is the unverified half of signing, and it is unverified in
  the worst way.** A signature mismatch upstream is a single opaque 403 that says
  nothing about which input was wrong, so a path-encoding bug is indistinguishable from
  a bad key, a clock skew, or a wrong region. The model id carries a colon, which a
  harness may send raw or as `%3A`; both are normalised to `%3A` and every other escape
  is refused. If the first live run 403s, this is the first thing to instrument, and the
  cheap instrument is to log the canonical request locally and diff it against
  `aws --debug`'s.
- **§4.1's audit-redaction requirement is not met for the signed path.** The redactor is
  built once at connector construction from a fixed list, and a refreshed session token
  is a value that did not exist then — so rotating credentials cannot be added to it
  without making the redaction set mutable, which is TCB and a lock on the audit writer's
  path. Nothing writes request headers into an audit record today, so the exposure is
  currently zero rather than merely small; that is a property of what the audit payloads
  happen to contain, not a guarantee. Anyone adding a header to an audit record needs to
  resolve this first.
- ~~Is the `credential_process` expiry format read correctly?~~ **It was not, and the
  first real output caught it.** The parser accepted an RFC 3339 `Z` suffix only, which
  is what the format's documentation shows; `aws configure export-credentials --format
  process` writes `+00:00`. An unreadable `Expiration` is an error, not a warning, so
  every signed run with `KEEL_AWS_CREDENTIAL_PROCESS` set would have been refused at the
  command line before a VM booted — fail-closed, loudly, and completely unusable. Offsets
  are now applied rather than refused, bounded at ±14:00. The transferable point is not
  the bug: it is that this was found by running the real command and reading its keys,
  and that every remaining item in this list has the same shape and has not had that
  treatment. A documentation-derived wire assumption is a hypothesis.
- Does a 401/403 from a model host still read as a generic upstream refusal? It should
  name credential expiry and invalidate the cached credentials so the next request
  refreshes. With `credential_process` configured the 120s margin makes this rare; with
  static session credentials it is the expected failure and still surfaces badly.
