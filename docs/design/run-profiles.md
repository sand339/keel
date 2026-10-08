# Run profiles

**Status: proposed.** `--profile triage` (D58) is the only profile today, and
it is hardcoded in the CLI and in trusted admission. This note describes how
profiles generalize.

## 1. Decision

A **profile** is a named, declarative bundle that shapes a run for one
workflow. It has two halves:

- **Authority:** what the run may do.
  - Parsed by trusted admission, shown on the admission screen, and recorded
    in the admission manifest.
  - Every authority field maps onto a trusted building block shared by all
    profiles.
- **Workflow:** how the run is equipped.
  - Guest tools, MCP servers, a skill or system prompt, and the output layout.
  - Untrusted packaging that the kernel never reads.

**A profile adds no trusted code.** It can only select, combine, and narrow
trusted building blocks. A new workflow is a new file, not a new review of the
TCB.

## 2. Problem and context

Keel's runs are configured flag by flag: `--allow`, `--scope`, `--auth`,
`--model-cost-budget`, `--policy`. That works for ad hoc coding tasks. It
stops working once a workflow needs a consistent set of constraints every
time:

- **Forgotten constraints.** An operator who forgets one flag gets a run with
  more authority than the workflow intends, and nothing says so.
- **Unattributable results.** Shadow reports and evidence can only be compared
  across runs if the runs were configured the same way, and the manifest can
  only say so if the configuration has a name and a digest.
- **Hardcoded workflow logic.** The triage profile proves that a workflow
  needs more than authority flags, such as guest tooling and output locations.
  That logic is currently hardcoded.

## 3. Principles

1. **Authority is trusted, workflow is not.** Only the authority half crosses
   into trusted admission. The workflow half shapes the guest, which is
   untrusted anyway.
2. **Profiles narrow.** A profile can require admission, restrict scope,
   providers, and capabilities, and lower ceilings. Raising a ceiling above
   the defaults still needs the same trusted admission as a flag would.
3. **Flags only narrow a profile.** Command-line flags may add restrictions to
   a profile, never remove one. A profile that requires a scope still requires
   it.
4. **Every profile is admitted and recorded.** The admission screen shows the
   profile name, its file digest, and every authority field. The manifest
   records the same, so a run's evidence names exactly what it ran under.
5. **No profile-specific trusted code.** If a workflow needs a capability that
   no building block provides, the building block is added once, generically,
   as a recorded PLAN decision. The profile then uses it.

## 4. Structure

A profile is a YAML file. Natural-language parts, such as a skill, live in
the workflow half.

```yaml
name: triage
version: 1
authority:
  admission: required        # always shown on the trusted terminal
  scope: required            # the analyst declares it with --scope or --scope-file
  providers: [anthropic, bedrock]
  capabilities: []           # e.g. push:branch, pr:create; none by default
  budget:
    usd: 20
workflow:
  tools: [browser]
  outputs: [.keel-browser/]
  skill: |
    Reproduce the reported issue against the declared scope only.
    Save screenshots and a HAR file for each step.
```

**Authority fields** map onto trusted building blocks (§5). Unknown authority
fields are refused rather than ignored, so a typo cannot silently drop a
restriction.

**Workflow fields** are passed to the untrusted runtime:
- `tools` selects guest components already in the image;
- `outputs` documents where artifacts land;
- `skill` is written into the guest for the harness to load.

The kernel never sees them.

### Loading

- **Built-in profiles** ship with Keel and are installed by setup.
- **Operator profiles** live in `~/.keel/profiles/NAME.yaml`.
- `--profile NAME` resolves an operator profile first, then a built-in one.
- The untrusted CLI reads the file and passes it to the trusted runtime.
  Trusted admission parses only `authority`, refuses unknown fields, and
  hashes the whole file into the manifest.

The profile file is operator input, like `--scope`. The admission screen is
the check, as it already is for scope rules and an OpenRouter price snapshot.

## 5. Trusted building blocks

| Building block | Status | Authority field |
|---|---|---|
| Mandatory trusted admission | Built | `admission` |
| Declared scope, refused without a prompt outside it | Built (D58) | `scope` |
| Approved model providers | Built (D58) | `providers` |
| Capabilities and egress hosts | Built | `capabilities` |
| Model budget ceilings | Built | `budget` |
| Admission manifest | Built (D57) | (records all of the above) |
| Per-host request and byte limits | Planned (triage note §4.1) | `limits` |
| Test-credential bindings | Planned (triage note §4.1) | `credentials` |
| Enforced payload flow for admitted content | Planned (triage note §4.1) | `payload_flow` |

The planned blocks are generic: once built, any profile may use them.

## 6. Worked example: triage

The triage profile as built (D58, D60) maps onto the structure above.

| Today | As a profile |
|---|---|
| `--profile triage` hardcoded in the CLI and `keel-input` | `triage.yaml`, a built-in profile |
| Scope required, admission forced | `authority.scope: required`, `authority.admission: required` |
| `KEEL_TRIAGE_PROVIDERS`, default `anthropic,bedrock` | `authority.providers` |
| Browser and `.keel-browser/` output | `workflow.tools`, `workflow.outputs` |

Behavior does not change. The difference is that the constraints are data,
and the next workflow needs no code.

## 7. Migration

1. **Generalize admission.** Trusted admission accepts a profile's
   `authority` section instead of the hardcoded `triage` name. `triage`
   becomes the first built-in profile file. `KEEL_TRIAGE_PROVIDERS` becomes
   the file's `providers`, and an operator can override it with a stricter
   profile.
2. **Pass workflow packaging.** The untrusted runtime passes `workflow` to
   the guest: it writes the skill and enables only the named tools.
3. **Record the profile.** The manifest records the profile name, file
   digest, and parsed authority. `keel status` and the reports show the
   profile name.

This should land when a second real profile exists, so the schema is shaped
by two workflows rather than guessed from one.

## 8. Budget

Generalizing admission replaces the hardcoded triage parsing. The estimate is
about 60 trusted lines net:

- profile file parsing and digest, offset by removing triage-specific code;
- the unknown-field refusal.

Workflow packaging is untrusted. Each new building block in §5 is costed in
its own decision.

## 9. Open questions

1. Should built-in profiles be signed or pinned by digest in setup, so an
   edited built-in profile is noticed at admission?
2. Should profiles compose, with one profile extending another, or stay flat
   for readability? Flat is simpler to admit and review.
3. Should a workspace be able to suggest a profile, for example through a
   `.keel/profile` file, given that the workspace is untrusted? Suggesting is
   harmless only if admission always shows the result.
4. Do some workflows need profile-specific guest images or extra tool disks?
   The root filesystem is a read-only disk (D61), so a second read-only disk
   per profile is cheap. If so, the image choice belongs in `workflow`, and
   its digest in the manifest.
