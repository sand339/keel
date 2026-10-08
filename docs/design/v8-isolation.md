# V8 isolation modes

Keel supports two V8 execution modes in addition to its existing agent VM:

| Mode | Command | Boundary | Assurance |
|---|---|---|---|
| `vm-v8` | `keel run --isolation vm-v8 v8 SCRIPT` | Node/V8 inside the existing microVM | Strong; recommended |
| `v8-sandboxed` | `keel run --isolation v8-sandboxed --allow isolation:v8-sandboxed v8 SCRIPT` | Deno permissions on the host | Lower; explicit opt-in |

Plain `vm` remains the default for Claude and other full harnesses. Keel never
changes modes after a failure. A failed VM boot therefore cannot become a host
V8 run.

## Terminal launcher

Bare `keel mux` presents all three runtime profiles before workspace selection:

```text
Claude Code — microVM
V8 script — microVM
V8 script — host sandbox [lower assurance]
```

A V8 selection requires an existing Git worktree and then asks for a relative
`.js`, `.mjs`, or `.cjs` entry file. The display-only renderer bounds the input
for usability. The CLI independently canonicalizes the path, requires a real
file inside the selected worktree, and reconstructs the exact `v8` harness and
isolation mode. Active V8 mux tabs carry `V8/VM` or `V8/host` in their label.

The launcher does not grant authority. Selecting the host profile still
requires `--allow isolation:v8-sandboxed` or an accepted policy containing that
capability. The trusted input process performs the same admission check used
for a direct command.

## Why there are two modes

V8 startup is much faster than booting a complete agent environment. It is
useful for small evaluators, deterministic transformations, policy fixtures,
and JavaScript agent loops that need a narrow API. It does not provide the same
containment as a VM when it runs directly on the host.

`vm-v8` keeps the main Keel claim: assume the JavaScript engine and workload are
fully compromised, then contain them below the language runtime. Node's
permission model removes unnecessary file and process access, while the VM is
the load-bearing boundary.

`v8-sandboxed` makes a different claim. Deno's V8 isolate and permission model
are a semi-trusted core. An engine escape may become host code execution. This
mode is useful only when the operator accepts that trade for startup speed.

## Admission and downgrade prevention

The serialized run request includes one of `vm`, `vm-v8`, or `v8-sandboxed`.
Both the untrusted CLI and trusted input process validate it:

- `vm-v8` and `v8-sandboxed` accept only the `v8` harness;
- a `v8` harness cannot run under plain `vm`;
- `v8-sandboxed` requires the exact
  `isolation:v8-sandboxed` capability;
- unknown values fail closed; and
- no backend fallback exists.

The grant can be supplied directly or by an accepted policy:

```text
For this session, allow the v8-sandboxed isolation mode.
```

The policy compiler normalizes that sentence to the closed capability
`isolation:v8-sandboxed`. The accepted artifact and run request bind the grant,
and the trusted runtime rechecks it before starting the untrusted backend.
Because capabilities appear in the enforcement-state audit record, the weaker
mode is visible during later review.

## `vm-v8` implementation

The guest image installs Alpine's ARM64 Node 20 package. Node embeds V8 and runs
the selected workspace script with:

- `--permission` (Node 24 removed the `--experimental-permission` spelling);
- read access to the workspace, public run CA, and preloaded Keel SDK;
- write access only to the workspace; and
- no child-process, worker, native-addon, or host filesystem permission.

The launch script verifies `KEEL_ISOLATION=vm-v8` before invoking Node. The SDK
is preloaded as `globalThis.Keel`, so a script can use it without loading a
package:

```js
console.log(process.versions.v8);
const response = await Keel.fetch("https://docs.rs/");
console.log(response.status);
```

The guest still has no network device, route, DNS resolver, or real credential.
`Keel.fetch` connects only to the guest's loopback proxy. The request then
follows the normal path:

```text
JavaScript
  -> guest loopback proxy
  -> VSOCK
  -> untrusted connection classifier
  -> trusted kernel policy and gate
  -> trusted TLS and credential injector
  -> upstream
```

Node is not part of the trusted Rust budget. Its compromise is already assumed
by the microVM threat model.

## `v8-sandboxed` implementation

Setup downloads Deno 2.9.7 for Apple silicon and verifies the release archive
against its pinned SHA-256 digest. The host runtime then:

1. canonicalizes the entry script and requires it to be inside the Git
   workspace;
2. creates a mode-0700 temporary control directory;
3. writes only the public run CA, import map, wrapper, and Deno cache there;
4. starts a loopback-only HTTP proxy;
5. clears the inherited environment;
6. passes a narrow set of non-secret model placeholders and proxy variables;
7. runs Deno with no prompt, no project configuration, cached-only module
   resolution, workspace-only file permissions, and network access only to that
   loopback proxy; and
8. waits for proxy workers and removes the control directory when the script
   exits.

The wrapper installs the same `globalThis.Keel` surface as the VM mode. The
host SDK uses `Deno.createHttpClient` with Keel's public run CA and loopback
proxy. JavaScript cannot open a direct public socket through Deno permissions.
The proxy presents the destination to the same trusted broker protocol used by
the VM relay. A missing broker returns HTTP 403.

The runtime does not pass API keys, AWS keys, GitHub tokens, or Git
authorization values to Deno. The trusted process removes them before starting
the runtime, and the host launcher additionally starts Deno with an empty
environment.

## Common SDK

Both modes expose:

```js
Keel.fetch(input, init)
Keel.modelHeaders(headers?)
```

`Keel.fetch` supports HTTP and HTTPS through the broker. `modelHeaders` returns
the non-secret placeholder expected by the trusted model proxy. The proxy
replaces or signs it only for the admitted model endpoint. Scripts may also use
ordinary local JavaScript APIs within the permissions listed above.

The SDK is convenience code outside the TCB. It cannot grant a destination:
the trusted broker resolves the host, checks structural network denials,
evaluates policy and provenance, performs any approval, injects credentials,
and audits the action.

## Security boundaries

### What both modes preserve

- the trusted input path and `Ctrl-]` approval;
- exact-host egress intent and structural private-network denials;
- trusted DNS resolution and TLS termination;
- sentinel credentials and trusted injection;
- policy, provenance, budgets, and audit;
- a canonical Git worktree requirement; and
- explicit, serialized mode selection.

### What `v8-sandboxed` weakens

- a V8 or Deno sandbox escape can reach the host process;
- the host kernel, rather than a VM boundary, must contain the resulting
  process;
- denial of service against the local runtime is easier; and
- Deno joins the semi-trusted review surface even though it is outside the
  first-party Rust TCB count.

This is why the host mode requires an explicit grant and is never the default.
Do not use it for hostile native dependencies, shell-heavy coding agents, or
workloads whose evaluation assumes VM containment.

## Reproducibility and supply chain

The host Deno archive URL, version, and SHA-256 are in
`spikes/fetch-deno.sh`. The VM's Node build comes from the pinned Alpine image
and repository used by `spikes/build-phase1-image.sh`; the complete resulting
root filesystem and initramfs are hashed after assembly. Neither mode downloads
JavaScript modules at run time: Deno uses `--cached-only`, and Node receives no
package installation path.

## Tests

The implementation is covered at four levels:

1. CLI tests verify defaults, accepted mode/harness pairs, and the explicit
   host-mode grant.
2. Trusted admission tests parse raw JSON and reject forged or downgraded
   requests independently of the CLI.
3. Runtime tests verify a missing broker fails closed, Deno receives bounded
   permissions, and unrelated host environment values do not cross.
4. Launcher tests verify profile navigation, bounded entry paths, nested result
   framing, and independent CLI path and capability validation.
5. Image and live smoke tests run the pinned engine in each backend, verify
   workspace writes, and exercise a denied host-file read.

The broader workspace suite and `ci/check_invariants.py` still apply. The only
new trusted code is bounded request validation in `keel-input`; engine,
launcher, SDK, proxy, image, and policy-compiler changes remain outside the
trusted crate set.

## Choosing a mode

Use `vm-v8` for untrusted inputs, third-party code, security evaluation, and
anything that may later gain more tools. Use `v8-sandboxed` for small,
source-controlled scripts when measured VM startup dominates the work and the
lower assurance is acceptable. Use plain `vm` for full terminal agents such as
Claude Code.
