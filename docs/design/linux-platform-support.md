# Extending Keel to Linux

**Status: future platform work; not implemented.**

This document describes how to add a supported Linux host runtime while
preserving Keel's existing security boundary. It targets native KVM execution,
not Docker or a container runtime as the isolation boundary.

## Objective

Run the same Keel policy kernel, broker, audit, provenance, terminal, and guest
workload on Linux with security properties equivalent to the macOS
Virtualization.framework runtime.

The first supported configuration should be:

- Ubuntu 24.04 LTS;
- x86_64;
- KVM;
- Cloud Hypervisor;
- a pinned Linux kernel and initramfs;
- a pinned `virtiofsd`;
- interactive and noninteractive Claude Code sessions.

ARM64 Linux can follow once the x86_64 path is stable. Other distributions
should be accepted only after their kernel, KVM, cgroup, and packaging behavior
passes the same conformance suite.

## Existing portable components

The following components should require little or no Linux-specific redesign:

- `keel-kernel` authorization, budgets, grants, and session facts;
- Cedar policy evaluation and policy-bundle verification;
- provenance accounting and floor persistence;
- credential custody, TLS termination, SigV4, and Git credential scope;
- authenticated audit chains;
- the trusted terminal-input state machine;
- the untrusted terminal renderer and tab-aware session manager;
- guest MCP, egress, Git, and terminal protocols;
- the Linux guest init process and workload environment.

The main platform-specific implementation is currently concentrated in the VZ
launcher, setup checks, renderer confinement command, guest image architecture,
and runtime configuration names.

## Proposed host architecture

```text
keel CLI
   |
trusted keel-input + kernel broker
   |
untrusted Linux runtime supervisor
   |-- cloud-hypervisor
   |-- virtiofsd
   |-- vsock service relay
   `-- guest console/PTY relay
          |
       Linux guest
```

Cloud Hypervisor is the recommended first backend because it supports direct
kernel boot, virtio-vsock, virtio-fs, serial consoles, and an intentionally
small virtual device surface. Firecracker remains an alternative for later
noninteractive fleet workloads, but its block-device and API lifecycle model
requires more adaptation for an interactive local workspace.

Cloud Hypervisor and `virtiofsd` remain outside Keel's TCB. They provide
isolation mechanisms; Keel's trusted kernel still decides authority, holds
credentials, and records actions.

## Workstream 1: platform abstraction

Replace macOS-specific runtime assumptions with a small host-backend contract:

```text
prepare(run)
start(run, channels)
wait()
terminate(deadline)
inspect()
cleanup()
```

The contract should describe behavior instead of exposing VZ or KVM concepts to
the rest of the system. It needs:

- canonical kernel and initramfs paths;
- CPU and memory configuration;
- read-write workspace attachment;
- read-only control attachment;
- console transport;
- service transports for MCP, egress, Git, and terminal traffic;
- process and helper ownership;
- shutdown and cleanup results;
- host-side network-device inventory.

Rename `KEEL_VZ_BACKEND` and VZ-specific configuration fields to backend-neutral
names. Keep compatibility aliases for one release if existing installations
depend on them.

## Workstream 2: Cloud Hypervisor backend

Build an untrusted `keel-ch` launcher that:

- checks `/dev/kvm` availability and permissions;
- creates a unique VM identity and vsock CID;
- boots the admitted kernel and initramfs directly;
- assigns the configured vCPU and memory limits;
- attaches no network device;
- starts and supervises `virtiofsd`;
- attaches the selected workspace and control directory;
- exposes the guest console to Keel's existing PTY protocol;
- routes the existing guest service ports over vsock;
- reports backend state and process identifiers to the supervisor;
- terminates the VM and helpers within bounded deadlines.

The launcher should use Cloud Hypervisor's API socket rather than parsing
human-readable process output for lifecycle state.

## Workstream 3: vsock and relay extraction

The current VZ backend combines Apple VM configuration with service handlers.
Extract backend-independent relay code for:

- MCP calls;
- model and ordinary egress;
- mediated Git operations;
- guest terminal traffic;
- connection accounting and shutdown.

The Linux backend should adapt Cloud Hypervisor's host vsock socket to these
same byte-stream interfaces. No authorization logic moves into the adapter.
Every consequential request must still reach the trusted kernel broker.

## Workstream 4: workspace sharing

Run a pinned `virtiofsd` instance per VM. Configure it so the guest sees only:

- the selected canonical Git worktree;
- a read-only run control directory;
- no host home directory, SSH directory, cloud configuration, or credential
  cache.

The supervisor must own and terminate `virtiofsd`. Workspace containment,
symlink behavior, UID/GID mapping, file locking, executable bits, and Git
rename semantics require live tests.

For stronger fleet isolation, replace live host-directory sharing with an
ephemeral block or overlay image. Local interactive Linux support can begin
with virtio-fs because it matches the current VZ workspace model.

## Workstream 5: multi-architecture guest images

The current packaged guest is ARM64. Add reproducible builds for:

- `x86_64-unknown-linux-musl`;
- `aarch64-unknown-linux-musl`.

Each architecture needs pinned:

- Linux kernel;
- guest initramfs;
- Claude Code binary;
- guest MCP and relay helpers;
- shell, Git, CA bundle, tmux, curl, and required system tools.

Publish image manifests with architecture, component versions, and digests.
Run admission should bind the exact kernel and initramfs digests before boot.

## Workstream 6: Linux host confinement

`vm-v8` needs no separate Linux boundary: Node/V8 runs inside the same guest
image and KVM boundary as other VM harnesses. The lower-assurance
`v8-sandboxed` profile must not be enabled on Linux merely because Deno runs
there. Linux support requires a platform adapter using namespaces, seccomp, and
Landlock or bubblewrap, plus the same explicit
`isolation:v8-sandboxed` grant and conformance tests. Until that adapter exists,
Linux must reject the host V8 profile.

The macOS renderer currently uses `sandbox-exec` as defense in depth. On Linux:

- retain pipe-only renderer input and exclusive trusted ownership of the real
  terminal;
- prevent renderer access to `/dev/tty`;
- drop capabilities and set `no_new_privs`;
- apply a small seccomp profile;
- use Landlock or a mount namespace to restrict filesystem access;
- place each run in a dedicated cgroup;
- record every VM and helper process in the run resource registry.

Host confinement supplements the microVM and trusted input boundary. It must
not become a second policy engine.

## Workstream 7: setup, packaging, and diagnostics

Linux setup must:

- identify supported distribution and architecture;
- check KVM availability and group membership;
- install or download pinned Cloud Hypervisor and `virtiofsd` artifacts;
- verify artifact digests;
- install the correct guest image;
- configure backend-neutral runtime paths;
- check cgroup v2, vsock, seccomp, and Landlock availability;
- report unsupported optional defenses separately from required isolation;
- avoid requiring Docker during normal use.

Release artifacts should include an SBOM, checksums, signatures, and exact
supported host combinations.

## Network isolation

The Linux VM configuration must contain no virtual NIC. The guest must report:

- no default route;
- no external DNS resolver;
- no metadata reachability;
- no private-network reachability.

The host must independently confirm:

- no network device was configured;
- all guest egress arrived through the expected vsock relay;
- structural metadata and private-address denials still happen before policy;
- killing the broker makes egress fail closed.

Host firewall rules can provide additional defense, but successful isolation
must not depend on a mutable global firewall configuration.

## Lifecycle and teardown

Linux support should integrate the planned
[run admission and verified teardown](run-admission-and-verified-teardown.md)
work rather than creating another temporary lifecycle:

- bind backend and image digests before boot;
- record VM, Cloud Hypervisor API socket, vsock socket, `virtiofsd`, cgroup, and
  temporary directories;
- stop accepting actions before termination;
- terminate and verify every recorded process;
- remove sockets, mounts, cgroups, and transient files;
- emit a durable teardown receipt.

## Testing strategy

### Portable CI

Run on ordinary Linux CI:

- formatting, Clippy, and unit tests;
- trusted dependency and LOC invariants;
- request and admission schema tests;
- relay protocol tests;
- command construction and failure-path tests;
- guest-image reproducibility checks.

### KVM integration CI

Run on a dedicated KVM-capable worker:

- boot and shutdown;
- MCP round trip;
- interactive terminal and resize;
- detach and reattach;
- workspace read/write behavior;
- mediated Git push;
- approved and denied egress;
- no-network preflight;
- process, socket, mount, and cgroup teardown;
- backend crash and forced-kill recovery;
- repeated parallel sessions.

### Cross-platform conformance

The same scenario suite must run against macOS VZ and Linux Cloud Hypervisor.
Backend-specific code may differ; authorization decisions, audit records,
provenance behavior, guest-visible tools, and teardown outcomes must match.

## Milestones

1. **Compile:** all host crates build and unit tests pass on Ubuntu x86_64.
2. **Boot:** an x86_64 guest boots with no NIC and exits cleanly.
3. **Channels:** MCP, egress, Git, and terminal protocols pass over vsock.
4. **Workspace:** virtio-fs supports a real Git and Claude workflow.
5. **Security parity:** policy, credentials, provenance, audit, and approvals
   pass the shared conformance suite.
6. **Lifecycle:** detach, reattach, crash recovery, admission, and verified
   teardown pass.
7. **Release:** signed installer artifacts and Linux documentation are
   published.

## Acceptance criteria

- A supported Linux host can install and run Keel without Docker.
- The guest has no NIC, route, host DNS, metadata access, or direct private
  network path.
- The guest receives no real credentials.
- Every external action crosses the same trusted broker used on macOS.
- Workspace access is limited to the admitted worktree.
- Terminal approval remains exclusively owned by trusted input.
- Mac and Linux produce equivalent policy and audit outcomes for the shared
  scenario suite.
- `keel stop` verifies removal of all Linux backend resources.
- Kernel and initramfs digests are bound before VM creation.

## Expected effort

| Target | Estimated effort | Approximate new code |
|---|---:|---:|
| ARM64 Linux development prototype | 2–3 weeks | 1,500–2,500 lines |
| Ubuntu x86_64 feature parity | 4–6 weeks | 3,000–5,000 lines |
| Polished ARM64/x86_64 release | 6–9 weeks | 4,000–7,000 lines |

Most additions should remain outside the TCB. Any trusted Linux-specific code
must be justified against the enforced TCB cap rather than treated as an
automatic platform exception.

## Principal risks

- Cloud Hypervisor vsock behavior may not map cleanly to the current four-port
  VZ listener model.
- `virtiofsd` security and filesystem semantics may vary by distribution.
- Standard hosted CI generally cannot provide the KVM coverage required for a
  credible release.
- Supporting multiple distributions too early can hide backend bugs behind
  packaging differences.
- Duplicating VZ relay logic in a Linux binary would create two drifting
  enforcement-adjacent implementations; extraction should happen first.
