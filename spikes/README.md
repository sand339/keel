# Phase 0 native isolation spikes

## Transparent egress

`keel-conn` classifies both raw TLS `ClientHello` traffic by SNI and proxy-mode
HTTP CONNECT traffic by authority. Its tests cover fragmented records,
malformed names, missing SNI, and port validation. `run-egress-compat.sh`
exercises curl, Git, npm, Cargo, and Claude Code with every proxy variable
removed. The trusted boundary terminates the client connection with a
host-bound certificate under an ephemeral Keel CA and opens a separately
authenticated `rustls` connection to the upstream fixture.

```sh
./spikes/run-egress-compat.sh
```

## Exclusive trusted terminal

`run-tty-proof.sh` builds and runs a pseudo-terminal proof on macOS. The C
harness creates a raw PTY, applies `TIOCEXCL`, and removes pathname access after
handing the open capability to the trusted runtime. The trusted, safe-Rust
`keel-input` process is the only slave-side owner. It launches `keel-render`
with pipes for all standard descriptors; the renderer verifies that none is a
TTY and that reopening the real TTY is denied.

The proof sends a representative ANSI TUI frame through the renderer, enters
trusted mode with the secure-attention byte, injects a guest frame during the
takeover, and completes a fresh challenge. It fails unless the TUI frame
renders, the trusted screen appears, the injected frame is absent, and the
challenge succeeds:

```sh
./spikes/run-tty-proof.sh
```

The first macOS run used the signed `vmette` 0.11.0 universal release as a
known-good Virtualization.framework probe. On Apple silicon with macOS 26.6.2,
it booted an Alpine 3.20 guest per run. A process inside the guest connected to
the host's dynamically assigned virtio-vsock port and exchanged the marker
`keel-vsock-probe`.

The checked-in `keel-libkrun-spike` source is the Keel-owned follow-up. It
configures one vCPU, 2 GiB of RAM, an external kernel, a 64 MiB virtiofs
shared-memory window for the root, and one guest-to-host vsock port. No network
device is configured. The guest starts `keel-mcp-guest`, which submits a typed
MCP report containing its default-route, DNS, metadata, and RFC1918
observations. The host rejects the run if any observation indicates network
reachability.

Docker Desktop's private libkrun 1.14 build aborts inside its non-unwinding C
ABI while constructing this VM, so it is retained only as failure evidence.
`keel-vz-spike` is the candidate backend. It uses Virtualization.framework
directly and hands the accepted virtio-vsock file descriptor to Keel's `rmcp`
server. Its initramfs contains only the freestanding static guest probe built
by `build-vz-initramfs.sh`.

Downloaded VM binaries, images, and root filesystems remain under the ignored
`.phase0/` directory.

Fetch and verify the pinned vmette 0.11.0 bundle with:

```sh
./spikes/fetch-phase0.sh
```

## Phase 1 guest image

`build-phase1-image.sh` assembles the development guest under the ignored
`.phase1/` directory. It verifies a pinned Claude Code ARM64 musl binary,
cross-builds the static `keel-mcp-guest` bridge, installs a pinned Alpine 3.20
root filesystem, and imports the kernel-matched virtiofs and vsock modules from
the pinned vmette initramfs.

```sh
./spikes/build-phase1-image.sh
./spikes/build-vz-runtime.sh
```

The image has no network device. At boot it reports the in-guest network
preflight over vsock, mounts the workspace and read-only control shares, and
starts localhost-to-vsock relays for smart HTTP Git, mediated egress, and the
Claude MCP server. The harness runs in a real guest PTY managed by a transparent
tmux session, while a dedicated vsock stream carries only terminal input and
output. Kernel console output remains on a separate diagnostic stream. The
control share chooses the harness through `keel-launch.sh`. PID 1 powers the VM
down when the workload exits. Host-side persistent sessions keep the trusted
runtime and VM in a native PTY supervisor and expose a mode-0600 Unix attachment
socket; they do not place model credentials in an external terminal
multiplexer.

A minimal boot check can use an executable `launch` file in a control
directory:

```sh
target/release/keel-vz-spike \
  .phase0/vendor/vmette/vmette-v0.11.0-universal-apple-darwin/assets/aarch64/vmlinuz-virt \
  .phase1/keel-phase1-initramfs.cpio.zst \
  "$PWD" \
  "$PWD/.phase1/smoke-control"
```

For live Claude requests, set `ANTHROPIC_API_KEY` in the host environment.
`keel-input` takes custody of it before launching untrusted code, and the guest
receives only a sentinel scoped to `POST /v1/messages`. Pull requests use
`GH_TOKEN`, `GITHUB_TOKEN`, or the active `gh auth` keyring entry; the
broker-backed GitHub client likewise sends only a sentinel, scoped to
`POST /repos/*`. The workspace needs its real HTTPS `origin` before launch.
