# Pinned artifacts

`keel setup` downloads and builds everything Keel runs. This page lists every
external artifact, where it comes from, how it is pinned, and how to update
it. Nothing here is redistributed in this repository: each user's setup
fetches it from the original source.

## Checksum-pinned downloads

Each script downloads into `.phase0/`, `.phase1/` (aarch64 guest),
`.phase1-x86_64/` (x86_64 guest), or, for the Linux runtime,
`target/downloads/`; refuses a file whose SHA-256 differs from the pinned
value; and reuses a verified file on later runs. `KEEL_GUEST_ARCH` selects the
guest architecture; it defaults to the build host's.

| Artifact | Version | Source | Pinned in |
|---|---|---|---|
| Guest Linux kernel (`linux-virt`) and its modules, aarch64 and x86_64 | 6.12.112-r0 | Alpine Linux v3.21 `main` (`dl-cdn.alpinelinux.org`) | `spikes/fetch-guest-kernel.sh` |
| Claude Code (Linux arm64 or x64 musl) | 2.1.287 | `downloads.claude.ai` | `spikes/build-phase1-image.sh` |
| `agent-browser` (musl arm64 or x64 binary from the npm package) | 0.38.2 | `registry.npmjs.org` | `spikes/build-phase1-image.sh` (package and binary checksums) |
| Deno (host: macOS arm64, Linux x86_64 and aarch64) | 2.9.7 | GitHub releases, `denoland/deno` | `spikes/fetch-deno.sh` |
| Cloud Hypervisor (Linux host, static x86_64 and aarch64 binaries) | v53.0 | GitHub releases, `cloud-hypervisor/cloud-hypervisor` | `spikes/build-linux-runtime.sh` |
| virtiofsd (Linux host, built from source) | 1.14.0 | crates.io, `cargo install --locked` (its lockfile, checksummed by crates.io) | `spikes/build-linux-runtime.sh` |
| `@xterm/headless` | 6.0.0 | `registry.npmjs.org` | `spikes/fetch-xterm-headless.sh` |
| `@xterm/addon-serialize` | 0.14.0 | `registry.npmjs.org` | `spikes/fetch-xterm-headless.sh` |
| vmette bundle (phase-0 smoke image only) | 0.11.0 | GitHub releases, `chamuka-inc/vmette` | `spikes/fetch-phase0.sh` |

## Digest-pinned build images

The guest image is assembled in Docker containers pinned by image digest.
Docker is a build tool here, not the runtime isolation boundary.

| Image | Pinned in |
|---|---|
| `alpine:3.23@sha256:85fe1e81…` | `spikes/build-phase1-image.sh` (`alpine_image`) |
| `rust:1.97-alpine3.23@sha256:c4a364dd…` | `spikes/build-phase1-image.sh` (`rust_image`) |

## Source dependencies

- **Rust crates** are pinned by `Cargo.lock` and built with `--locked`.
  `cargo deny check` (configured in `deny.toml`) checks advisories, bans,
  licenses, and sources.
- **The Rust toolchain** is pinned by `rust-toolchain.toml` (1.97.1).

## Locked guest packages

Every Alpine package the image build installs is pinned in
[`spikes/guest-packages.lock`](../spikes/guest-packages.lock) (aarch64) and
[`spikes/guest-packages-x86_64.lock`](../spikes/guest-packages-x86_64.lock)
(x86_64): repository, name, exact version, and SHA-256, dependencies included.
Each lock has two sets:

- `rootfs`: the guest root filesystem, from Alpine 3.23 `main` and `community`
  (Chromium, Node, Python, git, tmux, and the gcc, make, npm, pip, Rust, and Go
  toolchains);
- `tools`: what the build adds to the pinned base image to make the squashfs
  disk, the stage-1 busybox, and the zstd initramfs.

`spikes/build-phase1-image.sh` downloads each locked file into
`.phase1/apk-cache/` (`.phase1-x86_64/apk-cache/` for x86_64), refuses one
whose digest differs, and installs the files offline, so nothing is resolved against Alpine's live index. apk still checks
each package's Alpine signature. The build then fails unless the installed set
equals the `rootfs` set exactly.

**The guest image is reproducible.** Timestamps in the root disk and the
initramfs are fixed, the font caches are regenerated against fixed directory
times, and the initramfs is written in sorted order with fixed inode numbers.
Three builds of the same checkout on one machine produced byte-identical
`keel-phase1-rootfs.squashfs` and `keel-phase1-initramfs.cpio.zst`.
Limits:

- **The guest bridge.** `keel-mcp-guest` is compiled from this checkout in the
  pinned Rust image and reused while its sources are unchanged. Byte-identical
  output across different machines is expected but not yet verified.
- **Updates are deliberate.** Chromium and every other guest package stay at
  their locked versions until the lock is refreshed, so security fixes no
  longer arrive with each setup.
- **Alpine prunes old versions.** The CDN keeps only the current version in a
  branch. A cached file keeps working; a fresh checkout whose lock names a
  pruned version fails to download, and the fix is to refresh the lock.

Each build still records the SHA-256 of every root filesystem file in
`.phase1/rootfs.sha256` (or `.phase1-x86_64/rootfs.sha256`), and each run records the image digests in its
admission manifest (`kernel.run-admitted`).

To refresh a lock, run `spikes/lock-guest-packages.sh` (with
`KEEL_GUEST_ARCH=x86_64` for the x86_64 lock), review the diff of the lock
file (Chromium's version especially), then follow the steps below from step 3.

## Updating a pin

1. Change the version and the expected SHA-256 together in the script named
   above. Compute the digest from a download you have verified against the
   project's own release notes or signatures where it publishes them.
2. For the guest kernel, check the new kernel's configuration as described in
   `spikes/fetch-guest-kernel.sh` (Landlock first in `CONFIG_LSM`, seccomp, and
   the virtio-fs, vsock, block, squashfs, and overlay drivers).
3. Run `keel setup`, then `keel doctor`, then a VM smoke run (`keel run
   --isolation vm-v8 v8 docs/examples/v8-smoke.mjs`) and a Claude session.
4. Record the change in the [decision log](DECISIONS.md) when it changes a security property.

Alpine removes superseded packages from its CDN, so an old kernel pin
eventually fails to download with 404. That is the signal to update it.
