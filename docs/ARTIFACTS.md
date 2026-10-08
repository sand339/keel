# Pinned artifacts

`keel setup` downloads and builds everything Keel runs. This page lists every
external artifact, where it comes from, how it is pinned, and how to update
it. Nothing here is redistributed in this repository: each user's setup
fetches it from the original source.

## Checksum-pinned downloads

Each script downloads into `.phase0/` or `.phase1/`, refuses a file whose
SHA-256 differs from the pinned value, and reuses a verified file on later
runs.

| Artifact | Version | Source | Pinned in |
|---|---|---|---|
| Guest Linux kernel (`linux-virt`) and its modules | 6.12.111-r0 | Alpine Linux v3.21 `main` (`dl-cdn.alpinelinux.org`) | `spikes/fetch-guest-kernel.sh` |
| Claude Code (Linux arm64 musl) | 2.1.287 | `downloads.claude.ai` | `spikes/build-phase1-image.sh` |
| `agent-browser` (musl arm64 binary from the npm package) | 0.38.2 | `registry.npmjs.org` | `spikes/build-phase1-image.sh` (package and binary checksums) |
| Deno (host, Apple silicon) | 2.9.7 | GitHub releases, `denoland/deno` | `spikes/fetch-deno.sh` |
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

## Not pinned: guest packages

The guest root filesystem is built with `apk add` from Alpine 3.23 `main` and
`community`. The pinned base image fixes the starting point, but the packages
themselves are not pinned, so their versions follow Alpine's repository on the
day setup runs:
- Chromium, Node, Python, git, tmux;
- the build toolchains: gcc, make, npm, pip, Rust, and Go.

**The guest image is therefore not reproducible.** Each build records the
SHA-256 of every file in the root filesystem in `.phase1/rootfs.sha256`. Each
run records the digests of the kernel, initramfs, root disk, and components in
its admission manifest (`kernel.run-admitted`), so a run always says which
image it used, even though a later build may differ.

Pinning the package set, for example with a lockfile of exact apk versions or
a snapshot repository, is future work.

## Updating a pin

1. Change the version and the expected SHA-256 together in the script named
   above. Compute the digest from a download you have verified against the
   project's own release notes or signatures where it publishes them.
2. For the guest kernel, check the new kernel's configuration as described in
   `spikes/fetch-guest-kernel.sh` (Landlock first in `CONFIG_LSM`, seccomp, and
   the virtio-fs, vsock, block, squashfs, and overlay drivers).
3. Run `keel setup`, then `keel doctor`, then a VM smoke run (`keel run
   --isolation vm-v8 v8 docs/examples/v8-smoke.mjs`) and a Claude session.
4. Record the change in [PLAN](PLAN.md) when it changes a security property.

Alpine removes superseded packages from its CDN, so an old kernel pin
eventually fails to download with 404. That is the signal to update it.
