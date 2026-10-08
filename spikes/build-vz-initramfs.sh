#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
suffix=""
compiler_define=""
if [ "${1:-}" = "--broken-preflight" ]; then
    suffix="-broken"
    compiler_define="-DKEEL_FORCE_BROKEN_PREFLIGHT"
elif [ "$#" -ne 0 ]; then
    echo "usage: $0 [--broken-preflight]" >&2
    exit 2
fi
artifact_dir="$repo_root/.phase0/vz-initramfs$suffix"
guest_binary="$repo_root/.phase0/bin/keel-mcp-guest$suffix"
initramfs="$repo_root/.phase0/keel-initramfs$suffix.cpio.gz"
base_initramfs="$repo_root/.phase0/vendor/vmette/vmette-v0.11.0-universal-apple-darwin/assets/aarch64/initramfs-vmette"
rust_sysroot=$(rustc --print sysroot)
host_triple=$(rustc -vV | sed -n 's/^host: //p')
linux_linker="$rust_sysroot/lib/rustlib/$host_triple/bin/gcc-ld/ld.lld"

mkdir -p "$repo_root/.phase0/bin" "$artifact_dir"
clang \
    -target aarch64-unknown-linux-musl \
    -nostdlib \
    -static \
    "-fuse-ld=$linux_linker" \
    -fno-stack-protector \
    -ffreestanding \
    -Wl,-e,_start \
    -O2 \
    $compiler_define \
    "$repo_root/spikes/guest-probe.c" \
    -o "$guest_binary"
(
    cd "$artifact_dir"
    gzip -dc "$base_initramfs" | cpio -idu 2>/dev/null
)
cp "$repo_root/spikes/vz-init.sh" "$artifact_dir/init"
cp "$guest_binary" "$artifact_dir/keel-mcp-guest"
chmod 0755 "$artifact_dir/init" "$artifact_dir/keel-mcp-guest"

(
    cd "$artifact_dir"
    find . -print | cpio -o -H newc 2>/dev/null
) | gzip -n > "$initramfs"

file "$guest_binary" "$initramfs"
