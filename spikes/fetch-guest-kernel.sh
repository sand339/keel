#!/bin/sh
# Fetches the pinned Alpine linux-virt guest kernel and its modules.
#
# Alpine ships the aarch64 kernel as an EFI zboot image: a PE wrapper around a
# gzip-compressed ARM64 Image. Virtualization.framework's Linux boot loader
# takes the raw Image, so the payload is extracted here. The modules are
# copied into the guest image by build-phase1-image.sh.
#
# Alpine removes superseded package versions from its CDN. When this download
# fails with 404, bump the version and digest together after checking the new
# kernel's configuration (Landlock first in CONFIG_LSM, seccomp filters,
# virtio-fs and vsock modules) and booting it.
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
version="6.12.111-r0"
release="6.12.111-0-virt"
expected="6ecce0b88acb8ea77513dc9eae8eeb1aee6707deec3cb99bcb26e8a7ab1408ca"
url="https://dl-cdn.alpinelinux.org/alpine/v3.21/main/aarch64/linux-virt-$version.apk"
kernel_root="$repo_root/.phase1/kernel"
package="$kernel_root/linux-virt-$version.apk"

digest() {
    shasum -a 256 "$1" | awk '{print $1}'
}

mkdir -p "$kernel_root"
if [ ! -f "$package" ] || [ "$(digest "$package")" != "$expected" ]; then
    temporary="$package.partial"
    rm -f "$temporary"
    curl --fail --location --show-error "$url" --output "$temporary"
    actual=$(digest "$temporary")
    if [ "$actual" != "$expected" ]; then
        rm -f "$temporary"
        echo "guest kernel checksum mismatch: expected $expected, got $actual" >&2
        exit 1
    fi
    mv "$temporary" "$package"
fi

unpacked="$kernel_root/package"
rm -rf "$unpacked"
mkdir -p "$unpacked"
tar -xzf "$package" -C "$unpacked" boot/vmlinuz-virt "lib/modules/$release" 2>/dev/null ||
    tar -xzf "$package" -C "$unpacked"
test -f "$unpacked/boot/vmlinuz-virt"
test -d "$unpacked/lib/modules/$release"

python3 - "$unpacked/boot/vmlinuz-virt" "$kernel_root/Image" <<'PY'
import struct
import sys
import zlib

source, target = sys.argv[1:]
data = open(source, "rb").read()
if data[4:8] != b"zimg" or data[24:28] != b"gzip":
    sys.exit("guest kernel is not a gzip EFI zboot image")
offset, size = struct.unpack_from("<II", data, 8)
image = zlib.decompressobj(31).decompress(data[offset:offset + size])
if image[56:60] != b"ARMd":
    sys.exit("extracted guest kernel is not an ARM64 Image")
open(target, "wb").write(image)
PY

rm -rf "$kernel_root/modules"
mkdir -p "$kernel_root/modules"
cp -R "$unpacked/lib/modules/$release" "$kernel_root/modules/"
printf '%s\n' "$release" > "$kernel_root/release"
printf '%s  %s\n' "$expected" "$package"
