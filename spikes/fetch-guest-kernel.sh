#!/bin/sh
# Fetches the pinned Alpine linux-virt guest kernel and its modules.
#
# Alpine ships the aarch64 kernel as an EFI zboot image: a PE wrapper around a
# gzip-compressed ARM64 Image. Virtualization.framework's Linux boot loader
# takes the raw Image, so the payload is extracted here. The x86_64 kernel is
# a bzImage, which Cloud Hypervisor boots directly. Either is saved as
# `Image`. The modules are copied into the guest image by
# build-phase1-image.sh. KEEL_GUEST_ARCH selects the architecture, as there.
#
# Alpine removes superseded package versions from its CDN. When this download
# fails with 404, bump the version and digest together after checking the new
# kernel's configuration (Landlock first in CONFIG_LSM, seccomp filters,
# virtio-fs and vsock modules) and booting it.
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
# SHA-256 with sha256sum where it exists (Linux), and shasum on macOS.
sha256() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$@"; else shasum -a 256 "$@"; fi
}
version="6.12.112-r0"
release="6.12.112-0-virt"
case "${KEEL_GUEST_ARCH:-$(uname -m)}" in
arm64 | aarch64)
    guest_arch=aarch64
    expected="45f06ab578a351afbb07cb6aca31d8a258f1514e42ae377a9ec13f76078f3fa8"
    kernel_root="$repo_root/.phase1/kernel"
    ;;
x86_64 | amd64)
    guest_arch=x86_64
    expected="6ef528f560ab6eca01c39729edc636ad47478cb583323b31a376832d7fa70c11"
    kernel_root="$repo_root/.phase1-x86_64/kernel"
    ;;
*)
    echo "unsupported guest architecture: ${KEEL_GUEST_ARCH:-$(uname -m)}" >&2
    exit 1
    ;;
esac
url="https://dl-cdn.alpinelinux.org/alpine/v3.21/main/$guest_arch/linux-virt-$version.apk"
package="$kernel_root/linux-virt-$version.apk"

digest() {
    sha256 "$1" | awk '{print $1}'
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

python3 - "$guest_arch" "$unpacked/boot/vmlinuz-virt" "$kernel_root/Image" <<'PY'
import struct
import sys
import zlib

arch, source, target = sys.argv[1:]
data = open(source, "rb").read()
if arch == "x86_64":
    # The Linux boot protocol's magic, at a fixed offset in every bzImage.
    if data[0x202:0x206] != b"HdrS":
        sys.exit("guest kernel is not an x86 bzImage")
    open(target, "wb").write(data)
    sys.exit(0)
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
