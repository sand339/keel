#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
vendor_root="$repo_root/.phase0/vendor/vmette"
archive_name="vmette-v0.11.0-universal-apple-darwin.tar.gz"
bundle_name="vmette-v0.11.0-universal-apple-darwin"
archive="$vendor_root/$archive_name"
bundle="$vendor_root/$bundle_name"
expected="387930f89597deebc78c35f7334e9fd72b292674f1154ec18a3984ea9e2c58af"
url="https://github.com/chamuka-inc/vmette/releases/download/v0.11.0/$archive_name"

digest() {
    shasum -a 256 "$1" | awk '{print $1}'
}

mkdir -p "$vendor_root"
if [ ! -f "$archive" ] || [ "$(digest "$archive")" != "$expected" ]; then
    temporary="$archive.partial"
    rm -f "$temporary"
    curl --fail --location --show-error "$url" --output "$temporary"
    actual=$(digest "$temporary")
    if [ "$actual" != "$expected" ]; then
        rm -f "$temporary"
        echo "vmette checksum mismatch: expected $expected, got $actual" >&2
        exit 1
    fi
    mv "$temporary" "$archive"
fi

rm -rf "$bundle"
tar -xzf "$archive" -C "$vendor_root"
test -f "$bundle/assets/aarch64/vmlinuz-virt"
test -f "$bundle/assets/aarch64/initramfs-vmette"

printf '%s  %s\n' "$expected" "$archive"
