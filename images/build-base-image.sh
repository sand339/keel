#!/bin/sh
set -eu

usage() {
    echo "usage: $0 BASE_INITRAMFS BASE_SHA256 HARNESS.tar.gz HARNESS_SHA256 CA.pem CA_SHA256 OUTPUT.cpio.gz" >&2
    exit 2
}

[ "$#" -eq 7 ] || usage
absolute_file() {
    file_dir=$(CDPATH= cd -- "$(dirname -- "$1")" && pwd)
    printf '%s/%s\n' "$file_dir" "$(basename -- "$1")"
}

base_image=$(absolute_file "$1")
base_digest=$2
harness_archive=$(absolute_file "$3")
harness_digest=$4
ca_certificate=$(absolute_file "$5")
ca_digest=$6
case $7 in
    /*) output=$7 ;;
    *) output="$(pwd)/$7" ;;
esac

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
build_root=$(mktemp -d "${TMPDIR:-/tmp}/keel-image.XXXXXX")
trap 'chmod -R u+w "$build_root" 2>/dev/null || true; rm -rf "$build_root"' EXIT HUP INT TERM

digest() {
    shasum -a 256 "$1" | awk '{print $1}'
}

verify_digest() {
    actual=$(digest "$1")
    [ "$actual" = "$2" ] || {
        echo "digest mismatch for $1: expected $2, got $actual" >&2
        exit 1
    }
}

verify_digest "$base_image" "$base_digest"
verify_digest "$harness_archive" "$harness_digest"
verify_digest "$ca_certificate" "$ca_digest"
grep -q '^-----BEGIN CERTIFICATE-----$' "$ca_certificate" || {
    echo "CA input is not a PEM certificate" >&2
    exit 1
}

root="$build_root/root"
mkdir -p "$root"
(
    cd "$root"
    gzip -dc "$base_image" | cpio -idu 2>/dev/null
)

mkdir -p \
    "$root/etc/ssl/certs" \
    "$root/etc/keel" \
    "$root/opt/keel/harness" \
    "$root/usr/local/bin" \
    "$root/usr/local/libexec"
python3 "$repo_root/images/extract_bundle.py" \
    "$harness_archive" "$root/opt/keel/harness"
[ -x "$root/opt/keel/harness/bin/keel-harness" ] || {
    echo "harness archive must contain executable bin/keel-harness" >&2
    exit 1
}
[ -x "$root/opt/keel/harness/bin/git" ] || {
    echo "harness archive must contain executable bin/git" >&2
    exit 1
}

cp "$ca_certificate" "$root/etc/ssl/certs/keel-ca.pem"
if [ -f "$root/etc/ssl/certs/ca-certificates.crt" ]; then
    cat "$ca_certificate" >> "$root/etc/ssl/certs/ca-certificates.crt"
else
    cp "$ca_certificate" "$root/etc/ssl/certs/ca-certificates.crt"
fi
cp "$repo_root/images/guest/init" "$root/init"
cp "$repo_root/images/guest/keel-launch" "$root/usr/local/bin/keel-launch"
ln -sf /opt/keel/harness/bin/keel-harness "$root/usr/local/bin/keel-harness"

rust_sysroot=$(rustc --print sysroot)
host_triple=$(rustc -vV | sed -n 's/^host: //p')
linux_linker="$rust_sysroot/lib/rustlib/$host_triple/bin/gcc-ld/ld.lld"
compile_agent() {
    destination=$1
    shift
    clang \
        -target aarch64-unknown-linux-musl \
        -nostdlib \
        -static \
        "--ld-path=$linux_linker" \
        -fno-stack-protector \
        -ffreestanding \
        -Wall -Wextra -Werror \
        -Wl,-e,_start \
        -O2 \
        "$@" \
        "$repo_root/images/guest/keel-guest-net.c" \
        -o "$root/usr/local/libexec/$destination"
}

compile_agent keel-dns -DKEEL_DNS
compile_agent keel-egress-http -DKEEL_LOCAL_PORT=80 -DKEEL_VSOCK_PORT=5001
compile_agent keel-egress-https -DKEEL_LOCAL_PORT=443 -DKEEL_VSOCK_PORT=5001
compile_agent keel-git-http -DKEEL_LOCAL_PORT=9418 -DKEEL_VSOCK_PORT=5002
clang \
    -target aarch64-unknown-linux-musl \
    -nostdlib \
    -static \
    "--ld-path=$linux_linker" \
    -fno-stack-protector \
    -ffreestanding \
    -Wall -Wextra -Werror \
    -Wl,-e,_start \
    -O2 \
    -DKEEL_EXIT_AFTER_PROBE \
    "$repo_root/spikes/guest-probe.c" \
    -o "$root/usr/local/libexec/keel-boot-preflight"

cat > "$root/etc/keel/image-manifest" <<EOF
format=keel-base-v1
base_sha256=$base_digest
harness_sha256=$harness_digest
ca_sha256=$ca_digest
egress_vsock_port=5001
git_vsock_port=5002
EOF

chmod 0555 \
    "$root/init" \
    "$root/usr/local/bin/keel-launch" \
    "$root/usr/local/libexec/keel-boot-preflight" \
    "$root/usr/local/libexec/keel-dns" \
    "$root/usr/local/libexec/keel-egress-http" \
    "$root/usr/local/libexec/keel-egress-https" \
    "$root/usr/local/libexec/keel-git-http"
mkdir -p "$(dirname -- "$output")"
archive="$build_root/keel-base.cpio"
python3 "$repo_root/images/write_newc.py" "$root" > "$archive"
gzip -n < "$archive" > "$output"

echo "$(digest "$output")  $output"
