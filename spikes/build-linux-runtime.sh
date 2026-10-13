#!/bin/sh
# Builds Keel's Linux runtime: the host binaries with the Cloud Hypervisor
# backend, the pinned Cloud Hypervisor release, and virtiofsd from its pinned
# crates.io release. Everything lands in target/release, where `keel setup`
# installs it from.
#
# Cloud Hypervisor publishes static binaries for both architectures; their
# digests are pinned here. virtiofsd publishes source only, so it is built
# with its own lockfile, which crates.io checksums pin.
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cloud_hypervisor_version="v53.0"
virtiofsd_version="1.14.0"
case "$(uname -m)" in
x86_64)
    cloud_hypervisor_asset="cloud-hypervisor-static"
    cloud_hypervisor_sha256="448af3d4e59b22c2987f7df94c213ad40fb53a10d437e42b5ee6c4fce7c29ecc"
    ;;
aarch64)
    cloud_hypervisor_asset="cloud-hypervisor-static-aarch64"
    cloud_hypervisor_sha256="f192b510eea1c710cbc439d716bb0573c223fc463dbe3e6523788a2b7ef62850"
    ;;
*)
    echo "unsupported Linux architecture: $(uname -m)" >&2
    exit 1
    ;;
esac
release="$repo_root/target/release"
downloads="$repo_root/target/downloads"
mkdir -p "$release" "$downloads"
cd "$repo_root"

cargo build --release --locked \
    -p keel-cli \
    -p keel-input \
    -p keel-render \
    -p keel-isolate --features keel-isolate/ch-backend \
    --bin keel \
    --bin keel-input-runtime \
    --bin keel-render-spike \
    --bin keel-runtime \
    --bin keel-extract \
    --bin keel-ch

download="$downloads/$cloud_hypervisor_asset-$cloud_hypervisor_version"
if [ ! -f "$download" ] ||
    [ "$(sha256sum "$download" | cut -d ' ' -f 1)" != "$cloud_hypervisor_sha256" ]; then
    curl -fL --retry 3 \
        "https://github.com/cloud-hypervisor/cloud-hypervisor/releases/download/$cloud_hypervisor_version/$cloud_hypervisor_asset" \
        -o "$download.partial"
    actual=$(sha256sum "$download.partial" | cut -d ' ' -f 1)
    if [ "$actual" != "$cloud_hypervisor_sha256" ]; then
        rm -f "$download.partial"
        echo "Cloud Hypervisor checksum mismatch: expected $cloud_hypervisor_sha256, got $actual" >&2
        exit 1
    fi
    mv "$download.partial" "$download"
fi
install -m 0755 "$download" "$release/cloud-hypervisor"

cargo install --locked --quiet "virtiofsd@$virtiofsd_version" \
    --root "$repo_root/target/virtiofsd"
install -m 0755 "$repo_root/target/virtiofsd/bin/virtiofsd" "$release/virtiofsd"

"$release/cloud-hypervisor" --version
"$release/virtiofsd" --version
echo "built the Keel Linux runtime in target/release"
