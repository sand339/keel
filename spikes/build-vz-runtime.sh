#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_root"

cargo build --release \
    -p keel-cli \
    -p keel-input \
    -p keel-render \
    -p keel-isolate --features vz-backend \
    --bin keel \
    --bin keel-input-runtime \
    --bin keel-render-spike \
    --bin keel-runtime \
    --bin keel-vz-spike

codesign --force --sign - \
    --entitlements "$repo_root/spikes/macos-hypervisor.entitlements" \
    "$repo_root/target/release/keel-vz-spike"

echo "built the optimized Keel PTY runtime and signed target/release/keel-vz-spike"
