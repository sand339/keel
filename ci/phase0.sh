#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_root"

cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
if [ "$(uname -s)" = "Darwin" ]; then
    cargo clippy -p keel-isolate --all-targets \
        --features libkrun-backend,vz-backend -- -D warnings
    ./spikes/run-tty-proof.sh
fi
cargo test --workspace --all-targets
cargo test --workspace --doc
python3 ci/check_invariants.py

if command -v cargo-deny >/dev/null 2>&1; then
    cargo deny check
elif [ "${CI_REQUIRE_CARGO_DENY:-0}" = "1" ]; then
    echo "error: cargo-deny is required in CI" >&2
    exit 1
else
    echo "warning: cargo-deny not installed; dependency policy check skipped" >&2
fi
