#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_root"

# Offline and locked: the proof builds from dependencies earlier steps already
# fetched into the normal Cargo home, never from a fresh resolution.
cargo build --offline --locked \
    -p keel-input --bin keel-tty-spike \
    -p keel-render --bin keel-render-spike

mkdir -p .phase0
cc -std=c17 -Wall -Wextra -Werror \
    spikes/tty-proof.c -o .phase0/tty-proof

.phase0/tty-proof \
    "$repo_root/target/debug/keel-tty-spike" \
    "$repo_root/target/debug/keel-render-spike"
