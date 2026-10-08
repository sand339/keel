#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
"$repo_root/spikes/fetch-xterm-headless.sh"
deno="$repo_root/.phase1/deno/host/deno"
output="$repo_root/target/release/keel-xterm-renderer"
temporary="$output.partial"
"$deno" compile --quiet --no-check \
    --output "$temporary" \
    "$repo_root/spikes/keel-xterm-renderer.ts"
codesign --force --sign - "$temporary"
mv "$temporary" "$output"
"$output" --version
"$deno" run --quiet --allow-run="$output" \
    "$repo_root/spikes/test-xterm-renderer.ts" "$output"
