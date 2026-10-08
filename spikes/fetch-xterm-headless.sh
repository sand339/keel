#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
downloads="$repo_root/.phase1/downloads"
destination="$repo_root/.phase1/xterm"
mkdir -p "$downloads" "$destination"

fetch_module() {
    archive_name=$1
    url=$2
    sha256=$3
    member=$4
    output=$5
    archive="$downloads/$archive_name"
    if [ ! -f "$archive" ] ||
        [ "$(shasum -a 256 "$archive" | awk '{print $1}')" != "$sha256" ]; then
        temporary="$archive.partial"
        curl -fL --retry 3 "$url" -o "$temporary"
        actual=$(shasum -a 256 "$temporary" | awk '{print $1}')
        if [ "$actual" != "$sha256" ]; then
            echo "xterm checksum mismatch for $archive_name: expected $sha256, got $actual" >&2
            exit 1
        fi
        mv "$temporary" "$archive"
    fi
    python3 - "$archive" "$member" "$destination/$output" <<'PY'
from pathlib import Path
import sys
import tarfile

archive, member, output = map(Path, sys.argv[1:])
with tarfile.open(archive, "r:gz") as source:
    names = source.getnames()
    if member.as_posix() not in names:
        raise SystemExit(f"missing expected xterm member: {member}")
    extracted = source.extractfile(member.as_posix())
    if extracted is None:
        raise SystemExit(f"xterm member is not a file: {member}")
    data = extracted.read()
output.write_bytes(data)
PY
}

fetch_module \
    "xterm-headless-6.0.0.tgz" \
    "https://registry.npmjs.org/@xterm/headless/-/headless-6.0.0.tgz" \
    "07e4970b1674e7ef6cbd57c8c17746eaadcd41aa7df5b33695fd649e6ec4d78a" \
    "package/lib-headless/xterm-headless.mjs" \
    "xterm-headless.mjs"

fetch_module \
    "xterm-addon-serialize-0.14.0.tgz" \
    "https://registry.npmjs.org/@xterm/addon-serialize/-/addon-serialize-0.14.0.tgz" \
    "f9a290923dc9c6178446e3fc082c29812a7096a1664fd7bf904022c141c5bbfb" \
    "package/lib/addon-serialize.mjs" \
    "addon-serialize.mjs"
