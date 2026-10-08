#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
version="2.9.7"
release="https://github.com/denoland/deno/releases/download/v$version"
root="$repo_root/.phase1/deno"
downloads="$repo_root/.phase1/downloads"

fetch() {
    name=$1
    sha256=$2
    destination=$3
    archive="$downloads/$name"
    mkdir -p "$downloads" "$destination"
    if [ ! -f "$archive" ] ||
        [ "$(shasum -a 256 "$archive" | awk '{print $1}')" != "$sha256" ]; then
        temporary="$archive.partial"
        curl -fL --retry 3 "$release/$name" -o "$temporary"
        actual=$(shasum -a 256 "$temporary" | awk '{print $1}')
        if [ "$actual" != "$sha256" ]; then
            echo "Deno checksum mismatch for $name: expected $sha256, got $actual" >&2
            exit 1
        fi
        mv "$temporary" "$archive"
    fi
    python3 - "$archive" "$destination" <<'PY'
from pathlib import Path
from zipfile import ZipFile
import sys

archive = Path(sys.argv[1])
destination = Path(sys.argv[2])
with ZipFile(archive) as source:
    members = source.namelist()
    if members != ["deno"]:
        raise SystemExit(f"unexpected Deno archive members: {members}")
    source.extract("deno", destination)
(destination / "deno").chmod(0o755)
PY
}

fetch \
    "deno-aarch64-apple-darwin.zip" \
    "5cd46d6268f6f78f5d88bdc7159d20bd44cdaa4b3303474839f87ec6fe7ae25c" \
    "$root/host"

"$root/host/deno" --version
