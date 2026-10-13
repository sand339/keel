#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
# SHA-256 with sha256sum where it exists (Linux), and shasum on macOS.
sha256() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$@"; else shasum -a 256 "$@"; fi
}
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
        [ "$(sha256 "$archive" | awk '{print $1}')" != "$sha256" ]; then
        temporary="$archive.partial"
        curl -fL --retry 3 "$release/$name" -o "$temporary"
        actual=$(sha256 "$temporary" | awk '{print $1}')
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

# The host's own Deno: it runs the host V8 profile on macOS and builds the
# terminal renderer everywhere.
case "$(uname -s)-$(uname -m)" in
Darwin-arm64)
    fetch \
        "deno-aarch64-apple-darwin.zip" \
        "5cd46d6268f6f78f5d88bdc7159d20bd44cdaa4b3303474839f87ec6fe7ae25c" \
        "$root/host"
    ;;
Linux-x86_64)
    fetch \
        "deno-x86_64-unknown-linux-gnu.zip" \
        "c6527f24f4b16031d3ae4fa9f658d5f11534c8d84ce7dc8502420280919c3490" \
        "$root/host"
    ;;
Linux-aarch64)
    fetch \
        "deno-aarch64-unknown-linux-gnu.zip" \
        "c832298b1ad4422481334855f6003e0f54145762c5a134f20a489511d2f65bbf" \
        "$root/host"
    ;;
*)
    echo "no pinned Deno for $(uname -s) $(uname -m)" >&2
    exit 1
    ;;
esac

"$root/host/deno" --version
