#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
"$repo_root/spikes/fetch-deno.sh"
phase_root="$repo_root/.phase1"
download_root="$phase_root/downloads"
target_root="$phase_root/target-linux"
cargo_root="$phase_root/cargo-home"
rootfs="$phase_root/rootfs"
initramfs="$phase_root/keel-phase1-initramfs.cpio.zst"
rootfs_image="$phase_root/keel-phase1-rootfs.squashfs"
stage1="$phase_root/stage1"
kernel_modules="$repo_root/.phase1/kernel/modules"

rust_image="rust:1.97-alpine3.23@sha256:c4a364ddbf684fe038e6fa6a4f25b30c8dc85247423e0e660676ece0d17be4a2"
alpine_image="alpine:3.23@sha256:85fe1e81d6758c208f3e1eed4338a1997e19d4be002d4dd32d3100c9a8c010a0"
claude_version="2.1.287"
claude_sha256="83d95a9fa28b1fadd8c012fda873aed8f8998e23dfabe6dd4efd05bcdd7383ba"
claude_binary="$download_root/claude-$claude_version-linux-arm64-musl"
guest_binary="$target_root/release/keel-mcp-guest"
# agent-browser (vercel-labs) drives the guest's Chromium, as an MCP server
# for the agent and a CLI for the analyst. Only its musl arm64 binary is used.
agent_browser_version="0.38.2"
agent_browser_package_sha256="2bb1d6e4660b2a109c912c8bb552f727125dbcd681c6d1eefc1af573b4546c49"
agent_browser_sha256="eafeca9ca0fdb2fa2aa60c4554723348c739656b0ddba0d82ff654d4d33311b1"
agent_browser_binary="$download_root/agent-browser-$agent_browser_version-linux-musl-arm64"

mkdir -p "$download_root" "$target_root" "$cargo_root"
if [ ! -f "$claude_binary" ] ||
    [ "$(shasum -a 256 "$claude_binary" | awk '{print $1}')" != "$claude_sha256" ]; then
    temporary="$claude_binary.partial"
    curl -fL \
        "https://downloads.claude.ai/claude-code-releases/$claude_version/linux-arm64-musl/claude" \
        -o "$temporary"
    actual=$(shasum -a 256 "$temporary" | awk '{print $1}')
    if [ "$actual" != "$claude_sha256" ]; then
        echo "Claude checksum mismatch: expected $claude_sha256, got $actual" >&2
        exit 1
    fi
    mv "$temporary" "$claude_binary"
fi
if [ ! -f "$agent_browser_binary" ] ||
    [ "$(shasum -a 256 "$agent_browser_binary" | awk '{print $1}')" != "$agent_browser_sha256" ]; then
    package="$download_root/agent-browser-$agent_browser_version.tgz"
    curl -fL \
        "https://registry.npmjs.org/agent-browser/-/agent-browser-$agent_browser_version.tgz" \
        -o "$package.partial"
    actual=$(shasum -a 256 "$package.partial" | awk '{print $1}')
    if [ "$actual" != "$agent_browser_package_sha256" ]; then
        rm -f "$package.partial"
        echo "agent-browser package checksum mismatch: expected $agent_browser_package_sha256, got $actual" >&2
        exit 1
    fi
    tar -xzOf "$package.partial" package/bin/agent-browser-linux-musl-arm64 > "$agent_browser_binary.partial"
    rm -f "$package.partial"
    actual=$(shasum -a 256 "$agent_browser_binary.partial" | awk '{print $1}')
    if [ "$actual" != "$agent_browser_sha256" ]; then
        rm -f "$agent_browser_binary.partial"
        echo "agent-browser binary checksum mismatch: expected $agent_browser_sha256, got $actual" >&2
        exit 1
    fi
    mv "$agent_browser_binary.partial" "$agent_browser_binary"
fi

if [ ! -x "$guest_binary" ] ||
    find "$repo_root/Cargo.lock" \
        "$repo_root/Cargo.toml" \
        "$repo_root/crates/trusted/keel-kernel" \
        "$repo_root/crates/untrusted/keel-mcp" \
        -type f -newer "$guest_binary" -print -quit | grep -q .; then
    docker run --rm --platform linux/arm64 \
        -e CARGO_HOME=/phase1-cargo \
        -e CARGO_TARGET_DIR=/phase1-target \
        -v "$repo_root:/work:ro" \
        -v "$target_root:/phase1-target" \
        -v "$cargo_root:/phase1-cargo" \
        -w /work \
        "$rust_image" \
        cargo build --locked --release -p keel-mcp --bin keel-mcp-guest
fi

python3 - "$rootfs" <<'PY'
from pathlib import Path
import shutil
import sys

path = Path(sys.argv[1])
if path.exists():
    shutil.rmtree(path)
path.mkdir()
PY

# Modules must match the pinned guest kernel exactly.
if [ ! -d "$kernel_modules" ]; then
    echo "missing pinned guest kernel modules; run ./spikes/fetch-guest-kernel.sh first" >&2
    exit 1
fi
mkdir -p "$rootfs/lib/modules"
cp -R "$kernel_modules/." "$rootfs/lib/modules/"

docker run --rm --platform linux/arm64 \
    -v "$rootfs:/rootfs" \
    "$alpine_image" \
    apk add --no-cache --initdb --root /rootfs \
        --keys-dir /etc/apk/keys \
        --repository https://dl-cdn.alpinelinux.org/alpine/v3.23/main \
        --repository https://dl-cdn.alpinelinux.org/alpine/v3.23/community \
        alpine-base bash ca-certificates curl git nodejs tmux \
        chromium font-dejavu nss-tools \
        build-base npm py3-pip rust cargo go

test -x "$rootfs/usr/bin/curl"
test -x "$rootfs/usr/bin/node"
test -x "$rootfs/usr/lib/chromium/chromium"
test -x "$rootfs/usr/bin/certutil"
# Some tools are absolute symlinks inside the image, which a host-side test
# would resolve against the host, so a link counts as present.
for tool in gcc make npm pip3 rustc cargo go; do
    test -x "$rootfs/usr/bin/$tool" || test -L "$rootfs/usr/bin/$tool"
done
# Headless Chromium runs with the GPU disabled and never loads Mesa's Gallium
# drivers. LLVM stays: rustc links against it.
rm -f "$rootfs"/usr/lib/libgallium*

mkdir -p "$rootfs/etc/claude-code" "$rootfs/etc/keel" "$rootfs/root" \
    "$rootfs/usr/local/bin" "$rootfs/usr/local/lib/keel"
cp "$repo_root/spikes/phase1-init.sh" "$rootfs/init"
cp "$repo_root/spikes/keel-launch.sh" "$rootfs/usr/local/bin/keel-launch"
cp "$guest_binary" "$rootfs/usr/local/bin/keel-mcp-guest"
cp "$claude_binary" "$rootfs/usr/local/bin/claude"
cp "$agent_browser_binary" "$rootfs/usr/local/bin/agent-browser"
cp "$repo_root/spikes/keel-chromium.sh" "$rootfs/usr/local/bin/keel-chromium"
cp "$repo_root/spikes/keel-v8-sdk.mjs" "$rootfs/usr/local/lib/keel/v8-sdk.mjs"
# Auto mode delegates every permission decision to a server-side classifier, and
# reaches it over Claude Code's control plane. The trusted proxy allows exactly
# one endpoint on the model host, `POST /v1/messages`, so that control plane is
# refused by design and auto mode then fails closed: tool calls are declined with
# "Auto mode could not evaluate this action" rather than reaching a gate. Turning
# it off here stops it being offered at all, instead of being offered and then
# stalling mid-task. Auto mode is also the wrong adjudicator for this system --
# the trusted kernel and the operator gate are, and they are the only ones the
# audit log can speak for. `disableAutoMode` is restrictive, so it is honored
# from this admin tier (`/etc/claude-code` is the Linux managed-settings folder).
#
# Claude Code also refreshes configured plugin marketplaces during startup. A
# hardened guest must not turn that background maintenance into unrelated egress
# prompts, or fetch executable plugin content outside the admitted task. An
# explicit empty managed allowlist disables every marketplace. Keel's MCP server
# is still injected separately with --mcp-config by keel-launch.
cat > "$rootfs/etc/claude-code/managed-settings.json" <<'JSON'
{
  "strictKnownMarketplaces": [],
  "permissions": {
    "disableAutoMode": "disable"
  }
}
JSON
cat > "$rootfs/etc/keel/mcp.json" <<'JSON'
{
  "mcpServers": {
    "keel": {
      "type": "stdio",
      "command": "/usr/local/bin/keel-mcp-guest",
      "args": ["stdio", "tcp", "18082"]
    },
    "browser": {
      "type": "stdio",
      "command": "/usr/local/bin/agent-browser",
      "args": ["mcp"]
    }
  }
}
JSON
# Chromium's flags for the keel-chromium wrapper (see spikes/keel-chromium.sh).
# /dev/shm is not writable under Landlock, so shared memory uses /tmp.
#
# Chromium also calls Google services on its own: sign-in, push messaging,
# variations, network time, and search. Each would be an approval prompt, or
# an out-of-scope refusal in a triage run. The managed policy turns those
# features off, and the endpoint switches send whatever remains to a closed
# loopback port, which Chromium never routes through a proxy, so it fails
# locally without an action.
cat > "$rootfs/etc/keel/chromium.flags" <<'FLAGS'
--no-sandbox
--disable-quic
--disable-dev-shm-usage
--disable-gpu
--disable-crash-reporter
--no-first-run
--no-default-browser-check
--no-pings
--disable-domain-reliability
--disable-client-side-phishing-detection
--disable-features=PushMessaging,OptimizationHints,MediaRouter,DialMediaRouteProvider,AutofillServerCommunication,NetworkTimeServiceQuerying,CertificateTransparencyComponentUpdater,Translate
--gaia-url=http://127.0.0.1:9
--google-apis-url=http://127.0.0.1:9
--lso-url=http://127.0.0.1:9
--gcm-checkin-url=http://127.0.0.1:9
--gcm-mcs-endpoint=127.0.0.1:9
--gcm-registration-url=http://127.0.0.1:9
--variations-server-url=http://127.0.0.1:9
--google-base-url=http://127.0.0.1:9
FLAGS
mkdir -p "$rootfs/etc/chromium/policies/managed"
cat > "$rootfs/etc/chromium/policies/managed/keel.json" <<'JSON'
{
  "BrowserSignin": 0,
  "SyncDisabled": true,
  "MetricsReportingEnabled": false,
  "SafeBrowsingProtectionLevel": 0,
  "SearchSuggestEnabled": false,
  "NetworkPredictionOptions": 2,
  "TranslateEnabled": false,
  "ComponentUpdatesEnabled": false,
  "BackgroundModeEnabled": false,
  "DefaultSearchProviderEnabled": false,
  "PromotionalTabsEnabled": false,
  "SpellCheckServiceEnabled": false,
  "UrlKeyedAnonymizedDataCollectionEnabled": false,
  "DnsOverHttpsMode": "off",
  "BuiltInDnsClientEnabled": false
}
JSON
cat > "$rootfs/etc/keel/tmux.conf" <<'TMUX'
set -g status on
set -g status-position bottom
set -g status-style 'fg=black,bg=white'
set -g status-left ' KEEL '
set -g status-left-length 8
set -g status-right ' Ctrl-A: /new /tab /close /resume /detach /approve /floor-lift '
set -g status-right-length 80
set -g window-status-format ''
set -g window-status-current-format ''
set -g escape-time 50
set -g focus-events on
set -g set-clipboard off
set -g default-terminal "screen-256color"
set -g prefix None
set -g prefix2 C-g
unbind-key C-b
bind-key r refresh-client
TMUX
printf 'nameserver 0.0.0.0\n' > "$rootfs/etc/resolv.conf"
chmod 0755 \
    "$rootfs/init" \
    "$rootfs/usr/local/bin/claude" \
    "$rootfs/usr/local/bin/keel-launch" \
    "$rootfs/usr/local/bin/keel-mcp-guest" \
    "$rootfs/usr/local/bin/agent-browser" \
    "$rootfs/usr/local/bin/keel-chromium"

# A managed-settings file that does not parse is discarded with a warning the
# operator never sees, and auto mode would be back without anything saying so.
python3 - "$rootfs/etc/claude-code/managed-settings.json" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as handle:
    settings = json.load(handle)
if settings.get("permissions", {}).get("disableAutoMode") != "disable":
    sys.exit(f"{path} no longer disables auto mode")
if settings.get("strictKnownMarketplaces") != []:
    sys.exit(f"{path} no longer disables plugin marketplaces")
PY

docker run --rm --platform linux/arm64 \
    -v "$rootfs:/rootfs:ro" \
    "$alpine_image" \
    /rootfs/usr/local/bin/claude --version
docker run --rm --platform linux/arm64 \
    -v "$rootfs:/rootfs:ro" \
    "$alpine_image" \
    /rootfs/usr/local/bin/keel-mcp-guest invalid too many arguments >/dev/null 2>&1 &&
    { echo "guest bridge unexpectedly accepted invalid arguments" >&2; exit 1; }

# The root filesystem ships as a read-only squashfs disk image, attached as a
# virtio block device and read on demand, so its size costs page cache rather
# than RAM held for the whole run (PLAN D61). Every entry is owned by root, as
# on any Linux image: the guest workload keeps UID 0 but no capabilities, and
# could not otherwise reach its own home directory or settings.
rm -f "$rootfs_image"
docker run --rm --platform linux/arm64 \
    -v "$rootfs:/rootfs:ro" \
    -v "$phase_root:/out" \
    "$alpine_image" \
    sh -c 'apk add --no-cache -q squashfs-tools >/dev/null &&
        mksquashfs /rootfs /out/keel-phase1-rootfs.squashfs \
            -comp zstd -Xcompression-level 6 -all-root -no-xattrs -noappend -quiet -no-progress'
test -s "$rootfs_image"

# The initramfs is only stage 1: static busybox, the three modules that mount
# the root disk, and spikes/phase1-stage1-init.sh. Modules come from the pinned
# kernel package, decompressed for busybox insmod.
python3 - "$stage1" <<'PY'
from pathlib import Path
import shutil
import sys

path = Path(sys.argv[1])
if path.exists():
    shutil.rmtree(path)
(path / "bin").mkdir(parents=True)
(path / "lib" / "modules").mkdir(parents=True)
PY
docker run --rm --platform linux/arm64 \
    -v "$stage1:/stage1" \
    "$alpine_image" \
    sh -c 'apk add --no-cache -q busybox-static >/dev/null && cp /bin/busybox.static /stage1/bin/busybox'
for module in drivers/block/virtio_blk fs/squashfs/squashfs fs/overlayfs/overlay; do
    gzip -dc "$kernel_modules/$(cat "$repo_root/.phase1/kernel/release")/kernel/$module.ko.gz" \
        > "$stage1/lib/modules/$(basename "$module").ko"
done
cp "$repo_root/spikes/phase1-stage1-init.sh" "$stage1/init"
chmod 0755 "$stage1/init" "$stage1/bin/busybox"
(
    cd "$stage1"
    find . -print | cpio -o -H newc -R 0:0 2>/dev/null
) |
    docker run --rm -i --platform linux/arm64 "$alpine_image" \
        sh -c 'apk add --no-cache -q zstd >/dev/null && zstd -q -T0 -6 -c' > "$initramfs"

(
    cd "$rootfs"
    find . -type f -print0 | sort -z | xargs -0 shasum -a 256
) > "$phase_root/rootfs.sha256"
shasum -a 256 "$initramfs" "$rootfs_image"
