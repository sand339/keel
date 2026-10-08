#!/bin/sh
# Launches the guest's Chromium for agent-browser with Keel's flags.
#
# Chromium's own sandbox needs user namespaces, which the workload confinement
# denies; the VM is the boundary instead (DECISIONS D35). Keel's flags turn off
# QUIC, so all traffic is TCP through the egress relay, and switch off or
# redirect Chromium's own calls to Google services, so a run sees no browser
# background traffic.
#
# Flags are appended after the launcher's own. Chromium honors only the last
# --disable-features, so the launcher's list and Keel's are merged into one.
set -eu

# Screenshots, downloads, and HAR files go to the workspace, which the host
# sees directly. The directory ignores itself, so it never shows up in Git,
# and it is created only when the browser is first used.
output=/workspace/.keel-browser
if [ -d /workspace ] && [ ! -e "$output/.gitignore" ]; then
    mkdir -p "$output/screenshots" "$output/downloads" "$output/har"
    printf '*\n' > "$output/.gitignore"
fi

features=""
remaining=$#
while [ "$remaining" -gt 0 ]; do
    argument=$1
    shift
    remaining=$((remaining - 1))
    case "$argument" in
        --disable-features=*) features="$features,${argument#--disable-features=}" ;;
        *) set -- "$@" "$argument" ;;
    esac
done
while IFS= read -r flag; do
    case "$flag" in
        "") ;;
        --disable-features=*) features="$features,${flag#--disable-features=}" ;;
        *) set -- "$@" "$flag" ;;
    esac
done < /etc/keel/chromium.flags
exec /usr/lib/chromium/chromium "$@" "--disable-features=${features#,}"
