#!/bin/sh
set -eu

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

shutdown_guest() {
    status=$?
    trap - EXIT
    echo "[keel-init] workload exited with status $status"
    sync
    poweroff -f
    while :; do
        sleep 3600
    done
}
trap shutdown_guest EXIT

mount -t proc proc /proc 2>/dev/null || true
mount -t sysfs sysfs /sys 2>/dev/null || true
mount -t devtmpfs devtmpfs /dev 2>/dev/null || true
mkdir -p /dev/pts
mount -t devpts devpts /dev/pts
for module in virtio virtio_ring virtio_rng virtiofs vsock vmw_vsock_virtio_transport_common \
    vmw_vsock_virtio_transport; do
    modprobe "$module" 2>/dev/null || true
done

mkdir -p /workspace /run/keel /tmp /var/tmp
chmod 1777 /tmp /var/tmp
mount -t virtiofs keel-workspace /workspace
mount -t virtiofs keel-control /run/keel
mount -t cgroup2 none /sys/fs/cgroup
ifconfig lo 127.0.0.1 up

# Guest services. Each binds as root, then drops to the service UID so the
# workload, which holds no capabilities, cannot signal or inspect it.
# The Git, egress, and MCP relays attribute each connection to its guest
# process by asking PID 1, which is the supervisor exec'd at the end of this
# script.
/usr/local/bin/keel-mcp-guest relay 18080 5002 --attribute &
/usr/local/bin/keel-mcp-guest relay 18081 5001 --attribute &
/usr/local/bin/keel-mcp-guest relay 18082 5000 --attribute &

# The boot report includes a confined child's own check of the workload
# confinement, including that it cannot signal the services above. The host
# refuses to continue if any layer is missing.
/usr/local/bin/keel-mcp-guest 5000 keel-phase0

export GIT_CONFIG_COUNT=2
export GIT_CONFIG_KEY_0=remote.origin.url
export GIT_CONFIG_VALUE_0=http://127.0.0.1:18080/origin
export GIT_CONFIG_KEY_1=remote.origin.pushurl
export GIT_CONFIG_VALUE_1=http://127.0.0.1:18080/origin
export HTTP_PROXY=http://127.0.0.1:18081
export HTTPS_PROXY=http://127.0.0.1:18081
export ALL_PROXY=
export NO_PROXY=127.0.0.1,localhost
export http_proxy=$HTTP_PROXY
export https_proxy=$HTTPS_PROXY
export all_proxy=$ALL_PROXY
export no_proxy=$NO_PROXY
export HOME=/root

refresh_tmux_when_ready() {
    attempts=0
    ready=0
    while [ "$attempts" -lt 30 ]; do
        sleep 1
        client=$(/usr/bin/tmux -L keel list-clients -F '#{client_tty}' 2>/dev/null |
            sed -n '1p')
        if [ -n "$client" ]; then
            /usr/bin/tmux -L keel refresh-client -t "$client" 2>/dev/null || true
            if /usr/bin/tmux -L keel capture-pane -p -t keel:0.0 2>/dev/null |
                grep -q '[^[:space:]]'; then
                ready=$((ready + 1))
            else
                ready=0
            fi
            if [ "$ready" -ge 3 ]; then
                return
            fi
        fi
        attempts=$((attempts + 1))
    done
}

valid_dimension() {
    case ${1:-} in
        '' | *[!0-9]*) return 1 ;;
    esac
    [ "$1" -ge 1 ] && [ "$1" -le 65535 ]
}

cd /workspace
# The pty below is created before the harness runs, so its size has to be known
# here. This process is init: its environment comes from the kernel, not from
# the host process that knows the operator's terminal, so the size arrives on
# the read-only control mount instead. A pty left at the default would make the
# harness paint 80x24 into whatever window the operator actually has.
rows=24
columns=80
if [ -r /run/keel/terminal-size ] &&
    read -r file_rows file_columns _ < /run/keel/terminal-size &&
    valid_dimension "${file_rows:-}" && valid_dimension "${file_columns:-}"; then
    rows=$file_rows
    columns=$file_columns
fi
export TERM=${TERM:-xterm-256color}
refresh_tmux_when_ready &
# Everything the operator's terminal runs, from tmux down to the harness and
# its tools, is confined: UID 0 without capabilities, Landlock, seccomp, and a
# bounded cgroup. The terminal bridge itself drops to the service UID.
#
# PID 1 becomes the Rust supervisor. It keeps root, which attribution needs,
# while the kernel delivers no signal to PID 1 from inside the guest unless it
# installs a handler, so the root-UID workload cannot kill it. It reaps
# orphans and powers the guest off when the terminal command ends.
trap - EXIT
exec /usr/local/bin/keel-mcp-guest supervise -- \
    /usr/local/bin/keel-mcp-guest terminal 5003 "$rows" "$columns" \
    /usr/local/bin/keel-mcp-guest confine -- \
    /usr/bin/tmux -f /etc/keel/tmux.conf -L keel new-session -A -s keel /run/keel/launch
