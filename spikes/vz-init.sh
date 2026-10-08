#!/bin/sh

BB=/bin/busybox
if [ ! -x "$BB" ]; then
    echo "[keel-init] busybox missing" >&2
    exit 10
fi

$BB mkdir -p /bin /sbin /proc /sys /dev
for applet in depmod ln mkdir modprobe mount; do
    [ -e "/bin/$applet" ] || $BB ln -sf busybox "/bin/$applet"
    [ -e "/sbin/$applet" ] || $BB ln -sf busybox "/sbin/$applet"
done
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

mount -t proc proc /proc 2>/dev/null
mount -t sysfs sysfs /sys 2>/dev/null
mount -t devtmpfs devtmpfs /dev 2>/dev/null
depmod -a 2>/dev/null || true

for module in virtio virtio_ring virtio_rng vsock vmw_vsock_virtio_transport_common \
    vmw_vsock_virtio_transport; do
    modprobe "$module" 2>/dev/null || true
done

echo "[keel-init] starting MCP vsock probe"
exec /keel-mcp-guest
