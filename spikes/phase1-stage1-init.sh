#!/bin/busybox sh
# Stage 1 of the guest boot, run from the small initramfs.
#
# The guest root filesystem is a read-only squashfs image attached as the
# first virtio block device. It is read on demand, so it costs page cache, not
# RAM held for the whole run. A tmpfs overlay above it keeps the root writable,
# as the RAM-backed root was, and is discarded with the VM. This stage loads
# the three modules that needs, assembles the overlay, and hands over to the
# guest's real init, which mounts everything else.
set -eu
busybox=/bin/busybox

$busybox mkdir -p /proc /dev /lower /upper /root
$busybox mount -t proc proc /proc
$busybox mount -t devtmpfs devtmpfs /dev
# The kernel found no console in this initramfs; use the one devtmpfs provides.
exec >/dev/console 2>&1 </dev/console

for module in virtio_blk squashfs overlay; do
    $busybox insmod "/lib/modules/$module.ko"
done

attempts=0
while [ ! -b /dev/vda ]; do
    attempts=$((attempts + 1))
    if [ "$attempts" -gt 200 ]; then
        echo "[keel-stage1] no root disk at /dev/vda" >&2
        exit 1
    fi
    $busybox sleep 0.05
done

$busybox mount -t squashfs -o ro /dev/vda /lower
$busybox mount -t tmpfs -o mode=0755 tmpfs /upper
$busybox mkdir -p /upper/data /upper/work
$busybox mount -t overlay overlay \
    -o lowerdir=/lower,upperdir=/upper/data,workdir=/upper/work /root

# This stage's console is open on /dev, so devtmpfs and proc move into the new
# root rather than unmounting; the real init tolerates finding them mounted.
$busybox mount --move /dev /root/dev
$busybox mount --move /proc /root/proc
exec $busybox switch_root /root /init
