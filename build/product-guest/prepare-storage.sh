#!/bin/bash
set -euo pipefail
# Included only in the certified image. Device mapping is part of its platform certification.
[[ $(id -u) == 0 && -f /etc/csweet-product-guest ]] || exit 2
[[ $(cat /sys/class/dmi/id/sys_vendor) == "Microsoft Corporation" ]] || exit 2
[[ $(cat /sys/class/dmi/id/product_name) == "Virtual Machine" ]] || exit 2
[[ -b /dev/sdb && -b /dev/sr0 && -b /dev/sr1 ]] || exit 2
# Never format a mounted disk, a root device, or a disk with partitions.
[[ -z $(lsblk -nr -o MOUNTPOINTS /dev/sdb | tr -d '[:space:]') ]] || exit 2
[[ $(lsblk -nr -o TYPE /dev/sdb | wc -l) == 1 ]] || exit 2
[[ $(findmnt -n -o SOURCE /) != /dev/sdb ]] || exit 2
[[ -z $(blkid -o value -s TYPE /dev/sdb || true) ]] || exit 2
# A certified image boots with its OS filesystem read-only.
findmnt -n -o OPTIONS / | tr ',' '\n' | grep -qx ro || exit 2
mkdir -p /run/csweet-product /media/csweet-artifact /media/csweet-boot
mount -t iso9660 -o ro,nosuid,nodev,noexec /dev/sr0 /media/csweet-artifact
mount -t iso9660 -o ro,nosuid,nodev,noexec /dev/sr1 /media/csweet-boot
mkfs.ext4 -q -m 0 /dev/sdb
mount -t ext4 -o nosuid,nodev /dev/sdb /run/csweet-product
mkdir -p /run/csweet-product/docker /run/csweet-product/containerd /run/csweet-product/home /run/csweet-product/docker-config
mount --bind /run/csweet-product/docker /var/lib/docker
mount --bind /run/csweet-product/containerd /var/lib/containerd
