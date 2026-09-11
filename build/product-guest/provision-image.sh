#!/bin/bash
set -euo pipefail
# Runs inside the offline image customization appliance, never on Headquarters or the host OS.
for program in docker chromium setpriv dotnet update-grub python3; do command -v "$program" >/dev/null; done
docker compose version >/dev/null
[[ -d /boot/grub && -d /boot/efi ]] || exit 2
# Payload archives are trusted publisher build outputs, not product artifacts.
# Still reject traversal, links, device files and privileged permission bits before extraction.
python3 - <<'PY'
import tarfile,pathlib
for source,destination in [("/tmp/csweet-guest.tar","/opt/csweet-product"),("/tmp/csweet-probe.tar","/opt/csweet/browser-probe")]:
    with tarfile.open(source) as archive:
        for member in archive.getmembers():
            path=pathlib.PurePosixPath(member.name)
            assert not path.is_absolute() and ".." not in path.parts
            assert member.isfile() or member.isdir()
            assert not member.mode & 0o6000
        archive.extractall(destination,filter="data")
PY
chmod 755 /opt/csweet-product/CSweet.WebHost.ProductGuest /opt/csweet/browser-probe/CSweet.WebHost.BrowserProbe /opt/csweet/browser-probe/.playwright/node/linux-x64/node
install -m 755 /tmp/prepare-storage.sh /opt/csweet-product/prepare-storage.sh
install -m 644 /tmp/csweet-product-storage.service /tmp/csweet-product-guest.service /etc/systemd/system/
touch /etc/csweet-product-guest
mkdir -p /media/csweet-artifact /media/csweet-boot /var/lib/docker /var/lib/containerd /etc/docker
cat > /etc/docker/daemon.json <<'JSON'
{"data-root":"/var/lib/docker","exec-root":"/run/docker","log-driver":"local","log-opts":{"max-size":"1m","max-file":"3"},"live-restore":false}
JSON
systemctl enable csweet-product-storage.service csweet-product-guest.service
for unit in ssh.service sshd.service systemd-networkd.service NetworkManager.service; do systemctl mask "$unit" || true; done
passwd -l root
find /etc/ssh -maxdepth 1 -type f -name 'ssh_host_*' -delete
find /root -type f \( -name authorized_keys -o -name id_rsa -o -name id_ed25519 \) -delete
truncate -s 0 /etc/machine-id
# Preserve the pinned base's root UUID/UEFI mapping, but make the OS immutable and disable swap.
awk 'BEGIN {OFS="\t"} $3=="swap" {next} $2=="/" {$4="ro,nosuid,nodev"} {print}' /etc/fstab > /tmp/csweet-fstab
cat /tmp/csweet-fstab > /etc/fstab
cat >> /etc/fstab <<'FSTAB'
tmpfs /tmp tmpfs nosuid,nodev,size=128M,mode=1777 0 0
tmpfs /var/log tmpfs nosuid,nodev,noexec,size=32M 0 0
tmpfs /var/lib/systemd tmpfs nosuid,nodev,noexec,size=16M 0 0
FSTAB
mkdir -p /etc/systemd/journald.conf.d
printf '[Journal]\nStorage=volatile\nRuntimeMaxUse=16M\n' > /etc/systemd/journald.conf.d/csweet.conf
# No automatic update jobs or writable-root remount during guest boot.
systemctl mask systemd-remount-fs.service apt-daily.service apt-daily-upgrade.service unattended-upgrades.service || true
update-grub
rm -f /tmp/csweet-guest.tar /tmp/csweet-probe.tar /tmp/prepare-storage.sh /tmp/csweet-product-storage.service /tmp/csweet-product-guest.service /tmp/csweet-fstab
