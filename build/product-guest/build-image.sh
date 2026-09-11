#!/bin/bash
set -euo pipefail
# Hardened Linux release builder only. All inputs are sealed, trusted platform release inputs.
# Usage: build-image.sh base.qcow2 BASE_SHA256 product-guest.tar browser-probe.tar output-directory
[[ $# == 5 && $(id -u) == 0 ]] || { echo 'Use the documented root release-builder invocation.' >&2; exit 2; }
base=$(realpath -e -- "$1"); guest=$(realpath -e -- "$3"); probe=$(realpath -e -- "$4")
[[ "$2" =~ ^[a-f0-9]{64}$ && $(sha256sum -- "$base" | cut -d' ' -f1) == "$2" ]] || exit 2
[[ ! -e "$5" && ! -L "$5" ]] || { echo 'The output directory must not exist.' >&2; exit 2; }
for program in qemu-img virt-customize sha256sum tar python3; do command -v "$program" >/dev/null; done
# Reject base-image external backing chains before opening it for customization.
qemu-img info --output=json "$base" | python3 -c 'import json,sys; x=json.load(sys.stdin); assert not x.get("backing-filename") and x["format"] in ("raw","qcow2","vhdx")'
script_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
mkdir -m 700 -- "$5"; output=$(realpath -e -- "$5")
qemu-img convert -O qcow2 "$base" "$output/product.qcow2"
# The base has a supported Hyper-V Gen2 kernel, GRUB/UEFI, Docker/Compose, Chromium,
# user namespaces, setpriv, and .NET 10 already installed from the pinned offline snapshot.
# virt-customize runs only platform provisioning code inside its isolated appliance, with no network.
virt-customize --no-network -a "$output/product.qcow2" \
  --mkdir /opt/csweet-product --mkdir /opt/csweet/browser-probe \
  --upload "$guest:/tmp/csweet-guest.tar" --upload "$probe:/tmp/csweet-probe.tar" \
  --upload "$script_root/prepare-storage.sh:/tmp/prepare-storage.sh" \
  --upload "$script_root/csweet-product-storage.service:/tmp/csweet-product-storage.service" \
  --upload "$script_root/csweet-product-guest.service:/tmp/csweet-product-guest.service" \
  --run "$script_root/provision-image.sh"
qemu-img convert -O vhdx -o subformat=dynamic "$output/product.qcow2" "$output/product.vhdx"
qemu-img check "$output/product.qcow2"
sha256sum "$base" "$guest" "$probe" "$script_root/"*.sh "$script_root/"*.service "$output/product.vhdx" > "$output/input-and-image.sha256"
qemu-img --version > "$output/builder-versions.txt"
virt-customize --version >> "$output/builder-versions.txt"
printf '%s\n' 'Image built from pinned offline inputs. Not certified; run hardened real-VM acceptance before signing.' > "$output/STATUS.txt"
