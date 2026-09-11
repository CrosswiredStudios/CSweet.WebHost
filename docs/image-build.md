# Offline product image build

Run only in the hardened Linux release builder. The builder is separate from Headquarters, Node and product agents. Inputs are trusted platform release outputs, not agent repositories. Nothing here grants a release certificate automatically.

## Inputs

Use a pinned x64 Linux Gen2/UEFI base image with a Hyper-V VSOCK kernel and GRUB. It must already contain Docker and Compose, /usr/bin/chromium with sandboxed user namespaces, setpriv, Python with tarfile's data filter, and the .NET 10 ASP.NET Core runtime. Use an offline, version-pinned package snapshot. Chromium must be the real supported distribution binary, not a Snap launcher. The root filesystem and media mount points must support the supplied read-only boot configuration. The release builder needs qemu-img, libguestfs/virt-customize, Python and tar.

Build the two guest payloads from the reviewed WebHost source on Linux, using a locked dependency restore and the recorded SDK/tool versions:

```sh
dotnet publish src/CSweet.WebHost.ProductGuest -c Release -r linux-x64 --self-contained false -o release/product-guest
dotnet publish src/CSweet.WebHost.BrowserProbe -c Release -r linux-x64 --self-contained false -o release/browser-probe
tar -C release/product-guest -cf release/product-guest.tar .
tar -C release/browser-probe -cf release/browser-probe.tar .
sudo bash build/product-guest/build-image.sh /sealed/base.qcow2 "$BASE_SHA256" release/product-guest.tar release/browser-probe.tar /sealed/output-new
```

The output directory must not exist. The base hash is mandatory and external backing chains are rejected. Payload archives must contain regular files/directories only; traversal, links, devices and privileged permission bits fail validation. virt-customize has networking disabled and runs the platform provisioning script inside its appliance. It installs the guest/browser services, locks root access, removes SSH keys, disables network services and configures bounded writable paths with read-only root storage.

The output contains a standalone dynamically allocated product.vhdx, input/image hashes, builder versions and an explicit uncertified status. Dynamic allocation reduces distribution and verification cost; runtime admission still reserves the full virtual disk size and growth overhead. The scripts record pinned inputs; they do not promise bit-for-bit reproducibility across different filesystem and builder versions.

## Acceptance and signing

Publish the Windows RuntimeHost and Node payloads from the same reviewed release. Run [operational acceptance](acceptance.md) against those exact files and this image on dedicated Hyper-V hardware. In particular verify device mapping, read-only root/media, Chromium sandbox/UID, renewal after the original deadline, disconnected expiry, real physical resource bounds, cleanup and static/game/server/database flows. Preserve results and hashes as release evidence.

Only the independent release authority may sign the measured certification. Required controls include signed-lease-renewal and bounded-browser-tests, in addition to all existing runtime controls. Configure the corresponding certificate and public key in Headquarters and the protected runtime. Then follow [enrollment](enrollment.md). Changing any certified runtime file or the guest image requires a new measured and signed release.

Development verification has parsed these scripts and compiled/tested the protocol code. It has not executed the Linux image builder, launched Chromium in a product VM, signed a release or installed host services.
