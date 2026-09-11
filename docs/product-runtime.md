# Product runtime boundary

The Windows RuntimeHost is separate from Office and from the network-facing WebHost Node.
It runs under its installer-managed service account. Its fixed ProgramData configuration pins
Headquarters' public verification key, the host ID, release certification key, image and protected
payload/artifact/state directories. Node receives access to the named pipe through its exact SID;
it receives no write access to the configuration, executable payload or protected state.

The runtime accepts signed assignments and separately signed controls. Controls bind the host,
workload, command ID, action, exact request body and a maximum 60-second admission window.
Their replay ledger is durable. A lost response to a mutation must be reconciled with a new
status request; automatic mutation replay is deliberately rejected.

VM creation persists its identity before creating Hyper-V resources. Assignment retry looks up
that identity and never launches a second VM. A background worker reaps lease-expired or 30-minute-idle VMs without
Node or Headquarters connectivity. Runtime service failure recovery still needs the installer
and platform certification; background-worker unit tests do not establish this guarantee.

Two read-only DVDs carry the immutable ZIP artifact and boot authorization. The second contains
public verification material and the signed assignment, without credentials. Artifact uploads stream
through the protected local pipe with an exact signed digest, byte limit and separately reserved cache
capacity. Node supplies no host filesystem paths or extraction directives. The dedicated
Linux guest uses VSOCK port 2762. Office keeps its existing port and protocol.

A ZIP contains site/ for static content or source/ and optional images/*.tar for containers.
Extraction verifies the digest before writing, rejects traversal, links, duplicate names and
special entries, and bounds expanded size. Docker only runs inside the product guest.
It imports supplied image archives, builds with networking disabled, and runs normalized Compose.
All dependencies and images must already exist in the input or certified cache; external
connection brokering has not been implemented and requests needing it fail closed.

Guest HTTP forwarding has one constant destination: its localhost entry service on port 18080.
It strips Headquarters credentials and forwarding headers. Product cookies use a separate validated collection. Responses are bounded to 4 MiB per exchange, with contiguous ranges for assets up to 256 MiB and bounded WebSocket frames. The gateway validates redirect destinations and maintains a separate private-access cookie.

The host associates every guest diagnostic with its canonical assignment, build, project and
source revision. Guest-provided identities cannot select another project. Diagnostics are
sanitized again before persistence. Signed evidence reads remain available after VM teardown, with
bounded pagination and seven-day retention; raw guest diagnostic responses do not leave this boundary.
These records remain evidence, not agent instructions. See [enrollment and evidence flow](enrollment.md).

## Certified image installation inputs

The build/product-guest offline builder consumes a hash-pinned Linux base and trusted published ProductGuest/BrowserProbe payloads. See image-build.md. Its output still requires exact-image real-VM certification.
The image builder must provide a supported Linux kernel with Hyper-V VSOCK, Docker and its
Compose plugin, the published ProductGuest binary and these service units. The immutable root
must be mounted read-only from boot, with precreated /media mount points and /var/lib/docker
and /var/lib/containerd bind targets. Writable OS paths must use bounded tmpfs. No SSH keys,
agent/MCP credentials, organization secrets or external network adapter may be present.

prepare-storage.sh is guest-only. Certification must demonstrate the exact device mapping,
absence of a host network adapter, read-only root and optical media, CPU/memory/process/disk
bounds, cleanup after guest and host-controller crashes, expiry while Node is disconnected,
and that product containers cannot reach host resources or the private management interface.
The signed certification binds the exact guest image and runtime DLL/executable/dependency file
set. Runtime requires suite version 1 and every mandatory control. It refuses a missing, altered,
expired or wrong-purpose certification.

Real release certification/signing must run in the hardened release environment. This workspace
has not produced or certified a product image and has not launched a product VM.

## Implementation references

- [Hyper-V sockets](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/make-integration-service)
- [Compose service settings](https://docs.docker.com/reference/compose-file/services/)
- [Compose internal networks](https://docs.docker.com/reference/compose-file/networks/)
- [Compose trust model](https://docs.docker.com/compose/trust-model/)

## Storage admission and recovery

The privileged provider queries the verified standalone VHDX's virtual size with Get-VHD. It reserves
OS differencing growth, scratch growth, both private media copies, VM memory state and metadata before
creating any VM. Reservations are durably attached to the protected workload record and released only
after physical teardown succeeds. An interrupted Creating record is torn down on the next reaper sweep.
Older active records without a physical reservation block new admission until reconciled or destroyed.

The current reservation is deliberately conservative: twice each disk's full virtual size plus 256 MiB
per disk, a full memory-sized state allowance plus 64 MiB, exact artifact media length and boot media
with 64 KiB padding. A small compressed or sparse base image never reduces the OS reservation.
The configured HostCapacity.DiskMb is the per-host physical reservation budget; the manifest DiskMb
continues to size the guest's scratch disk. Host heartbeats report remaining physical capacity.

StateRoot and ArtifactMediaRoot must be on the same protected fixed local volume. Admission also keeps
the full outstanding VM reservations, full MaximumArtifactCacheBytes and a 1 GiB host floor free on
that volume. It gives no allocation credit for existing sparse/compressed files. This can reject work
before the disk is full. These checks are admission safeguards, not filesystem quotas: unrelated disk
writers, live allocation monitoring, boot/restart recovery and real physical bounds still need installer
and provider certification. The cache has its own bounded ingestion lock and expiry worker.

The Get-VHD inspection follows Microsoft's [Hyper-V storage guidance](https://learn.microsoft.com/en-us/windows-server/administration/performance-tuning/role/hyper-v-server/storage-io-performance).

## Automatic local evidence collection

RuntimeHost polls its owned Ready/Failed guests every 30 seconds, with at most two concurrent polls and
a ten-second deadline per guest. Initializing guests are excluded to avoid competing with their build
connection. Collection rechecks the signed assignment and live lease and never extends idle time.
No Node request or Headquarters connection is required for this local collection.

Each bounded guest snapshot is validated, canonically bound, sanitized and committed in one atomic
transaction. Repeated snapshots reuse diagnostic identities and do not duplicate events or extend
retention. Failed retrievals attempt a separately bounded host-generated diagnostic, deduplicated per
assignment/minute, with no raw transport errors or paths. One failed guest or full evidence store does
not block polling the others. Service shutdown cancels the sweep.

This is best-effort collection of the guest's bounded ring, not lossless telemetry. A guest dying before
polling, a burst exceeding the ring, an initialization that never returns, or a host/storage failure can
still lose evidence. The existing seven-day export survives teardown. Headquarters ingestion, lifecycle reconciliation, browser telemetry and assigned-agent ticket routing are connected in 0.2.0; see enrollment.md.
