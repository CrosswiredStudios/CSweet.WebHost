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
It strips credentials, cookies, forwarding and host headers. Response redirects and cookies are
not propagated. Static and container responses are bounded to 4 MiB per response currently.
Streaming large game assets, range responses and WebSockets remain required before general
game demos are supported.

The host associates every guest diagnostic with its canonical assignment, build, project and
source revision. Guest-provided identities cannot select another project. Diagnostics are
sanitized again before persistence. Signed evidence reads remain available after VM teardown, with
bounded pagination and seven-day retention; raw guest diagnostic responses do not leave this boundary.
These records remain evidence, not agent instructions. See [enrollment and evidence flow](enrollment.md).

## Certified image installation inputs

The build/product-guest files are provisioning inputs, not a finished or certified VM image.
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
