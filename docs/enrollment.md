# Independent WebHost enrollment

This is implemented transport and registration code, not an installed or certified hosting release.
No inbound management listener is exposed by Node.

## Owner and installer flow

1. Install the optional Web Previews plugin in the business. Registration checks its current installation
   and organization grant; disabling the plugin disables subsequent heartbeats.
2. The hardened installer provisions a dedicated Node account and a fresh ECDSA P-256 operational identity.
   Keep the private key on that host. It is distinct from Office credentials, agent identities,
   Headquarters workload-signing keys and release-certification keys.
3. A current human business owner registers the public key with
   POST /api/core/organizations/{organizationId}/web-hosts/.
   The request contains requestId, providerInstallationId, displayName, identityPublicKeyBase64,
   maximumCapacity and expiresAt. Use a stable requestId for retries; changed terms or a previously used
   identity key are rejected. Identity expiry is bounded to 90 days.
4. Headquarters must have CSweet:WebHost:ControlPlaneId, AuthorizationVerificationKeyId and
   AuthorizationVerificationPublicKeyBase64 configured by its operator. No fallback signing key is generated.
   Registration returns a WebHostBootstrap with the assigned host ID, business, control-plane audience,
   identity expiry and public workload-verification material. These are public configuration values.
5. The installer writes ProgramData/CSweet/WebHost/node.json with headquartersOrigin, bootstrap,
   identityPrivateKeyPath and stateRoot. It writes the matching enrollment into the separate protected
   runtime-host.json configuration. Node cannot change the privileged runtime's trust anchors.
6. Run CSweet.WebHost.Node run under the dedicated Node account. It reads the SYSTEM-owned runtime pipe,
   signs a heartbeat and posts it over HTTPS every 30 seconds. RuntimeHost must already be installed;
   its service registration/recovery and real certification remain release work.
7. Owners can list registrations or POST /{hostId}/revoke. Revocation disables the host identity and
   preview access immediately in Headquarters, while retaining Stopping jobs until physical teardown is
   confirmed. Independent VM leases remain the disconnected-host backstop. Stop delivery is still pending.

The Node configuration and identity files must be administrator/SYSTEM-owned and protected against
replacement by other accounts, including through parent directories. The private key is readable only
by the Node account, SYSTEM and administrators. The state directory is dedicated to Node, separate from
RuntimeHost protected state. Preserve it across restarts. Recovery from lost sequence state requires
a fresh owner-approved enrollment rather than resetting Headquarters replay history.

## Authentication boundary

Signed heartbeats bind a WebHost-specific purpose, control-plane audience, host, request ID, monotonically
increasing sequence, action, exact body digest and a maximum 60-second validity window. Headquarters
consumes the sequence with an optimistic database concurrency token; replay and stale concurrent
requests cannot both commit. Node reserves each sequence durably before sending. Lost responses consume
a sequence; subsequent heartbeats use a new one.

The transport requires the exact HTTPS Headquarters origin, normal certificate validation, no redirects,
no proxy, no cookies and no inherited/default credentials. Both request and response bodies and read
times are bounded. The heartbeat endpoint has a per-source request limit and independently verifies
the signed host identity instead of accepting browser, agent or Office authentication.

Connected is inventory status only. Self-reported Certified=true never authorizes execution.
Registration views and receipts report ExecutionReady=false until independently verified certification,
transactional scheduling, signed dispatch and artifact provenance are connected.

## Evidence flow implemented in RuntimeHost

A signed diagnostics command captures live guest logs into canonical, sanitized host records.
A separately signed evidence command reads those records without requiring a live VM.
Its ProductGuestRequest includes diagnosticAfterSequence; pages contain at most 100 events with
host-assigned sequences and NextSequence/HasMore continuation. Each event retains its exact preview,
project, build and source revision. Raw guest diagnostics are not forwarded to Node.

Evidence expires seven days after the event, and replay cannot extend that window. Reads exclude expired
events immediately; an independent hourly worker removes expired records and finding references even
when Headquarters is disconnected. Headquarters ingestion and triage/ticket attachment must copy
authorized evidence before expiry. That downstream integration is still pending.
