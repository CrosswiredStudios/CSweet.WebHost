# Independent WebHost enrollment and installation

Node connects outbound to Headquarters over HTTPS. RuntimeHost is a separate privileged Windows service; the unprivileged Node exchanges only signed envelopes, verified artifact bytes and bounded results over its protected pipe.

## Operator setup

1. Install the Web Previews plugin in the business. Configure Headquarters CSweet:WebHost:ControlPlaneId, AuthorizationVerificationKeyId and AuthorizationVerificationPublicKeyBase64. The public key must match Execution:AuthorizationSigningKeyPem, supplied through protected operator configuration. Keep the private key out of tracked settings.
2. Set Execution:ReleaseVerificationPublicKeyBase64 to the independent release authority, and populate Execution:ApprovedReleases with the signed certificates for the exact approved runtime/image. Leave Execution:Enabled false until setup and acceptance are complete. Self-reported host certification is insufficient.
3. Configure Gateway:HeadquartersOrigin and Gateway:PreviewHostSuffix under CSweet:WebHost. Use a separate registrable site, e.g. https://hq.example.com and preview.example.net. Configure wildcard DNS and TLS for *.preview.example.net to the API. Do not share Headquarters cookies or authentication middleware with product origins. The preview middleware terminates those requests before Headquarters routing.
4. On the dedicated host, prepare a separate ECDSA P-256 operational identity. Keep its private key on that host. The business owner POSTs requestId, providerInstallationId, displayName, identityPublicKeyBase64, maximumCapacity and expiresAt to /api/core/organizations/{organizationId}/web-hosts/. Stable request IDs make registration retries idempotent. Identity lifetime is at most 90 days.
5. Save the returned WebHostBootstrap. Publish the Windows Node and RuntimeHost payloads in the hardened release workflow. Supply the independently certified Linux guest VHDX and exact runtime payload. See [acceptance](acceptance.md).
6. Review and run scripts/Install-WebHost.ps1 as an administrator on a fresh dedicated Hyper-V host. It requires the runtime and Node publish directories, image, signed certificate, pinned release public-key file, bootstrap, identity private-key file and exact Headquarters HTTPS origin. It validates the certificate before mutation, rejects unsafe paths/ancestor replacement permissions, sets explicit ACLs, creates separate SYSTEM/virtual-account services, registers the dedicated guest socket, and configures service recovery. It does not start services or launch VMs.
7. Review protected configuration under ProgramData/CSweet/WebHost, then start CSweet.WebHost.RuntimeHost followed by CSweet.WebHost.Node. Verify Node status and the owner host inventory. Apply the Headquarters migration through the normal deployment process, configure wildcard routing, and complete acceptance before enabling admission.

The fresh-host installer deliberately refuses an existing installation. Upgrade requires draining previews, preserving Node sequence state and reviewing the exact new certified release. Lost identity sequence state requires fresh owner enrollment; do not reset Headquarters replay history.

## Business and agent flow

The owner approves exact project hosting terms in the existing Approvals inbox. An authorized consuming agent preflights a successful BuildId plus immutable source manifest, starts with a stable key, polls the operation and reads diagnostics. Headquarters verifies every artifact and signs only current granted work. Static artifacts contain site files; container artifacts contain verified source/ files and offline images/*.tar inputs.

The Web Previews page appears only for businesses with the plugin. Team members see previews in their current project scope. The Open action mints a one-use, one-minute POST ticket. Its separate browser cookie lasts at most 30 minutes and never longer than the preview lease. Each request, range chunk and WebSocket operation rechecks membership and execution authority. Product cookies are separate and cannot replace the gateway cookie.

Owners can assign Software QA 0.7.0, a project board and a parent planning item for triage. The assigned agent reads canonical retained findings, uses its approved model, and files a deduplicated ticket only through ordinary board-scoped work-item permission. Evidence is copied into the ticket before the seven-day diagnostic retention window expires.

## Revocation, recovery and retention

Owners can revoke a host through /web-hosts/{hostId}/revoke or revoke standing hosting access in Approvals. Browser access closes on the next checked operation; stopping jobs retain their quota until protected teardown is acknowledged. Native hard/idle expiry remains active while Headquarters or Node is disconnected.

Signed heartbeat, poll, artifact and result exchanges bind audience, host, purpose, exact body, monotonic sequence and a maximum 60-second message lifetime. Node durably reserves sequence numbers, persists outcomes before acknowledgement and never repeats a VM mutation after an uncertain result. Headquarters reconciles stale commands. Expired/revoked host identities permit only cleanup polling, reconciliation, retained evidence and teardown acknowledgements; they cannot obtain artifacts or start products.

RuntimeHost collects bounded diagnostics independently, including a best-effort final capture before teardown. Headquarters sanitizes and binds evidence to the preview/project/build/source. Runtime and Headquarters retain raw evidence for seven days. Completed transport records retain acknowledgement digests, not diagnostic payload copies; HTTP payloads are discarded after delivery or bounded timeout cleanup. Ticket evidence deliberately survives runtime retention.

No services, real VMs, release certificates or public deployments were created by development verification. Build scheduling through the certified toolchain, in-place renewal and bounded headless browser jobs are implemented. Include the new operations in reviewed standing grants; older approvals do not automatically expand. See image-build.md and acceptance.md for operational release gates.
