# Operational acceptance for WebHost 0.2.0

Run this suite in the hardened platform environment against the exact published RuntimeHost payload and Linux guest image. Unit tests and an operator-written certificate are not substitutes for these checks. Retain the measured results and image/runtime hashes with the release. Signing keys must remain in the approved release workflow.

## Required boundary checks

- Verify a dedicated guest kernel, absence of a network adapter, read-only root/boot/artifact media, disposable bounded scratch storage and absence of Office, agent, MCP or organizational credentials.
- Attempt resource exhaustion for CPU, RAM, processes, logs, scratch disk and container volumes. Observe physical host disk use including sparse/differencing growth, media, paging and controller crash recovery. Admission reservations alone do not establish a hard physical quota.
- Try unprivileged changes to service binaries, configuration, trust anchors, pipe ownership, VM identity records, ancestors and reparse points. Node must not acquire Hyper-V or protected-state write authority.
- Reject forged/expired/wrong-purpose assignments, mismatched image/runtime hashes, artifact substitutions, ZIP traversal/symlinks and workload replay. A delayed start after stop must never create a VM.
- Disconnect Node/Headquarters, kill guest and controllers, restart services and reboot the host during upload/start/initialization/stop. Confirm hard and idle expiry, independent cleanup, durable fencing and no duplicate physical execution. Retain quota until teardown is confirmed.
- Prove product traffic cannot reach host/HQ services, private management sockets or external destinations. Exercise container networking and build isolation with adversarial Dockerfiles and images.

## Product flow checks

1. Build a static site and a browser game through the certified toolchain, verify public artifact hashes, approve scoped grants, preflight and start. Load HTML, JS, WASM and ranged assets through wildcard TLS. Confirm wrong project/user/origin fails.
2. Build an offline container application with a database and WebSocket endpoint. Verify its container health, cookie-based product sessions, bidirectional text/binary messages, resource bounds and loss of disposable state after stop.
3. Remove team membership, revoke the provider/agent/grant/host, expire browser tickets/sessions and cancel requests while traffic is active. Confirm no credential forwarding and bounded closure/cleanup.
4. Trigger build, runtime, HTTP and browser errors. Observe canonical sanitized evidence and finding IDs, deduplication, assigned QA delivery and a board-authorized ticket with copied evidence. Remove board permission and prove filing fails without side effects.
5. Stop/expire the preview, read retained evidence, advance retention and verify runtime/HQ payload removal while copied ticket evidence remains. Replay evidence/outcomes and prove retention and ticket identity do not change.

6. Renew a short-lived preview within its standing limit and verify the same VM, files, database and workload identity survive beyond the old deadline. Reject altered resources, source, expired leases, excessive total lifetime and insufficient CPU budgets. Kill controllers between guest acknowledgement and protected persistence; confirm conservative deadlines and recovery. Record the signed-lease-renewal control.
7. Run Chromium checks for a static game and container app, including delayed DOM, JavaScript errors, failed selectors and unreachable pages. Prove external navigation, downloads, service workers and arbitrary scripts cannot expand test authority. Verify browser sandboxing, the dedicated UID, process timeout/kill, evidence bounds, rerun idempotency and seven-day deletion. Record the bounded-browser-tests control.

## Release status

The development tests cover protocol behavior, provenance, policy, dispatch, gateway transport, diagnostic binding and ticket permission checks. No hardened real-VM acceptance was run in the development workspace. The offline image builder, in-place renewal, toolchain build scheduling and bounded headless jobs are implemented. Complete physical-bound certification and installed-release acceptance must still be performed and recorded before operational use.
