# C-Sweet WebHost

Optional product preview execution service, independent of Office. Version 0.1.0 remains
**in development, not an operational hosting release**.

Implemented code includes:

- Strict static/container manifest validation and constrained Compose normalization.
- Scoped grant policy, atomic local quota admission and persistent assignment/control replay protection.
- A separate Windows RuntimeHost service, signed control requests, protected VM identity records and expiry worker.
- A Hyper-V product provider requiring release certification covering the exact runtime payload and guest image.
- A dedicated Linux product guest for verified ZIP artifacts, static responses, offline image import/build,
  normalized container execution, health checks and sanitized diagnostics. Product commands execute only inside the guest.
- Bounded guest HTTP forwarding to a fixed local entry point, without host credentials or cookies.
- Automatic bounded guest diagnostic polling, atomic sanitized snapshots and canonical preview/project/build/source binding.
- Outbound HTTPS Node heartbeats with a separate operational identity, durable sequence reservation and protected runtime inventory.
- Signed diagnostic exports after VM teardown, seven-day retention, independent cleanup and 30-minute idle expiry.
- Persistent physical VM storage reservations, conservative free-space admission and interrupted-creation cleanup.
- Guest provisioning inputs and behavioral tests.

See [the product runtime boundary](docs/product-runtime.md) for the protocol, installation requirements
and explicit current limitations.

Build and test:

```powershell
dotnet build CSweet.WebHost.slnx -c Release
dotnet test tests/CSweet.WebHost.Tests -c Release
```

Headquarters has a separate grant proposal/owner approval integration. Its current preflight checks
the installed plugin and current authority, but reports RuntimeUnavailable because certified scheduling
and dispatch are not connected yet. Owner-managed host registration and revocation are implemented; see [enrollment](docs/enrollment.md).

Still required before live hosting:

1. A built product guest image, installer and hardened real-VM certification.
2. Authenticated command dispatch and source/build artifact integration; local protected artifact ingestion is implemented.
3. Transactional Headquarters admission, provider scheduling, build/preview record integration and lifecycle reconciliation.
4. Private gateway sessions, isolated preview origins, live membership checks, streaming/ranges and WebSockets.
5. Browser tests, Headquarters diagnostic ingestion and finding-to-agent-to-ticket delivery.
6. The complete real static/game/server/database acceptance scenarios.

The Node executable provides `validate <preview.json>`, `status` and `run`. Readiness intentionally
reports not ready. RuntimeHost code is compiled but not installed. No product VM has been launched.
The local admission store is not a distributed Headquarters quota service. A claimed assignment
survives uncertain startup and must be reconciled, never relaunched with a fresh idempotency key.

Sibling checkouts are detected automatically. Clone CSweet.Isolation, CSweet.WebHost.Contracts and CSweet.Office.Contracts beside this repository. Explicit UseLocal properties set to false retain package-only release validation. No NuGet publication is needed for local source builds.
