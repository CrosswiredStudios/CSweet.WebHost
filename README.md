# C-Sweet WebHost

Version 0.2.0 implements private product preview hosting independently of Office. Product code runs only in disposable, independently certified Hyper-V guests. Installation and real-VM certification have not been performed in this development workspace.

The implementation includes signed outbound Node dispatch, verified static/container build artifacts, transactional Headquarters admission, durable command acknowledgements, crash reconciliation, independent lease/idle enforcement, a private browser gateway, bounded ranges and WebSockets, product cookie isolation, browser failure reporting, retained diagnostics, and owner-assigned QA triage with deduplicated work tickets.

Defaults are two previews per project, 2 vCPU/4 GiB/10 GiB each, two-hour hard expiry, 30-minute idle expiry and seven-day diagnostics. Quota remains occupied until protected physical teardown is confirmed. An owner must install the optional Web Previews plugin and approve scoped standing access. A self-reported certified host never grants execution authority.

## Development

Clone CSweet.Isolation, CSweet.WebHost.Contracts and CSweet.Office.Contracts beside this repository. Sibling source references are automatic; no NuGet publication is needed locally. Explicit UseLocal properties set to false support package-only release verification.

```powershell
dotnet build CSweet.WebHost.slnx -c Release
dotnet test tests/CSweet.WebHost.Tests -c Release
```

See [enrollment and installation](docs/enrollment.md), [the runtime boundary](docs/product-runtime.md), and [operational acceptance](docs/acceptance.md).

The Node CLI provides validate, status, run, and read-only verify-release commands. The installer configures separate Windows services and ACLs but does not start them. It requires an independently signed certificate for the exact runtime payload and guest image.

## Limits and release work

This is a private demo/test host, not public or production hosting. Internet egress and external connection brokering are disabled. Container image inputs and build dependencies must be provided offline. Runtime diagnostics are bounded, best effort; they are not lossless logs.

The gateway supports 4 MiB transfers and contiguous asset ranges up to 256 MiB. WebSockets use bounded 64 KiB messages, eight buffered guest messages, at most 16 sockets per guest and a two-minute orphan timeout. The durable control transport adds latency; this is not a low-latency multiplayer service.

Build requests reuse the existing certified toolchain scheduler. In-place signed renewal preserves the live guest within its original grant and total lifetime budget. Bounded headless Chromium checks run as an unprivileged process inside that guest and export sanitized failures for QA. New source or artifact content requires a new preview.

The offline image builder is documented in [image builds](docs/image-build.md). Hardened real-VM certification and the complete static/game/server/database acceptance suite must pass against the exact installed release before operational use.
