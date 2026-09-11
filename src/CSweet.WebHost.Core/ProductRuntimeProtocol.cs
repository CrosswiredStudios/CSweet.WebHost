using CSweet.WebHost.Contracts;
namespace CSweet.WebHost.Core;
public sealed record ProductRuntimeRequest(SignedProductAssignment? Assignment = null, SignedProductControl? Control = null,
    long? ArtifactLength = null, bool Inspect = false);
public sealed record ProductRuntimeResponse(string Code, ProductRuntimeHandle? Handle = null,
    ProductGuestResponse? Guest = null, WebHostHeartbeat? Status = null, PreviewDiagnosticPage? Evidence = null, DateTimeOffset? LeaseExpiresAt = null);
