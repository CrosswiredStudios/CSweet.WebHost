using CSweet.WebHost.Contracts;

namespace CSweet.WebHost.Core;

public sealed record ProductRuntimeHandle(Guid AssignmentId, Guid WorkloadId, string ProviderInstanceId);
/// <summary>Implemented only by a certified product VM provider. Never by a host Docker runner.</summary>
public interface IProductVmProvider
{
    Task<ProductProviderStatus> ProbeAsync(CancellationToken token);
    Task<ProductRuntimeHandle> StartAsync(SignedProductAssignment assignment, ProductWorkloadSpecification spec, CancellationToken token);
    Task StopAndDestroyAsync(ProductRuntimeHandle handle, CancellationToken token);
}
public sealed class ProductRuntime(AssignmentVerifier verifier, AssignmentLedger ledger, DurableState state,
    IEnumerable<IProductVmProvider> providers, TimeProvider clock)
{
    public async Task<ProductRuntimeHandle?> StartAsync(SignedProductAssignment assignment, CancellationToken token)
    {
        var spec = verifier.Verify(assignment);
        IProductVmProvider? selected = null;
        foreach (var provider in providers)
        {
            var probe = await provider.ProbeAsync(token);
            if (probe.Id == assignment.ProviderId && probe.Available && probe.Certified &&
                probe.CertificationExpiresAt > clock.GetUtcNow() && probe.GuestImageDigest == spec.GuestImageDigest)
            { selected = provider; break; }
        }
        if (selected is null) throw new InvalidOperationException("No certified product VM provider is available. Host Docker fallback is forbidden.");
        if (!await ledger.ClaimAsync(assignment, token)) return null;
        // The provider must independently verify the signature and lease within its privileged boundary.
        // Claimed is intentionally durable before the side effect. Unknown outcomes require reconciliation,
        // never a second launch using the same or a new idempotency key.
        return await selected.StartAsync(assignment, spec, token);
    }
    public Task<IReadOnlyList<AssignmentReceipt>> ExpiredAsync(CancellationToken token = default) =>
        state.TransactionAsync<IReadOnlyList<AssignmentReceipt>>(data =>
            data.Assignments.Values.Where(x => x.ExpiresAt <= clock.GetUtcNow() && x.State != "Destroyed").ToList(), token);
}
