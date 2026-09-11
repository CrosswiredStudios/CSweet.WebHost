using System.Text.Json;
using CSweet.WebHost.Contracts;
namespace CSweet.WebHost.Core;

public static class ProductRenewal
{
    public static ProductWorkloadSpecification Validate(SignedProductAssignment previous, SignedProductAssignment next, AssignmentVerifier verifier)
    {
        var prior = verifier.Verify(previous); var renewed = verifier.Verify(next);
        if (previous == next) return renewed;
        if (next.WorkloadId != previous.WorkloadId || next.AssignmentId != previous.AssignmentId || next.WebHostId != previous.WebHostId ||
            next.ProviderId != previous.ProviderId || next.SigningKeyId != previous.SigningKeyId || next.IssuedAt != previous.IssuedAt ||
            next.FencingEpoch != checked(previous.FencingEpoch + 1) || next.ExpiresAt <= previous.ExpiresAt ||
            renewed.Manifest.LifetimeSeconds <= prior.Manifest.LifetimeSeconds ||
            JsonSerializer.Serialize(prior with { Manifest = prior.Manifest with { LifetimeSeconds = renewed.Manifest.LifetimeSeconds } }, PreviewJson.Options) !=
            JsonSerializer.Serialize(renewed, PreviewJson.Options))
            throw new UnauthorizedAccessException("Renewal may extend only the lifetime of the exact live workload.");
        return renewed;
    }
}
