using System.Text.Json;
using CSweet.Isolation.Security;
using CSweet.WebHost.Contracts;

namespace CSweet.WebHost.Core;

/// <summary>Called only after the broker resolves live actor, provider, membership, and grant.
/// Caller-supplied grant records are never an authorization source.</summary>
public sealed class PreviewAdmission(DurableState state, TimeProvider clock)
{
    public Task<PreviewOperation> AdmitAsync(Guid organizationId, Guid installationId, PreviewRequest request,
        PreviewGrant liveGrant, CancellationToken token = default) => state.TransactionAsync(data =>
    {
        var now = clock.GetUtcNow();
        var digest = WorkloadAuthorizationEnvelope.Digest(JsonSerializer.Serialize(request, PreviewJson.Options));
        var previous = data.Operations.Values.SingleOrDefault(x => x.OrganizationId == organizationId &&
            x.InstallationId == installationId && x.IdempotencyKey == request.IdempotencyKey);
        var policy = PreviewPolicy.Evaluate(organizationId, installationId, request, liveGrant,
            WebPreviewCapabilities.Start,
            previous is null ? data.Operations.Values.Count(x => x.OrganizationId == organizationId &&
                x.ProjectId == request.ProjectId && Active(x, now)) : 0,
            previous is null ? data.ReservedCpuSeconds.GetValueOrDefault(liveGrant.Id) : 0, now);
        if (!policy.Allowed) throw new PreviewPolicyException(policy.Problems);
        if (previous is not null)
        {
            if (data.RequestDigests.GetValueOrDefault(previous.Id) != digest || previous.GrantId != liveGrant.Id ||
                previous.GrantRevision != liveGrant.Revision)
                throw new InvalidOperationException("The idempotency key is already bound to another request or grant revision.");
            return previous;
        }
        var operation = new PreviewOperation(Guid.NewGuid(), organizationId, request.ProjectId, installationId,
            request.ProviderInstallationId, liveGrant.Id, liveGrant.Revision, policy.ManifestDigest,
            request.IdempotencyKey, PreviewPhase.Requested, now, now.AddSeconds(request.Manifest.LifetimeSeconds));
        data.Operations.Add(operation.Id, operation);
        data.RequestDigests.Add(operation.Id, digest);
        data.ReservedCpuSeconds[liveGrant.Id] = checked(data.ReservedCpuSeconds.GetValueOrDefault(liveGrant.Id) +
            (long)request.Manifest.Resources.CpuCount * request.Manifest.LifetimeSeconds);
        return operation;
    }, token);

    private static bool Active(PreviewOperation operation, DateTimeOffset now) => operation.ExpiresAt > now &&
        operation.Phase is PreviewPhase.Requested or PreviewPhase.Building or PreviewPhase.Starting or PreviewPhase.Ready or
            PreviewPhase.Unhealthy or PreviewPhase.Stopping;
}
public sealed class PreviewPolicyException(IReadOnlyList<PreviewProblem> problems)
    : InvalidOperationException("The requested preview exceeds its current authority.")
{
    public IReadOnlyList<PreviewProblem> Problems { get; } = problems;
}
