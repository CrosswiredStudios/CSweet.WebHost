using System.Text.Json;
using CSweet.Isolation.Security;
using CSweet.WebHost.Contracts;

namespace CSweet.WebHost.Core;

public static class PreviewPolicy
{
    public static PreviewPreflight Evaluate(Guid organizationId, Guid installationId, PreviewRequest request,
        PreviewGrant grant, string capability, int activePreviews, long reservedCpuSeconds, DateTimeOffset now)
    {
        var problems = ManifestValidator.Validate(request.Manifest).ToList();
        if (request.Manifest is null) return new(false, problems, WorkloadAuthorizationEnvelope.Digest("null"));
        void Deny(string field, string message) => problems.Add(new("GrantRequired", field, message));
        if (grant.Revoked || grant.ExpiresAt <= now || grant.Id == Guid.Empty || grant.Revision < 1 ||
            grant.OrganizationId != organizationId || grant.InstallationId != installationId ||
            grant.ProjectId != request.ProjectId || grant.ProviderInstallationId != request.ProviderInstallationId)
            Deny("grant", "A current grant for this installation, project, and provider is required.");
        if (!grant.Capabilities.Contains(capability, StringComparer.Ordinal)) Deny("capability", "The operation needs an explicit capability grant.");
        if (!grant.RepositoryIds.Contains(request.RepositoryId)) Deny("repositoryId", "This source repository is not granted.");
        if (request.Manifest.Resources is not null && !request.Manifest.Resources.Fits(grant.MaximumResources))
            Deny("resources", "Request a larger resource allowance.");
        if (request.Manifest.LifetimeSeconds > grant.MaximumLifetimeSeconds ||
            now.AddSeconds(request.Manifest.LifetimeSeconds) > grant.ExpiresAt)
            Deny("lifetimeSeconds", "The requested lifetime exceeds the grant.");
        if (activePreviews < 0 || activePreviews >= grant.MaximumConcurrentPreviews)
            Deny("concurrency", "No preview slot is available.");
        var cpuSeconds = (long)(request.Manifest.Resources?.CpuCount ?? 0) * request.Manifest.LifetimeSeconds;
        if (reservedCpuSeconds < 0 || cpuSeconds < 0 || reservedCpuSeconds > grant.MaximumCpuSeconds ||
            cpuSeconds > grant.MaximumCpuSeconds - reservedCpuSeconds)
            Deny("usage", "The request exceeds the remaining CPU-time budget.");
        foreach (var connection in request.Manifest.ConnectionIds ?? [])
            if (!grant.ConnectionIds.Contains(connection, StringComparer.Ordinal)) Deny("connectionIds", "An external connection requires its own grant.");
        if (string.IsNullOrWhiteSpace(request.IdempotencyKey) || request.IdempotencyKey.Length > 200)
            problems.Add(new("InvalidRequest", "idempotencyKey", "Supply a stable request key of at most 200 characters."));
        var digest = WorkloadAuthorizationEnvelope.Digest(JsonSerializer.Serialize(request.Manifest, PreviewJson.Options));
        return new(problems.Count == 0, problems, digest);
    }
}
