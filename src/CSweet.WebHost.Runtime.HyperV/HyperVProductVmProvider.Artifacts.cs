using CSweet.Isolation.Security;
using CSweet.WebHost.Contracts;
namespace CSweet.WebHost.Runtime.HyperV;

public sealed partial class HyperVProductVmProvider
{
    public async Task IngestArtifactAsync(SignedProductAssignment assignment, long length, Stream input, CancellationToken token)
    {
        var spec = verifier.Verify(assignment);
        if (assignment.ProviderId != Id || spec.GuestImageDigest != configuration.GuestImageDigest ||
            !spec.Manifest.Resources.Fits(configuration.HostCapacity) ||
            !WorkloadAuthorizationEnvelope.IsDigest(spec.Manifest.ArtifactDigest) ||
            length < 1 || length > uint.MaxValue || length > checked((long)spec.Manifest.Resources.DiskMb * 1024 * 1024 / 2))
            throw new UnauthorizedAccessException("The artifact exceeds its exact authorized input bounds.");
        var certification = await VerifyReleaseAsync(token);
        if (assignment.ExpiresAt > certification.ExpiresAt) throw new UnauthorizedAccessException("The product authorization exceeds certification.");
        await ArtifactCache().IngestAsync(spec.Manifest.ArtifactDigest!, length, assignment.ExpiresAt, input,
            () => { verifier.Verify(assignment); }, token);
    }

    public Task<int> ReapArtifactsAsync(CancellationToken token) => ArtifactCache().PruneAsync(token);

    private ProductArtifactCache ArtifactCache()
    {
        // Cleanup must still work after a release certificate expires, but never relax the protected path boundary.
        WindowsProtectedPaths.Verify(configuration.ArtifactMediaRoot);
        return new(ProtectedRoot(configuration.ArtifactMediaRoot), configuration.MaximumArtifactCacheBytes, clock);
    }
}
