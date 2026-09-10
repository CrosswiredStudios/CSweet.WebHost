using System.Security.Cryptography;
using System.Text.Json;
using CSweet.Isolation.Security;
using CSweet.WebHost.Contracts;

namespace CSweet.WebHost.Core;

public sealed class AssignmentVerifier(WebHostEnrollment enrollment, TimeProvider clock)
{
    public WebHostEnrollment Enrollment => enrollment;
    public ProductWorkloadSpecification Verify(SignedProductAssignment assignment)
    {
        var now = clock.GetUtcNow();
        if (assignment.Version != 1 || assignment.WebHostId != enrollment.Id ||
            assignment.AssignmentId == Guid.Empty || assignment.WorkloadId == Guid.Empty || assignment.FencingEpoch < 1 ||
            assignment.SigningKeyId != enrollment.VerificationKeyId || assignment.IssuedAt > now ||
            assignment.ExpiresAt <= now || assignment.ExpiresAt <= assignment.IssuedAt ||
            assignment.SpecificationJson is not { Length: > 0 and <= 1048576 } ||
            string.IsNullOrWhiteSpace(assignment.ProviderId) || string.IsNullOrWhiteSpace(assignment.SignatureBase64) ||
            assignment.IssuedAt.Ticks % TimeSpan.TicksPerSecond != 0 || assignment.ExpiresAt.Ticks % TimeSpan.TicksPerSecond != 0 ||
            !WorkloadAuthorizationEnvelope.IsDigest(assignment.SpecificationDigest) ||
            WorkloadAuthorizationEnvelope.Digest(assignment.SpecificationJson) != assignment.SpecificationDigest)
            throw new UnauthorizedAccessException("The assignment identity, lifetime, or digest is invalid.");
        try
        {
            using var key = ECDsa.Create();
            var publicKey = Convert.FromBase64String(enrollment.VerificationPublicKeyBase64);
            key.ImportSubjectPublicKeyInfo(publicKey, out var read);
            if (read != publicKey.Length || !key.VerifyData(assignment.Payload(),
                Convert.FromBase64String(assignment.SignatureBase64), HashAlgorithmName.SHA256))
                throw new UnauthorizedAccessException("The assignment signature is invalid.");
        }
        catch (Exception error) when (error is CryptographicException or FormatException)
        { throw new UnauthorizedAccessException("The assignment signature is invalid.", error); }
        var spec = JsonSerializer.Deserialize<ProductWorkloadSpecification>(assignment.SpecificationJson, PreviewJson.Options)
            ?? throw new InvalidDataException("The product specification is missing.");
        if (spec.Version != 1 || spec.OrganizationId == Guid.Empty || spec.ProjectId == Guid.Empty ||
            spec.InstallationId == Guid.Empty || spec.ProviderInstallationId == Guid.Empty ||
            spec.GrantId == Guid.Empty || spec.GrantRevision < 1 || spec.RepositoryId == Guid.Empty ||
            spec.BuildId == Guid.Empty || !Enum.IsDefined(spec.Kind) ||
            !WorkloadAuthorizationEnvelope.IsDigest(spec.GuestImageDigest) || ManifestValidator.Validate(spec.Manifest).Count > 0)
            throw new InvalidDataException("The product specification is invalid.");
        if (assignment.ExpiresAt - assignment.IssuedAt > TimeSpan.FromSeconds(spec.Manifest.LifetimeSeconds))
            throw new UnauthorizedAccessException("The assignment exceeds the approved product lifetime.");
        return spec;
    }
}
