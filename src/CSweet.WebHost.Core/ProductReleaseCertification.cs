using System.Security.Cryptography;
using System.Text.Json;
using CSweet.Isolation.Security;
using CSweet.WebHost.Contracts;

namespace CSweet.WebHost.Core;

public sealed record ProductReleaseCertification(string Purpose, string ProviderId, string ProviderVersion,
    string GuestImageDigest, string SuiteVersion, IReadOnlyList<string> Controls, IReadOnlyDictionary<string,string> RuntimeFiles,
    DateTimeOffset IssuedAt, DateTimeOffset ExpiresAt);
public sealed record SignedProductReleaseCertification(string CertificateJson, string SignatureBase64);
public static class ProductReleaseCertificationVerifier
{
    public const string Purpose = "CSweet.WebHost.ProductVmCertification.v1";
    public static readonly IReadOnlyList<string> RequiredControls =
        ["dedicated-kernel", "no-external-network-device", "read-only-artifacts", "cpu-memory-disk-limits",
         "guest-product-protocol-v1", "independent-lease-reaper", "no-agent-identity", "signed-lease-renewal", "bounded-browser-tests"];
    public static ProductReleaseCertification Verify(SignedProductReleaseCertification envelope, string pinnedPublicKey,
        string providerId, string providerVersion, string guestImageDigest, DateTimeOffset now)
    {
        if (envelope.CertificateJson is not { Length: > 0 and <= 65536 } || string.IsNullOrWhiteSpace(envelope.SignatureBase64)) throw new InvalidDataException("Certification exceeds the input limit.");
        using var key = ECDsa.Create();
        var bytes = Convert.FromBase64String(pinnedPublicKey);
        key.ImportSubjectPublicKeyInfo(bytes, out var read);
        if (read != bytes.Length || !key.VerifyData(System.Text.Encoding.UTF8.GetBytes(envelope.CertificateJson),
            Convert.FromBase64String(envelope.SignatureBase64), HashAlgorithmName.SHA256))
            throw new UnauthorizedAccessException("The product runtime certification is not signed by the pinned release authority.");
        var certificate = JsonSerializer.Deserialize<ProductReleaseCertification>(envelope.CertificateJson, PreviewJson.Options)
            ?? throw new InvalidDataException("Certification is missing.");
        if (certificate.Purpose != Purpose || certificate.ProviderId != providerId ||
            certificate.ProviderVersion != providerVersion || certificate.GuestImageDigest != guestImageDigest ||
            !WorkloadAuthorizationEnvelope.IsDigest(certificate.GuestImageDigest) ||
            certificate.SuiteVersion != "1" || certificate.RuntimeFiles is not { Count: > 0 and <= 512 } || certificate.IssuedAt > now || certificate.ExpiresAt <= now ||
            certificate.Controls is null || RequiredControls.Except(certificate.Controls, StringComparer.Ordinal).Any())
            throw new UnauthorizedAccessException("The product runtime certification does not cover this provider and image.");
        foreach (var file in certificate.RuntimeFiles)
            if (file.Key.Length is < 1 or > 128 || file.Key.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not ('.' or '-' or '_')) ||
                file.Key is "." or ".." || !WorkloadAuthorizationEnvelope.IsDigest(file.Value))
                throw new UnauthorizedAccessException("The product runtime certification contains an invalid payload entry.");
        return certificate;
    }
}

