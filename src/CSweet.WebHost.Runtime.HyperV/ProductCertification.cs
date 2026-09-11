using System.Security.Cryptography;
using System.Text.Json;
using CSweet.Isolation.Security;
using CSweet.WebHost.Contracts;

namespace CSweet.WebHost.Runtime.HyperV;

public sealed record ProductCertification(string Purpose, string ProviderId, string ProviderVersion,
    string GuestImageDigest, string SuiteVersion, IReadOnlyList<string> Controls, IReadOnlyDictionary<string,string> RuntimeFiles,
    DateTimeOffset IssuedAt, DateTimeOffset ExpiresAt);
public sealed record SignedProductCertification(string CertificateJson, string SignatureBase64);
public static class ProductCertificationVerifier
{
    public const string Purpose = CSweet.WebHost.Core.ProductReleaseCertificationVerifier.Purpose;
    public static readonly IReadOnlyList<string> RequiredControls = CSweet.WebHost.Core.ProductReleaseCertificationVerifier.RequiredControls;
    public static ProductCertification Verify(SignedProductCertification envelope, string pinnedPublicKey,
        string providerId, string providerVersion, string guestImageDigest, DateTimeOffset now)
    {
        var certificate = CSweet.WebHost.Core.ProductReleaseCertificationVerifier.Verify(
            new(envelope.CertificateJson, envelope.SignatureBase64), pinnedPublicKey, providerId, providerVersion, guestImageDigest, now);
        return new(certificate.Purpose, certificate.ProviderId, certificate.ProviderVersion, certificate.GuestImageDigest,
            certificate.SuiteVersion, certificate.Controls, certificate.RuntimeFiles, certificate.IssuedAt, certificate.ExpiresAt);
    }
}