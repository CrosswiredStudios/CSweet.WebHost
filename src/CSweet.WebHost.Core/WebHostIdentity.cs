using System.Security.Cryptography;
using CSweet.Isolation.Security;
using CSweet.WebHost.Contracts;
namespace CSweet.WebHost.Core;

public static class WebHostIdentity
{
    public static void ValidatePublicKey(string publicKeyBase64)
    {
        using var key = ImportPublicKey(publicKeyBase64);
    }
    public static void Verify(SignedWebHostMessage message, Guid controlPlaneId, Guid webHostId,
        string publicKeyBase64, long lastSequence, DateTimeOffset now)
    {
        if (message.Version != 1 || controlPlaneId == Guid.Empty || message.ControlPlaneId != controlPlaneId ||
            webHostId == Guid.Empty || message.WebHostId != webHostId || message.RequestId == Guid.Empty ||
            message.Sequence <= lastSequence || message.Sequence < 1 || message.Action != "heartbeat" ||
            message.BodyJson is not { Length: > 0 and <= 1048576 } ||
            !WorkloadAuthorizationEnvelope.IsDigest(message.BodyDigest) ||
            WorkloadAuthorizationEnvelope.Digest(message.BodyJson) != message.BodyDigest ||
            message.IssuedAt > now.AddSeconds(5) || message.ExpiresAt <= now ||
            message.ExpiresAt <= message.IssuedAt || message.ExpiresAt - message.IssuedAt > TimeSpan.FromMinutes(1) ||
            message.IssuedAt.Ticks % TimeSpan.TicksPerSecond != 0 || message.ExpiresAt.Ticks % TimeSpan.TicksPerSecond != 0 ||
            message.SignatureBase64 is not { Length: > 0 and <= 256 })
            throw new UnauthorizedAccessException("The WebHost identity proof is invalid or was already consumed.");
        try
        {
            using var key = ImportPublicKey(publicKeyBase64);
            if (!key.VerifyData(message.Payload(), Convert.FromBase64String(message.SignatureBase64), HashAlgorithmName.SHA256))
                throw new UnauthorizedAccessException("The WebHost identity proof is invalid.");
        }
        catch (Exception error) when (error is FormatException or CryptographicException or ArgumentException)
        { throw new UnauthorizedAccessException("The WebHost identity proof is invalid.", error); }
    }
    private static ECDsa ImportPublicKey(string publicKeyBase64)
    {
        if (publicKeyBase64 is not { Length: > 0 and <= 256 })
            throw new ArgumentException("A WebHost identity must be an ECDSA P-256 public key.");
        var key = ECDsa.Create();
        try
        {
            var bytes = Convert.FromBase64String(publicKeyBase64);
            key.ImportSubjectPublicKeyInfo(bytes, out var read);
            if (read != bytes.Length || key.ExportParameters(false).Curve.Oid.Value != "1.2.840.10045.3.1.7" ||
                Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()) != publicKeyBase64)
                throw new ArgumentException("A WebHost identity must be an ECDSA P-256 public key.");
            return key;
        }
        catch { key.Dispose(); throw; }
    }
}
