using System.Security.Cryptography;
using CSweet.Isolation.Security;
using CSweet.WebHost.Contracts;
namespace CSweet.WebHost.Core;

public sealed class ProductControlVerifier(WebHostEnrollment enrollment, DurableState state, TimeProvider clock)
{
    public async Task ClaimAsync(SignedProductControl command, CancellationToken token)
    {
        var now = clock.GetUtcNow();
        if (command.Version != 1 || command.WebHostId != enrollment.Id || command.CommandId == Guid.Empty ||
            command.WorkloadId == Guid.Empty || command.Action is not ("initialize" or "status" or "reconcile" or "diagnostics" or "evidence" or "http" or "stop" or "renew" or "test") ||
            command.BodyJson is not { Length: > 0 and <= ProductGuestProtocol.MaximumFrameBytes } ||
            command.SigningKeyId != enrollment.VerificationKeyId || string.IsNullOrWhiteSpace(command.SignatureBase64) ||
            command.IssuedAt > now || command.ExpiresAt <= now || command.ExpiresAt <= command.IssuedAt ||
            command.ExpiresAt-command.IssuedAt > TimeSpan.FromMinutes(1) ||
            command.IssuedAt.Ticks % TimeSpan.TicksPerSecond != 0 || command.ExpiresAt.Ticks % TimeSpan.TicksPerSecond != 0 ||
            !WorkloadAuthorizationEnvelope.IsDigest(command.BodyDigest) ||
            WorkloadAuthorizationEnvelope.Digest(command.BodyJson) != command.BodyDigest)
            throw new UnauthorizedAccessException("The product control authorization is invalid.");
        try
        {
            using var key = ECDsa.Create();
            var bytes = Convert.FromBase64String(enrollment.VerificationPublicKeyBase64);
            key.ImportSubjectPublicKeyInfo(bytes, out var read);
            if (read != bytes.Length || !key.VerifyData(command.Payload(),Convert.FromBase64String(command.SignatureBase64),HashAlgorithmName.SHA256))
                throw new UnauthorizedAccessException("The product control signature is invalid.");
        }
        catch (Exception error) when (error is FormatException or CryptographicException)
        { throw new UnauthorizedAccessException("The product control signature is invalid.",error); }
        await state.TransactionAsync(data =>
        {
            foreach (var expired in data.ControlCommands.Where(x => x.Value <= now).Select(x => x.Key).ToArray())
                data.ControlCommands.Remove(expired);
            if (data.ControlCommands.Count >= 100000) throw new InvalidOperationException("The runtime control budget is exhausted.");
            if (!data.ControlCommands.TryAdd(command.CommandId, command.ExpiresAt))
                throw new UnauthorizedAccessException("This product control was already consumed; reconcile its outcome with a new status request.");
            return true;
        },token);
    }
}
