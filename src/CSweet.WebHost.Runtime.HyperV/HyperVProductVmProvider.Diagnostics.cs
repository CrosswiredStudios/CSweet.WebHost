using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using CSweet.WebHost.Contracts;
using CSweet.WebHost.Core;

namespace CSweet.WebHost.Runtime.HyperV;

public sealed partial class HyperVProductVmProvider
{
    public async Task<IReadOnlyList<Guid>> ListDiagnosticTargetsAsync(CancellationToken token)
    {
        await using var held = await LockAsync(token);
        // Initialization owns the guest connection until it completes. Poll only after it has
        // reported Ready or Failed, avoiding contention with an authorized long-running build.
        return (await ReadRecordsAsync(token)).Where(record => record.State is "Ready" or "Failed" &&
            record.VmId is not null && record.ExpiresAt > clock.GetUtcNow() &&
            (record.IdleExpiresAt ?? record.ExpiresAt) > clock.GetUtcNow()).Select(record => record.WorkloadId).ToArray();
    }

    public async Task CollectDiagnosticsAsync(Guid workloadId, DiagnosticStore store, CancellationToken token)
    {
        // Exchange revalidates ownership, the signature and the live lease. Only HTTP renews idle time.
        await ExchangeAsync(workloadId, new(Guid.NewGuid(), "diagnostics"), store, token);
    }
    public async Task RecordCollectionFailureAsync(Guid workloadId, DiagnosticStore store, CancellationToken token)
    {
        ProductVmRecord record;
        SignedProductAssignment assignment;
        await using (var held = await LockAsync(token))
        {
            record = (await ReadRecordsAsync(token)).Single(x => x.WorkloadId == workloadId);
            if (record.State == "Destroyed" || record.ExpiresAt <= clock.GetUtcNow() ||
                (record.IdleExpiresAt ?? record.ExpiresAt) <= clock.GetUtcNow()) return;
            var path = Path.Combine(InstanceDirectory(workloadId), "assignment.json");
            if (new FileInfo(path).Length > 2 * 1024 * 1024) throw new InvalidDataException("Protected assignment is too large.");
            assignment = JsonSerializer.Deserialize<SignedProductAssignment>(await File.ReadAllTextAsync(path, token), PreviewJson.Options)
                ?? throw new InvalidDataException("Protected assignment is unavailable.");
        }
        var spec = verifier.Verify(assignment);
        if (assignment.AssignmentId != record.AssignmentId || assignment.WorkloadId != workloadId)
            throw new InvalidDataException("Protected assignment identity changed.");
        var now = clock.GetUtcNow();
        var minute = new DateTimeOffset(now.UtcTicks - now.UtcTicks % TimeSpan.TicksPerMinute, TimeSpan.Zero);
        var occurredAt = minute < assignment.IssuedAt ? assignment.IssuedAt : minute;
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(assignment.AssignmentId.ToString("N") +
            ":host-diagnostics-unavailable:" + occurredAt.UtcTicks.ToString(System.Globalization.CultureInfo.InvariantCulture)));
        await store.RecordAsync(new(new Guid(hash.AsSpan(0, 16)), workloadId, spec.ProjectId, spec.BuildId,
            spec.Manifest.SourceRevision, "webhost", "runtime", "GuestDiagnosticsUnavailable",
            "The host could not retrieve guest diagnostics. The guest may be unavailable; reconcile its runtime status.",
            occurredAt, false), [], token);
    }
}

