using System.Net.Sockets;
using System.Text.Json;

namespace CSweet.WebHost.Core;

/// <summary>Local runtime inspection only. Implementations must derive targets from protected ownership
/// records and recheck their signed assignment before contacting a guest.</summary>
public interface IProductDiagnosticSource
{
    Task<IReadOnlyList<Guid>> ListDiagnosticTargetsAsync(CancellationToken token);
    Task CollectDiagnosticsAsync(Guid workloadId, DiagnosticStore store, CancellationToken token);
    Task RecordCollectionFailureAsync(Guid workloadId, DiagnosticStore store, CancellationToken token);
}

public sealed record DiagnosticCollectionResult(int Collected, int Failed);

public sealed class ProductDiagnosticCollector(IProductDiagnosticSource source, DiagnosticStore store)
{
    public async Task<DiagnosticCollectionResult> CollectAsync(CancellationToken token)
    {
        var targets = await source.ListDiagnosticTargetsAsync(token);
        if (targets.Count > 4096 || targets.Any(id => id == Guid.Empty) || targets.Distinct().Count() != targets.Count)
            throw new InvalidDataException("Diagnostic collection requires bounded unique owned workloads.");
        int collected = 0, failed = 0;
        await Parallel.ForEachAsync(targets, new ParallelOptions { MaxDegreeOfParallelism = 2, CancellationToken = token },
            async (id, cancellation) =>
            {
                using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
                deadline.CancelAfter(TimeSpan.FromSeconds(10));
                try
                {
                    await source.CollectDiagnosticsAsync(id, store, deadline.Token);
                    Interlocked.Increment(ref collected);
                }
                catch (Exception error) when (!cancellation.IsCancellationRequested &&
                    error is IOException or SocketException or UnauthorizedAccessException or InvalidOperationException or
                        ArgumentException or JsonException or OperationCanceledException or TimeoutException)
                {
                    Interlocked.Increment(ref failed);
                    // A timed-out guest uses a separate short persistence deadline. Shutdown still
                    // cancels this operation, and a full evidence store cannot block other guests.
                    using var evidenceDeadline = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
                    evidenceDeadline.CancelAfter(TimeSpan.FromSeconds(2));
                    try { await source.RecordCollectionFailureAsync(id, store, evidenceDeadline.Token); }
                    catch (Exception persistenceError) when (!cancellation.IsCancellationRequested &&
                        persistenceError is IOException or UnauthorizedAccessException or InvalidOperationException or
                            ArgumentException or JsonException or OperationCanceledException) { }
                }
            });
        return new(collected, failed);
    }
}

