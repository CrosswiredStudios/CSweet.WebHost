using CSweet.WebHost.Core;

namespace CSweet.WebHost.Tests;

public sealed class DiagnosticCollectionTests : IDisposable
{
    private readonly string statePath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
    public void Dispose() { if (Directory.Exists(statePath)) Directory.Delete(statePath, recursive: true); }

    private sealed class Source(IReadOnlyList<Guid> targets, Func<Guid, CancellationToken, Task> collect) : IProductDiagnosticSource
    {
        private int failureRecords;
        public int FailureRecords => failureRecords;
        public Task RecordCollectionFailureAsync(Guid id, DiagnosticStore store, CancellationToken token)
        { token.ThrowIfCancellationRequested(); Interlocked.Increment(ref failureRecords); return Task.CompletedTask; }
        public Task<IReadOnlyList<Guid>> ListDiagnosticTargetsAsync(CancellationToken token) => Task.FromResult(targets);
        public Task CollectDiagnosticsAsync(Guid id, DiagnosticStore store, CancellationToken token) => collect(id, token);
    }

    private ProductDiagnosticCollector Collector(IProductDiagnosticSource source) =>
        new(source, new DiagnosticStore(new DurableState(statePath), TimeProvider.System));

    [Fact]
    public async Task Polling_is_bounded_and_a_failed_guest_does_not_block_other_guests()
    {
        var ids = Enumerable.Range(0, 8).Select(_ => Guid.NewGuid()).ToArray();
        int active = 0, maximum = 0;
        var source = new Source(ids, async (id, token) =>
        {
            var current = Interlocked.Increment(ref active);
            lock (ids) maximum = Math.Max(maximum, current);
            try
            {
                await Task.Delay(10, token);
                if (id == ids[1]) throw new IOException("raw transport error is never exported");
                if (id == ids[2]) throw new OperationCanceledException("per-guest timeout");
            }
            finally { Interlocked.Decrement(ref active); }
        });
        var result = await Collector(source).CollectAsync(default);
        Assert.Equal(6, result.Collected);
        Assert.Equal(2, result.Failed);
        Assert.Equal(2, source.FailureRecords);
        Assert.InRange(maximum, 1, 2);
    }

    [Fact]
    public async Task Service_shutdown_cancels_the_sweep_instead_of_retrying_guests()
    {
        using var stop = new CancellationTokenSource();
        var source = new Source([Guid.NewGuid()], async (_, token) =>
        {
            stop.Cancel();
            await Task.Delay(Timeout.Infinite, token);
        });
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Collector(source).CollectAsync(stop.Token));
    }

    [Fact]
    public async Task Invalid_target_inventories_fail_before_contacting_any_guest()
    {
        var id = Guid.NewGuid();
        var calls = 0;
        foreach (var targets in new IReadOnlyList<Guid>[] { [Guid.Empty], [id, id], Enumerable.Range(0, 4097).Select(_ => Guid.NewGuid()).ToArray() })
        {
            var source = new Source(targets, (_, _) => { calls++; return Task.CompletedTask; });
            await Assert.ThrowsAsync<InvalidDataException>(() => Collector(source).CollectAsync(default));
        }
        Assert.Equal(0, calls);
    }
}


