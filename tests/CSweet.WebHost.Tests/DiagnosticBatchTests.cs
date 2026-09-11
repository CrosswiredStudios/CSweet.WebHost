using CSweet.WebHost.Contracts;
using CSweet.WebHost.Core;

namespace CSweet.WebHost.Tests;

public sealed class DiagnosticBatchTests : IDisposable
{
    private readonly string path = Path.Combine(Path.GetTempPath(), "csweet-batch-" + Guid.NewGuid().ToString("N"));
    public void Dispose() { if (Directory.Exists(path)) Directory.Delete(path, recursive: true); }
    private static PreviewDiagnostic Event(Guid preview) => new(Guid.NewGuid(), preview, Guid.NewGuid(), Guid.NewGuid(),
        new string('a', 40), "web", "runtime", "Crash", "password=sensitive", DateTimeOffset.UtcNow, false);

    [Fact]
    public async Task Repeated_snapshots_are_deduplicated_and_keep_original_export_sequences()
    {
        var preview = Guid.NewGuid(); var events = new[] { Event(preview), Event(preview) };
        var store = new DiagnosticStore(new DurableState(path), TimeProvider.System);
        await store.RecordBatchAsync(events, []);
        var before = await store.ReadAsync(preview);
        await store.RecordBatchAsync(events, []);
        var after = await store.ReadAsync(preview);
        Assert.Equal(2, after.Items.Count);
        Assert.Equal(before.NextSequence, after.NextSequence);
        Assert.All(after.Items, item => Assert.DoesNotContain("sensitive", item.Diagnostic.Summary));
    }

    [Fact]
    public async Task A_conflicting_late_event_rolls_back_the_entire_batch()
    {
        var preview = Guid.NewGuid(); var existing = Event(preview); var candidate = Event(preview);
        var store = new DiagnosticStore(new DurableState(path), TimeProvider.System);
        await store.RecordAsync(existing, []);
        await Assert.ThrowsAsync<InvalidOperationException>(() => store.RecordBatchAsync(
            [candidate, existing with { BuildId = Guid.NewGuid() }], []));
        Assert.Equal(existing.Id, Assert.Single((await store.ReadAsync(preview)).Items).Diagnostic.Id);
        await Assert.ThrowsAsync<ArgumentException>(() => store.RecordBatchAsync(
            [candidate, Event(preview) with { Id = Guid.Empty }], []));
        Assert.Single((await store.ReadAsync(preview)).Items);
    }
}
