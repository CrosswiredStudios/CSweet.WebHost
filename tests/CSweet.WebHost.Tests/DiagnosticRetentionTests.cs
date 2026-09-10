using CSweet.WebHost.Contracts;
using CSweet.WebHost.Core;
namespace CSweet.WebHost.Tests;

public sealed class DiagnosticRetentionTests
{
    private sealed class Clock : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = DateTimeOffset.Parse("2026-09-10T12:00:00Z");
        public override DateTimeOffset GetUtcNow() => Now;
    }
    private static PreviewDiagnostic Event(Guid preview, Guid project, DateTimeOffset time, string summary = "failure 123") =>
        new(Guid.NewGuid(), preview, project, Guid.NewGuid(), new string('a', 40), "app", "runtime", "Crash", summary, time, false);

    [Fact] public async Task Export_is_preview_scoped_paginated_and_sanitized_across_restart()
    {
        var path = Path.Combine(Path.GetTempPath(), "csweet-evidence-test-" + Guid.NewGuid().ToString("N"));
        try
        {
            var clock = new Clock(); var store = new DiagnosticStore(new DurableState(path), clock);
            var preview = Guid.NewGuid(); var project = Guid.NewGuid();
            await store.RecordAsync(Event(Guid.NewGuid(), Guid.NewGuid(), clock.Now), []);
            var first = Event(preview, project, clock.Now, "password=secret\nBearer sensitive-token");
            await store.RecordAsync(first, ["secret"]);
            var second = Event(preview, project, clock.Now); await store.RecordAsync(second, []);
            var page = await store.ReadAsync(preview, limit: 1);
            Assert.True(page.HasMore); Assert.Equal(first.Id, Assert.Single(page.Items).Diagnostic.Id);
            Assert.DoesNotContain("secret", page.Items[0].Diagnostic.Summary);
            Assert.DoesNotContain("sensitive-token", page.Items[0].Diagnostic.Summary);
            var restarted = new DiagnosticStore(new DurableState(path), clock);
            var next = await restarted.ReadAsync(preview, page.NextSequence, 1);
            Assert.False(next.HasMore); Assert.Equal(second.Id, Assert.Single(next.Items).Diagnostic.Id);
            Assert.True(next.NextSequence > page.NextSequence);
            Assert.Empty((await restarted.ReadAsync(preview, next.NextSequence)).Items);
            await Assert.ThrowsAsync<ArgumentException>(() => restarted.ReadAsync(Guid.Empty));
            await Assert.ThrowsAsync<ArgumentException>(() => restarted.ReadAsync(preview, limit: 257));
        }
        finally { if (Directory.Exists(path)) Directory.Delete(path, recursive: true); }
    }

    [Fact] public async Task Retention_cannot_be_extended_by_replay_and_removes_finding_evidence()
    {
        var path = Path.Combine(Path.GetTempPath(), "csweet-retention-test-" + Guid.NewGuid().ToString("N"));
        try
        {
            var state = new DurableState(path); var clock = new Clock(); var store = new DiagnosticStore(state, clock);
            var preview = Guid.NewGuid(); var project = Guid.NewGuid(); var first = Event(preview, project, clock.Now);
            await store.RecordAsync(first, []);
            clock.Now = clock.Now.AddDays(6);
            var replay = await store.RecordAsync(first, []); Assert.Equal(1, replay.Occurrences);
            var newer = Event(preview, project, clock.Now); await store.RecordAsync(newer, []);
            var before = await store.ReadAsync(preview);
            Assert.Equal(first.OccurredAt.AddDays(7), before.Items[0].RetainUntil);
            clock.Now = first.OccurredAt.AddDays(7);
            Assert.Equal(1, await store.PruneAsync());
            var page = await store.ReadAsync(preview); Assert.Equal(newer.Id, Assert.Single(page.Items).Diagnostic.Id);
            var finding = await state.TransactionAsync(data => Assert.Single(data.Findings.Values));
            Assert.Equal(1, finding.Occurrences); Assert.Equal(newer.Id, Assert.Single(finding.DiagnosticIds));
            await Assert.ThrowsAsync<ArgumentException>(() => store.RecordAsync(first, []));
            clock.Now = newer.OccurredAt.AddDays(7);
            await store.PruneAsync();
            Assert.Empty((await store.ReadAsync(preview)).Items);
            await state.TransactionAsync(data => { Assert.Empty(data.Findings); Assert.Empty(data.DiagnosticRetainUntil); return true; });
        }
        finally { if (Directory.Exists(path)) Directory.Delete(path, recursive: true); }
    }

    [Fact] public async Task Changed_evidence_cannot_reuse_a_host_diagnostic_identity()
    {
        var path = Path.Combine(Path.GetTempPath(), "csweet-binding-test-" + Guid.NewGuid().ToString("N"));
        try
        {
            var clock = new Clock(); var store = new DiagnosticStore(new DurableState(path), clock);
            var item = Event(Guid.NewGuid(), Guid.NewGuid(), clock.Now);
            await store.RecordAsync(item, []);
            await Assert.ThrowsAsync<InvalidOperationException>(() => store.RecordAsync(item with { PreviewId = Guid.NewGuid() }, []));
            await Assert.ThrowsAsync<InvalidOperationException>(() => store.RecordAsync(item with { BuildId = Guid.NewGuid() }, []));
        }
        finally { if (Directory.Exists(path)) Directory.Delete(path, recursive: true); }
    }
}
