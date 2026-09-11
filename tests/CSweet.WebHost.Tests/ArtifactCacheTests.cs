using System.Security.Cryptography;
using CSweet.Isolation.Artifacts;
using CSweet.WebHost.Runtime.HyperV;
namespace CSweet.WebHost.Tests;

public sealed class ArtifactCacheTests
{
    private sealed class Clock : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = DateTimeOffset.Parse("2026-09-10T12:00:00Z");
        public override DateTimeOffset GetUtcNow() => Now;
    }
    private sealed class Fixture : IDisposable
    {
        public string Root { get; } = Path.Combine(Path.GetTempPath(), "csweet-cache-test-" + Guid.NewGuid().ToString("N"));
        public Clock Clock { get; } = new();
        public byte[] Data { get; } = new byte[100000];
        public string Digest => "sha256:" + Convert.ToHexStringLower(SHA256.HashData(Data));
        public ProductArtifactCache Cache(long capacity = 350000) => new(Root, capacity, Clock);
        public Task AddAsync(DateTimeOffset expiry, Action? authorize = null) =>
            Cache().IngestAsync(Digest, Data.Length, expiry, new MemoryStream(Data), authorize ?? (() => { }), default);
        public void Dispose() { if (Directory.Exists(Root)) Directory.Delete(Root, recursive: true); }
    }

    [Fact] public async Task Retry_reuses_media_without_needing_space_for_another_upload()
    {
        using var f = new Fixture();
        await f.AddAsync(f.Clock.Now.AddHours(1));
        var media = Path.Combine(f.Root, f.Digest[7..] + ".iso");
        var initial = File.GetLastWriteTimeUtc(media);
        var stored = Directory.EnumerateFiles(f.Root).Sum(path => new FileInfo(path).Length);
        await f.Cache(stored + 65536).IngestAsync(f.Digest, f.Data.Length, f.Clock.Now.AddHours(2),
            new MemoryStream(f.Data), () => { }, default);
        Assert.Equal(initial, File.GetLastWriteTimeUtc(media));
        Assert.True(await SingleFileIso9660.VerifyArtifactDigestAsync(media, f.Digest));
        Assert.Empty(Directory.EnumerateFiles(f.Root, "*.upload"));
        var other = f.Data.ToArray(); other[0] = 1;
        var digest = "sha256:" + Convert.ToHexStringLower(SHA256.HashData(other));
        await Assert.ThrowsAsync<InvalidOperationException>(() => f.Cache(stored + 65536).IngestAsync(digest,
            other.Length, f.Clock.Now.AddHours(1), new MemoryStream(other), () => { }, default));
    }

    [Fact] public async Task Cleanup_preserves_the_longest_authorized_lease_and_recovers_after_restart()
    {
        using var f = new Fixture(); var start = f.Clock.Now;
        await f.AddAsync(start.AddHours(2));
        await f.AddAsync(start.AddHours(1));
        f.Clock.Now = start.AddHours(1);
        Assert.Equal(0, await f.Cache().PruneAsync(default));
        Assert.Single(Directory.EnumerateFiles(f.Root, "*.iso"));
        f.Clock.Now = start.AddHours(2);
        Assert.Equal(1, await f.Cache().PruneAsync(default));
        Assert.Empty(Directory.EnumerateFiles(f.Root, "*.iso"));
        Assert.Empty(Directory.EnumerateFiles(f.Root, "*.lease.json"));
    }

    [Fact] public async Task Failed_or_expired_uploads_cannot_commit_or_extend_cache_leases()
    {
        using var f = new Fixture();
        await Assert.ThrowsAsync<EndOfStreamException>(() => f.Cache().IngestAsync(f.Digest, f.Data.Length,
            f.Clock.Now.AddHours(1), new MemoryStream([1, 2]), () => { }, default));
        var wrong = f.Data.ToArray(); wrong[0] = 1;
        await Assert.ThrowsAsync<InvalidDataException>(() => f.Cache().IngestAsync(f.Digest, f.Data.Length,
            f.Clock.Now.AddHours(1), new MemoryStream(wrong), () => { }, default));
        var calls = 0;
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => f.AddAsync(f.Clock.Now.AddHours(1),
            () => { if (++calls == 2) throw new UnauthorizedAccessException("Grant revoked during transfer."); }));
        Assert.Empty(Directory.EnumerateFiles(f.Root, "*.iso"));
        Assert.Empty(Directory.EnumerateFiles(f.Root, "*.upload"));
        Assert.Empty(Directory.EnumerateFiles(f.Root, "*.lease.json"));
    }

    [Fact] public async Task Recovery_removes_only_generated_temporary_files_and_expired_leased_media()
    {
        using var f = new Fixture(); Directory.CreateDirectory(f.Root);
        var stale = Path.Combine(f.Root, Guid.NewGuid().ToString("N") + ".upload");
        await File.WriteAllTextAsync(stale, "interrupted upload");
        var unrelated = Path.Combine(f.Root, "operator.upload");
        var unleased = Path.Combine(f.Root, new string('a',64) + ".iso");
        await File.WriteAllTextAsync(unrelated, "operator file");
        await File.WriteAllTextAsync(unleased, "legacy media");
        Assert.Equal(1, await f.Cache().PruneAsync(default));
        Assert.False(File.Exists(stale)); Assert.True(File.Exists(unrelated)); Assert.True(File.Exists(unleased));
    }

    [Fact] public async Task Tampered_lease_cannot_delete_a_path_outside_the_cache()
    {
        using var f = new Fixture(); await f.AddAsync(f.Clock.Now.AddHours(1));
        var lease = Directory.GetFiles(f.Root, "*.lease.json").Single();
        await File.WriteAllTextAsync(lease, """{"digest":"../../outside","expiresAt":"2000-01-01T00:00:00Z"}""");
        await Assert.ThrowsAsync<InvalidDataException>(() => f.Cache().PruneAsync(default));
        Assert.Single(Directory.EnumerateFiles(f.Root, "*.iso"));
    }
}
