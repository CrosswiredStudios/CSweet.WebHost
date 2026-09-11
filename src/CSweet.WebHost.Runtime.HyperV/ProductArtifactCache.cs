using System.Security.Cryptography;
using System.Text.Json;
using CSweet.Isolation.Artifacts;
using CSweet.Isolation.Security;
using CSweet.WebHost.Contracts;
namespace CSweet.WebHost.Runtime.HyperV;

/// <summary>Only use under an installer-protected root after workload authorization.
/// No caller-provided paths are accepted. Its lock is separate from physical VM admission.</summary>
public sealed class ProductArtifactCache(string directory, long maximumBytes, TimeProvider clock)
{
    private const long TransactionReserve = 65536;
    private sealed record Lease(string Digest, DateTimeOffset ExpiresAt);

    public async Task IngestAsync(string digest, long length, DateTimeOffset expiresAt, Stream input,
        Action reauthorize, CancellationToken token)
    {
        if (!WorkloadAuthorizationEnvelope.IsDigest(digest) || length is < 1 or > uint.MaxValue ||
            expiresAt <= clock.GetUtcNow() || maximumBytes <= TransactionReserve)
            throw new ArgumentException("Supply an authorized immutable artifact, bounded length and live lease.");
        reauthorize();
        var root = Root();
        await using var held = await LockAsync(root, token);
        await PruneLockedAsync(root, digest, token);
        var destination = Path.Combine(root, digest[7..] + ".iso");
        var existing = File.Exists(destination);
        CheckFile(destination);
        if (existing && !await SingleFileIso9660.VerifyArtifactDigestAsync(destination, digest, token))
            throw new InvalidDataException("An existing protected artifact is corrupt.");
        var storedBytes = Directory.EnumerateFiles(root).Where(x => Path.GetFileName(x) != "ingestion.lock")
            .Sum(x => { CheckFile(x); return new FileInfo(x).Length; });
        // Reserve space for both raw upload and ISO plus metadata, without double-counting a retry.
        if (storedBytes > maximumBytes - TransactionReserve ||
            (!existing && length > (maximumBytes - 2 * TransactionReserve - storedBytes) / 2))
            throw new InvalidOperationException("The protected artifact cache has insufficient capacity.");
        var raw = Path.Combine(root, Guid.NewGuid().ToString("N") + ".upload");
        var media = Path.Combine(root, Guid.NewGuid().ToString("N") + ".upload");
        try
        {
            if (existing)
                await ReceiveAsync(input, Stream.Null, length, digest, token);
            else
            {
                await using var output = new FileStream(raw, FileMode.CreateNew, FileAccess.ReadWrite,
                    FileShare.None, 65536, FileOptions.Asynchronous | FileOptions.WriteThrough);
                await ReceiveAsync(input, output, length, digest, token);
                output.Flush(true); output.Position = 0;
                await using var iso = new FileStream(media, FileMode.CreateNew, FileAccess.Write,
                    FileShare.None, 65536, FileOptions.Asynchronous | FileOptions.WriteThrough);
                await SingleFileIso9660.WriteAsync(output, length, iso, token);
                iso.Flush(true);
            }
            reauthorize();
            if (expiresAt <= clock.GetUtcNow()) throw new UnauthorizedAccessException("The upload outlived its authorization.");
            var leasePath = Path.Combine(root, digest[7..] + ".lease.json");
            var previous = await ReadLeaseAsync(leasePath, token);
            if (previous is not null && previous.Digest != digest) throw new InvalidDataException("The protected artifact lease changed identity.");
            var lease = new Lease(digest, previous is not null && previous.ExpiresAt > expiresAt ? previous.ExpiresAt : expiresAt);
            // Persist retention before the immutable media becomes visible; a crash cannot expose an unleased new artifact.
            await SaveLeaseAsync(root, leasePath, lease, token);
            if (!existing) File.Move(media, destination, overwrite: false);
        }
        finally
        {
            DeleteGenerated(raw); DeleteGenerated(media);
        }
    }

    public async Task<int> PruneAsync(CancellationToken token)
    {
        var root = Root();
        await using var held = await LockAsync(root, token);
        return await PruneLockedAsync(root, null, token);
    }

    private async Task<int> PruneLockedAsync(string root, string? retainedDigest, CancellationToken token)
    {
        var removed = 0;
        // No upload can be active while this cross-process lock is held.
        foreach (var path in Directory.EnumerateFiles(root, "*.upload"))
            if (Guid.TryParseExact(Path.GetFileNameWithoutExtension(path), "N", out _))
            { DeleteGenerated(path); removed++; }
        foreach (var path in Directory.EnumerateFiles(root, "*.lease.json"))
        {
            token.ThrowIfCancellationRequested();
            var lease = await ReadLeaseAsync(path, token) ?? throw new InvalidDataException("An artifact lease disappeared.");
            if (!WorkloadAuthorizationEnvelope.IsDigest(lease.Digest) ||
                Path.GetFileName(path) != lease.Digest[7..] + ".lease.json")
                throw new InvalidDataException("A protected artifact lease contains an invalid identity.");
            if (lease.Digest == retainedDigest || lease.ExpiresAt > clock.GetUtcNow()) continue;
            var media = Path.Combine(root, lease.Digest[7..] + ".iso");
            DeleteGenerated(media);
            DeleteGenerated(path);
            removed++;
        }
        // Media without a lease is retained and charged, never guessed to be safe to delete.
        return removed;
    }

    private static async Task ReceiveAsync(Stream input, Stream output, long length, string digest, CancellationToken token)
    {
        var buffer = new byte[65536];
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        while (length > 0)
        {
            var read = await input.ReadAsync(buffer.AsMemory(0, (int)Math.Min(buffer.Length, length)), token);
            if (read == 0) throw new EndOfStreamException("The product artifact upload ended early.");
            hash.AppendData(buffer, 0, read);
            await output.WriteAsync(buffer.AsMemory(0, read), token);
            length -= read;
        }
        if ("sha256:" + Convert.ToHexStringLower(hash.GetHashAndReset()) != digest)
            throw new InvalidDataException("The product artifact does not match the authorized digest.");
    }
    private static async Task<Lease?> ReadLeaseAsync(string path, CancellationToken token)
    {
        CheckFile(path);
        if (!File.Exists(path)) return null;
        if (new FileInfo(path).Length > 4096) throw new InvalidDataException("The protected artifact lease is too large.");
        return JsonSerializer.Deserialize<Lease>(await File.ReadAllTextAsync(path, token), PreviewJson.Options)
            ?? throw new InvalidDataException("The protected artifact lease is empty.");
    }
    private static async Task SaveLeaseAsync(string root, string destination, Lease lease, CancellationToken token)
    {
        var temporary = Path.Combine(root, Guid.NewGuid().ToString("N") + ".upload");
        try
        {
            await using (var file = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                4096, FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await JsonSerializer.SerializeAsync(file, lease, PreviewJson.Options, token);
                file.Flush(true);
            }
            File.Move(temporary, destination, overwrite: true);
        }
        finally { DeleteGenerated(temporary); }
    }
    private string Root()
    {
        if (!Path.IsPathFullyQualified(directory)) throw new ArgumentException("The protected cache root must be absolute.");
        var root = Path.GetFullPath(directory);
        for (var parent = new DirectoryInfo(root); parent is not null; parent = parent.Parent)
            if (parent.LinkTarget is not null) throw new InvalidDataException("Artifact cache paths cannot traverse links.");
        Directory.CreateDirectory(root);
        return root;
    }
    private static void CheckFile(string path)
    {
        if (new FileInfo(path).LinkTarget is not null || Directory.Exists(path))
            throw new InvalidDataException("Artifact cache entries cannot be links or directories.");
    }
    private static void DeleteGenerated(string path)
    {
        CheckFile(path);
        if (File.Exists(path)) File.Delete(path);
    }
    private static async Task<FileStream> LockAsync(string root, CancellationToken token)
    {
        var path = Path.Combine(root, "ingestion.lock"); CheckFile(path);
        var elapsed = System.Diagnostics.Stopwatch.StartNew();
        while (true)
        {
            token.ThrowIfCancellationRequested();
            try { return new(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None); }
            catch (IOException) when (elapsed.Elapsed < TimeSpan.FromSeconds(10)) { await Task.Delay(50, token); }
        }
    }
}
