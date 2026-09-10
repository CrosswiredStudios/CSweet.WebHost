using System.IO.Compression;
using System.Security.Cryptography;
using CSweet.Isolation.Security;

namespace CSweet.WebHost.Core;

public static class ProductArtifact
{
    // The artifact is a plain ZIP: source/, images/*.tar and/or site/. No executable host-side hooks.
    public static async Task ExtractAsync(string archivePath, string destination, string digest, long maximumBytes,
        CancellationToken token)
    {
        if (!WorkloadAuthorizationEnvelope.IsDigest(digest) || maximumBytes < 1)
            throw new InvalidDataException("An exact artifact digest and extraction budget are required.");
        await using var source = new FileStream(archivePath, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (source.Length > maximumBytes) throw new InvalidDataException("The input artifact exceeds its disk budget.");
        var actual = "sha256:" + Convert.ToHexStringLower(await SHA256.HashDataAsync(source, token));
        if (actual != digest) throw new InvalidDataException("The mounted artifact does not match the authorized digest.");
        source.Position = 0;
        var root = Path.GetFullPath(destination);
        if (Directory.Exists(root) || File.Exists(root)) throw new InvalidDataException("Product extraction needs a fresh destination.");
        for (var parent = new DirectoryInfo(root).Parent; parent is not null; parent = parent.Parent)
            if (parent.LinkTarget is not null) throw new InvalidDataException("Product extraction must not traverse links.");
        using var archive = new ZipArchive(source, ZipArchiveMode.Read, leaveOpen: true);
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        long expanded = 0;
        if (archive.Entries.Count > 100000) throw new InvalidDataException("The artifact contains too many entries.");
        foreach (var entry in archive.Entries)
        {
            var name = entry.FullName.TrimEnd('/');
            var kind = (entry.ExternalAttributes >> 16) & 0xf000;
            if (name.Length is < 1 or > 1024 || name.Contains('\\') || name.Contains(':') || name.Any(char.IsControl) ||
                name.Split('/').Any(x => x is "" or "." or ".." || x.EndsWith('.') || x.EndsWith(' ')) ||
                !names.Add(name) || (kind != 0 && kind != 0x8000 && kind != 0x4000) ||
                (entry.ExternalAttributes & (int)FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException("The artifact contains an unsafe, duplicate, or special entry.");
            expanded = checked(expanded + entry.Length);
            if (expanded > maximumBytes) throw new InvalidDataException("The expanded artifact exceeds its disk budget.");
            var target = Path.GetFullPath(Path.Combine(root, name));
            if (!target.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.Ordinal))
                throw new InvalidDataException("The artifact escaped its destination.");
        }
        Directory.CreateDirectory(root);
        var buffer = new byte[65536]; long written = 0;
        foreach (var entry in archive.Entries)
        {
            token.ThrowIfCancellationRequested();
            var target = Path.Combine(root, entry.FullName.Replace('/', Path.DirectorySeparatorChar));
            if (entry.FullName.EndsWith('/')) { Directory.CreateDirectory(target); continue; }
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            await using var input = entry.Open();
            await using var output = new FileStream(target, FileMode.CreateNew, FileAccess.Write, FileShare.None);
            long entryWritten = 0;
            while (true)
            {
                var read = await input.ReadAsync(buffer, token); if (read == 0) break;
                written = checked(written + read); entryWritten += read;
                if (written > maximumBytes || entryWritten > entry.Length) throw new InvalidDataException("The artifact exceeded its declared size.");
                await output.WriteAsync(buffer.AsMemory(0, read), token);
            }
            if (entryWritten != entry.Length) throw new InvalidDataException("The artifact entry is truncated.");
        }
    }
}
