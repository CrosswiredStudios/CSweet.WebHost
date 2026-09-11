using System.Security.Cryptography;
using System.Text.Json;
using CSweet.WebHost.Contracts;

namespace CSweet.WebHost.Core;

/// <summary>Read-only verification for installation tooling. Privileged runtime additionally verifies installed ACLs.</summary>
public static class ProductReleasePayloadVerifier
{
    public static async Task<ProductReleaseCertification> VerifyAsync(string certificatePath, string publicKey,
        string imagePath, string runtimeRoot, string providerVersion, CancellationToken token)
    {
        var certificateFile = new FileInfo(certificatePath);
        if (!certificateFile.Exists || certificateFile.Length > 65536) throw new InvalidDataException("The release certificate is unavailable.");
        NoLinks(certificateFile); NoLinks(new FileInfo(imagePath)); NoLinks(new DirectoryInfo(runtimeRoot));
        var signed = JsonSerializer.Deserialize<SignedProductReleaseCertification>(await File.ReadAllTextAsync(certificatePath, token), PreviewJson.Options)
            ?? throw new InvalidDataException("The release certificate is missing.");
        await using var image = File.OpenRead(imagePath);
        var imageDigest = "sha256:" + Convert.ToHexStringLower(await SHA256.HashDataAsync(image, token));
        var certificate = ProductReleaseCertificationVerifier.Verify(signed, publicKey, "webhost-hyperv-gen2", providerVersion, imageDigest, DateTimeOffset.UtcNow);
        var required = new[] { "CSweet.WebHost.RuntimeHost.dll", "CSweet.WebHost.Runtime.HyperV.dll", "CSweet.WebHost.Core.dll", "CSweet.WebHost.Contracts.dll",
            "CSweet.Isolation.HyperV.dll", "CSweet.Isolation.Security.dll", "CSweet.Isolation.Artifacts.dll" };
        if (required.Except(certificate.RuntimeFiles.Keys, StringComparer.OrdinalIgnoreCase).Any()) throw new InvalidDataException("Required runtime files are not certified.");
        var files = Directory.EnumerateFiles(runtimeRoot).Where(x => x.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) || x.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ||
            x.EndsWith(".deps.json", StringComparison.OrdinalIgnoreCase) || x.EndsWith(".runtimeconfig.json", StringComparison.OrdinalIgnoreCase)).ToDictionary(x => Path.GetFileName(x)!, StringComparer.OrdinalIgnoreCase);
        if (!files.Keys.ToHashSet(StringComparer.OrdinalIgnoreCase).SetEquals(certificate.RuntimeFiles.Keys)) throw new InvalidDataException("The certified payload file set differs.");
        foreach (var file in certificate.RuntimeFiles)
        {
            var path = Path.Combine(runtimeRoot, file.Key); NoLinks(new FileInfo(path));
            await using var input = File.OpenRead(path);
            if ("sha256:" + Convert.ToHexStringLower(await SHA256.HashDataAsync(input, token)) != file.Value) throw new InvalidDataException("A certified runtime file differs.");
        }
        return certificate;
    }
    private static void NoLinks(FileSystemInfo file)
    {
        for (FileSystemInfo? item = file; item is not null; item = item is DirectoryInfo directory ? directory.Parent : ((FileInfo)item).Directory)
            if (!item.Exists || item.LinkTarget is not null || (item.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException("Release inputs cannot traverse links or missing paths.");
    }
}
