using System.Security.Cryptography;
using System.Text.Json;
using CSweet.Isolation.Artifacts;
using CSweet.Isolation.HyperV;
using CSweet.Isolation.Security;
using CSweet.WebHost.Contracts;
using CSweet.WebHost.Core;

namespace CSweet.WebHost.Runtime.HyperV;

/// <summary>Installer-owned configuration, readable only by the privileged WebHost RuntimeHost.
/// None of these paths or trust anchors may come from an agent request or the unprivileged Node.</summary>
public sealed record HyperVProductConfiguration(string StateRoot, string GuestImagePath, string GuestImageDigest,
    string ArtifactMediaRoot, string RuntimePayloadRoot, string CertificationPath, string CertificationPublicKeyBase64,
    ResourceBudget HostCapacity, long MaximumArtifactCacheBytes);
public sealed record ProductVmRecord(Guid AssignmentId, Guid WorkloadId, string VmName, string? VmId,
    string State, DateTimeOffset ExpiresAt, ResourceBudget Resources, DateTimeOffset? IdleExpiresAt = null, long? PhysicalDiskBytes = null);

public sealed partial class HyperVProductVmProvider(HyperVProductConfiguration configuration,
    AssignmentVerifier verifier, TimeProvider clock) : IProductVmProvider, IProductDiagnosticSource
{
    public const string Id = "webhost-hyperv-gen2";
    public const string Version = "0.2.0";
    private string InstancesRoot => Path.Combine(ProtectedRoot(configuration.StateRoot), "instances");

    public async Task<ProductProviderStatus> ProbeAsync(CancellationToken token)
    {
        try
        {
            if (!OperatingSystem.IsWindows()) return Unavailable("Hyper-V requires Windows.");
            var certificate = await VerifyReleaseAsync(token);
            await PowerShellHyperV.RunAsync("Import-Module Hyper-V -ErrorAction Stop; $null = Get-VMHost -ErrorAction Stop; if ((Get-Service vmms -ErrorAction Stop).Status -ne 'Running') { throw 'VMMS is unavailable.' }; if (-not (Test-Path -LiteralPath 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Virtualization\\GuestCommunicationServices\\00000aca-facb-11e6-bd58-64006a7986d3')) { throw 'The product guest socket is not installed.' }");
            return new(Id, Version, configuration.GuestImageDigest, true, certificate.ExpiresAt, true, null);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or CryptographicException or
            FormatException or JsonException or ArgumentException or HyperVCommandException)
        { return Unavailable("The protected product runtime installation or release certification is unavailable."); }
    }

    public async Task<ProductRuntimeHandle> StartAsync(SignedProductAssignment assignment,
        ProductWorkloadSpecification suppliedSpec, CancellationToken token)
    {
        // This check is intentionally repeated inside the privileged boundary.
        var spec = verifier.Verify(assignment);
        if (assignment.ProviderId != Id || spec != suppliedSpec &&
            JsonSerializer.Serialize(spec, PreviewJson.Options) != JsonSerializer.Serialize(suppliedSpec, PreviewJson.Options))
            throw new UnauthorizedAccessException("The supplied product specification does not match its authorization.");
        var certification = await VerifyReleaseAsync(token);
        if (assignment.ExpiresAt > certification.ExpiresAt) throw new UnauthorizedAccessException("The workload exceeds the runtime certification lifetime.");
        if (spec.GuestImageDigest != configuration.GuestImageDigest ||
            !spec.Manifest.Resources.Fits(configuration.HostCapacity))
            throw new UnauthorizedAccessException("The product exceeds the certified image or host capacity.");
        if (!WorkloadAuthorizationEnvelope.IsDigest(spec.Manifest.ArtifactDigest))
            throw new InvalidDataException("Product dispatch requires an ingested immutable input artifact.");
        var inputMedia = Path.Combine(ProtectedRoot(configuration.ArtifactMediaRoot), spec.Manifest.ArtifactDigest![7..] + ".iso");
        if (!await SingleFileIso9660.VerifyArtifactDigestAsync(inputMedia, spec.Manifest.ArtifactDigest, token))
            throw new InvalidDataException("The product input artifact is missing or corrupt.");
        token.ThrowIfCancellationRequested();

        var bootBytes = JsonSerializer.SerializeToUtf8Bytes(new ProductGuestBoot(1, verifier.Enrollment, assignment), PreviewJson.Options);
        var physicalDiskBytes = ProductStorageBudget.RequiredBytes(spec.Manifest.Resources,
            await ReadOsVirtualSizeAsync(token), new FileInfo(inputMedia).Length, bootBytes.Length);
        Directory.CreateDirectory(InstancesRoot);
        // The lock covers physical host admission, VM creation, and committed metadata.
        await using var held = await LockAsync(token);
        verifier.Verify(assignment); // Waiting for physical admission must not outlive authorization.
        if (await new DurableState(configuration.StateRoot).TransactionAsync(data => data.StoppedWorkloads.Contains(assignment.WorkloadId), token))
            throw new UnauthorizedAccessException("This workload was stopped before physical admission.");
        var records = await ReadRecordsAsync(token);
        if (records.Any(x => x.AssignmentId == assignment.AssignmentId || x.WorkloadId == assignment.WorkloadId))
            throw new InvalidOperationException("This product identity already has protected VM history; reconcile it instead of relaunching.");
        var active = records.Where(x => x.State != "Destroyed").ToList();
        var requested = spec.Manifest.Resources;
        if (active.Sum(x => (long)x.Resources.CpuCount) + requested.CpuCount > configuration.HostCapacity.CpuCount ||
            active.Sum(x => (long)x.Resources.MemoryMb) + requested.MemoryMb > configuration.HostCapacity.MemoryMb ||
            physicalDiskBytes > AvailablePhysicalDiskBytes(records))
            throw new InvalidOperationException("The WebHost has insufficient unreserved physical capacity.");

        var directory = InstanceDirectory(assignment.WorkloadId);
        Directory.CreateDirectory(directory);
        var vmName = "csweet-webhost-" + assignment.WebHostId.ToString("N") + "-" + assignment.WorkloadId.ToString("N");
        var record = new ProductVmRecord(assignment.AssignmentId, assignment.WorkloadId, vmName, null, "Creating",
            assignment.ExpiresAt, spec.Manifest.Resources, IdleDeadline(clock.GetUtcNow(), assignment.ExpiresAt), physicalDiskBytes);
        await SaveAsync(record, token);
        try
        {
            await File.WriteAllTextAsync(Path.Combine(directory, "assignment.json"), JsonSerializer.Serialize(assignment, PreviewJson.Options), token);
            var media = Path.Combine(directory, "artifact.iso");
            File.Copy(inputMedia, media, overwrite: false);
            if (!await SingleFileIso9660.VerifyArtifactDigestAsync(media, spec.Manifest.ArtifactDigest, token))
                throw new InvalidDataException("The private input media copy failed verification.");
            var bootPath = Path.Combine(directory, "boot.iso");

            await using (var bootStream = new MemoryStream(bootBytes))
            await using (var bootMedia = new FileStream(bootPath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                await SingleFileIso9660.WriteAsync(bootStream, bootBytes.Length, bootMedia, token);
            var id = await PowerShellHyperV.CreateShellAsync(vmName, Path.Combine(directory, "vm"), requested.MemoryMb);
            if (!Guid.TryParse(id, out var vmId)) throw new InvalidDataException("Hyper-V returned an invalid VM identity.");
            record = record with { VmId = vmId.ToString("N") };
            await SaveAsync(record, token);
            await PowerShellHyperV.ConfigureAsync(vmName, configuration.GuestImagePath,
                Path.Combine(directory, "os.vhdx"), Path.Combine(directory, "scratch.vhdx"),
                requested.CpuCount, checked(requested.CpuCount * 100), requested.MemoryMb, requested.DiskMb, media, bootPath);
            // Payload bootstrap and guest readiness must succeed before this can become Ready.
            if (clock.GetUtcNow() >= assignment.ExpiresAt) throw new UnauthorizedAccessException("The product lease expired during creation.");
            await PowerShellHyperV.StartAsync(vmName);
            record = record with { State = "Booting" };
            await SaveAsync(record, token);
            return new(assignment.AssignmentId, assignment.WorkloadId, vmId.ToString("N"));
        }
        catch
        {
            // Retain metadata on any cleanup failure so the independent reaper retries it.
            try
            {
                await PowerShellHyperV.DestroyAsync(vmName);
                await DeleteDisksAsync(record);
            }
            catch (Exception cleanup) when (cleanup is IOException or HyperVCommandException or UnauthorizedAccessException) { }
            throw;
        }
    }

    public async Task StopAndDestroyAsync(ProductRuntimeHandle handle, CancellationToken token)
    {
        await using var held = await LockAsync(token);
        var record = (await ReadRecordsAsync(token)).SingleOrDefault(x => x.AssignmentId == handle.AssignmentId &&
            x.WorkloadId == handle.WorkloadId) ?? throw new UnauthorizedAccessException("The product workload is not owned by this WebHost.");
        if (record.VmId != handle.ProviderInstanceId) throw new UnauthorizedAccessException("The product VM identity does not match.");
        await PowerShellHyperV.DestroyAsync(record.VmName);
        await DeleteDisksAsync(record);
    }

    /// <summary>Must run in the privileged service independently of Node and Headquarters connectivity.</summary>
    public async Task ReapExpiredAsync(CancellationToken token)
    {
        await using var held = await LockAsync(token);
        foreach (var record in await ReadRecordsAsync(token))
        {
            if (record.State == "Destroyed" || (record.State != "Creating" && record.ExpiresAt > clock.GetUtcNow() &&
                (record.IdleExpiresAt ?? record.ExpiresAt) > clock.GetUtcNow())) continue;
            try { await PowerShellHyperV.DestroyAsync(record.VmName); await DeleteDisksAsync(record); }
            catch (Exception error) when (error is IOException or HyperVCommandException or UnauthorizedAccessException)
            { /* Keep the record and retry on the next sweep. */ }
        }
    }
    private static DateTimeOffset IdleDeadline(DateTimeOffset now, DateTimeOffset expiresAt) =>
        now.AddMinutes(30) < expiresAt ? now.AddMinutes(30) : expiresAt;
    private async Task<ProductCertification> VerifyReleaseAsync(CancellationToken token)
    {
        ProtectedRoot(configuration.StateRoot); ProtectedRoot(configuration.ArtifactMediaRoot);
        foreach (var path in new[] { configuration.StateRoot, configuration.ArtifactMediaRoot, configuration.RuntimePayloadRoot,
            configuration.CertificationPath, configuration.GuestImagePath }) WindowsProtectedPaths.Verify(path);
        if (!Path.IsPathFullyQualified(configuration.GuestImagePath) || !Path.IsPathFullyQualified(configuration.CertificationPath))
            throw new InvalidDataException("Runtime paths must be absolute installer-owned paths.");
        var info = new FileInfo(configuration.CertificationPath);
        if (!info.Exists || info.Length > 65536 || info.LinkTarget is not null)
            throw new InvalidDataException("The signed certification is unavailable.");
        var envelope = JsonSerializer.Deserialize<SignedProductCertification>(
            await File.ReadAllTextAsync(info.FullName, token), PreviewJson.Options)
            ?? throw new InvalidDataException("The signed certification is missing.");
        var certificate = ProductCertificationVerifier.Verify(envelope, configuration.CertificationPublicKeyBase64,
            Id, Version, configuration.GuestImageDigest, clock.GetUtcNow());
        var payloadRoot = ProtectedRoot(configuration.RuntimePayloadRoot);
        var required = new[] { "CSweet.WebHost.RuntimeHost.dll", "CSweet.WebHost.Runtime.HyperV.dll", "CSweet.WebHost.Core.dll",
            "CSweet.WebHost.Contracts.dll", "CSweet.Isolation.HyperV.dll", "CSweet.Isolation.Security.dll", "CSweet.Isolation.Artifacts.dll" };
        if (required.Except(certificate.RuntimeFiles.Keys, StringComparer.OrdinalIgnoreCase).Any())
            throw new InvalidDataException("The certification omits a required runtime component.");
        var actualFiles = Directory.EnumerateFiles(payloadRoot).Where(x => x.EndsWith(".dll",StringComparison.OrdinalIgnoreCase) ||
            x.EndsWith(".exe",StringComparison.OrdinalIgnoreCase) || x.EndsWith(".deps.json",StringComparison.OrdinalIgnoreCase) ||
            x.EndsWith(".runtimeconfig.json",StringComparison.OrdinalIgnoreCase)).Select(Path.GetFileName).ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (!actualFiles.SetEquals(certificate.RuntimeFiles.Keys)) throw new InvalidDataException("The certified runtime file set has changed.");
        foreach (var file in certificate.RuntimeFiles)
        {
            var path = Path.Combine(payloadRoot,file.Key);
            WindowsProtectedPaths.Verify(path);
            if (new FileInfo(path).LinkTarget is not null) throw new InvalidDataException("Certified runtime files cannot be links.");
            await using var input = File.OpenRead(path);
            if ("sha256:"+Convert.ToHexStringLower(await SHA256.HashDataAsync(input,token)) != file.Value)
                throw new InvalidDataException("A certified runtime component has changed.");
        }
        ProtectedRoot(Path.GetDirectoryName(configuration.GuestImagePath)!);
        if (new FileInfo(configuration.GuestImagePath).LinkTarget is not null) throw new InvalidDataException("The guest image cannot be a link.");
        await using var image = File.OpenRead(configuration.GuestImagePath);
        var digest = "sha256:" + Convert.ToHexStringLower(await SHA256.HashDataAsync(image, token));
        if (digest != configuration.GuestImageDigest) throw new InvalidDataException("The product guest image is corrupt.");
        return certificate;
    }
    private ProductProviderStatus Unavailable(string reason) => new(Id, Version,
        WorkloadAuthorizationEnvelope.IsDigest(configuration.GuestImageDigest) ? configuration.GuestImageDigest : "",
        false, null, false, reason);
    private static string ProtectedRoot(string path)
    {
        if (!Path.IsPathFullyQualified(path)) throw new InvalidDataException("Runtime state requires an absolute path.");
        var directory = new DirectoryInfo(Path.GetFullPath(path));
        for (var parent = directory; parent is not null; parent = parent.Parent)
            if (parent.Exists && parent.LinkTarget is not null) throw new InvalidDataException("Runtime paths must not traverse links.");
        return directory.FullName;
    }
    private string InstanceDirectory(Guid workloadId)
    {
        if (workloadId == Guid.Empty) throw new ArgumentException("A workload identity is required.");
        return ProtectedRoot(Path.Combine(InstancesRoot, workloadId.ToString("N")));
    }
    private async Task<FileStream> LockAsync(CancellationToken token)
    {
        Directory.CreateDirectory(ProtectedRoot(configuration.StateRoot));
        var started = System.Diagnostics.Stopwatch.StartNew();
        while (true)
        {
            token.ThrowIfCancellationRequested();
            try { return new FileStream(Path.Combine(configuration.StateRoot, "runtime.lock"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None); }
            catch (IOException) when (started.Elapsed < TimeSpan.FromSeconds(10)) { await Task.Delay(50, token); }
        }
    }
    private async Task<List<ProductVmRecord>> ReadRecordsAsync(CancellationToken token)
    {
        var records = new List<ProductVmRecord>();
        if (!Directory.Exists(InstancesRoot)) return records;
        foreach (var directory in Directory.EnumerateDirectories(InstancesRoot))
        {
            if (!Guid.TryParseExact(Path.GetFileName(directory), "N", out var workloadId))
                throw new InvalidDataException("Protected VM state contains an unexpected directory.");
            var path = Path.Combine(InstanceDirectory(workloadId), "instance.json");
            if (!File.Exists(path)) throw new InvalidDataException("Protected VM state is incomplete; operator recovery is required.");
            if (new FileInfo(path).Length > 65536) throw new InvalidDataException("VM metadata is too large.");
            var record = JsonSerializer.Deserialize<ProductVmRecord>(await File.ReadAllTextAsync(path, token), PreviewJson.Options)
                ?? throw new InvalidDataException("Protected VM metadata is corrupt.");
            if (record.WorkloadId != workloadId || record.AssignmentId == Guid.Empty ||
                record.VmName != "csweet-webhost-" + verifier.Enrollment.Id.ToString("N") + "-" + workloadId.ToString("N") ||
                (record.VmId is not null && !Guid.TryParseExact(record.VmId, "N", out _))) throw new InvalidDataException("Protected VM metadata identity is invalid.");
            records.Add(record);
        }
        return records;
    }
    private async Task SaveAsync(ProductVmRecord record, CancellationToken token)
    {
        var path = Path.Combine(InstanceDirectory(record.WorkloadId), "instance.json");
        var temporary = path + ".tmp";
        await using (var stream = new FileStream(temporary, FileMode.Create, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
        { await JsonSerializer.SerializeAsync(stream, record, PreviewJson.Options, token); stream.Flush(true); }
        File.Move(temporary, path, overwrite: true);
    }
    private async Task DeleteDisksAsync(ProductVmRecord record)
    {
        // Resolve and recheck all targets before recursive deletion. Preserve a tombstone to prevent replay.
        var root = InstanceDirectory(record.WorkloadId);
        foreach (var file in new[] { "artifact.iso", "boot.iso", "os.vhdx", "scratch.vhdx" })
        {
            var path = Path.Combine(root, file);
            if (File.Exists(path)) File.Delete(path);
        }
        var vmDirectory = ProtectedRoot(Path.Combine(root, "vm"));
        if (!vmDirectory.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("VM cleanup escaped its protected root.");
        if (Directory.Exists(vmDirectory)) Directory.Delete(vmDirectory, recursive: true);
        await SaveAsync(record with { State = "Destroyed" }, CancellationToken.None);
    }
}
