using System.Globalization;
using CSweet.Isolation.HyperV;

namespace CSweet.WebHost.Runtime.HyperV;

public sealed partial class HyperVProductVmProvider
{
    private async Task<long> ReadOsVirtualSizeAsync(CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        var result = await PowerShellHyperV.RunAsync("""
            $ErrorActionPreference = 'Stop'
            Import-Module Hyper-V -ErrorAction Stop
            $disk = Get-VHD -Path $env:CSWEET_PRODUCT_IMAGE -ErrorAction Stop
            if ($disk.VhdFormat.ToString() -ne 'VHDX' -or
                $disk.VhdType.ToString() -notin @('Dynamic', 'Fixed') -or
                -not [String]::IsNullOrWhiteSpace($disk.ParentPath)) {
                throw 'Product images must be standalone VHDX disks.'
            }
            $disk.Size.ToString([Globalization.CultureInfo]::InvariantCulture)
            """, new Dictionary<string, string> { ["CSWEET_PRODUCT_IMAGE"] = configuration.GuestImagePath });
        token.ThrowIfCancellationRequested();
        if (!long.TryParse(result, NumberStyles.None, CultureInfo.InvariantCulture, out var bytes) || bytes < 1 ||
            bytes > checked(configuration.HostCapacity.DiskMb * ProductStorageBudget.Megabyte))
            throw new InvalidDataException("The certified product image's virtual disk exceeds host capacity.");
        return bytes;
    }

    private long AvailablePhysicalDiskBytes(IReadOnlyCollection<ProductVmRecord> records)
    {
        var root = Path.GetPathRoot(ProtectedRoot(configuration.StateRoot));
        var cacheRoot = Path.GetPathRoot(ProtectedRoot(configuration.ArtifactMediaRoot));
        if (root is null || !string.Equals(root, cacheRoot, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Product state and artifact cache must use the same protected local volume.");
        var volume = new DriveInfo(root);
        if (!volume.IsReady || volume.DriveType != DriveType.Fixed)
            throw new InvalidDataException("Product storage requires an available fixed local volume.");
        return ProductStorageBudget.AvailableBytes(configuration.HostCapacity.DiskMb * ProductStorageBudget.Megabyte,
            ProductStorageBudget.ReservedBytes(records), volume.AvailableFreeSpace, configuration.MaximumArtifactCacheBytes);
    }
}

