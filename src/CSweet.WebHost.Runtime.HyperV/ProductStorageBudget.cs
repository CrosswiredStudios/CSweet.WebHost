using CSweet.WebHost.Contracts;

namespace CSweet.WebHost.Runtime.HyperV;

/// <summary>Conservative host reservations, separate from the product's authorized scratch disk.
/// These are admission bounds, not filesystem quotas or a substitute for provider certification.</summary>
public static class ProductStorageBudget
{
    public const long Megabyte = 1024 * 1024;
    public const long FreeSpaceFloorBytes = 1024 * Megabyte;

    public static long RequiredBytes(ResourceBudget resources, long osVirtualBytes,
        long artifactMediaBytes, long bootPayloadBytes)
    {
        if (resources.DiskMb < 1 || resources.MemoryMb < 1 || osVirtualBytes < 1 ||
            artifactMediaBytes < 1 || bootPayloadBytes < 1 || bootPayloadBytes > 2 * Megabyte)
            throw new InvalidDataException("The product storage reservation inputs are invalid.");
        try
        {
            // Reserve twice each virtual disk's full logical size, plus 256 MiB each for format/block
            // overhead. Never estimate differencing growth from the small current image file length.
            // VM state gets a full memory-sized allocation and 64 MiB for configuration metadata.
            return checked(2 * (osVirtualBytes + resources.DiskMb * Megabyte) + 512 * Megabyte +
                resources.MemoryMb * Megabyte + 64 * Megabyte + artifactMediaBytes + bootPayloadBytes + 65536);
        }
        catch (OverflowException error) { throw new InvalidDataException("The product storage reservation overflowed.", error); }
    }

    public static long ReservedBytes(IEnumerable<ProductVmRecord> records)
    {
        long total = 0;
        foreach (var record in records.Where(record => record.State != "Destroyed"))
        {
            if (record.PhysicalDiskBytes is not { } bytes || bytes < 1)
                throw new InvalidDataException("Existing VM storage is unaccounted for; teardown or operator reconciliation is required.");
            try { total = checked(total + bytes); }
            catch (OverflowException error) { throw new InvalidDataException("Protected storage reservations overflowed.", error); }
        }
        return total;
    }

    public static long AvailableBytes(long capacityBytes, long reservedBytes, long volumeFreeBytes, long cacheCapacityBytes)
    {
        if (capacityBytes < 1 || reservedBytes < 0 || volumeFreeBytes < 0 || cacheCapacityBytes < 1)
            throw new InvalidDataException("The host storage budget is invalid.");
        // Keep every outstanding reservation, the entire cache allowance, and the host floor free.
        // Deliberately give no credit for already allocated files: sparse/compressed file lengths do
        // not prove physical allocation, and other processes may consume this volume concurrently.
        var physical = SubtractFloor(SubtractFloor(SubtractFloor(volumeFreeBytes, reservedBytes),
            cacheCapacityBytes), FreeSpaceFloorBytes);
        return Math.Min(SubtractFloor(capacityBytes, reservedBytes), physical);
    }

    private static long SubtractFloor(long value, long amount) => value > amount ? value - amount : 0;
}
