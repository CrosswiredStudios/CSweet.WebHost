using CSweet.WebHost.Contracts;
using CSweet.WebHost.Runtime.HyperV;

namespace CSweet.WebHost.Tests;

public sealed class ProductStorageBudgetTests
{
    private const long Mb = ProductStorageBudget.Megabyte;
    private static readonly ResourceBudget Resources = new(2, 4096, 10240, 120, 30);
    private static ProductVmRecord Record(long? bytes, string state = "Ready") =>
        new(Guid.NewGuid(), Guid.NewGuid(), "test", null, state, DateTimeOffset.UtcNow.AddHours(1), Resources,
            PhysicalDiskBytes: bytes);

    [Fact]
    public void Reservation_covers_full_os_and_scratch_growth_media_and_memory_state()
    {
        var bytes = ProductStorageBudget.RequiredBytes(Resources, 8192 * Mb, 100 * Mb, 1000);
        Assert.Equal((2 * (8192 + 10240) + 512 + 4096 + 64 + 100) * Mb + 1000 + 65536, bytes);
        Assert.True(bytes > Resources.DiskMb * Mb);
    }

    [Fact]
    public void Small_current_image_size_cannot_reduce_the_virtual_disk_reservation()
    {
        var small = ProductStorageBudget.RequiredBytes(Resources, 8192 * Mb, Mb, 1000);
        var large = ProductStorageBudget.RequiredBytes(Resources, 16384 * Mb, Mb, 1000);
        Assert.Equal(16384 * Mb, large - small);
    }

    [Fact]
    public void Durable_reservations_include_uncertain_creation_and_release_only_after_destroy()
    {
        Assert.Equal(3000, ProductStorageBudget.ReservedBytes([Record(1000, "Creating"), Record(2000, "Failed"),
            Record(null, "Destroyed")]));
        Assert.Throws<InvalidDataException>(() => ProductStorageBudget.ReservedBytes([Record(null)]));
        Assert.Throws<InvalidDataException>(() => ProductStorageBudget.ReservedBytes([Record(-1)]));
        Assert.Throws<InvalidDataException>(() => ProductStorageBudget.ReservedBytes([Record(long.MaxValue), Record(1)]));
    }

    [Fact]
    public void Admission_honors_both_host_budget_and_free_volume_with_cache_and_floor()
    {
        var roomy = ProductStorageBudget.AvailableBytes(100000 * Mb, 30000 * Mb, 200000 * Mb, 10000 * Mb);
        Assert.Equal(70000 * Mb, roomy);
        var limited = ProductStorageBudget.AvailableBytes(100000 * Mb, 30000 * Mb, 80000 * Mb, 10000 * Mb);
        Assert.Equal((80000 - 30000 - 10000 - 1024) * Mb, limited);
        Assert.Equal(0, ProductStorageBudget.AvailableBytes(100000 * Mb, 30000 * Mb, 20000 * Mb, 10000 * Mb));
    }

    [Fact]
    public void Invalid_and_overflowing_reservations_fail_closed()
    {
        Assert.Throws<InvalidDataException>(() => ProductStorageBudget.RequiredBytes(Resources, long.MaxValue, Mb, 1000));
        Assert.Throws<InvalidDataException>(() => ProductStorageBudget.RequiredBytes(Resources, 0, Mb, 1000));
        Assert.Throws<InvalidDataException>(() => ProductStorageBudget.RequiredBytes(Resources, Mb, Mb, 3 * Mb));
        Assert.Throws<InvalidDataException>(() => ProductStorageBudget.AvailableBytes(Mb, 0, Mb, 0));
    }
}
