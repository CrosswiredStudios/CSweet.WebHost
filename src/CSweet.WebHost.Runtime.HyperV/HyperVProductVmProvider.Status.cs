using CSweet.WebHost.Contracts;
namespace CSweet.WebHost.Runtime.HyperV;

public sealed partial class HyperVProductVmProvider
{
    /// <summary>Read-only inventory for the SID-authorized Node. Reports no credentials, paths or product content.</summary>
    public async Task<WebHostHeartbeat> InspectAsync(CancellationToken token)
    {
        var status = await ProbeAsync(token);
        var available = new ResourceBudget(0, 0, 0, 0, 0);
        if (status.Available)
        {
            await using var held = await LockAsync(token);
            var active = (await ReadRecordsAsync(token)).Where(x => x.State != "Destroyed").ToArray();
            var capacity = configuration.HostCapacity;
            available = capacity with
            {
                CpuCount = (int)Math.Max(0, capacity.CpuCount - active.Sum(x => (long)x.Resources.CpuCount)),
                MemoryMb = (int)Math.Max(0, capacity.MemoryMb - active.Sum(x => (long)x.Resources.MemoryMb)),
                DiskMb = (int)Math.Max(0, capacity.DiskMb - active.Sum(x => (long)x.Resources.DiskMb))
            };
        }
        return new(verifier.Enrollment.Id, clock.GetUtcNow(), available, [status]);
    }
}
