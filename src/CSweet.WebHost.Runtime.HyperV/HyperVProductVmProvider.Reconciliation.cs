using CSweet.Isolation.HyperV;
using CSweet.WebHost.Core;

namespace CSweet.WebHost.Runtime.HyperV;

public sealed partial class HyperVProductVmProvider
{
    public async Task StopWorkloadAsync(Guid workloadId, CancellationToken token)
    {
        if (workloadId == Guid.Empty) throw new ArgumentException("An exact workload identity is required.");
        // Commit before taking the VM lock: a concurrent launch either sees the tombstone inside
        // admission, or completes under that lock before this stop destroys it. Never report a
        // missing VM as stopped without fencing its still-valid signed assignment.
        await new DurableState(configuration.StateRoot).TransactionAsync(data =>
        {
            if (data.StoppedWorkloads.Count >= 100000 && !data.StoppedWorkloads.Contains(workloadId))
                throw new InvalidOperationException("Protected stop history is full.");
            data.StoppedWorkloads.Add(workloadId);
            return true;
        }, token);
        await using var held = await LockAsync(token);
        var record = (await ReadRecordsAsync(token)).SingleOrDefault(x => x.WorkloadId == workloadId);
        if (record is null || record.State == "Destroyed") return;
        await PowerShellHyperV.DestroyAsync(record.VmName);
        await DeleteDisksAsync(record);
    }

    public async Task<ProductRuntimeResponse> ReconcileAsync(Guid workloadId, CancellationToken token)
    {
        await using var held = await LockAsync(token);
        var record = (await ReadRecordsAsync(token)).SingleOrDefault(x => x.WorkloadId == workloadId);
        if (record is null) return new("Missing");
        return new(record.State, record.VmId is null ? null : new(record.AssignmentId, record.WorkloadId, record.VmId), LeaseExpiresAt: record.ExpiresAt);
    }
}
