using System.Text.Json;
using CSweet.Isolation.HyperV;
using CSweet.WebHost.Contracts;
using CSweet.WebHost.Core;
namespace CSweet.WebHost.Runtime.HyperV;

public sealed partial class HyperVProductVmProvider
{
    public async Task<ProductGuestResponse> RenewAsync(Guid workload, ProductGuestRequest request, CancellationToken token)
    {
        var next = request.Renewal ?? throw new InvalidDataException("A signed renewal is required.");
        var certificate = await VerifyReleaseAsync(token);
        if (next.ExpiresAt > certificate.ExpiresAt) throw new UnauthorizedAccessException("Renewal exceeds certification.");
        await using var held = await LockAsync(token);
        var record = (await ReadRecordsAsync(token)).Single(x => x.WorkloadId == workload);
        if (record.State != "Ready" || record.ExpiresAt <= clock.GetUtcNow() || (record.IdleExpiresAt ?? record.ExpiresAt) <= clock.GetUtcNow() || record.VmId is null)
            throw new UnauthorizedAccessException("An expired, stopped or unready preview cannot be renewed.");
        var path = Path.Combine(InstanceDirectory(workload), "assignment.json");
        var previous = JsonSerializer.Deserialize<SignedProductAssignment>(await File.ReadAllTextAsync(path, token), PreviewJson.Options)!;
        ProductRenewal.Validate(previous, next, verifier);
        if (next.WorkloadId != workload || next.AssignmentId != record.AssignmentId) throw new UnauthorizedAccessException();
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        var remaining = record.ExpiresAt - clock.GetUtcNow();
        deadline.CancelAfter(remaining < TimeSpan.FromSeconds(10) ? remaining : TimeSpan.FromSeconds(10));
        var transport = new WindowsHyperVSocketTransport(new() { LinuxVsockPort = ProductGuestProtocol.Port, ConnectTimeoutSeconds = 5 });
        await using var stream = await transport.ConnectAsync(Guid.ParseExact(record.VmId, "N"), deadline.Token);
        await ProductGuestProtocol.WriteAsync(stream, request, deadline.Token);
        var response = await ProductGuestProtocol.ReadAsync<ProductGuestResponse>(stream, deadline.Token);
        if (response.RequestId != request.RequestId || response.Kind != "renew" || response.Phase != PreviewPhase.Ready || response.Diagnostics is not null)
            throw new InvalidDataException("The guest did not confirm renewal.");
        // Commit only after guest acknowledgement. A crash between files leaves the earlier host deadline in force.
        var temporary = path + ".renewing";
        await File.WriteAllTextAsync(temporary, JsonSerializer.Serialize(next, PreviewJson.Options), deadline.Token);
        File.Move(temporary, path, overwrite: true);
        await SaveAsync(record with { ExpiresAt = next.ExpiresAt, IdleExpiresAt = IdleDeadline(clock.GetUtcNow(), next.ExpiresAt) }, deadline.Token);
        return response;
    }
}
