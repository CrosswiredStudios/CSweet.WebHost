using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using CSweet.Isolation.HyperV;
using CSweet.WebHost.Contracts;
using CSweet.WebHost.Core;

namespace CSweet.WebHost.Runtime.HyperV;

public sealed partial class HyperVProductVmProvider
{
    public async Task<ProductRuntimeHandle?> FindHandleAsync(Guid workloadId, CancellationToken token)
    {
        await using var held = await LockAsync(token);
        var record = (await ReadRecordsAsync(token)).SingleOrDefault(x => x.WorkloadId == workloadId);
        return record?.VmId is null ? null : new(record.AssignmentId,record.WorkloadId,record.VmId);
    }
    public async Task<ProductGuestResponse> ExchangeAsync(Guid workloadId, ProductGuestRequest request,
        DiagnosticStore diagnosticStore, CancellationToken token)
    {
        ProductVmRecord record; SignedProductAssignment assignment;
        await using (var held = await LockAsync(token))
        {
            record = (await ReadRecordsAsync(token)).SingleOrDefault(x => x.WorkloadId == workloadId)
                ?? throw new UnauthorizedAccessException("The product workload is unknown.");
            if (record.State == "Destroyed" || record.ExpiresAt <= clock.GetUtcNow() ||
                (record.IdleExpiresAt ?? record.ExpiresAt) <= clock.GetUtcNow() || record.VmId is null)
                throw new UnauthorizedAccessException("The product workload is not live.");
            if (request.Kind == "http")
            {
                ProductGuestProtocol.ValidateHttp(request.Http ?? throw new InvalidDataException("An HTTP request is required."));
                // Record authorized user activity before I/O so the idle reaper cannot race a request already in flight.
                record = record with { IdleExpiresAt = IdleDeadline(clock.GetUtcNow(), record.ExpiresAt) };
                await SaveAsync(record, token);
            }
            var path = Path.Combine(InstanceDirectory(workloadId),"assignment.json");
            if (new FileInfo(path).Length > 2*1024*1024) throw new InvalidDataException("Protected assignment exceeds its input limit.");
            assignment = JsonSerializer.Deserialize<SignedProductAssignment>(await File.ReadAllTextAsync(path,token),PreviewJson.Options)
                ?? throw new InvalidDataException("Protected assignment is unavailable.");
            if (assignment.AssignmentId != record.AssignmentId || assignment.WorkloadId != record.WorkloadId)
                throw new InvalidDataException("Protected assignment identity changed.");
        }
        var spec = verifier.Verify(assignment);
        var transport = new WindowsHyperVSocketTransport(new() { LinuxVsockPort=ProductGuestProtocol.Port, ConnectTimeoutSeconds=30 });
        await using var stream = await transport.ConnectAsync(Guid.ParseExact(record.VmId!,"N"),token);
        await ProductGuestProtocol.WriteAsync(stream,request,token);
        var response = await ProductGuestProtocol.ReadAsync<ProductGuestResponse>(stream,token);
        if (response.RequestId != request.RequestId || response.Kind != request.Kind || !Enum.IsDefined(response.Phase))
            throw new InvalidDataException("The product guest response does not match its request.");
        if (response.Diagnostics is { } diagnostics)
        {
            if (request.Kind != "diagnostics" || diagnostics.Count > 256)
                throw new InvalidDataException("Unexpected product diagnostic payload.");
            foreach (var diagnostic in diagnostics)
            {
                if (diagnostic.Sequence < 1 || diagnostic.Summary is null || diagnostic.Source is null ||
                    diagnostic.Service is null || diagnostic.Code is null || diagnostic.Summary.Length > 8192 ||
                    diagnostic.Source.Length > 128 || diagnostic.Service.Length > 128 || diagnostic.Code.Length > 128 ||
                    diagnostic.OccurredAt < assignment.IssuedAt || diagnostic.OccurredAt > clock.GetUtcNow().AddSeconds(30))
                    throw new InvalidDataException("Invalid product diagnostic metadata.");
                var hash = SHA256.HashData(Encoding.UTF8.GetBytes(assignment.AssignmentId.ToString("N")+":"+diagnostic.Sequence));
                var source = diagnostic.Source == "build" ? "build" : "runtime";
                await diagnosticStore.RecordAsync(new(new Guid(hash.AsSpan(0,16)),workloadId,spec.ProjectId,spec.BuildId,
                    spec.Manifest.SourceRevision,diagnostic.Service,source,diagnostic.Code,diagnostic.Summary,
                    diagnostic.OccurredAt,false),[],token);
            }
        }
        if (request.Kind is "initialize" or "status" or "stop")
        {
            await using var held = await LockAsync(token);
            var current = (await ReadRecordsAsync(token)).Single(x => x.WorkloadId == workloadId);
            if (current.State != "Destroyed" && current.ExpiresAt > clock.GetUtcNow())
                await SaveAsync(current with
                {
                    State = response.Phase.ToString()
                }, token);
        }
        // Only the retained, sanitized canonical evidence API exports diagnostics outside this boundary.
        return response with { Diagnostics = null };
    }
}
