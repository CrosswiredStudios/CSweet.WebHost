using System.Text.Json;
using CSweet.WebHost.Contracts;
using CSweet.WebHost.Core;

namespace CSweet.WebHost.Node;

/// <summary>Only transports exact signed runtime envelopes and data; never constructs VM commands or authority.</summary>
public sealed class NodeDispatchLoop(WebHostMessageSigner signer, HeadquartersClient headquarters,
    RuntimeHostClient runtime, DurableState state)
{
    private readonly SemaphoreSlim messages = new(1, 1);
    private readonly SemaphoreSlim reports = new(1, 1);

    public async Task RunAsync(CancellationToken token) => await Task.WhenAll(HeartbeatLoopAsync(token), WorkerAsync(token), WorkerAsync(token));

    private async Task HeartbeatLoopAsync(CancellationToken token)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(30));
        do
        {
            try
            {
                var heartbeat = (await runtime.InvokeAsync(new(Inspect: true), null, token)).Status
                    ?? throw new InvalidDataException("Protected inventory is unavailable.");
                await SendAsync("heartbeat", heartbeat, message => headquarters.HeartbeatAsync(message, token), token);
            }
            catch (Exception error) when (Expected(error, token)) { Console.Error.WriteLine("WebHost heartbeat unavailable; local leases remain enforced."); }
        } while (await timer.WaitForNextTickAsync(token));
    }
    private async Task WorkerAsync(CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            try
            {
                await FlushResultsAsync(token);
                if (await state.TransactionAsync(data => data.NodeCommandResults.Count >= 8, token))
                { await Task.Delay(TimeSpan.FromSeconds(5), token); continue; }
                var receipt = await SendAsync("poll", new WebHostCommandPoll(), message => headquarters.PollAsync(message, token), token);
                if (receipt.Command is null) { await Task.Delay(TimeSpan.FromSeconds(2), token); continue; }
                if (receipt.Command is { } delivery)
                {
                    var request = JsonSerializer.Deserialize<ProductRuntimeRequest>(delivery.RuntimeRequestJson, PreviewJson.Options)
                        ?? throw new InvalidDataException("The dispatched runtime request is empty.");
                    if (delivery.CommandId == Guid.Empty || delivery.PreviewId == Guid.Empty || request.Inspect ||
                        (request.Assignment is null) == (request.Control is null) ||
                        request.Assignment is { } assignment && assignment.WorkloadId != delivery.PreviewId ||
                        request.Control is { } control && (control.WorkloadId != delivery.PreviewId || control.CommandId != delivery.CommandId))
                        throw new InvalidDataException("The command envelope does not match its identity.");
                    ProductRuntimeResponse result;
                    try
                    {
                        if (delivery.ArtifactLength is { } length)
                        {
                            if (request.Assignment is null || request.ArtifactLength != length || length < 1 || length > uint.MaxValue)
                                throw new InvalidDataException("The artifact delivery does not match its assignment.");
                            await using var artifact = await SendAsync("artifact", new WebHostArtifactRequest(delivery.CommandId),
                                message => headquarters.OpenArtifactAsync(message, token), token);
                            result = await runtime.InvokeAsync(request, artifact, token);
                        }
                        else
                        {
                            if (request.ArtifactLength is not null) throw new InvalidDataException("Artifact input is missing.");
                            result = await runtime.InvokeAsync(request, null, token);
                        }
                    }
                    catch (Exception error) when (Expected(error, token)) { result = new("RejectedOrFailed"); }
                    var json = JsonSerializer.Serialize(result, PreviewJson.Options);
                    if (json.Length > 8 * 1024 * 1024) throw new InvalidDataException("The runtime result exceeds its bound.");
                    // Persist before reporting. A restarted Node resends only the outcome, never the VM mutation.
                    await state.TransactionAsync(data => { data.NodeCommandResults[delivery.CommandId] = json; return true; }, token);
                    await FlushResultsAsync(token);
                }
            }
            catch (Exception error) when (Expected(error, token)) { Console.Error.WriteLine("WebHost command delivery unavailable; uncertain outcomes require reconciliation."); }
            await Task.Delay(TimeSpan.FromMilliseconds(100), token);
        }
    }
    private async Task FlushResultsAsync(CancellationToken token)
    {
        await reports.WaitAsync(token);
        try
        {
            foreach (var result in await state.TransactionAsync(data => data.NodeCommandResults.Take(8).ToArray(), token))
            {
                var receipt = await SendAsync("result", new WebHostCommandResult(result.Key, result.Value),
                    message => headquarters.CompleteAsync(message, token), token);
                if (!receipt.Accepted || receipt.CommandId != result.Key) throw new InvalidDataException("The result acknowledgement does not match its command.");
                await state.TransactionAsync(data => data.NodeCommandResults.Remove(result.Key), token);
            }
        }
        finally { reports.Release(); }
    }
    private async Task<T> SendAsync<TBody, T>(string action, TBody body, Func<SignedWebHostMessage, Task<T>> send, CancellationToken token)
    {
        // Serializing only authenticated HTTP exchanges preserves strict sequence ordering while
        // two guest operations and the heartbeat can run independently.
        await messages.WaitAsync(token);
        try { return await send(await signer.SignAsync(action, body, token)); }
        finally { messages.Release(); }
    }
    private static bool Expected(Exception error, CancellationToken token) => !token.IsCancellationRequested &&
        error is HttpRequestException or IOException or InvalidOperationException or UnauthorizedAccessException or
            OperationCanceledException or ArgumentException or JsonException;
}
