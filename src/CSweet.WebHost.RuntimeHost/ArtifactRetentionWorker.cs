using CSweet.WebHost.Runtime.HyperV;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
namespace CSweet.WebHost.RuntimeHost;

public sealed class ArtifactRetentionWorker(HyperVProductVmProvider provider, ILogger<ArtifactRetentionWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken token)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromMinutes(1));
        do
        {
            try { await provider.ReapArtifactsAsync(token); }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException or System.Text.Json.JsonException)
            { logger.LogError("WebHost artifact cleanup could not complete; protected metadata was retained for recovery."); }
        } while (await timer.WaitForNextTickAsync(token));
    }
}
