using CSweet.WebHost.Core;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace CSweet.WebHost.RuntimeHost;

/// <summary>Collects local evidence while Headquarters or Node are disconnected. Runs independently
/// of expiry reconciliation and never records preview user activity.</summary>
public sealed class DiagnosticCollectionWorker(ProductDiagnosticCollector collector,
    ILogger<DiagnosticCollectionWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken token)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(30));
        do
        {
            try
            {
                var result = await collector.CollectAsync(token);
                if (result.Failed > 0) logger.LogWarning("WebHost could not collect diagnostics from {Count} product workloads.", result.Failed);
            }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException or InvalidOperationException or System.Text.Json.JsonException)
            { logger.LogWarning("WebHost diagnostic collection could not inspect protected workload state."); }
        } while (await timer.WaitForNextTickAsync(token));
    }
}
