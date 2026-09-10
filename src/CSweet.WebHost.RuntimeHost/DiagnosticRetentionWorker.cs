using CSweet.WebHost.Core;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
namespace CSweet.WebHost.RuntimeHost;

/// <summary>Retention proceeds even when Node and Headquarters are disconnected.</summary>
public sealed class DiagnosticRetentionWorker(DiagnosticStore diagnostics, ILogger<DiagnosticRetentionWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken token)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromHours(1));
        do
        {
            try { await diagnostics.PruneAsync(token); }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException)
            { logger.LogError("WebHost diagnostic retention failed; protected evidence was retained for operator recovery."); }
        } while (await timer.WaitForNextTickAsync(token));
    }
}
