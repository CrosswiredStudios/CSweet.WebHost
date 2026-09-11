using Microsoft.Extensions.Hosting;
namespace CSweet.WebHost.Node;
internal sealed class NodeWorker : BackgroundService
{
    protected override Task ExecuteAsync(CancellationToken stoppingToken) => NodeService.RunAsync(stoppingToken);
}
