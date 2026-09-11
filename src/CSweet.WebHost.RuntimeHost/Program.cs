using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using CSweet.Isolation.HyperV;
using CSweet.WebHost.Contracts;
using CSweet.WebHost.Core;
using CSweet.WebHost.Runtime.HyperV;
using CSweet.WebHost.RuntimeHost;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

// Configuration has one fixed installer-owned path. Environment variables and RPC payloads cannot replace trust anchors.
if (!OperatingSystem.IsWindows() || args.Length != 0) return 2;
var configurationPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
    "CSweet","WebHost","runtime-host.json");
var configFile = new FileInfo(configurationPath);
if (!configFile.Exists || configFile.Length > 65536 || configFile.LinkTarget is not null)
    throw new InvalidDataException("The protected WebHost runtime configuration is unavailable.");
WindowsProtectedPaths.Verify(configurationPath);
var config = JsonSerializer.Deserialize<RuntimeHostConfiguration>(await File.ReadAllTextAsync(configurationPath),PreviewJson.Options)
    ?? throw new InvalidDataException("The protected WebHost runtime configuration is empty.");
var builder = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings { Args=[], DisableDefaults=true });
builder.Services.AddLogging(log => { if (OperatingSystem.IsWindows()) log.AddEventLog(); });
builder.Services.AddWindowsService(options => options.ServiceName="CSweet.WebHost.RuntimeHost");
builder.Services.AddSingleton(config);
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton(new DurableState(config.Provider.StateRoot));
builder.Services.AddSingleton(new AssignmentVerifier(config.Enrollment,TimeProvider.System));
builder.Services.AddSingleton(config.Provider);
builder.Services.AddSingleton<HyperVProductVmProvider>();
builder.Services.AddSingleton<AssignmentLedger>();
builder.Services.AddSingleton(services => new ProductControlVerifier(config.Enrollment,
    services.GetRequiredService<DurableState>(),TimeProvider.System));
builder.Services.AddSingleton<DiagnosticStore>();
builder.Services.AddSingleton<IProductDiagnosticSource>(services => services.GetRequiredService<HyperVProductVmProvider>());
builder.Services.AddSingleton<ProductDiagnosticCollector>();
builder.Services.AddHostedService<DiagnosticCollectionWorker>();
builder.Services.AddHostedService<ProductReaper>();
builder.Services.AddHostedService<DiagnosticRetentionWorker>();
builder.Services.AddHostedService<ArtifactRetentionWorker>();
builder.Services.AddHostedService<ProductRpcWorker>();
await builder.Build().RunAsync();
return 0;

public sealed record RuntimeHostConfiguration(WebHostEnrollment Enrollment, HyperVProductConfiguration Provider,string NodeSid);


public sealed class ProductReaper(HyperVProductVmProvider provider,ILogger<ProductReaper> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken token)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(5));
        do
        {
            try { await provider.ReapExpiredAsync(token); }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException or HyperVCommandException)
            { logger.LogError("WebHost expiry reconciliation failed; protected state has been retained for retry."); }
        } while (await timer.WaitForNextTickAsync(token));
    }
}
public sealed class ProductRpcWorker(RuntimeHostConfiguration config,HyperVProductVmProvider provider,
    AssignmentVerifier verifier,AssignmentLedger ledger,ProductControlVerifier controls,DiagnosticStore diagnostics,
    ILogger<ProductRpcWorker> logger) : BackgroundService
{
    public const string PipeName="CSweet.WebHost.RuntimeHost.v1";
    protected override async Task ExecuteAsync(CancellationToken token)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        var security = new PipeSecurity();
        security.SetAccessRuleProtection(true,false);
        security.AddAccessRule(new(new SecurityIdentifier(WellKnownSidType.LocalSystemSid,null),PipeAccessRights.FullControl,AccessControlType.Allow));
        security.AddAccessRule(new(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid,null),PipeAccessRights.FullControl,AccessControlType.Allow));
        security.AddAccessRule(new(new SecurityIdentifier(config.NodeSid),PipeAccessRights.ReadWrite | PipeAccessRights.ReadPermissions,AccessControlType.Allow));
        // Bound concurrent commands while keeping expiry reconciliation independent from client I/O.
        var active = new List<Task>();
        try
        {
            while (!token.IsCancellationRequested)
            {
                active.RemoveAll(x => x.IsCompleted);
                if (active.Count >= 16) { await Task.WhenAny(active).WaitAsync(token); continue; }
                var pipe = NamedPipeServerStreamAcl.Create(PipeName,PipeDirection.InOut,16,PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous,65536,65536,security);
                try { await pipe.WaitForConnectionAsync(token); }
                catch { await pipe.DisposeAsync(); throw; }
                active.Add(HandleAsync(pipe,token));
            }
        }
        finally { await Task.WhenAll(active); }
    }
    private async Task HandleAsync(NamedPipeServerStream pipe,CancellationToken serviceToken)
    {
        await using var connection=pipe;
        using var timeout=CancellationTokenSource.CreateLinkedTokenSource(serviceToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(15));
        try
        {
            var request=await ProductGuestProtocol.ReadAsync<ProductRuntimeRequest>(pipe,timeout.Token);
            ProductRuntimeResponse response;
            if (request.Inspect && request.Assignment is null && request.Control is null && request.ArtifactLength is null)
                response = new("Inventory", Status: await provider.InspectAsync(timeout.Token));
            else if (!request.Inspect && request.Assignment is { } assignment && request.Control is null)
            {
                var spec=verifier.Verify(assignment);
                var remaining=assignment.ExpiresAt-DateTimeOffset.UtcNow;
                timeout.CancelAfter(remaining<TimeSpan.FromMinutes(5) ? remaining : TimeSpan.FromMinutes(5));
                var probe=await provider.ProbeAsync(timeout.Token);
                if (!probe.Available || !probe.Certified) throw new UnauthorizedAccessException("The product runtime is unavailable.");
                if(request.ArtifactLength is { } length)
                {
                    await provider.IngestArtifactAsync(assignment,length,pipe,timeout.Token);
                    response=new("ArtifactReady");
                }
                else if (await ledger.ClaimAsync(assignment,timeout.Token))
                    response=new("Booting",await provider.StartAsync(assignment,spec,timeout.Token));
                else response=new("Reconciled",await provider.FindHandleAsync(assignment.WorkloadId,timeout.Token));
            }
            else if (!request.Inspect && request.Control is { } control && request.Assignment is null && request.ArtifactLength is null)
            {
                await controls.ClaimAsync(control,timeout.Token);
                var command=JsonSerializer.Deserialize<ProductGuestRequest>(control.BodyJson,PreviewJson.Options)
                    ?? throw new InvalidDataException("A product command is required.");
                if (command.RequestId != control.CommandId || command.Kind != control.Action)
                    throw new UnauthorizedAccessException("The control body does not match its authorization.");
                timeout.CancelAfter(command.Kind=="initialize" ? TimeSpan.FromMinutes(10) : TimeSpan.FromSeconds(60));
                if (command.Kind == "evidence")
                    response = new("Evidence", Evidence: await diagnostics.ReadAsync(control.WorkloadId,
                        command.DiagnosticAfterSequence, token: timeout.Token));
                else if (command.Kind=="stop")
                {
                    var handle=await provider.FindHandleAsync(control.WorkloadId,timeout.Token)
                        ?? throw new UnauthorizedAccessException("The product workload is unknown.");
                    await provider.StopAndDestroyAsync(handle,timeout.Token);
                    response=new("Stopped",handle);
                }
                else response=new("Completed",Guest:await provider.ExchangeAsync(control.WorkloadId,command,diagnostics,timeout.Token));
            }
            else throw new InvalidDataException("Exactly one signed runtime operation is required.");
            await ProductGuestProtocol.WriteAsync(pipe,response,timeout.Token);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or InvalidOperationException or
            ArgumentException or JsonException or OperationCanceledException or HyperVCommandException or TimeoutException or System.Net.Sockets.SocketException)
        {
            logger.LogWarning("A WebHost runtime operation was rejected or failed. Reconcile its durable status before retrying.");
            try
            {
                using var replyTimeout=new CancellationTokenSource(TimeSpan.FromSeconds(2));
                await ProductGuestProtocol.WriteAsync(pipe,new ProductRuntimeResponse("RejectedOrFailed"),replyTimeout.Token);
            }
            catch (Exception writeError) when (writeError is IOException or OperationCanceledException) { }
        }
    }
}
