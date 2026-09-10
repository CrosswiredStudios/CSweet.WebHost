using System.Security.Cryptography;
using System.Text.Json;
using CSweet.WebHost.Contracts;
using CSweet.WebHost.Core;
namespace CSweet.WebHost.Node;

public sealed record NodeConfiguration(string HeadquartersOrigin, WebHostBootstrap Bootstrap,
    string IdentityPrivateKeyPath, string StateRoot);

public static class NodeService
{
    public static async Task RunAsync(CancellationToken token)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("The installed WebHost runtime requires Windows.");
        var directory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "CSweet", "WebHost");
        var path = Path.Combine(directory, "node.json");
        NodeProtectedFiles.Verify(path);
        if (new FileInfo(path).Length > 65536) throw new InvalidDataException("The installed Node configuration is too large.");
        var config = JsonSerializer.Deserialize<NodeConfiguration>(await File.ReadAllTextAsync(path, token), PreviewJson.Options)
            ?? throw new InvalidDataException("The installed Node configuration is unavailable.");
        NodeProtectedFiles.Verify(config.IdentityPrivateKeyPath, secret: true);
        if (new FileInfo(config.IdentityPrivateKeyPath).Length > 16384) throw new InvalidDataException("The Node identity file is too large.");
        using var identity = ECDsa.Create();
        identity.ImportFromPem(await File.ReadAllTextAsync(config.IdentityPrivateKeyPath, token));
        WebHostIdentity.ValidatePublicKey(Convert.ToBase64String(identity.ExportSubjectPublicKeyInfo()));
        using var headquarters = new HeadquartersClient(new Uri(config.HeadquartersOrigin, UriKind.Absolute));
        var signer = new WebHostMessageSigner(config.Bootstrap, identity, new DurableState(config.StateRoot), TimeProvider.System);
        var runtime = new RuntimeHostClient();
        using var interval = new PeriodicTimer(TimeSpan.FromSeconds(30));
        do
        {
            try
            {
                var status = (await runtime.InvokeAsync(new(Inspect: true), null, token)).Status
                    ?? throw new InvalidDataException("The protected runtime did not return its inventory.");
                var signed = await signer.HeartbeatAsync(status, token);
                await headquarters.HeartbeatAsync(signed, token);
            }
            catch (Exception error) when (!token.IsCancellationRequested &&
                error is HttpRequestException or IOException or InvalidOperationException or UnauthorizedAccessException or OperationCanceledException)
            {
                // Do not emit credentials, product diagnostics or remote response bodies to the operator log.
                Console.Error.WriteLine("WebHost could not refresh its Headquarters heartbeat. Existing VM leases remain independently enforced.");
            }
        } while (await interval.WaitForNextTickAsync(token));
    }
}
