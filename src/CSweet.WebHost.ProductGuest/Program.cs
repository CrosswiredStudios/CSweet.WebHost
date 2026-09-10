using System.Text.Json;
using CSweet.Isolation.HyperV;
using CSweet.WebHost.Contracts;
using CSweet.WebHost.Core;
using CSweet.WebHost.ProductGuest;

// These paths and devices are part of the signed product image, not agent-configurable command arguments.
if (args.Length != 0 || !OperatingSystem.IsLinux() ||
    !File.Exists("/etc/csweet-product-guest") || !Directory.Exists("/run/csweet-product"))
{
    Console.Error.WriteLine("This executable must run inside the certified CSweet product guest image.");
    return 2;
}
try
{
    const string bootPath = "/media/csweet-boot/artifact.csab";
    var info = new FileInfo(bootPath);
    if (!info.Exists || info.Length > 2 * 1024 * 1024) throw new InvalidDataException("Product boot media is unavailable.");
    var boot = JsonSerializer.Deserialize<ProductGuestBoot>(await File.ReadAllTextAsync(bootPath), PreviewJson.Options)
        ?? throw new InvalidDataException("Product boot configuration is empty.");
    new AssignmentVerifier(boot.Enrollment, TimeProvider.System).Verify(boot.Assignment);
    using var lifetime = new CancellationTokenSource(boot.Assignment.ExpiresAt - DateTimeOffset.UtcNow);
    await using var session = new ProductGuestSession(boot, "/media/csweet-artifact/artifact.csab",
        "/run/csweet-product", new GuestCommandRunner(), TimeProvider.System);
    var transport = new LinuxHyperVSocketGuestTransport(ProductGuestProtocol.Port);
    // One host connection at a time. A disconnect preserves the existing session, never starts the product again.
    while (!lifetime.IsCancellationRequested)
    {
        await using var connection = await transport.AcceptAsync(lifetime.Token);
        try
        {
            while (!lifetime.IsCancellationRequested)
            {
                var request = await ProductGuestProtocol.ReadAsync<ProductGuestRequest>(connection.Input, lifetime.Token);
                using var requestTimeout = CancellationTokenSource.CreateLinkedTokenSource(lifetime.Token);
                requestTimeout.CancelAfter(TimeSpan.FromMinutes(10));
                var response = await session.HandleAsync(request, requestTimeout.Token);
                await ProductGuestProtocol.WriteAsync(connection.Output, response, lifetime.Token);
                if (response.Phase == PreviewPhase.Stopped) return 0;
            }
        }
        catch (EndOfStreamException) { }
        catch (IOException) { }
    }
    return 0;
}
catch (OperationCanceledException) { return 0; }
catch (Exception error) when (error is IOException or UnauthorizedAccessException or JsonException or ArgumentException)
{
    Console.Error.WriteLine("The product guest could not establish its authorized runtime.");
    return 3;
}
