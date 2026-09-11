using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.DependencyInjection;
using System.Text.Json;
using CSweet.WebHost.Contracts;
using CSweet.WebHost.Core;

try
{
    if (args.Length == 5 && args[0] == "verify-release")
    {
        var keyFile = new FileInfo(args[2]); if (!keyFile.Exists || keyFile.Length > 1024) throw new InvalidDataException();
        var release = await ProductReleasePayloadVerifier.VerifyAsync(args[1], (await File.ReadAllTextAsync(args[2])).Trim(), args[3], args[4], "0.2.0", default);
        Console.WriteLine(JsonSerializer.Serialize(new { verified = true, release.ProviderVersion, release.GuestImageDigest, release.ExpiresAt }, PreviewJson.Options));
        return 0;
    }
    if (args.Length == 1 && args[0] == "run")
    {
        var builder = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings { Args = [], DisableDefaults = true });
        builder.Services.AddWindowsService(options => options.ServiceName = "CSweet.WebHost.Node");
        builder.Services.AddHostedService<CSweet.WebHost.Node.NodeWorker>();
        await builder.Build().RunAsync();
        return 0;
    }
    if (args.Length == 2 && args[0] == "validate")
    {
        var file = new FileInfo(Path.GetFullPath(args[1]));
        if (!file.Exists || file.Length > 1024 * 1024) throw new InvalidDataException("Manifest is missing or exceeds 1 MiB.");
        var manifest = JsonSerializer.Deserialize<PreviewManifest>(await File.ReadAllTextAsync(file.FullName), PreviewJson.Options)
            ?? throw new InvalidDataException("Manifest is empty.");
        var problems = ManifestValidator.Validate(manifest);
        Console.WriteLine(JsonSerializer.Serialize(new { manifestValid = problems.Count == 0, authorityGranted = false, problems }, PreviewJson.Options));
        return problems.Count == 0 ? 0 : 2;
    }
    if (args.Length == 1 && args[0] == "status")
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var inventory = await new CSweet.WebHost.Node.RuntimeHostClient().InvokeAsync(new(Inspect: true), null, deadline.Token);
        Console.WriteLine(JsonSerializer.Serialize(inventory, PreviewJson.Options));
        return inventory.Status?.Providers.Any(x => x.Available && x.Certified) == true ? 0 : 3;
    }
    Console.Error.WriteLine("Usage: CSweet.WebHost.Node validate <preview.json> | status | run | verify-release <certificate> <public-key> <image> <runtime-directory>");
    return 2;
}
catch (Exception error) when (error is IOException or JsonException or ArgumentException or UnauthorizedAccessException or OperationCanceledException or NotSupportedException)
{
    Console.Error.WriteLine(JsonSerializer.Serialize(new { code = "InvalidInput", message = "The input could not be read or validated." }));
    return 2;
}
