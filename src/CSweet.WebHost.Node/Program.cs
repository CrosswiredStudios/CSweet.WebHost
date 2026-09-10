using System.Text.Json;
using CSweet.WebHost.Contracts;
using CSweet.WebHost.Core;

try
{
    if (args.Length == 1 && args[0] == "run")
    {
        using var shutdown = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) => { e.Cancel = true; shutdown.Cancel(); };
        try { await CSweet.WebHost.Node.NodeService.RunAsync(shutdown.Token); }
        catch (OperationCanceledException) when (shutdown.IsCancellationRequested) { }
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
        Console.WriteLine(JsonSerializer.Serialize(new
        {
            service = "CSweet.WebHost", version = "0.1.0", executionReady = false,
            code = "ProductRuntimeNotCertified",
            message = "No certified WebHost product VM integration is installed. Office and host Docker are not fallback providers."
        }, PreviewJson.Options));
        return 3;
    }
    Console.Error.WriteLine("Usage: CSweet.WebHost.Node validate <preview.json> | status | run");
    return 2;
}
catch (Exception error) when (error is IOException or JsonException or ArgumentException or UnauthorizedAccessException)
{
    Console.Error.WriteLine(JsonSerializer.Serialize(new { code = "InvalidInput", message = "The input could not be read or validated." }));
    return 2;
}
