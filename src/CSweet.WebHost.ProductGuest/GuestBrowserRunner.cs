using System.Diagnostics;
using System.Text.Json;
using CSweet.WebHost.Contracts;
using CSweet.WebHost.Core;
namespace CSweet.WebHost.ProductGuest;
public interface IGuestBrowserRunner
{
    Task<IReadOnlyList<PreviewBrowserCheckResult>> RunAsync(PreviewMode mode, IReadOnlyList<PreviewBrowserCheck> checks, CancellationToken token);
}
public sealed class GuestBrowserRunner : IGuestBrowserRunner
{
    public async Task<IReadOnlyList<PreviewBrowserCheckResult>> RunAsync(PreviewMode mode, IReadOnlyList<PreviewBrowserCheck> checks, CancellationToken token)
    {
        BrowserTestPolicy.Validate(checks);
        if (!OperatingSystem.IsLinux() || !File.Exists("/etc/csweet-product-guest")) throw new PlatformNotSupportedException();
        var start = new ProcessStartInfo("/usr/bin/setpriv") { UseShellExecute = false, RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true, WorkingDirectory = "/run/csweet-product/browser" };
        start.Environment.Clear(); start.Environment["DOTNET_EnableDiagnostics"] = "0"; start.Environment["PATH"] = "/usr/bin:/bin"; start.Environment["HOME"] = start.WorkingDirectory; start.Environment["TMPDIR"] = start.WorkingDirectory;
        foreach (var argument in new[] { "--reuid=65532", "--regid=65532", "--clear-groups", "--no-new-privs", "/opt/csweet/browser-probe/CSweet.WebHost.BrowserProbe", mode == PreviewMode.Static ? "static" : "containers" }) start.ArgumentList.Add(argument);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token); deadline.CancelAfter(TimeSpan.FromSeconds(55));
        using var process = Process.Start(start) ?? throw new IOException("The guest browser runner is unavailable.");
        async Task<string> ReadBoundedAsync(StreamReader reader)
        {
            var buffer = new char[4096]; var output = new System.Text.StringBuilder();
            while (true) { var count = await reader.ReadAsync(buffer.AsMemory(), deadline.Token); if (count == 0) return output.ToString(); if (output.Length + count > 65536) throw new InvalidDataException("Browser evidence exceeds its bound."); output.Append(buffer, 0, count); }
        }
        var output = ReadBoundedAsync(process.StandardOutput); var errors = ReadBoundedAsync(process.StandardError);
        try
        {
            await process.StandardInput.WriteLineAsync(JsonSerializer.Serialize(checks, PreviewJson.Options).AsMemory(), deadline.Token); process.StandardInput.Close();
            await process.WaitForExitAsync(deadline.Token); await errors;
            if (process.ExitCode != 0) throw new InvalidOperationException("The guest browser job failed.");
            return JsonSerializer.Deserialize<PreviewBrowserCheckResult[]>(await output, PreviewJson.Options) ?? throw new InvalidDataException("Browser results are missing.");
        }
        finally
        {
            if (!process.HasExited) { try { process.Kill(entireProcessTree: true); } catch (InvalidOperationException) { } }
            deadline.Cancel(); try { await Task.WhenAll(output, errors); } catch (Exception error) when (error is IOException or OperationCanceledException) { }
        }
    }
}

