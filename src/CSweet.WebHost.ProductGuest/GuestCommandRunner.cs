using System.Diagnostics;
using System.Text;

namespace CSweet.WebHost.ProductGuest;

public sealed record GuestCommandResult(int ExitCode, string Output, bool Truncated);
public interface IGuestCommandRunner
{
    Task<GuestCommandResult> DockerAsync(string directory, IReadOnlyList<string> arguments, CancellationToken token);
}
// Installed inside the certified disposable guest. Never constructed by Headquarters or WebHost Node.
public sealed class GuestCommandRunner : IGuestCommandRunner
{
    public async Task<GuestCommandResult> DockerAsync(string directory, IReadOnlyList<string> arguments, CancellationToken token)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException("Product commands run only in the product guest.");
        var start = new ProcessStartInfo("/usr/bin/docker") { WorkingDirectory = directory, UseShellExecute = false,
            RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true };
        start.Environment.Clear();
        start.Environment["PATH"] = "/usr/bin:/bin";
        start.Environment["HOME"] = "/run/csweet-product/home";
        start.Environment["DOCKER_HOST"] = "unix:///var/run/docker.sock";
        start.Environment["DOCKER_CONFIG"] = "/run/csweet-product/docker-config";
        foreach (var argument in arguments) start.ArgumentList.Add(argument);
        using var process = Process.Start(start) ?? throw new IOException("The product command did not start.");
        var output = new StringBuilder(); var gate = new object(); var truncated = false;
        async Task DrainAsync(StreamReader reader)
        {
            var buffer = new char[4096];
            while (true)
            {
                var count = await reader.ReadAsync(buffer.AsMemory(), token); if (count == 0) break;
                lock (gate)
                {
                    var take = Math.Min(count, 65536 - output.Length);
                    output.Append(buffer, 0, take); truncated |= take < count;
                }
            }
        }
        var stdout = DrainAsync(process.StandardOutput); var stderr = DrainAsync(process.StandardError);
        try { await process.WaitForExitAsync(token); await Task.WhenAll(stdout, stderr); }
        catch
        {
            try { process.Kill(entireProcessTree: true); } catch (InvalidOperationException) { }
            try { await Task.WhenAll(stdout, stderr); } catch (OperationCanceledException) { }
            throw;
        }
        return new(process.ExitCode, output.ToString(), truncated);
    }
}
