using System.Net;
using System.Text.Json;
using CSweet.WebHost.Contracts;
using CSweet.WebHost.Core;

namespace CSweet.WebHost.ProductGuest;

public sealed class ProductGuestSession(ProductGuestBoot boot, string artifactPath, string scratchRoot,
    IGuestCommandRunner commands, TimeProvider clock, HttpMessageHandler? httpHandler = null) : IAsyncDisposable
{
    private readonly List<GuestDiagnostic> diagnostics = [];
    private readonly HttpClient http = new(httpHandler ?? new SocketsHttpHandler { UseProxy = false, AllowAutoRedirect = false,
        UseCookies = false, MaxResponseHeadersLength = 32 }) { Timeout = TimeSpan.FromSeconds(30) };
    private ProductWorkloadSpecification? specification;
    private PreviewPhase phase = PreviewPhase.Requested;
    private bool initialized;
    private long sequence;
    private int diagnosticCharacters;
    private string? lastLogSnapshotDigest;
    private string Workspace => Path.Combine(scratchRoot, "product");
    private string ComposePath => Path.Combine(scratchRoot, "runtime.compose.json");
    private string Project => "preview-" + boot.Assignment.WorkloadId.ToString("N");
    private static readonly HashSet<string> ForwardRequestHeaders = new(StringComparer.OrdinalIgnoreCase)
        { "Accept", "Accept-Language", "Content-Type", "Content-Encoding", "Range", "If-None-Match", "If-Modified-Since" };
    private static readonly HashSet<string> ForwardResponseHeaders = new(StringComparer.OrdinalIgnoreCase)
        { "Content-Type", "Content-Encoding", "Content-Range", "Accept-Ranges", "ETag", "Last-Modified", "Cache-Control" };

    public async Task<ProductGuestResponse> HandleAsync(ProductGuestRequest request, CancellationToken token)
    {
        if (request.RequestId == Guid.Empty) throw new InvalidDataException("A product request identity is required.");
        if (clock.GetUtcNow() >= boot.Assignment.ExpiresAt)
        {
            phase = PreviewPhase.Expired;
            return new(request.RequestId, request.Kind, phase, FailureCode: "LeaseExpired");
        }
        switch (request.Kind)
        {
            case "initialize":
                if (!initialized)
                {
                    initialized = true; // Failed starts are diagnostic outcomes, never an invitation to run again.
                    try { await InitializeAsync(token); }
                    catch (Exception error) when (error is IOException or UnauthorizedAccessException or
                        InvalidOperationException or JsonException or HttpRequestException or ArgumentException)
                    { phase = PreviewPhase.Failed; AddDiagnostic("runtime", "guest", "StartFailed", error.Message); }
                }
                return new(request.RequestId, request.Kind, phase);
            case "status":
                return new(request.RequestId, request.Kind, phase);
            case "diagnostics":
                if (specification?.Manifest.Mode == PreviewMode.Containers && File.Exists(ComposePath))
                {
                    var logs = await commands.DockerAsync(scratchRoot,
                        ["compose", "--ansi", "never", "-p", Project, "-f", ComposePath, "logs", "--no-color", "--timestamps", "--tail", "100"], token);
                    var snapshotDigest = CSweet.Isolation.Security.WorkloadAuthorizationEnvelope.Digest(logs.Output);
                    if (!string.IsNullOrWhiteSpace(logs.Output) && snapshotDigest != lastLogSnapshotDigest)
                    {
                        AddDiagnostic("runtime", "stack", "ContainerLog", logs.Output);
                        lastLogSnapshotDigest = snapshotDigest;
                    }
                }
                return new(request.RequestId, request.Kind, phase, Diagnostics: diagnostics.ToArray());
            case "http":
                if (phase != PreviewPhase.Ready || request.Http is null)
                    return new(request.RequestId, request.Kind, phase, FailureCode: "PreviewNotReady");
                ProductGuestProtocol.ValidateHttp(request.Http);
                var response = specification!.Manifest.Mode == PreviewMode.Static
                    ? await StaticAsync(request.Http, token) : await ForwardAsync(request.Http, token);
                if (response.StatusCode >= 500) AddDiagnostic("http", specification.Manifest.Entrypoint?.Service ?? "site",
                    "HttpServerError", "The preview returned HTTP " + response.StatusCode + ".");
                return new(request.RequestId, request.Kind, phase, Http: response);
            case "stop":
                await StopAsync(token);
                return new(request.RequestId, request.Kind, phase);
            default: throw new InvalidDataException("Unsupported product guest command.");
        }
    }
    private async Task InitializeAsync(CancellationToken token)
    {
        if (boot.Version != 1) throw new InvalidDataException("Unsupported product boot protocol.");
        specification = new AssignmentVerifier(boot.Enrollment, clock).Verify(boot.Assignment);
        if (specification.Kind != ProductWorkloadKind.Preview)
            throw new InvalidDataException("This guest entry point accepts preview workloads only.");
        if (specification.Manifest.ConnectionIds.Count != 0)
            throw new InvalidDataException("External connection brokering is not installed; this guest has no external network.");
        phase = PreviewPhase.Building;
        var diskBytes = checked((long)specification.Manifest.Resources.DiskMb * 1024 * 1024);
        // Leave at least half the disposable disk for image layers, container volumes, and runtime state.
        await ProductArtifact.ExtractAsync(artifactPath, Workspace, specification.Manifest.ArtifactDigest!, diskBytes / 2, token);
        if (specification.Manifest.Mode == PreviewMode.Static)
        {
            if (!File.Exists(Path.Combine(Workspace, "site", "index.html")))
                throw new InvalidDataException("A static product artifact must contain site/index.html.");
            phase = PreviewPhase.Ready;
            AddDiagnostic("health", "site", "Ready", "The static preview is ready.");
            return;
        }
        var images = Path.Combine(Workspace, "images");
        if (Directory.Exists(images))
            foreach (var image in Directory.EnumerateFiles(images, "*.tar", SearchOption.TopDirectoryOnly).Order())
                await RunAsync(["image", "load", "--input", image], token);
        var built = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var service in specification.Manifest.Compose.GetProperty("services").EnumerateObject())
        {
            if (!service.Value.TryGetProperty("build", out var build)) continue;
            var context = Path.GetFullPath(Path.Combine(Workspace, "source", (build.TryGetProperty("context", out var contextValue) ? contextValue.GetString()! : ".")));
            var sourceRoot = Path.GetFullPath(Path.Combine(Workspace, "source"));
            if (context != sourceRoot && !context.StartsWith(sourceRoot + Path.DirectorySeparatorChar, StringComparison.Ordinal))
                throw new InvalidDataException("The build context escaped the input source.");
            var dockerfile = build.TryGetProperty("dockerfile", out var file) ? file.GetString()! : "Dockerfile";
            var idPath = Path.Combine(scratchRoot, "image-" + service.Name + ".id");
            var arguments = new List<string> { "build", "--network", "none", "--pull=false", "--iidfile", idPath,
                "--file", Path.Combine(context, dockerfile) };
            if (build.TryGetProperty("target", out var target)) { arguments.Add("--target"); arguments.Add(target.GetString()!); }
            if (build.TryGetProperty("args", out var args))
                foreach (var arg in args.EnumerateObject()) { arguments.Add("--build-arg"); arguments.Add(arg.Name + "=" + arg.Value.GetString()); }
            arguments.Add(context);
            await RunAsync(arguments, token);
            var idFile = new FileInfo(idPath);
            if (!idFile.Exists || idFile.Length > 128 || idFile.LinkTarget is not null)
                throw new InvalidDataException("The build did not produce a bounded image identity.");
            built[service.Name] = (await File.ReadAllTextAsync(idPath, token)).Trim();
        }
        var normalized = ComposeNormalizer.Normalize(specification.Manifest, boot.Assignment.WorkloadId, built);
        await File.WriteAllTextAsync(ComposePath, normalized, token);
        phase = PreviewPhase.Starting;
        await RunAsync(["compose", "--ansi", "never", "-p", Project, "-f", ComposePath, "up", "-d", "--no-build", "--pull", "never"], token);
        var health = new GuestHttpRequest("GET", specification.Manifest.Entrypoint!.HealthPath,
            new Dictionary<string, string>(), []);
        var deadline = clock.GetUtcNow().AddSeconds(60);
        while (clock.GetUtcNow() < deadline)
        {
            token.ThrowIfCancellationRequested();
            try
            {
                var result = await ForwardAsync(health, token);
                if (result.StatusCode is >= 200 and < 400)
                { phase = PreviewPhase.Ready; AddDiagnostic("health", "stack", "Ready", "The product entry point passed its health check."); return; }
            }
            catch (HttpRequestException) { }
            await Task.Delay(1000, token);
        }
        throw new IOException("The product entry point did not pass its startup health check.");
    }
    private async Task RunAsync(IReadOnlyList<string> arguments, CancellationToken token)
    {
        var result = await commands.DockerAsync(scratchRoot, arguments, token);
        if (!string.IsNullOrWhiteSpace(result.Output)) AddDiagnostic("build", "stack", "CommandOutput", result.Output);
        if (result.ExitCode != 0) throw new IOException("A product build or runtime command failed with exit code " + result.ExitCode + ".");
    }
    private async Task<GuestHttpResponse> ForwardAsync(GuestHttpRequest request, CancellationToken token)
    {
        ProductGuestProtocol.ValidateHttp(request);
        // Resolve against a constant guest-local origin; never accept an authority, destination, or proxy from the caller.
        var origin = new Uri("http://127.0.0.1:18080");
        var target = new Uri(origin, request.Path);
        if (target.Scheme != origin.Scheme || target.Host != origin.Host || target.Port != origin.Port || target.UserInfo.Length != 0)
            throw new InvalidDataException("The preview request changed its destination.");
        using var message = new HttpRequestMessage(new HttpMethod(request.Method), target);
        if (request.Body.Length > 0) message.Content = new ByteArrayContent(request.Body);
        foreach (var header in request.Headers)
            if (ForwardRequestHeaders.Contains(header.Key))
            {
                if (!message.Headers.TryAddWithoutValidation(header.Key, header.Value))
                    message.Content?.Headers.TryAddWithoutValidation(header.Key, header.Value);
            }
        using var response = await http.SendAsync(message, HttpCompletionOption.ResponseHeadersRead, token);
        var headers = response.Headers.Concat(response.Content.Headers)
            .Where(x => ForwardResponseHeaders.Contains(x.Key))
            .ToDictionary(x => x.Key, x => string.Join(", ", x.Value), StringComparer.OrdinalIgnoreCase);
        await using var input = await response.Content.ReadAsStreamAsync(token);
        using var output = new MemoryStream();
        var buffer = new byte[65536];
        while (true)
        {
            var read = await input.ReadAsync(buffer, token); if (read == 0) break;
            if (output.Length + read > ProductGuestProtocol.MaximumHttpBodyBytes)
                throw new InvalidDataException("The preview response exceeds its transfer limit.");
            await output.WriteAsync(buffer.AsMemory(0, read), token);
        }
        return new((int)response.StatusCode, headers, output.ToArray());
    }
    private async Task<GuestHttpResponse> StaticAsync(GuestHttpRequest request, CancellationToken token)
    {
        if (request.Method is not ("GET" or "HEAD")) return new(405, new Dictionary<string, string>(), []);
        var path = Uri.UnescapeDataString(request.Path.Split('?')[0]);
        if (path.Contains('\\') || path.Contains(':') || path.Any(char.IsControl) ||
            path.Split('/').Any(x => x is "." or "..")) return new(400, new Dictionary<string, string>(), []);
        var root = Path.GetFullPath(Path.Combine(Workspace, "site"));
        var target = Path.GetFullPath(Path.Combine(root, path.TrimStart('/')));
        if (target == root || path.EndsWith('/')) target = Path.Combine(target, "index.html");
        if (!target.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.Ordinal))
            return new(404, new Dictionary<string, string>(), []);
        var file = new FileInfo(target);
        if (!file.Exists) return new(404, new Dictionary<string, string>(), []);
        if (file.Length > ProductGuestProtocol.MaximumHttpBodyBytes)
            return new(413, new Dictionary<string, string>(), []);
        var type = file.Extension.ToLowerInvariant() switch
        {
            ".html" => "text/html; charset=utf-8", ".css" => "text/css; charset=utf-8",
            ".js" or ".mjs" => "text/javascript; charset=utf-8", ".json" => "application/json",
            ".wasm" => "application/wasm", ".svg" => "image/svg+xml", ".png" => "image/png",
            ".jpg" or ".jpeg" => "image/jpeg", ".webp" => "image/webp", ".ogg" => "audio/ogg",
            ".mp3" => "audio/mpeg", ".woff2" => "font/woff2", _ => "application/octet-stream"
        };
        return new(200, new Dictionary<string, string> { ["Content-Type"] = type },
            request.Method == "HEAD" ? [] : await File.ReadAllBytesAsync(target, token));
    }
    private void AddDiagnostic(string source, string service, string code, string text)
    {
        var clean = DiagnosticSanitizer.Sanitize(text, []);
        var record = new GuestDiagnostic(++sequence, source, service, code, clean, clock.GetUtcNow());
        diagnostics.Add(record); diagnosticCharacters += clean.Length;
        var limit = Math.Min(specification?.Manifest.Resources.MaximumLogBytes ?? 65536, 1024 * 1024) / 2;
        while (diagnostics.Count > 256 || diagnosticCharacters > limit)
        { diagnosticCharacters -= diagnostics[0].Summary.Length; diagnostics.RemoveAt(0); }
    }
    private async Task StopAsync(CancellationToken token)
    {
        if (File.Exists(ComposePath))
            await commands.DockerAsync(scratchRoot,
                ["compose", "--ansi", "never", "-p", Project, "-f", ComposePath, "down", "--volumes", "--remove-orphans"], token);
        phase = PreviewPhase.Stopped;
    }
    public async ValueTask DisposeAsync()
    {
        http.Dispose();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        try { await StopAsync(timeout.Token); } catch (Exception error) when (error is IOException or OperationCanceledException) { }
    }
}
