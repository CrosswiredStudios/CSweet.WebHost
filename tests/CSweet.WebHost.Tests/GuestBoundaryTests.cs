using System.Buffers.Binary;
using System.IO.Compression;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using CSweet.Isolation.Security;
using CSweet.WebHost.Contracts;
using CSweet.WebHost.Core;
using CSweet.WebHost.ProductGuest;
using CSweet.WebHost.Runtime.HyperV;

namespace CSweet.WebHost.Tests;

public sealed class GuestBoundaryTests
{
    private static readonly DateTimeOffset Now = DateTimeOffset.Parse("2026-09-10T12:00:00Z");
    private sealed class Clock : TimeProvider { public DateTimeOffset Current = Now; public override DateTimeOffset GetUtcNow() => Current; }
    private static string Root()
    {
        var root = Path.Combine(AppContext.BaseDirectory, "test-state", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root); return root;
    }
    private static (string Path, string Digest) Archive(string root, params (string Name, string Content, int Attributes)[] entries)
    {
        var path = Path.Combine(root, Guid.NewGuid().ToString("N") + ".zip");
        using (var archive = ZipFile.Open(path, ZipArchiveMode.Create))
            foreach (var item in entries)
            {
                var entry = archive.CreateEntry(item.Name); entry.ExternalAttributes = item.Attributes;
                using var writer = new StreamWriter(entry.Open()); writer.Write(item.Content);
            }
        return (path, "sha256:" + Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(path))));
    }
    private static ProductGuestBoot Boot(string digest, PreviewMode mode = PreviewMode.Static, Action<ECDsa, ProductGuestBoot>? capture = null)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var enrollment = new WebHostEnrollment(Guid.NewGuid(), "test", "key", Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()), Now);
        var compose = JsonDocument.Parse(mode == PreviewMode.Static ? "null" :
            """{"services":{"app":{"build":{"context":"."}}}}""").RootElement.Clone();
        var manifest = new PreviewManifest(1, mode, new string('a', 40), digest, compose,
            mode == PreviewMode.Static ? null : new("app", 8080), ResourceBudget.Default, 7200, []);
        var spec = new ProductWorkloadSpecification(1, Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(),
            Guid.NewGuid(), 1, Guid.NewGuid(), Guid.NewGuid(), ProductWorkloadKind.Preview, manifest, "sha256:" + new string('b',64));
        var json = JsonSerializer.Serialize(spec, PreviewJson.Options);
        var assignment = new SignedProductAssignment(1, enrollment.Id, Guid.NewGuid(), Guid.NewGuid(), 1,
            HyperVProductVmProvider.Id, json, WorkloadAuthorizationEnvelope.Digest(json), "key", "", Now, Now.AddHours(2));
        assignment = assignment with { SignatureBase64 = Convert.ToBase64String(key.SignData(assignment.Payload(), HashAlgorithmName.SHA256)) };
        var result = new ProductGuestBoot(1, enrollment, assignment); capture?.Invoke(key, result); return result;
    }
    private sealed class Commands : IGuestCommandRunner
    {
        public List<IReadOnlyList<string>> Calls { get; } = [];
        public Task<GuestCommandResult> DockerAsync(string directory, IReadOnlyList<string> args, CancellationToken token)
        {
            Calls.Add(args.ToArray());
            var position = args.ToList().IndexOf("--iidfile");
            if (position >= 0) File.WriteAllText(args[position+1], "sha256:" + new string('c',64));
            return Task.FromResult(new GuestCommandResult(0, "password=test-secret", false));
        }
    }
    private sealed class Handler : HttpMessageHandler
    {
        public List<string> Requests { get; } = [];
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            Requests.Add(request.ToString());
            Assert.Equal("127.0.0.1", request.RequestUri!.Host);
            Assert.Equal(18080, request.RequestUri.Port);
            Assert.False(request.Headers.Contains("Authorization"));
            Assert.False(request.Headers.Contains("Cookie"));
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("healthy") });
        }
    }
    [Theory]
    [InlineData("../escape")]
    [InlineData("/absolute")]
    [InlineData("source/../../escape")]
    [InlineData("source\\file")]
    [InlineData("C:secret")]
    public async Task Archive_traversal_is_rejected_before_extraction(string name)
    {
        var root = Root(); var archive = Archive(root, (name, "bad", 0)); var target = Path.Combine(root, "out");
        await Assert.ThrowsAsync<InvalidDataException>(() => ProductArtifact.ExtractAsync(archive.Path, target, archive.Digest, 65536, default));
        Assert.False(Directory.Exists(target));
    }
    [Fact] public async Task Archive_rejects_symlinks_duplicates_bombs_and_wrong_digest()
    {
        var root = Root();
        foreach (var entries in new[]
        {
            new[] { ("site/link", "/etc/passwd", unchecked((int)0xa1ff0000)) },
            new[] { ("site/a", "1", 0), ("site/A", "2", 0) },
            new[] { ("site/bomb", new string('a', 100000), 0) }
        })
        {
            var archive = Archive(root, entries);
            await Assert.ThrowsAsync<InvalidDataException>(() => ProductArtifact.ExtractAsync(archive.Path,
                Path.Combine(root, Guid.NewGuid().ToString("N")), archive.Digest, 32768, default));
        }
        var valid = Archive(root, ("site/index.html", "valid", 0));
        await Assert.ThrowsAsync<InvalidDataException>(() => ProductArtifact.ExtractAsync(valid.Path,
            Path.Combine(root,"wrong"), "sha256:" + new string('0',64), 32768, default));
    }
    [Fact] public async Task Static_guest_serves_exact_artifact_and_denies_traversal_and_expiry()
    {
        var root = Root(); var archive = Archive(root, ("site/index.html", "<h1>Demo</h1>", 0));
        var commands = new Commands(); var clock = new Clock();
        await using var guest = new ProductGuestSession(Boot(archive.Digest), archive.Path, root, commands, clock);
        var first = await guest.HandleAsync(new(Guid.NewGuid(), "initialize"), default);
        Assert.Equal(PreviewPhase.Ready, first.Phase);
        Assert.Equal(PreviewPhase.Ready, (await guest.HandleAsync(new(Guid.NewGuid(),"initialize"),default)).Phase);
        var response = await guest.HandleAsync(new(Guid.NewGuid(), "http", new("GET", "/", new Dictionary<string,string>(), [])), default);
        Assert.Equal("<h1>Demo</h1>", Encoding.UTF8.GetString(response.Http!.Body));
        var traversal = await guest.HandleAsync(new(Guid.NewGuid(), "http", new("GET", "/%2e%2e/secret", new Dictionary<string,string>(), [])), default);
        Assert.Equal(400, traversal.Http!.StatusCode);
        clock.Current = Now.AddHours(2);
        Assert.Equal("LeaseExpired", (await guest.HandleAsync(new(Guid.NewGuid(),"http", new("GET","/",new Dictionary<string,string>(),[])),default)).FailureCode);
        Assert.Empty(commands.Calls);
    }
    [Fact] public async Task Invalid_boot_never_extracts_or_executes_and_retains_failure()
    {
        var root = Root(); var archive = Archive(root, ("site/index.html", "hello", 0)); var boot = Boot(archive.Digest);
        var commands = new Commands();
        await using var guest = new ProductGuestSession(boot with { Assignment = boot.Assignment with { FencingEpoch = 2 } },
            archive.Path, root, commands, new Clock());
        Assert.Equal(PreviewPhase.Failed, (await guest.HandleAsync(new(Guid.NewGuid(),"initialize"),default)).Phase);
        Assert.False(Directory.Exists(Path.Combine(root,"product"))); Assert.Empty(commands.Calls);
        var diagnostics = await guest.HandleAsync(new(Guid.NewGuid(),"diagnostics"),default);
        Assert.Contains(diagnostics.Diagnostics!, x => x.Code == "StartFailed");
    }
    [Fact] public async Task Container_guest_builds_offline_executes_only_normalized_compose_and_strips_credentials()
    {
        var root = Root(); var archive = Archive(root, ("source/Dockerfile", "FROM scratch", 0));
        var commands = new Commands(); var handler = new Handler();
        await using var guest = new ProductGuestSession(Boot(archive.Digest, PreviewMode.Containers), archive.Path, root,
            commands, new Clock(), handler);
        Assert.Equal(PreviewPhase.Ready, (await guest.HandleAsync(new(Guid.NewGuid(),"initialize"),default)).Phase);
        Assert.Contains(commands.Calls, x => x.Take(3).SequenceEqual(new[] { "build","--network","none" }));
        var compose = JsonDocument.Parse(await File.ReadAllTextAsync(Path.Combine(root,"runtime.compose.json")));
        var service = compose.RootElement.GetProperty("services").GetProperty("app");
        Assert.False(service.TryGetProperty("build",out _)); Assert.True(service.GetProperty("read_only").GetBoolean());
        Assert.Equal("never",service.GetProperty("pull_policy").GetString());
        var response = await guest.HandleAsync(new(Guid.NewGuid(),"http",new("GET","/test",
            new Dictionary<string,string> { ["Authorization"]="Bearer sensitive", ["Cookie"]="headquarters=session" },[])),default);
        Assert.Equal(200,response.Http!.StatusCode); Assert.Equal(2,handler.Requests.Count);
        var diagnostics = await guest.HandleAsync(new(Guid.NewGuid(),"diagnostics"),default);
        Assert.All(diagnostics.Diagnostics!, x => Assert.DoesNotContain("test-secret",x.Summary));
    }
    [Theory]
    [InlineData("//external/")]
    [InlineData("/\\external/")]
    [InlineData("http://external/")]
    [InlineData("/path\r\nInjected: true")]
    public void Http_rejects_destination_override_and_header_injection(string path) =>
        Assert.Throws<InvalidDataException>(() => ProductGuestProtocol.ValidateHttp(new("GET",path,new Dictionary<string,string>(),[])));

    [Fact] public async Task Frames_reject_oversized_length_and_duplicate_command_properties()
    {
        var buffer = new byte[4]; BinaryPrimitives.WriteInt32BigEndian(buffer, ProductGuestProtocol.MaximumFrameBytes+1);
        await Assert.ThrowsAsync<InvalidDataException>(() => ProductGuestProtocol.ReadAsync<ProductGuestRequest>(new MemoryStream(buffer),default));
        var payload = Encoding.UTF8.GetBytes("""{"requestId":"00000000-0000-0000-0000-000000000001","kind":"status","kind":"stop"}""");
        using var stream = new MemoryStream(); BinaryPrimitives.WriteInt32BigEndian(buffer,payload.Length);
        stream.Write(buffer); stream.Write(payload); stream.Position=0;
        await Assert.ThrowsAsync<JsonException>(() => ProductGuestProtocol.ReadAsync<ProductGuestRequest>(stream,default));
    }
    [Fact] public void Certification_requires_product_purpose_exact_image_and_all_controls()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var pub = Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()); var digest = "sha256:"+new string('b',64);
        var valid = new ProductCertification(ProductCertificationVerifier.Purpose,HyperVProductVmProvider.Id,
            HyperVProductVmProvider.Version,digest,"1",ProductCertificationVerifier.RequiredControls,new Dictionary<string,string> { ["runtime.dll"]=digest },Now.AddDays(-1),Now.AddDays(1));
        SignedProductCertification Sign(ProductCertification cert)
        { var json = JsonSerializer.Serialize(cert,PreviewJson.Options); return new(json,Convert.ToBase64String(key.SignData(Encoding.UTF8.GetBytes(json),HashAlgorithmName.SHA256))); }
        Assert.Equal(valid.GuestImageDigest,ProductCertificationVerifier.Verify(Sign(valid),pub,valid.ProviderId,valid.ProviderVersion,digest,Now).GuestImageDigest);
        foreach (var invalid in new[] { valid with { Purpose="CSweet.Office" },valid with { Controls=[] },
            valid with { ExpiresAt=Now },valid with { GuestImageDigest="sha256:"+new string('c',64) } })
            Assert.Throws<UnauthorizedAccessException>(() => ProductCertificationVerifier.Verify(Sign(invalid),pub,valid.ProviderId,valid.ProviderVersion,digest,Now));
    }
    [Fact] public async Task Large_static_assets_support_bounded_ranges_head_and_unsatisfied_ranges()
    {
        var root = Root(); var content = new string('x', ProductGuestProtocol.MaximumHttpBodyBytes + 17);
        var archive = Archive(root, ("site/index.html", content, 0));
        await using var guest = new ProductGuestSession(Boot(archive.Digest), archive.Path, root, new Commands(), new Clock());
        Assert.Equal(PreviewPhase.Ready, (await guest.HandleAsync(new(Guid.NewGuid(), "initialize"), default)).Phase);
        async Task<GuestHttpResponse> Request(string method, string? range = null) => (await guest.HandleAsync(new(Guid.NewGuid(), "http",
            new(method, "/", range is null ? new Dictionary<string,string>() : new Dictionary<string,string> { ["Range"] = range }, [])), default)).Http!;
        var head = await Request("HEAD"); Assert.Equal(content.Length.ToString(), head.Headers["Content-Length"]); Assert.Empty(head.Body);
        var first = await Request("GET", "bytes=0-4194303"); Assert.Equal(206, first.StatusCode); Assert.Equal(4194304, first.Body.Length);
        var last = await Request("GET", "bytes=4194304-8388607"); Assert.Equal(206, last.StatusCode); Assert.Equal(17, last.Body.Length);
        Assert.Equal(first.Headers["ETag"], last.Headers["ETag"]);
        Assert.Equal(413, (await Request("GET")).StatusCode);
        Assert.Equal(416, (await Request("GET", "bytes=99999999-")).StatusCode);
        Assert.Equal(416, (await Request("GET", "bytes=0-1,4-5")).StatusCode);
        Assert.Equal(3, (await Request("GET", "bytes=-3")).Body.Length);
    }    [Theory]
    [InlineData("connect", 0, "game")]
    [InlineData("open", 65537, "game")]
    [InlineData("open", 0, "game\r\nCookie: stolen")]
    public void WebSockets_reject_unknown_operations_oversized_messages_and_protocol_injection(string operation, int length, string protocol) =>
        Assert.Throws<InvalidDataException>(() => ProductGuestProtocol.ValidateHttp(new("GET", "/socket", new Dictionary<string,string>(),
            new byte[length], Socket: new(operation, Guid.NewGuid(), [protocol]))));

    [Fact] public async Task Container_WebSocket_round_trip_uses_fixed_guest_loopback_and_bounded_messages()
    {
        // The test server occupies the same guest-only port as the normalized container ingress.
        using var listener = new HttpListener(); listener.Prefixes.Add("http://127.0.0.1:18080/"); listener.Start();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var server = Task.Run(async () =>
        {
            var context = await listener.GetContextAsync().WaitAsync(timeout.Token);
            Assert.Equal("/socket", context.Request.RawUrl); Assert.Equal("game", context.Request.Headers["Sec-WebSocket-Protocol"]);
            Assert.Null(context.Request.Headers["Authorization"]); Assert.Equal("session=product", context.Request.Headers["Cookie"]);
            var accepted = await context.AcceptWebSocketAsync("game"); using var socket = accepted.WebSocket;
            var bytes = new byte[64]; var received = await socket.ReceiveAsync(bytes.AsMemory(), timeout.Token);
            Assert.Equal(System.Net.WebSockets.WebSocketMessageType.Text, received.MessageType);
            await socket.SendAsync(bytes.AsMemory(0, received.Count), received.MessageType, true, timeout.Token);
            await Task.Delay(300, timeout.Token);
        }, timeout.Token);
        var root = Root(); var archive = Archive(root, ("source/Dockerfile", "FROM scratch", 0));
        await using var guest = new ProductGuestSession(Boot(archive.Digest, PreviewMode.Containers), archive.Path, root, new Commands(), new Clock(), new Handler());
        Assert.Equal(PreviewPhase.Ready, (await guest.HandleAsync(new(Guid.NewGuid(), "initialize"), timeout.Token)).Phase);
        var id = Guid.NewGuid();
        async Task<GuestHttpResponse> Operation(string operation, byte[]? data = null) => (await guest.HandleAsync(new(Guid.NewGuid(), "http",
            new("GET", "/socket", new Dictionary<string,string> { ["Authorization"] = "Bearer never-forward" }, data ?? [],
                new Dictionary<string,string> { ["session"] = "product" }, new(operation, id, operation == "open" ? ["game"] : null))), timeout.Token)).Http!;
        var opened = await Operation("open"); Assert.Equal("game", opened.Headers["X-CSweet-Socket-Protocol"]);
        await Operation("send-text", Encoding.UTF8.GetBytes("hello"));
        GuestHttpResponse response;
        do { response = await Operation("receive"); if (response.Headers["X-CSweet-Socket-State"] == "open") await Task.Delay(10, timeout.Token); }
        while (response.Headers["X-CSweet-Socket-State"] == "open");
        Assert.Equal("message", response.Headers["X-CSweet-Socket-State"]); Assert.Equal("hello", Encoding.UTF8.GetString(response.Body));
        await Operation("close"); Assert.Equal("closed", (await Operation("receive")).Headers["X-CSweet-Socket-State"]);
        await server;
    }
    [Fact] public async Task Signed_renewal_preserves_the_guest_and_rejects_changed_resource_authority()
    {
        var root = Root(); var archive = Archive(root, ("site/index.html", "same instance", 0));
        SignedProductAssignment next = null!, escalated = null!;
        var boot = Boot(archive.Digest, capture: (key, initial) =>
        {
            var spec = JsonSerializer.Deserialize<ProductWorkloadSpecification>(initial.Assignment.SpecificationJson, PreviewJson.Options)!;
            SignedProductAssignment Sign(ProductWorkloadSpecification value)
            {
                var json = JsonSerializer.Serialize(value, PreviewJson.Options);
                var assignment = initial.Assignment with { SpecificationJson = json, SpecificationDigest = WorkloadAuthorizationEnvelope.Digest(json),
                    ExpiresAt = Now.AddHours(3), FencingEpoch = 2, SignatureBase64 = "" };
                return assignment with { SignatureBase64 = Convert.ToBase64String(key.SignData(assignment.Payload(), HashAlgorithmName.SHA256)) };
            }
            next = Sign(spec with { Manifest = spec.Manifest with { LifetimeSeconds = 10800 } });
            escalated = Sign(spec with { Manifest = spec.Manifest with { LifetimeSeconds = 10800, Resources = ResourceBudget.Default with { CpuCount = 8 } } });
        });
        var clock = new Clock(); var commands = new Commands();
        await using var guest = new ProductGuestSession(boot, archive.Path, root, commands, clock);
        await guest.HandleAsync(new(Guid.NewGuid(), "initialize"), default);
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => guest.HandleAsync(new(Guid.NewGuid(), "renew", Renewal: escalated), default));
        await guest.HandleAsync(new(Guid.NewGuid(), "renew", Renewal: next), default);
        await guest.HandleAsync(new(Guid.NewGuid(), "renew", Renewal: next), default);
        clock.Current = Now.AddHours(2).AddSeconds(1);
        var page = await guest.HandleAsync(new(Guid.NewGuid(), "http", new("GET", "/", new Dictionary<string,string>(), [])), default);
        Assert.Equal("same instance", Encoding.UTF8.GetString(page.Http!.Body)); Assert.Empty(commands.Calls);
        clock.Current = Now.AddHours(3);
        Assert.Equal("LeaseExpired", (await guest.HandleAsync(new(Guid.NewGuid(), "status"), default)).FailureCode);
    }
    private sealed class BrowserRunner(bool fail) : IGuestBrowserRunner
    {
        public int Calls { get; private set; }
        public Task<IReadOnlyList<PreviewBrowserCheckResult>> RunAsync(PreviewMode mode, IReadOnlyList<PreviewBrowserCheck> checks, CancellationToken token)
        {
            Calls++; Assert.Equal(PreviewMode.Static, mode);
            if (fail) throw new IOException("password=runner-private-error");
            return Task.FromResult<IReadOnlyList<PreviewBrowserCheckResult>>([
                new(0, false, "BrowserAssertionFailed", "password=browser-private-error")]);
        }
    }
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Browser_failures_preserve_page_context_without_secrets_and_reject_external_checks(bool fail)
    {
        var root = Root(); var archive = Archive(root, ("site/index.html", "game", 0)); var runner = new BrowserRunner(fail);
        await using var guest = new ProductGuestSession(Boot(archive.Digest), archive.Path, root, new Commands(), new Clock(), browserRunner: runner);
        await guest.HandleAsync(new(Guid.NewGuid(), "initialize"), default);
        await Assert.ThrowsAsync<InvalidDataException>(() => guest.HandleAsync(new(Guid.NewGuid(), "test", Checks: [new("https://external.example/")]), default));
        Assert.Equal(0, runner.Calls);
        var response = await guest.HandleAsync(new(Guid.NewGuid(), "test", Checks: [new("/game?token=private-query", "#play")]), default);
        Assert.False(Assert.Single(response.TestResults!).Passed); Assert.Equal(1, runner.Calls);
        Assert.Equal(PreviewPhase.Ready, response.Phase);
        var evidence = await guest.HandleAsync(new(Guid.NewGuid(), "diagnostics"), default);
        var json = JsonSerializer.Serialize(evidence.Diagnostics, PreviewJson.Options);
        Assert.Contains("/game", json); Assert.Contains("#play", json);
        Assert.DoesNotContain("private-query", json); Assert.DoesNotContain("browser-private-error", json); Assert.DoesNotContain("runner-private-error", json);
    }
}
