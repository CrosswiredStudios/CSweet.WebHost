using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using CSweet.WebHost.Contracts;
using CSweet.WebHost.Core;
using CSweet.Isolation.Security;
namespace CSweet.WebHost.Node;

public sealed class HeadquartersClient : IDisposable
{
    private readonly HttpClient http;
    private readonly Uri origin;
    public HeadquartersClient(Uri headquarters, HttpMessageHandler? handler = null)
    {
        if (headquarters.Scheme != Uri.UriSchemeHttps || !string.IsNullOrEmpty(headquarters.UserInfo) ||
            headquarters.AbsolutePath != "/" || !string.IsNullOrEmpty(headquarters.Query) || !string.IsNullOrEmpty(headquarters.Fragment))
            throw new ArgumentException("Configure the exact HTTPS Headquarters origin without credentials, path, query or fragment.");
        origin = headquarters;
        http = new HttpClient(handler ?? new HttpClientHandler
        {
            AllowAutoRedirect = false, UseCookies = false, UseDefaultCredentials = false,
            AutomaticDecompression = DecompressionMethods.None, UseProxy = false
        }) { Timeout = Timeout.InfiniteTimeSpan };
    }
    public async Task<WebHostHeartbeatReceipt> HeartbeatAsync(SignedWebHostMessage message, CancellationToken token)
    {
        var receipt = await PostAsync<WebHostHeartbeatReceipt>(message, "heartbeat", 16384, token);
        CheckReceipt(message, receipt.RequestId, receipt.Sequence);
        return receipt;
    }
    public async Task<WebHostCommandPollReceipt> PollAsync(SignedWebHostMessage message, CancellationToken token)
    {
        var receipt = await PostAsync<WebHostCommandPollReceipt>(message, "poll", 16 * 1024 * 1024, token);
        CheckReceipt(message, receipt.RequestId, receipt.Sequence);
        return receipt;
    }
    public async Task<WebHostCommandResultReceipt> CompleteAsync(SignedWebHostMessage message, CancellationToken token)
    {
        var receipt = await PostAsync<WebHostCommandResultReceipt>(message, "result", 16384, token);
        CheckReceipt(message, receipt.RequestId, receipt.Sequence);
        return receipt;
    }
    public async Task<Stream> OpenArtifactAsync(SignedWebHostMessage message, CancellationToken token)
    {
        using var request = Request(message, "artifact");
        var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(TimeSpan.FromMinutes(5));
        HttpResponseMessage? response = null;
        try
        {
            response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, deadline.Token);
            response.EnsureSuccessStatusCode();
            return new OwnedArtifactStream(await response.Content.ReadAsStreamAsync(deadline.Token), response, deadline);
        }
        catch { response?.Dispose(); deadline.Dispose(); throw; }
    }
    private async Task<T> PostAsync<T>(SignedWebHostMessage message, string action, int limit, CancellationToken token)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(TimeSpan.FromSeconds(30));
        using var request = Request(message, action);
        using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, deadline.Token);
        response.EnsureSuccessStatusCode();
        await using var stream = await response.Content.ReadAsStreamAsync(deadline.Token);
        using var body = new MemoryStream();
        var buffer = new byte[8192];
        while (true)
        {
            var read = await stream.ReadAsync(buffer, deadline.Token);
            if (read == 0) break;
            if (body.Length + read > limit) throw new InvalidDataException("The Headquarters response exceeds its bound.");
            body.Write(buffer, 0, read);
        }
        return JsonSerializer.Deserialize<T>(body.ToArray(), PreviewJson.Options)
            ?? throw new InvalidDataException("The Headquarters response is empty.");
    }
    private HttpRequestMessage Request(SignedWebHostMessage message, string action)
    {
        if (message.Action != action) throw new ArgumentException("The signed host message has a different purpose.");
        return new(HttpMethod.Post, new Uri(origin, "/api/web-host/v1/" + action))
            { Content = JsonContent.Create(message, options: PreviewJson.Options) };
    }
    private static void CheckReceipt(SignedWebHostMessage message, Guid id, long sequence)
    {
        if (message.RequestId != id || message.Sequence != sequence)
            throw new InvalidDataException("The Headquarters response belongs to another request.");
    }
    public void Dispose() => http.Dispose();

    private sealed class OwnedArtifactStream(Stream inner, HttpResponseMessage response, CancellationTokenSource deadline) : Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken token = default)
        {
            using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(token, deadline.Token);
            return await inner.ReadAsync(buffer, cancellation.Token);
        }
        protected override void Dispose(bool disposing)
        {
            if (disposing) { inner.Dispose(); response.Dispose(); deadline.Dispose(); }
            base.Dispose(disposing);
        }
        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}

public sealed class WebHostMessageSigner(WebHostBootstrap bootstrap, ECDsa identity, DurableState state, TimeProvider clock)
{
    public Task<SignedWebHostMessage> HeartbeatAsync(WebHostHeartbeat heartbeat, CancellationToken token)
    {
        if (heartbeat.WebHostId != bootstrap.Enrollment.Id) throw new UnauthorizedAccessException("The runtime belongs to another host.");
        return SignAsync("heartbeat", heartbeat, token);
    }
    public async Task<SignedWebHostMessage> SignAsync<T>(string action, T content, CancellationToken token)
    {
        if (bootstrap.ControlPlaneId == Guid.Empty || bootstrap.Enrollment.Id == Guid.Empty || (bootstrap.IdentityExpiresAt <= clock.GetUtcNow() && action is not ("poll" or "result")) ||
            action is not ("heartbeat" or "poll" or "result" or "artifact"))
            throw new UnauthorizedAccessException("The WebHost identity or message purpose is unavailable.");
        var sequence = await state.TransactionAsync(data =>
        {
            if (data.NodeIdentityHostId is { } prior && prior != bootstrap.Enrollment.Id)
                throw new UnauthorizedAccessException("The Node state belongs to another host enrollment.");
            data.NodeIdentityHostId = bootstrap.Enrollment.Id;
            return data.NodeSequence = checked(data.NodeSequence + 1);
        }, token);
        var now = DateTimeOffset.FromUnixTimeSeconds(clock.GetUtcNow().ToUnixTimeSeconds());
        var expires = now.AddSeconds(60);
        if (action is not ("poll" or "result") && expires > bootstrap.IdentityExpiresAt) expires = DateTimeOffset.FromUnixTimeSeconds(bootstrap.IdentityExpiresAt.ToUnixTimeSeconds());
        var body = JsonSerializer.Serialize(content, PreviewJson.Options);
        var message = new SignedWebHostMessage(1, bootstrap.ControlPlaneId, bootstrap.Enrollment.Id, Guid.NewGuid(),
            sequence, action, body, WorkloadAuthorizationEnvelope.Digest(body), "", now, expires);
        return message with { SignatureBase64 = Convert.ToBase64String(identity.SignData(message.Payload(), HashAlgorithmName.SHA256)) };
    }
}
