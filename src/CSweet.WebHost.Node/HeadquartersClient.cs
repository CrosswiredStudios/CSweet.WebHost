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
    private readonly Uri endpoint;
    public HeadquartersClient(Uri headquarters)
    {
        if (headquarters.Scheme != Uri.UriSchemeHttps || !string.IsNullOrEmpty(headquarters.UserInfo) ||
            headquarters.AbsolutePath != "/" || !string.IsNullOrEmpty(headquarters.Query) || !string.IsNullOrEmpty(headquarters.Fragment))
            throw new ArgumentException("Configure the exact HTTPS Headquarters origin without credentials, path, query or fragment.");
        endpoint = new Uri(headquarters, "/api/web-host/v1/heartbeat");
        http = new HttpClient(new HttpClientHandler
        {
            AllowAutoRedirect = false, UseCookies = false, UseDefaultCredentials = false,
            AutomaticDecompression = DecompressionMethods.None, UseProxy = false
        }) { Timeout = TimeSpan.FromSeconds(30) };
    }
    public async Task<WebHostHeartbeatReceipt> HeartbeatAsync(SignedWebHostMessage message, CancellationToken token)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(TimeSpan.FromSeconds(30));
        token = deadline.Token;
        using var request = new HttpRequestMessage(HttpMethod.Post, endpoint)
        { Content = JsonContent.Create(message, options: PreviewJson.Options) };
        using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, token);
        response.EnsureSuccessStatusCode(); // In particular, never follow redirects with a signed identity.
        await using var stream = await response.Content.ReadAsStreamAsync(token);
        using var body = new MemoryStream();
        var buffer = new byte[4096];
        while (true)
        {
            var read = await stream.ReadAsync(buffer, token);
            if (read == 0) break;
            if (body.Length + read > 16384) throw new InvalidDataException("The Headquarters response exceeds its bound.");
            body.Write(buffer, 0, read);
        }
        var receipt = JsonSerializer.Deserialize<WebHostHeartbeatReceipt>(body.ToArray(), PreviewJson.Options)
            ?? throw new InvalidDataException("The Headquarters response is empty.");
        if (receipt.RequestId != message.RequestId || receipt.Sequence != message.Sequence)
            throw new InvalidDataException("The Headquarters response belongs to another request.");
        return receipt;
    }
    public void Dispose() => http.Dispose();
}

public sealed class WebHostMessageSigner(WebHostBootstrap bootstrap, ECDsa identity, DurableState state, TimeProvider clock)
{
    public async Task<SignedWebHostMessage> HeartbeatAsync(WebHostHeartbeat heartbeat, CancellationToken token)
    {
        if (bootstrap.ControlPlaneId == Guid.Empty || bootstrap.Enrollment.Id == Guid.Empty ||
            heartbeat.WebHostId != bootstrap.Enrollment.Id || bootstrap.IdentityExpiresAt <= clock.GetUtcNow())
            throw new UnauthorizedAccessException("The WebHost identity is unavailable or does not match the installed runtime.");
        // Reserve before I/O; a crash loses a number but can never reuse a signed request.
        var sequence = await state.TransactionAsync(data =>
        {
            if (data.NodeIdentityHostId is { } prior && prior != bootstrap.Enrollment.Id)
                throw new UnauthorizedAccessException("The Node state belongs to another host enrollment.");
            data.NodeIdentityHostId = bootstrap.Enrollment.Id;
            return data.NodeSequence = checked(data.NodeSequence + 1);
        }, token);
        var now = DateTimeOffset.FromUnixTimeSeconds(clock.GetUtcNow().ToUnixTimeSeconds());
        var expires = now.AddSeconds(60);
        if (expires > bootstrap.IdentityExpiresAt)
            expires = DateTimeOffset.FromUnixTimeSeconds(bootstrap.IdentityExpiresAt.ToUnixTimeSeconds());
        var body = JsonSerializer.Serialize(heartbeat, PreviewJson.Options);
        var message = new SignedWebHostMessage(1, bootstrap.ControlPlaneId, bootstrap.Enrollment.Id, Guid.NewGuid(),
            sequence, "heartbeat", body, WorkloadAuthorizationEnvelope.Digest(body), "", now, expires);
        return message with { SignatureBase64 = Convert.ToBase64String(identity.SignData(message.Payload(), HashAlgorithmName.SHA256)) };
    }
}
