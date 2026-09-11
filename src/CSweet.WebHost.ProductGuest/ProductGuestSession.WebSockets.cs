using System.Net.WebSockets;
using System.Threading.Channels;
using CSweet.WebHost.Contracts;
using CSweet.WebHost.Core;

namespace CSweet.WebHost.ProductGuest;
public sealed partial class ProductGuestSession
{
    private readonly Dictionary<Guid, SocketSession> sockets = [];
    private sealed record SocketMessage(byte[] Data, WebSocketMessageType Type);
    private sealed class SocketSession(ClientWebSocket socket, DateTimeOffset now) : IDisposable
    {
        public ClientWebSocket Socket { get; } = socket;
        public DateTimeOffset TouchedAt { get; set; } = now;
        public Channel<SocketMessage> Incoming { get; } = Channel.CreateBounded<SocketMessage>(new BoundedChannelOptions(8) { FullMode = BoundedChannelFullMode.Wait, SingleReader = true, SingleWriter = true });
        private readonly CancellationTokenSource lifetime = new();
        public async Task ReceiveAsync()
        {
            try
            {
                var buffer = new byte[65537];
                while (!lifetime.IsCancellationRequested)
                {
                    var length = 0; ValueWebSocketReceiveResult result;
                    do
                    {
                        result = await Socket.ReceiveAsync(buffer.AsMemory(length), lifetime.Token);
                        if (result.MessageType == WebSocketMessageType.Close) return;
                        length += result.Count; if (length > 65536) throw new InvalidDataException("A product WebSocket message exceeds its limit.");
                    } while (!result.EndOfMessage);
                    await Incoming.Writer.WriteAsync(new(buffer.AsSpan(0,length).ToArray(), result.MessageType), lifetime.Token);
                }
            }
            catch (Exception error) when (error is WebSocketException or IOException or OperationCanceledException or ObjectDisposedException) { }
            finally { Incoming.Writer.TryComplete(); Socket.Abort(); }
        }
        public void Dispose() { lifetime.Cancel(); Socket.Abort(); Socket.Dispose(); lifetime.Dispose(); }
    }
    private void SweepSockets()
    {
        foreach (var id in sockets.Where(x => x.Value.TouchedAt <= clock.GetUtcNow().AddMinutes(-2)).Select(x => x.Key).ToArray())
        { sockets[id].Dispose(); sockets.Remove(id); }
    }
    private async Task<GuestHttpResponse> SocketAsync(GuestHttpRequest request, CancellationToken token)
    {
        ProductGuestProtocol.ValidateHttp(request);
        if (specification?.Manifest.Mode != PreviewMode.Containers) throw new InvalidDataException("Static previews do not have a WebSocket server.");
        var operation = request.Socket!;
        if (operation.Operation == "open")
        {
            if (sockets.Count >= 16 || sockets.ContainsKey(operation.ConnectionId)) throw new InvalidOperationException("The preview WebSocket capacity is exhausted.");
            var origin = new Uri("ws://127.0.0.1:18080"); var target = new Uri(origin, request.Path);
            if (target.Scheme != origin.Scheme || target.Host != origin.Host || target.Port != origin.Port || target.UserInfo.Length > 0)
                throw new InvalidDataException("The WebSocket destination changed.");
            var socket = new ClientWebSocket(); socket.Options.Proxy = null; socket.Options.UseDefaultCredentials = false;
            foreach (var protocol in operation.Subprotocols ?? []) socket.Options.AddSubProtocol(protocol);
            if (request.ProductCookies is { Count: > 0 }) socket.Options.SetRequestHeader("Cookie", string.Join("; ", request.ProductCookies.Select(x => x.Key + "=" + x.Value)));
            try
            {
                using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token); deadline.CancelAfter(TimeSpan.FromSeconds(10));
                await socket.ConnectAsync(target, deadline.Token);
                var session = new SocketSession(socket, clock.GetUtcNow()); sockets.Add(operation.ConnectionId, session);
                _ = session.ReceiveAsync();
                return new(200, new Dictionary<string,string> { ["X-CSweet-Socket-State"] = "open", ["X-CSweet-Socket-Protocol"] = socket.SubProtocol ?? "" }, []);
            }
            catch { socket.Dispose(); throw; }
        }
        if (!sockets.TryGetValue(operation.ConnectionId, out var existing))
            return new(200, new Dictionary<string,string> { ["X-CSweet-Socket-State"] = "closed" }, []);
        existing.TouchedAt = clock.GetUtcNow();
        if (operation.Operation == "close") { existing.Dispose(); sockets.Remove(operation.ConnectionId); return new(204, new Dictionary<string,string>(), []); }
        if (operation.Operation == "receive")
        {
            if (existing.Incoming.Reader.TryRead(out var message))
                return new(200, new Dictionary<string,string> { ["X-CSweet-Socket-State"] = "message", ["X-CSweet-Socket-Type"] = message.Type == WebSocketMessageType.Text ? "text" : "binary" }, message.Data);
            return new(200, new Dictionary<string,string> { ["X-CSweet-Socket-State"] = existing.Incoming.Reader.Completion.IsCompleted ? "closed" : "open" }, []);
        }
        using var sendDeadline = CancellationTokenSource.CreateLinkedTokenSource(token); sendDeadline.CancelAfter(TimeSpan.FromSeconds(10));
        await existing.Socket.SendAsync(request.Body.AsMemory(), operation.Operation == "send-text" ? WebSocketMessageType.Text : WebSocketMessageType.Binary, true, sendDeadline.Token);
        return new(204, new Dictionary<string,string>(), []);
    }
}
