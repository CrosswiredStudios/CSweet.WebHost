using System.Buffers.Binary;
using System.Text.Json;
using CSweet.WebHost.Contracts;

namespace CSweet.WebHost.Core;

// Public verification material only; delivered by the privileged host on separate read-only boot media.
public sealed record ProductGuestBoot(int Version, WebHostEnrollment Enrollment, SignedProductAssignment Assignment);
public sealed record ProductGuestRequest(Guid RequestId, string Kind, GuestHttpRequest? Http = null,
    long DiagnosticAfterSequence = 0);
public sealed record ProductGuestResponse(Guid RequestId, string Kind, PreviewPhase Phase,
    GuestHttpResponse? Http = null, IReadOnlyList<GuestDiagnostic>? Diagnostics = null, string? FailureCode = null);
public sealed record GuestHttpRequest(string Method, string Path, IReadOnlyDictionary<string, string> Headers, byte[] Body);
public sealed record GuestHttpResponse(int StatusCode, IReadOnlyDictionary<string, string> Headers, byte[] Body);
public sealed record GuestDiagnostic(long Sequence, string Source, string Service, string Code, string Summary, DateTimeOffset OccurredAt);

public static class ProductGuestProtocol
{
    public const int Port = 2762;
    public const int MaximumFrameBytes = 8 * 1024 * 1024;
    public const int MaximumHttpBodyBytes = 4 * 1024 * 1024;
    public static async Task<T> ReadAsync<T>(Stream stream, CancellationToken token)
    {
        var header = new byte[4];
        await stream.ReadExactlyAsync(header, token);
        var length = BinaryPrimitives.ReadInt32BigEndian(header);
        if (length is < 2 or > MaximumFrameBytes) throw new InvalidDataException("Product frame exceeds its limit.");
        var buffer = new byte[length];
        await stream.ReadExactlyAsync(buffer, token);
        return JsonSerializer.Deserialize<T>(buffer, PreviewJson.Options) ?? throw new InvalidDataException("Product frame is empty.");
    }
    public static async Task WriteAsync<T>(Stream stream, T message, CancellationToken token)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(message, PreviewJson.Options);
        if (bytes.Length > MaximumFrameBytes) throw new InvalidDataException("Product frame exceeds its limit.");
        var header = new byte[4]; BinaryPrimitives.WriteInt32BigEndian(header, bytes.Length);
        await stream.WriteAsync(header, token); await stream.WriteAsync(bytes, token); await stream.FlushAsync(token);
    }
    public static void ValidateHttp(GuestHttpRequest request)
    {
        if (request.Method is not ("GET" or "HEAD" or "POST" or "PUT" or "PATCH" or "DELETE" or "OPTIONS") ||
            request.Path is not { Length: > 0 and <= 8192 } || !request.Path.StartsWith('/') ||
            request.Path.StartsWith("//") || request.Path.Contains('\\') || request.Path.Contains('#') ||
            request.Path.Any(char.IsControl) || request.Headers is null || request.Headers.Count > 64 ||
            request.Body is null || request.Body.Length > MaximumHttpBodyBytes)
            throw new InvalidDataException("The preview HTTP request is invalid.");
        foreach (var header in request.Headers)
            if (string.IsNullOrWhiteSpace(header.Key) || header.Key.Length > 128 || header.Value is null ||
                header.Value.Length > 8192 || header.Key.Any(c => !char.IsAsciiLetterOrDigit(c) && c != '-') ||
                header.Value.Any(char.IsControl))
                throw new InvalidDataException("The preview HTTP headers are invalid.");
        if (request.Headers.Sum(x => (long)x.Key.Length + x.Value.Length) > 32768)
            throw new InvalidDataException("The preview HTTP headers exceed their limit.");
    }
}
