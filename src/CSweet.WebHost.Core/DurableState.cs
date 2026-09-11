using System.Text.Json;
using CSweet.WebHost.Contracts;

namespace CSweet.WebHost.Core;

/// <summary>Single-host, cross-process serialized transactions with atomic, flushed replacement.
/// The root must be protected by the installer and inaccessible to product guests.</summary>
public sealed class DurableState
{
    private readonly string directory;
    public DurableState(string directory)
    {
        if (!Path.IsPathFullyQualified(directory)) throw new ArgumentException("State needs an absolute protected directory.");
        this.directory = Path.GetFullPath(directory);
        Directory.CreateDirectory(this.directory);
        if (new DirectoryInfo(this.directory).LinkTarget is not null) throw new IOException("State cannot be a symbolic link.");
    }
    public async Task<T> TransactionAsync<T>(Func<WebHostState, T> action, CancellationToken token = default)
    {
        var started = System.Diagnostics.Stopwatch.StartNew();
        FileStream? lease = null;
        while (lease is null)
        {
            token.ThrowIfCancellationRequested();
            try { lease = new FileStream(Path.Combine(directory, "state.lock"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None); }
            catch (IOException) when (started.Elapsed < TimeSpan.FromSeconds(5)) { await Task.Delay(25, token); }
        }
        await using var held = lease;
        var file = Path.Combine(directory, "state.json");
        if (File.Exists(file) && new FileInfo(file).Length > 128L * 1024 * 1024)
            throw new InvalidDataException("Protected state exceeds its storage budget.");
        var state = File.Exists(file)
            ? JsonSerializer.Deserialize<WebHostState>(await File.ReadAllTextAsync(file, token), PreviewJson.Options)
                ?? throw new InvalidDataException("State is corrupt; refusing to reset authorization history.")
            : new WebHostState();
        var result = action(state);
        var temporary = Path.Combine(directory, Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            await using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
            {
                await JsonSerializer.SerializeAsync(stream, state, PreviewJson.Options, token);
                if (stream.Length > 128L * 1024 * 1024)
                    throw new InvalidDataException("The transaction exceeds the protected state storage budget.");
                await stream.FlushAsync(token); stream.Flush(flushToDisk: true);
            }
            File.Move(temporary, file, overwrite: true);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
        return result;
    }
}
public sealed class WebHostState
{
    public Guid? NodeIdentityHostId { get; set; }
    public long NodeSequence { get; set; }
    public Dictionary<Guid, string> NodeCommandResults { get; set; } = [];
    public HashSet<Guid> StoppedWorkloads { get; set; } = [];
    public Dictionary<Guid, DateTimeOffset> ControlCommands { get; set; } = [];
    public Dictionary<Guid, PreviewOperation> Operations { get; set; } = [];
    public Dictionary<Guid, string> RequestDigests { get; set; } = [];
    public Dictionary<Guid, long> ReservedCpuSeconds { get; set; } = [];
    public Dictionary<Guid, AssignmentReceipt> Assignments { get; set; } = [];
    public Dictionary<Guid, Guid> WorkloadAssignments { get; set; } = [];
    public Dictionary<string, PreviewFinding> Findings { get; set; } = [];
    public long LastDiagnosticSequence { get; set; }
    public Dictionary<Guid, long> DiagnosticSequences { get; set; } = [];
    public Dictionary<Guid, DateTimeOffset> DiagnosticRetainUntil { get; set; } = [];
    public Dictionary<Guid, PreviewDiagnostic> Diagnostics { get; set; } = [];
}
public sealed record AssignmentReceipt(Guid AssignmentId, Guid WorkloadId, long Epoch, string PayloadDigest,
    DateTimeOffset ExpiresAt, string State);
