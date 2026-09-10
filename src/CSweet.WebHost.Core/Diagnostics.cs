using System.Text.RegularExpressions;
using CSweet.Isolation.Security;
using CSweet.WebHost.Contracts;

namespace CSweet.WebHost.Core;

public static partial class DiagnosticSanitizer
{
    [GeneratedRegex(@"(?i)(authorization|cookie|set-cookie|password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token)\s*[:=]\s*[^\r\n]+", RegexOptions.CultureInvariant)]
    private static partial Regex Credentials();
    [GeneratedRegex(@"(?i)\bBearer\s+[a-z0-9._~+/=-]+", RegexOptions.CultureInvariant)]
    private static partial Regex Bearer();
    [GeneratedRegex(@"https?://[^\s]+", RegexOptions.CultureInvariant)]
    private static partial Regex Url();
    [GeneratedRegex(@"\b[0-9a-fA-F]{8}-[0-9a-fA-F-]{27,}\b|\b\d+\b", RegexOptions.CultureInvariant)]
    private static partial Regex VolatileIdentifiers();

    public static string Sanitize(string value, IEnumerable<string> knownSecrets, int maximumCharacters = 4096)
    {
        if (maximumCharacters < 1 || maximumCharacters > 65536) throw new ArgumentOutOfRangeException(nameof(maximumCharacters));
        if (value.Length > 1024 * 1024) return "[diagnostic rejected: input limit exceeded]";
        foreach (var secret in knownSecrets.Where(x => !string.IsNullOrEmpty(x)).OrderByDescending(x => x.Length))
            value = value.Replace(secret, "[redacted]", StringComparison.Ordinal);
        value = Credentials().Replace(value, "$1=[redacted]");
        value = Bearer().Replace(value, "Bearer [redacted]");
        value = Url().Replace(value, "[url omitted]");
        value = new string(value.Where(x => !char.IsControl(x) || x is '\n' or '\t').ToArray());
        return value.Length <= maximumCharacters ? value : value[..maximumCharacters] + "[truncated]";
    }
    public static string Fingerprint(PreviewDiagnostic diagnostic) =>
        WorkloadAuthorizationEnvelope.Digest(string.Join("\n", diagnostic.ProjectId, diagnostic.Service,
            diagnostic.Source, diagnostic.Code, VolatileIdentifiers().Replace(diagnostic.Summary, "#")));
}
public sealed class DiagnosticStore(DurableState state, TimeProvider clock)
{
    public static readonly TimeSpan Retention = TimeSpan.FromDays(7);
    public Task<PreviewFinding> RecordAsync(PreviewDiagnostic diagnostic, IEnumerable<string> knownSecrets,
        CancellationToken token = default)
    {
        if (diagnostic.Id == Guid.Empty || diagnostic.PreviewId == Guid.Empty || diagnostic.ProjectId == Guid.Empty ||
            diagnostic.BuildId == Guid.Empty || diagnostic.Source is not ("build" or "runtime" or "browser") ||
            diagnostic.SourceRevision is not { Length: > 0 and <= 128 } || diagnostic.Summary is null ||
            diagnostic.Service is null || diagnostic.Code is null ||
            diagnostic.OccurredAt > clock.GetUtcNow().AddSeconds(30) ||
            diagnostic.OccurredAt <= clock.GetUtcNow() - Retention)
            throw new ArgumentException("Diagnostics require a recent exact preview, project, build, revision and evidence source.");
        var secrets = knownSecrets.ToArray();
        var clean = diagnostic with
        {
            Summary = DiagnosticSanitizer.Sanitize(diagnostic.Summary, secrets),
            Service = DiagnosticSanitizer.Sanitize(diagnostic.Service, secrets, 128),
            Code = DiagnosticSanitizer.Sanitize(diagnostic.Code, secrets, 128),
            Truncated = diagnostic.Truncated || diagnostic.Summary.Length > 4096
        };
        return state.TransactionAsync(data =>
        {
            Prune(data, clock.GetUtcNow());
            var fingerprint = DiagnosticSanitizer.Fingerprint(clean);
            if (data.Diagnostics.TryGetValue(clean.Id, out var prior))
            {
                if (prior != clean) throw new InvalidOperationException("Diagnostic identity was reused with different evidence.");
                return data.Findings[DiagnosticSanitizer.Fingerprint(prior)];
            }
            if (data.Diagnostics.Count >= 10000) throw new InvalidOperationException("Diagnostic storage budget exhausted.");
            data.Diagnostics.Add(clean.Id, clean);
            data.DiagnosticSequences.Add(clean.Id, checked(++data.LastDiagnosticSequence));
            // Replaying an event must never extend its retention window.
            data.DiagnosticRetainUntil.Add(clean.Id, clean.OccurredAt + Retention);
            var finding = data.Findings.TryGetValue(fingerprint, out var existing)
                ? existing with
                {
                    FirstSeen = clean.OccurredAt < existing.FirstSeen ? clean.OccurredAt : existing.FirstSeen,
                    LastSeen = clean.OccurredAt > existing.LastSeen ? clean.OccurredAt : existing.LastSeen,
                    Occurrences = checked(existing.Occurrences + 1), DiagnosticIds = [..existing.DiagnosticIds, clean.Id]
                }
                : new PreviewFinding(fingerprint, clean.ProjectId, clean.Source, [clean.Id], clean.OccurredAt, clean.OccurredAt, 1);
            data.Findings[fingerprint] = finding;
            return finding;
        }, token);
    }

    /// <summary>Requires authorization for this exact preview at the caller. Does not require a live VM.</summary>
    public Task<PreviewDiagnosticPage> ReadAsync(Guid previewId, long afterSequence = 0, int limit = 100,
        CancellationToken token = default)
    {
        if (previewId == Guid.Empty || afterSequence < 0 || limit is < 1 or > 256)
            throw new ArgumentException("Select an exact preview and a bounded evidence page.");
        return state.TransactionAsync(data =>
        {
            Prune(data, clock.GetUtcNow());
            var items = data.Diagnostics.Values.Where(x => x.PreviewId == previewId && data.DiagnosticSequences[x.Id] > afterSequence)
                .OrderBy(x => data.DiagnosticSequences[x.Id]).Take(limit + 1)
                .Select(x => new RetainedPreviewDiagnostic(data.DiagnosticSequences[x.Id], x, data.DiagnosticRetainUntil[x.Id])).ToArray();
            var page = items.Take(limit).ToArray();
            return new PreviewDiagnosticPage(previewId, page.Length == 0 ? afterSequence : page[^1].Sequence,
                page, items.Length > limit);
        }, token);
    }

    public Task<int> PruneAsync(CancellationToken token = default) => state.TransactionAsync(data => Prune(data, clock.GetUtcNow()), token);

    private static int Prune(WebHostState data, DateTimeOffset now)
    {
        // Upgrade existing protected evidence deterministically; never reset an existing export sequence.
        foreach (var diagnostic in data.Diagnostics.Values.OrderBy(x => x.OccurredAt).ThenBy(x => x.Id))
        {
            if (!data.DiagnosticSequences.ContainsKey(diagnostic.Id))
                data.DiagnosticSequences.Add(diagnostic.Id, checked(++data.LastDiagnosticSequence));
            data.DiagnosticRetainUntil.TryAdd(diagnostic.Id, diagnostic.OccurredAt + Retention);
        }
        var expired = data.DiagnosticRetainUntil.Where(x => x.Value <= now).Select(x => x.Key).ToArray();
        foreach (var id in expired)
        {
            data.Diagnostics.Remove(id); data.DiagnosticSequences.Remove(id); data.DiagnosticRetainUntil.Remove(id);
        }
        if (expired.Length > 0)
        {
            // Finding summaries cannot retain expired raw evidence or dangling diagnostic identities.
            foreach (var key in data.Findings.Keys.ToArray())
            {
                var finding = data.Findings[key];
                var remaining = finding.DiagnosticIds.Where(data.Diagnostics.ContainsKey).Select(id => data.Diagnostics[id]).ToArray();
                if (remaining.Length == 0) data.Findings.Remove(key);
                else data.Findings[key] = finding with
                {
                    DiagnosticIds = remaining.Select(x => x.Id).ToArray(), Occurrences = remaining.Length,
                    FirstSeen = remaining.Min(x => x.OccurredAt), LastSeen = remaining.Max(x => x.OccurredAt)
                };
            }
        }
        return expired.Length;
    }
}
