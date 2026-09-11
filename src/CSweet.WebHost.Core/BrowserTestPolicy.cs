using CSweet.WebHost.Contracts;
namespace CSweet.WebHost.Core;
public static class BrowserTestPolicy
{
    public static void Validate(IReadOnlyList<PreviewBrowserCheck>? checks)
    {
        if (checks is not { Count: > 0 and <= 10 }) throw new ArgumentException("Choose one to ten bounded browser checks.");
        if (System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(checks, PreviewJson.Options).Length > 32768) throw new ArgumentException("The combined browser checks exceed their input limit.");
        foreach (var check in checks)
        {
            if (check is null || check.Selector is { Length: > 256 } || check.ExpectedText is { Length: > 2048 } ||
                check.Selector?.Any(char.IsControl) == true || check.ExpectedText?.Any(char.IsControl) == true)
                throw new ArgumentException("Invalid browser assertion.");
            ProductGuestProtocol.ValidateHttp(new("GET", check.Path, new Dictionary<string,string>(), []));
        }
    }
    public static string FailureSummary(PreviewBrowserCheck check, PreviewBrowserCheckResult result) => DiagnosticSanitizer.Sanitize(
        $"Browser check {result.Index + 1} at {check.Path.Split('?')[0]}, selector {check.Selector ?? "body"}: {result.Summary}", []);}
