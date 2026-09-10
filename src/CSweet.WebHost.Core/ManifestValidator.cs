using System.Text.Json;
using System.Text.RegularExpressions;
using CSweet.WebHost.Contracts;
using CSweet.Isolation.Security;

namespace CSweet.WebHost.Core;

public static partial class ManifestValidator
{
    [GeneratedRegex("^[a-zA-Z0-9][a-zA-Z0-9_-]{0,62}$", RegexOptions.CultureInvariant)]
    private static partial Regex ServiceName();
    public static IReadOnlyList<PreviewProblem> Validate(PreviewManifest? manifest)
    {
        var errors = new List<PreviewProblem>();
        void Error(string field, string message) => errors.Add(new("InvalidManifest", field, message));
        if (manifest is null) return [new("InvalidManifest", "manifest", "A manifest is required.")];
        if (manifest.Version != 1) Error("version", "Only preview manifest version 1 is supported.");
        if (!Enum.IsDefined(manifest.Mode)) Error("mode", "Unknown preview mode.");
        if (manifest.SourceRevision is not { Length: 40 or 64 } || !manifest.SourceRevision.All(Uri.IsHexDigit))
            Error("sourceRevision", "Supply an exact Git commit, not a branch or tag.");
        if (manifest.LifetimeSeconds < 300) Error("lifetimeSeconds", "Request at least five minutes.");
        if (manifest.Resources is null) Error("resources", "Explicit resource limits are required.");
        else { try { manifest.Resources.Validate(); } catch (ArgumentException e) { Error("resources", e.Message); } }
        if (manifest.ConnectionIds is null || manifest.ConnectionIds.Any(string.IsNullOrWhiteSpace) ||
            manifest.ConnectionIds.Distinct(StringComparer.Ordinal).Count() != manifest.ConnectionIds.Count)
            Error("connectionIds", "Connection references must be nonempty and unique.");
        if (manifest.Mode == PreviewMode.Static)
        {
            if (!WorkloadAuthorizationEnvelope.IsDigest(manifest.ArtifactDigest)) Error("artifactDigest", "Static previews require a verified artifact.");
            if (manifest.Entrypoint is not null) Error("entrypoint", "Static previews have no container entrypoint.");
            if (manifest.Compose.ValueKind is not (JsonValueKind.Undefined or JsonValueKind.Null))
                Error("compose", "Static previews cannot contain services.");
            return errors;
        }
        if (!Object(manifest.Compose, "compose", ["services", "volumes"], errors)) return errors;
        if (!manifest.Compose.TryGetProperty("services", out var services) || services.ValueKind != JsonValueKind.Object ||
            !services.EnumerateObject().Any()) { Error("compose.services", "Declare at least one service."); return errors; }
        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (var service in services.EnumerateObject())
        {
            var path = "compose.services." + service.Name;
            if (!ServiceName().IsMatch(service.Name) || !names.Add(service.Name)) Error(path, "Service names must be valid and unique.");
            if (!Object(service.Value, path, ["image", "build", "command", "entrypoint", "environment", "depends_on", "volumes",
                "healthcheck", "working_dir", "user", "scale"], errors)) continue;
            if (!service.Value.TryGetProperty("image", out var image) && !service.Value.TryGetProperty("build", out _))
                Error(path, "Supply an image or build definition.");
            if (image.ValueKind != JsonValueKind.Undefined &&
                (image.ValueKind != JsonValueKind.String || !PinnedImage(image.GetString())))
                Error(path + ".image", "Use a registry-qualified image pinned by SHA-256 digest.");
            if (service.Value.TryGetProperty("build", out var build))
            {
                if (!Object(build, path + ".build", ["context", "dockerfile", "target", "args"], errors)) continue;
                foreach (var field in new[] { "context", "dockerfile" })
                    if (build.TryGetProperty(field, out var value) && (value.ValueKind != JsonValueKind.String || !RelativePath(value.GetString())))
                        Error(path + ".build." + field, "Use a repository-relative path; remote and host paths are forbidden.");
                if (build.TryGetProperty("target", out var target) && (target.ValueKind != JsonValueKind.String || !ServiceName().IsMatch(target.GetString()!)))
                    Error(path + ".build.target", "Use a valid build stage name.");
                if (build.TryGetProperty("args", out var args)) StringMap(args, path + ".build.args", errors);
            }
            foreach (var field in new[] { "command", "entrypoint" })
                if (service.Value.TryGetProperty(field, out var value) &&
                    (value.ValueKind != JsonValueKind.Array || value.EnumerateArray().Any(x => x.ValueKind != JsonValueKind.String)))
                    Error(path + "." + field, "Use an argument array.");
            if (service.Value.TryGetProperty("environment", out var env)) StringMap(env, path + ".environment", errors);
            foreach (var field in new[] { "working_dir", "user" })
                if (service.Value.TryGetProperty(field, out var value) && (value.ValueKind != JsonValueKind.String ||
                    string.IsNullOrWhiteSpace(value.GetString()) || value.GetString()!.Any(char.IsControl)))
                    Error(path + "." + field, "Use a nonempty literal string.");
            if (service.Value.TryGetProperty("scale", out var scale) && (scale.ValueKind != JsonValueKind.Number || !scale.TryGetInt32(out var count) || count < 1))
                Error(path + ".scale", "Replica count must be positive and fit the granted capacity.");
            if (service.Value.TryGetProperty("depends_on", out var dependencies))
            {
                if (dependencies.ValueKind != JsonValueKind.Array) Error(path + ".depends_on", "Use an array of service names.");
                else foreach (var dependency in dependencies.EnumerateArray())
                    if (dependency.ValueKind != JsonValueKind.String || !services.TryGetProperty(dependency.GetString()!, out _) || dependency.GetString() == service.Name)
                        Error(path + ".depends_on", "Dependencies must identify other services in this stack.");
            }
            if (service.Value.TryGetProperty("healthcheck", out var health))
            {
                if (Object(health, path + ".healthcheck", ["test", "interval", "timeout", "retries", "start_period"], errors))
                {
                    if (!health.TryGetProperty("test", out var test) || test.ValueKind != JsonValueKind.Array ||
                        !test.EnumerateArray().Any() || test.EnumerateArray().Any(x => x.ValueKind != JsonValueKind.String) ||
                        test[0].GetString() is not ("CMD" or "CMD-SHELL")) Error(path + ".healthcheck.test", "A CMD or CMD-SHELL test is required.");
                    foreach (var duration in new[] { "interval", "timeout", "start_period" })
                        if (health.TryGetProperty(duration, out var value) && (value.ValueKind != JsonValueKind.String ||
                            !Duration().IsMatch(value.GetString()!))) Error(path + ".healthcheck." + duration, "Use a positive duration in ms, s, m, or h.");
                    if (health.TryGetProperty("retries", out var retries) && (retries.ValueKind != JsonValueKind.Number || !retries.TryGetInt32(out var number) || number < 1))
                        Error(path + ".healthcheck.retries", "Use a positive retry count.");
                }
            }
            if (service.Value.TryGetProperty("volumes", out var mounts))
            {
                if (mounts.ValueKind != JsonValueKind.Array) Error(path + ".volumes", "Use explicit disposable volume objects.");
                else foreach (var mount in mounts.EnumerateArray())
                {
                    if (!Object(mount, path + ".volumes", ["type", "source", "target", "read_only"], errors)) continue;
                    if (!mount.TryGetProperty("type", out var type) || type.ValueKind != JsonValueKind.String || type.GetString() != "volume")
                        Error(path + ".volumes.type", "Only disposable named volumes are supported; bind mounts are forbidden.");
                    if (!mount.TryGetProperty("source", out var source) || source.ValueKind != JsonValueKind.String ||
                        !ServiceName().IsMatch(source.GetString()!) || !manifest.Compose.TryGetProperty("volumes", out var definitions) ||
                        definitions.ValueKind != JsonValueKind.Object || !definitions.TryGetProperty(source.GetString()!, out _))
                        Error(path + ".volumes.source", "Declare the disposable volume in compose.volumes.");
                    if (!mount.TryGetProperty("target", out var target) || target.ValueKind != JsonValueKind.String ||
                        !ContainerPath(target.GetString()))
                        Error(path + ".volumes.target", "Use a normal absolute container path.");
                    if (mount.TryGetProperty("read_only", out var readOnly) && readOnly.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
                        Error(path + ".volumes.read_only", "Use a boolean.");
                }
            }
        }
        if (manifest.Compose.TryGetProperty("volumes", out var volumes))
        {
            if (volumes.ValueKind != JsonValueKind.Object) Error("compose.volumes", "Use a map of empty disposable-volume definitions.");
            else
            {
                var volumeNames = new HashSet<string>(StringComparer.Ordinal);
                foreach (var volume in volumes.EnumerateObject())
                    if (!ServiceName().IsMatch(volume.Name) || !volumeNames.Add(volume.Name) ||
                        volume.Value.ValueKind != JsonValueKind.Object || volume.Value.EnumerateObject().Any())
                        Error("compose.volumes." + volume.Name, "Only empty disposable volume definitions are allowed.");
            }
        }
        if (manifest.Entrypoint is not { } entry || !names.Contains(entry.Service) || entry.Port is < 1 or > 65535 ||
            !ContainerPath(entry.HealthPath) || entry.HealthPath.Contains('?') || entry.HealthPath.Contains('#'))
            Error("entrypoint", "Identify a stack service, port, and absolute health path.");
        return errors;
    }

    [GeneratedRegex("^[1-9][0-9]*(ms|s|m|h)$", RegexOptions.CultureInvariant)]
    private static partial Regex Duration();
    public static bool RelativePath(string? path) => path is { Length: > 0 and <= 1024 } && !path.Any(char.IsControl) &&
        !path.StartsWith('/') && !path.Contains('\\') && !path.Contains(':') && !path.Contains('$') &&
        (path == "." || path.Split('/').All(x => x.Length > 0 && x is not ("." or "..")));
    private static bool ContainerPath(string? path) => path is { Length: > 0 and <= 1024 } && path.StartsWith('/') &&
        !path.Any(char.IsControl) && !path.Contains('\\') && !path.Contains('%') && !path.Contains('$') &&
        !path.Split('/').Any(x => x is "." or "..");
    private static bool PinnedImage(string? image)
    {
        if (image is null || image.Length > 512 || image.Any(char.IsWhiteSpace) || image.Any(char.IsControl) || image.Contains('$')) return false;
        var at = image.IndexOf('@');
        return at > 0 && image[..at].Contains('/') && WorkloadAuthorizationEnvelope.IsDigest(image[(at + 1)..]) &&
            !image[..at].Contains("..") && !image[..at].Contains("://");
    }
    private static void StringMap(JsonElement value, string path, List<PreviewProblem> errors)
    {
        if (value.ValueKind != JsonValueKind.Object) { errors.Add(new("InvalidManifest", path, "Use a literal string map.")); return; }
        var keys = new HashSet<string>(StringComparer.Ordinal);
        foreach (var pair in value.EnumerateObject())
            if (!keys.Add(pair.Name) || string.IsNullOrWhiteSpace(pair.Name) || pair.Name.Any(char.IsControl) ||
                pair.Value.ValueKind != JsonValueKind.String || pair.Value.GetString()!.Contains('\0') || pair.Value.GetString()!.Contains('$'))
                errors.Add(new("InvalidManifest", path, "Use unique literal strings; environment interpolation is forbidden."));
    }
    private static bool Object(JsonElement value, string path, string[] allowed, List<PreviewProblem> errors)
    {
        if (value.ValueKind != JsonValueKind.Object) { errors.Add(new("InvalidManifest", path, "Expected an object.")); return false; }
        var keys = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in value.EnumerateObject())
            if (!keys.Add(property.Name) || !allowed.Contains(property.Name, StringComparer.Ordinal))
                errors.Add(new("UnsupportedSetting", path + "." + property.Name, "This setting is not supported by the isolated preview runtime."));
        return true;
    }
}
