using System.Text.Json;
using CSweet.WebHost.Contracts;
using CSweet.WebHost.Core;

namespace CSweet.WebHost.Tests;

public sealed class NormalizationTests
{
    private static PreviewManifest Manifest(string services) => new(1, PreviewMode.Containers, new string('a', 40),
        null, JsonDocument.Parse("{\"services\":" + services + "}").RootElement.Clone(),
        new("app", 8080), ResourceBudget.Default, 7200, []);
    [Fact] public void Runtime_configuration_strips_builds_and_enforces_guest_only_access()
    {
        var manifest = Manifest("""{"app":{"build":{"context":"."}}}""");
        using var result = JsonDocument.Parse(ComposeNormalizer.Normalize(manifest, Guid.NewGuid(), new Dictionary<string,string>
        { ["app"] = "sha256:" + new string('a', 64) }));
        var app = result.RootElement.GetProperty("services").GetProperty("app");
        Assert.False(app.TryGetProperty("build", out _));
        Assert.Equal("never", app.GetProperty("pull_policy").GetString());
        Assert.True(app.GetProperty("read_only").GetBoolean());
        Assert.Equal("ALL", app.GetProperty("cap_drop")[0].GetString());
        Assert.Equal("127.0.0.1", app.GetProperty("ports")[0].GetProperty("host_ip").GetString());
        Assert.True(result.RootElement.GetProperty("networks").GetProperty("product").GetProperty("internal").GetBoolean());
    }
    [Fact] public void Missing_verified_build_output_is_not_replaced_with_a_mutable_tag() =>
        Assert.Throws<InvalidDataException>(() => ComposeNormalizer.Normalize(Manifest("""{"app":{"build":{"context":"."}}}"""),
            Guid.NewGuid(), new Dictionary<string,string>()));
}
