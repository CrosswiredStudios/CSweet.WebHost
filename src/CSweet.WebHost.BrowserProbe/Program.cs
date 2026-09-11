using System.Text.Json;
using CSweet.WebHost.Contracts;
using CSweet.WebHost.Core;
using Microsoft.Extensions.FileProviders;
using Microsoft.Playwright;

// Invoked only by the trusted guest controller under the dedicated unprivileged browser UID.
if (!OperatingSystem.IsLinux() || args.Length != 1 || args[0] is not ("static" or "containers") ||
    !File.Exists("/etc/csweet-product-guest")) return 2;
using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(50));
var line = await Console.In.ReadLineAsync(deadline.Token);
if (line is null || line.Length > 32768) return 2;
var checks = JsonSerializer.Deserialize<PreviewBrowserCheck[]>(line, PreviewJson.Options)!;
BrowserTestPolicy.Validate(checks);
WebApplication? site = null;
var origin = args[0] == "static" ? "http://127.0.0.1:18762" : "http://127.0.0.1:18080";
if (args[0] == "static")
{
    var builder = WebApplication.CreateSlimBuilder(new WebApplicationOptions { Args = [], ContentRootPath = "/run/csweet-product/browser" });
    builder.Logging.ClearProviders(); builder.WebHost.UseUrls(origin);
    site = builder.Build();
    var files = new PhysicalFileProvider("/run/csweet-product/product/site");
    site.UseDefaultFiles(new DefaultFilesOptions { FileProvider = files });
    site.UseStaticFiles(new StaticFileOptions { FileProvider = files });
    await site.StartAsync(deadline.Token);
}
try
{
    using var playwright = await Playwright.CreateAsync();
    await using var browser = await playwright.Chromium.LaunchAsync(new() { Headless = true, ChromiumSandbox = true, Timeout = 10000,
        ExecutablePath = "/usr/bin/chromium", Env = new Dictionary<string,string> { ["HOME"] = "/run/csweet-product/browser", ["TMPDIR"] = "/run/csweet-product/browser" } });
    await using var context = await browser.NewContextAsync(new() { AcceptDownloads = false, ServiceWorkers = ServiceWorkerPolicy.Block, ViewportSize = new() { Width = 1280, Height = 720 } });
    bool Allowed(string value, string scheme) => Uri.TryCreate(value, UriKind.Absolute, out var uri) && uri.Scheme == scheme && uri.Host == "127.0.0.1" && uri.Port == new Uri(origin).Port && uri.UserInfo.Length == 0;
    await context.RouteAsync("**/*", route => Allowed(route.Request.Url, "http") ? route.ContinueAsync() : route.AbortAsync());
    await context.RouteWebSocketAsync("**/*", async route => { if (Allowed(route.Url, "ws")) route.ConnectToServer(); else await route.CloseAsync(); });
    var results = new List<PreviewBrowserCheckResult>();
    for (var index = 0; index < checks.Length; index++)
    {
        var check = checks[index]; var page = await context.NewPageAsync(); var failed = false; string? browserError = null; int? status = null;
        page.PageError += (_, message) => { failed = true; browserError ??= message[..Math.Min(message.Length, 1024)]; }; page.Crash += (_, _) => failed = true;
        page.SetDefaultTimeout(3000); page.SetDefaultNavigationTimeout(3000);
        try
        {
            var response = await page.GotoAsync(origin + check.Path, new() { WaitUntil = WaitUntilState.Load });
            status = response?.Status; if (response is null || response.Status >= 400) failed = true;
            var locator = page.Locator(check.Selector ?? "body").First;
            await locator.WaitForAsync(new() { State = WaitForSelectorState.Visible, Timeout = 3000 });
            if (check.ExpectedText is not null) await Assertions.Expect(locator).ToContainTextAsync(check.ExpectedText, new() { Timeout = 3000 });
            results.Add(new(index, !failed, failed ? "BrowserAssertionFailed" : "BrowserCheckPassed", failed ? DiagnosticSanitizer.Sanitize($"HTTP {status}: the page or JavaScript runtime failed. {browserError}", [], 2048) : "The requested browser check passed."));
        }
        catch (PlaywrightException) { results.Add(new(index, false, "BrowserAssertionFailed", DiagnosticSanitizer.Sanitize($"HTTP {status}: the requested navigation, visible selector or text assertion failed. {browserError}", [], 2048))); }
        finally { await page.CloseAsync(); }
    }
    Console.WriteLine(JsonSerializer.Serialize(results, PreviewJson.Options)); return 0;
}
finally { if (site is not null) await site.DisposeAsync(); }
