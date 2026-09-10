using System.Security.Cryptography;
using System.Text.Json;
using CSweet.Isolation.Security;
using CSweet.Office.Contracts.Security;
using CSweet.WebHost.Contracts;
using CSweet.WebHost.Core;

namespace CSweet.WebHost.Tests;

public sealed class SecurityTests
{
    private static readonly DateTimeOffset Now = DateTimeOffset.Parse("2026-09-10T12:00:00Z");
    private static JsonElement Json(string value) => JsonDocument.Parse(value).RootElement.Clone();
    private static PreviewManifest Manifest(string? compose = null) => new(1, PreviewMode.Containers,
        new string('a', 40), null, Json(compose ?? """{"services":{"app":{"build":{"context":"."}}}}"""),
        new("app", 8080), ResourceBudget.Default, 7200, []);
    private static PreviewGrant Grant() => new(Guid.NewGuid(), 1, Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(),
        Guid.NewGuid(), WebPreviewCapabilities.All, [Guid.NewGuid()], ResourceBudget.Default, 2,
        100000, 14400, [], Now.AddDays(1), false);
    private static PreviewRequest Request(PreviewGrant grant, string key = "request-1") =>
        new(grant.ProjectId, grant.RepositoryIds[0], grant.ProviderInstallationId, Manifest(), key);
    private static DurableState State() => new(Path.Combine(AppContext.BaseDirectory, "test-state", Guid.NewGuid().ToString("N")));
    private sealed class Clock : TimeProvider { public override DateTimeOffset GetUtcNow() => Now; }
    private sealed class Signing : IDisposable
    {
        public ECDsa Key { get; } = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        public WebHostEnrollment Enrollment { get; }
        public Signing() { Enrollment = new(Guid.NewGuid(), "test-host", "key-1", Convert.ToBase64String(Key.ExportSubjectPublicKeyInfo()), Now); }
        public SignedProductAssignment Assignment()
        {
            var grant = Grant();
            var spec = new ProductWorkloadSpecification(1, grant.OrganizationId, grant.ProjectId, grant.InstallationId,
                grant.ProviderInstallationId, grant.Id, grant.Revision, grant.RepositoryIds[0], Guid.NewGuid(),
                ProductWorkloadKind.Preview, Manifest(), "sha256:" + new string('b', 64));
            var json = JsonSerializer.Serialize(spec, PreviewJson.Options);
            return Sign(new(1, Enrollment.Id, Guid.NewGuid(), Guid.NewGuid(), 1, "test-certified-provider", json,
                WorkloadAuthorizationEnvelope.Digest(json), "key-1", "", Now, Now.AddHours(2)));
        }
        public SignedProductAssignment Sign(SignedProductAssignment assignment) => assignment with
        { SignatureBase64 = Convert.ToBase64String(Key.SignData(assignment.Payload(), HashAlgorithmName.SHA256)) };
        public void Dispose() => Key.Dispose();
    }

    [Fact] public void Accepts_application_and_disposable_database_stack()
    {
        var compose = """{"services":{"app":{"build":{"context":"."},"depends_on":["db"]},"db":{"image":"docker.io/library/postgres@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","volumes":[{"type":"volume","source":"data","target":"/var/lib/postgresql/data"}]}},"volumes":{"data":{}}}""";
        Assert.Empty(ManifestValidator.Validate(Manifest(compose)));
    }

    [Theory]
    [InlineData("privileged", "true")]
    [InlineData("network_mode", "\"host\"")]
    [InlineData("pid", "\"host\"")]
    [InlineData("devices", "[\"/dev/kvm\"]")]
    [InlineData("use_api_socket", "true")]
    [InlineData("cap_add", "[\"SYS_ADMIN\"]")]
    [InlineData("ports", "[\"8080:8080\"]")]
    [InlineData("env_file", "\"/etc/passwd\"")]
    [InlineData("extends", "{\"file\":\"remote.yaml\"}")]
    public void Rejects_host_access_and_security_overrides(string key, string value)
    {
        var compose = "{\"services\":{\"app\":{\"build\":{\"context\":\".\"},\"" + key + "\":" + value + "}}}";
        Assert.Contains(ManifestValidator.Validate(Manifest(compose)), p => p.Code == "UnsupportedSetting");
    }

    [Theory]
    [InlineData("../secret")]
    [InlineData("/host")]
    [InlineData("C:\\Users")]
    [InlineData("https://attacker/repo")]
    public void Rejects_build_context_escape(string path) =>
        Assert.Contains(ManifestValidator.Validate(Manifest(JsonSerializer.Serialize(new
        { services = new { app = new { build = new { context = path } } } }))), p => p.Field.EndsWith(".context"));

    [Fact] public void Rejects_mutable_images_and_external_volumes()
    {
        var result = ManifestValidator.Validate(Manifest("""{"services":{"app":{"image":"nginx:latest"}},"volumes":{"data":{"external":true}}}"""));
        Assert.Contains(result, x => x.Field.EndsWith(".image"));
        Assert.Contains(result, x => x.Field == "compose.volumes.data");
    }

    [Fact] public void Rejects_duplicate_service_and_nested_keys()
    {
        var result = ManifestValidator.Validate(Manifest("""{"services":{"app":{"build":{"context":".","context":"../x"}},"app":{"build":{"context":"."}}}}"""));
        Assert.NotEmpty(result);
    }

    [Fact] public void Allows_standing_grant_without_new_approval()
    {
        var grant = Grant();
        Assert.True(PreviewPolicy.Evaluate(grant.OrganizationId, grant.InstallationId, Request(grant), grant,
            WebPreviewCapabilities.Start, 0, 0, Now).Allowed);
    }

    [Fact] public void Rejects_foreign_revoked_expired_and_overspent_grants()
    {
        var grant = Grant(); var request = Request(grant);
        foreach (var invalid in new[] { grant with { OrganizationId = Guid.NewGuid() }, grant with { ProjectId = Guid.NewGuid() },
            grant with { InstallationId = Guid.NewGuid() }, grant with { ProviderInstallationId = Guid.NewGuid() },
            grant with { Revoked = true }, grant with { ExpiresAt = Now }, grant with { Capabilities = [] },
            grant with { RepositoryIds = [] }, grant with { MaximumCpuSeconds = 1 } })
            Assert.False(PreviewPolicy.Evaluate(grant.OrganizationId, grant.InstallationId, request, invalid,
                WebPreviewCapabilities.Start, 0, 0, Now).Allowed);
    }

    [Fact] public async Task Admission_is_atomic_under_concurrent_requests()
    {
        var grant = Grant(); var admission = new PreviewAdmission(State(), new Clock());
        var results = await Task.WhenAll(Enumerable.Range(0, 10).Select(async i =>
        {
            try { await admission.AdmitAsync(grant.OrganizationId, grant.InstallationId, Request(grant, "key-" + i), grant); return true; }
            catch (PreviewPolicyException) { return false; }
        }));
        Assert.Equal(2, results.Count(x => x));
    }

    [Fact] public async Task Idempotent_replay_does_not_consume_second_slot_and_denies_changed_payload()
    {
        var grant = Grant(); var state = State(); var admission = new PreviewAdmission(state, new Clock());
        var request = Request(grant);
        var first = await admission.AdmitAsync(grant.OrganizationId, grant.InstallationId, request, grant);
        var second = await new PreviewAdmission(state, new Clock()).AdmitAsync(grant.OrganizationId, grant.InstallationId, request, grant);
        Assert.Equal(first.Id, second.Id);
        await Assert.ThrowsAsync<InvalidOperationException>(() => admission.AdmitAsync(grant.OrganizationId, grant.InstallationId,
            request with { Manifest = request.Manifest with { LifetimeSeconds = 8000 } }, grant));
        await Assert.ThrowsAsync<PreviewPolicyException>(() => admission.AdmitAsync(grant.OrganizationId, grant.InstallationId, request, grant with { Revoked = true }));
    }

    [Fact] public void Assignment_signature_binds_host_digest_and_expiry()
    {
        using var signing = new Signing(); var verifier = new AssignmentVerifier(signing.Enrollment, new Clock());
        var assignment = signing.Assignment();
        Assert.NotNull(verifier.Verify(assignment));
        foreach (var invalid in new[] { assignment with { WebHostId = Guid.NewGuid() },
            assignment with { ExpiresAt = Now }, assignment with { SpecificationJson = "{}" },
            assignment with { FencingEpoch = 2 }, assignment with { ProviderId = "other" } })
            Assert.Throws<UnauthorizedAccessException>(() => verifier.Verify(invalid));
    }

    [Fact] public void Office_signature_cannot_authorize_a_webhost_assignment()
    {
        using var signing = new Signing(); var assignment = signing.Assignment();
        var officePayload = AssignmentEnvelope.Payload(assignment.WebHostId, assignment.AssignmentId, assignment.WorkloadId,
            assignment.FencingEpoch, assignment.ProviderId, assignment.SpecificationDigest, assignment.IssuedAt, assignment.ExpiresAt);
        var invalid = assignment with { SignatureBase64 = Convert.ToBase64String(signing.Key.SignData(officePayload, HashAlgorithmName.SHA256)) };
        Assert.Throws<UnauthorizedAccessException>(() => new AssignmentVerifier(signing.Enrollment, new Clock()).Verify(invalid));
    }

    [Fact] public async Task Replay_ledger_survives_restart_and_rejects_workload_rebinding()
    {
        using var signing = new Signing(); var assignment = signing.Assignment(); var state = State();
        var verifier = new AssignmentVerifier(signing.Enrollment, new Clock());
        Assert.True(await new AssignmentLedger(state, verifier).ClaimAsync(assignment));
        Assert.False(await new AssignmentLedger(state, verifier).ClaimAsync(assignment));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => new AssignmentLedger(state, verifier)
            .ClaimAsync(signing.Sign(assignment with { AssignmentId = Guid.NewGuid(), FencingEpoch = 2 })));
    }

    [Fact] public async Task No_provider_never_falls_back_to_host_Docker()
    {
        using var signing = new Signing(); var state = State(); var verifier = new AssignmentVerifier(signing.Enrollment, new Clock());
        var runtime = new ProductRuntime(verifier, new AssignmentLedger(state, verifier), state, [], new Clock());
        await Assert.ThrowsAsync<InvalidOperationException>(() => runtime.StartAsync(signing.Assignment(), default));
    }

    [Fact] public async Task Diagnostics_redact_and_deduplicate_without_creating_tickets()
    {
        var store = new DiagnosticStore(State(), new Clock());
        var diagnostic = new PreviewDiagnostic(Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(),
            new string('a', 40), "app", "runtime", "crash", "error 123\npassword=secret\nhttps://host/?token=secret",
            Now, false);
        var first = await store.RecordAsync(diagnostic, ["secret"]);
        var retry = await store.RecordAsync(diagnostic, ["secret"]);
        Assert.Equal(1, retry.Occurrences);
        var second = await store.RecordAsync(diagnostic with { Id = Guid.NewGuid(), BuildId = Guid.NewGuid(),
            Summary = diagnostic.Summary.Replace("123", "456") }, ["secret"]);
        Assert.Equal(first.Fingerprint, second.Fingerprint);
        Assert.Equal(2, second.Occurrences);
        var clean = DiagnosticSanitizer.Sanitize(diagnostic.Summary, ["secret"]);
        Assert.DoesNotContain("secret", clean); Assert.DoesNotContain("https://", clean);
    }
}
