using System.Security.Cryptography;
using CSweet.WebHost.Contracts;
using CSweet.WebHost.Core;
using CSweet.WebHost.Node;
namespace CSweet.WebHost.Tests;

public sealed class NodeIdentityTests
{
    private sealed class Clock : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = DateTimeOffset.Parse("2026-09-10T12:00:00Z");
        public override DateTimeOffset GetUtcNow() => Now;
    }
    [Fact] public async Task Restart_preserves_sequence_and_host_binding()
    {
        var directory = Path.Combine(Path.GetTempPath(), "csweet-node-test-" + Guid.NewGuid().ToString("N"));
        try
        {
            using var identity = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var clock = new Clock();
            var publicKey = Convert.ToBase64String(identity.ExportSubjectPublicKeyInfo());
            var bootstrap = new WebHostBootstrap(Guid.NewGuid(), Guid.NewGuid(),
                new(Guid.NewGuid(), "Test", "test-only", publicKey, clock.Now), clock.Now.AddDays(1));
            var heartbeat = new WebHostHeartbeat(bootstrap.Enrollment.Id, clock.Now, ResourceBudget.Default,
                [new("provider", "0.1.0", "sha256:" + new string('a',64), false, null, false, null)]);
            var first = await new WebHostMessageSigner(bootstrap, identity, new DurableState(directory), clock).HeartbeatAsync(heartbeat, default);
            var second = await new WebHostMessageSigner(bootstrap, identity, new DurableState(directory), clock).HeartbeatAsync(heartbeat, default);
            Assert.Equal(1, first.Sequence); Assert.Equal(2, second.Sequence);
            WebHostIdentity.Verify(second, bootstrap.ControlPlaneId, bootstrap.Enrollment.Id, publicKey, first.Sequence, clock.Now);
            Assert.Throws<UnauthorizedAccessException>(() => WebHostIdentity.Verify(first, bootstrap.ControlPlaneId,
                bootstrap.Enrollment.Id, publicKey, second.Sequence, clock.Now));
            var other = bootstrap with { Enrollment = bootstrap.Enrollment with { Id = Guid.NewGuid() } };
            await Assert.ThrowsAsync<UnauthorizedAccessException>(() => new WebHostMessageSigner(other, identity, new DurableState(directory), clock)
                .HeartbeatAsync(heartbeat with { WebHostId = other.Enrollment.Id }, default));
            clock.Now = bootstrap.IdentityExpiresAt;
            await Assert.ThrowsAsync<UnauthorizedAccessException>(() => new WebHostMessageSigner(bootstrap, identity, new DurableState(directory), clock)
                .HeartbeatAsync(heartbeat, default));
        }
        finally { if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true); }
    }
    [Theory]
    [InlineData("http://headquarters.example/")]
    [InlineData("https://user:password@headquarters.example/")]
    [InlineData("https://headquarters.example/untrusted-path")]
    [InlineData("https://headquarters.example/?token=secret")]
    [InlineData("https://headquarters.example/#fragment")]
    public void Headquarters_endpoint_requires_a_clean_https_origin(string origin) =>
        Assert.Throws<ArgumentException>(() => new HeadquartersClient(new Uri(origin)));

    [Fact] public void Public_identity_keys_require_canonical_p256_encoding()
    {
        using var wrong = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        Assert.Throws<ArgumentException>(() => WebHostIdentity.ValidatePublicKey(Convert.ToBase64String(wrong.ExportSubjectPublicKeyInfo())));
        using var valid = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var value = Convert.ToBase64String(valid.ExportSubjectPublicKeyInfo());
        WebHostIdentity.ValidatePublicKey(value);
        Assert.Throws<ArgumentException>(() => WebHostIdentity.ValidatePublicKey(value + "\n"));
    }
}
