using System.Security.Cryptography;
using System.Text.Json;
using CSweet.Isolation.Security;
using CSweet.WebHost.Contracts;
using CSweet.WebHost.Core;
namespace CSweet.WebHost.Tests;

public sealed class ControlAuthorizationTests
{
    private static readonly DateTimeOffset Now=DateTimeOffset.Parse("2026-09-10T12:00:00Z");
    private sealed class Clock : TimeProvider { public override DateTimeOffset GetUtcNow()=>Now; }
    [Fact] public async Task Control_binds_action_body_host_workload_and_cannot_replay_after_restart()
    {
        using var key=ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var enrollment=new WebHostEnrollment(Guid.NewGuid(),"test","key",Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()),Now);
        var id=Guid.NewGuid(); var body=JsonSerializer.Serialize(new ProductGuestRequest(id,"stop"),PreviewJson.Options);
        var command=new SignedProductControl(1,enrollment.Id,id,Guid.NewGuid(),"stop",body,
            WorkloadAuthorizationEnvelope.Digest(body),"key","",Now,Now.AddSeconds(30));
        command=command with { SignatureBase64=Convert.ToBase64String(key.SignData(command.Payload(),HashAlgorithmName.SHA256)) };
        var state=new DurableState(Path.Combine(AppContext.BaseDirectory,"test-state",Guid.NewGuid().ToString("N")));
        var verifier=new ProductControlVerifier(enrollment,state,new Clock());
        foreach(var invalid in new[] { command with { Action="http" },command with { BodyJson="{}" },
            command with { WebHostId=Guid.NewGuid() },command with { WorkloadId=Guid.NewGuid() },
            command with { ExpiresAt=Now.AddMinutes(2) },command with { IssuedAt=Now.AddTicks(1) } })
            await Assert.ThrowsAsync<UnauthorizedAccessException>(()=>verifier.ClaimAsync(invalid,default));
        await verifier.ClaimAsync(command,default);
        await Assert.ThrowsAsync<UnauthorizedAccessException>(()=>new ProductControlVerifier(enrollment,state,new Clock()).ClaimAsync(command,default));
    }
    [Fact] public async Task Workload_signature_cannot_authorize_a_control_command()
    {
        using var key=ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var enrollment=new WebHostEnrollment(Guid.NewGuid(),"test","key",Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()),Now);
        var command=new SignedProductControl(1,enrollment.Id,Guid.NewGuid(),Guid.NewGuid(),"stop","{}",
            WorkloadAuthorizationEnvelope.Digest("{}"),"key","",Now,Now.AddSeconds(30));
        var wrong=WorkloadAuthorizationEnvelope.Encode(SignedProductAssignment.Purpose,1,command.WebHostId,
            command.CommandId,command.WorkloadId,1,command.Action,command.BodyDigest,command.IssuedAt,command.ExpiresAt);
        command=command with { SignatureBase64=Convert.ToBase64String(key.SignData(wrong,HashAlgorithmName.SHA256)) };
        var verifier=new ProductControlVerifier(enrollment,new DurableState(Path.Combine(AppContext.BaseDirectory,"test-state",Guid.NewGuid().ToString("N"))),new Clock());
        await Assert.ThrowsAsync<UnauthorizedAccessException>(()=>verifier.ClaimAsync(command,default));
    }
}
