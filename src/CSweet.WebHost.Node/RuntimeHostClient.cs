using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using CSweet.WebHost.Contracts;
using CSweet.WebHost.Core;
namespace CSweet.WebHost.Node;

/// <summary>Unprivileged transport only. It cannot mint grants, signatures, host paths or VM commands.</summary>
public sealed class RuntimeHostClient
{
    public const string PipeName="CSweet.WebHost.RuntimeHost.v1";
    public async Task<ProductRuntimeResponse> InvokeAsync(ProductRuntimeRequest request,Stream? artifact,CancellationToken token)
    {
        if(!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("The installed WebHost provider requires Windows.");
        if((artifact is null)!=(request.ArtifactLength is null)) throw new ArgumentException("The artifact stream and declared length must match.");
        using var timeout=CancellationTokenSource.CreateLinkedTokenSource(token);
        timeout.CancelAfter(TimeSpan.FromMinutes(10));
        await using var pipe=new NamedPipeClientStream(".",PipeName,PipeDirection.InOut,PipeOptions.Asynchronous,
            TokenImpersonationLevel.Identification);
        await pipe.ConnectAsync(10000,timeout.Token);
        var owner=pipe.GetAccessControl().GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
        if(owner is null || !owner.IsWellKnown(WellKnownSidType.LocalSystemSid))
            throw new UnauthorizedAccessException("The WebHost runtime pipe is not owned by SYSTEM.");
        await ProductGuestProtocol.WriteAsync(pipe,request,timeout.Token);
        if(artifact is not null)
        {
            var remaining=request.ArtifactLength!.Value;
            if(remaining<1 || remaining>uint.MaxValue) throw new InvalidDataException("The product artifact length is invalid.");
            var buffer=new byte[65536];
            while(remaining>0)
            {
                var read=await artifact.ReadAsync(buffer.AsMemory(0,(int)Math.Min(buffer.Length,remaining)),timeout.Token);
                if(read==0) throw new EndOfStreamException("The artifact source ended before its declared length.");
                await pipe.WriteAsync(buffer.AsMemory(0,read),timeout.Token); remaining-=read;
            }
            await pipe.FlushAsync(timeout.Token);
        }
        return await ProductGuestProtocol.ReadAsync<ProductRuntimeResponse>(pipe,timeout.Token);
    }
    public Task<ProductRuntimeResponse> StartAsync(SignedProductAssignment assignment,CancellationToken token)=>
        InvokeAsync(new(Assignment:assignment),null,token);
    public Task<ProductRuntimeResponse> ControlAsync(SignedProductControl command,CancellationToken token)=>
        InvokeAsync(new(Control:command),null,token);
    public Task<ProductRuntimeResponse> IngestAsync(SignedProductAssignment assignment,long length,Stream artifact,CancellationToken token)=>
        InvokeAsync(new(Assignment:assignment,ArtifactLength:length),artifact,token);
}
