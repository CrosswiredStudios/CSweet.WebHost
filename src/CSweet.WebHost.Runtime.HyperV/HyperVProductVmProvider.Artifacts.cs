using System.Security.Cryptography;
using CSweet.Isolation.Artifacts;
using CSweet.Isolation.Security;
using CSweet.WebHost.Contracts;
namespace CSweet.WebHost.Runtime.HyperV;

public sealed partial class HyperVProductVmProvider
{
    /// <summary>The stream is data only. Node supplies no host path, script, extraction directive or trust material.</summary>
    public async Task IngestArtifactAsync(SignedProductAssignment assignment,long length,Stream input,CancellationToken token)
    {
        var spec=verifier.Verify(assignment);
        if(assignment.ProviderId!=Id || spec.GuestImageDigest!=configuration.GuestImageDigest ||
            !spec.Manifest.Resources.Fits(configuration.HostCapacity) ||
            !WorkloadAuthorizationEnvelope.IsDigest(spec.Manifest.ArtifactDigest) ||
            length<1 || length>uint.MaxValue || length>checked((long)spec.Manifest.Resources.DiskMb*1024*1024/2))
            throw new UnauthorizedAccessException("The artifact exceeds its exact authorized input bounds.");
        var certification=await VerifyReleaseAsync(token);
        if(assignment.ExpiresAt>certification.ExpiresAt) throw new UnauthorizedAccessException("The product authorization exceeds certification.");
        var root=ProtectedRoot(configuration.ArtifactMediaRoot);
        var destination=Path.Combine(root,spec.Manifest.ArtifactDigest![7..]+".iso");
        // Artifact ingestion has a separate lock so a slow upload never blocks VM lease enforcement.
        var started=System.Diagnostics.Stopwatch.StartNew();
        FileStream? held=null;
        while(held is null)
        {
            token.ThrowIfCancellationRequested();
            try { held=new FileStream(Path.Combine(root,"ingestion.lock"),FileMode.OpenOrCreate,FileAccess.ReadWrite,FileShare.None); }
            catch(IOException) when(started.Elapsed<TimeSpan.FromSeconds(10)) { await Task.Delay(50,token); }
        }
        await using var lease=held;
        var existing=File.Exists(destination);
        if(existing && !await SingleFileIso9660.VerifyArtifactDigestAsync(destination,spec.Manifest.ArtifactDigest,token))
            throw new InvalidDataException("An existing protected artifact is corrupt.");
        var storedBytes=Directory.EnumerateFiles(root).Where(x=>x.EndsWith(".iso",StringComparison.Ordinal) ||
            x.EndsWith(".upload",StringComparison.Ordinal)).Sum(x=>new FileInfo(x).Length);
        // The installer reserves a separate cache budget in addition to active VM scratch capacity.
        if(configuration.MaximumArtifactCacheBytes<1 ||
            storedBytes>configuration.MaximumArtifactCacheBytes ||
            length> (configuration.MaximumArtifactCacheBytes-storedBytes-65536)/2)
            throw new InvalidOperationException("The protected artifact cache has insufficient capacity.");
        var temporary=Path.Combine(root,Guid.NewGuid().ToString("N")+".upload");
        var media=Path.Combine(root,Guid.NewGuid().ToString("N")+".upload");
        try
        {
            await using(var output=new FileStream(temporary,FileMode.CreateNew,FileAccess.ReadWrite,FileShare.None,
                65536,FileOptions.Asynchronous|FileOptions.WriteThrough))
            {
                var buffer=new byte[65536]; long remaining=length;
                using var hash=IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                while(remaining>0)
                {
                    var read=await input.ReadAsync(buffer.AsMemory(0,(int)Math.Min(buffer.Length,remaining)),token);
                    if(read==0) throw new EndOfStreamException("The product artifact upload ended early.");
                    hash.AppendData(buffer,0,read); await output.WriteAsync(buffer.AsMemory(0,read),token); remaining-=read;
                }
                if("sha256:"+Convert.ToHexStringLower(hash.GetHashAndReset())!=spec.Manifest.ArtifactDigest)
                    throw new InvalidDataException("The product artifact does not match the authorized digest.");
                verifier.Verify(assignment); // Do not accept a transfer which outlived its authorization.
                output.Flush(true);
                if(!existing)
                {
                    output.Position=0;
                    await using var iso=new FileStream(media,FileMode.CreateNew,FileAccess.Write,FileShare.None,
                        65536,FileOptions.Asynchronous|FileOptions.WriteThrough);
                    await SingleFileIso9660.WriteAsync(output,length,iso,token); iso.Flush(true);
                }
            }
            if(!existing) File.Move(media,destination,overwrite:false);
        }
        finally
        {
            // Both paths are generated locally under the verified protected media root.
            if(File.Exists(temporary)) File.Delete(temporary);
            if(File.Exists(media)) File.Delete(media);
        }
    }
}
