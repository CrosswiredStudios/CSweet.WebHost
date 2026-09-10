using System.Security.AccessControl;
using System.Security.Principal;
using CSweet.WebHost.Runtime.HyperV;
namespace CSweet.WebHost.Tests;

public sealed class ProtectedPathTests
{
    [Fact] public void Protected_runtime_rejects_unprivileged_write_or_owner()
    {
        if(!OperatingSystem.IsWindows()) return;
        var system=new SecurityIdentifier(WellKnownSidType.LocalSystemSid,null);
        var users=new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid,null);
        var acl=new DirectorySecurity(); acl.SetOwner(system); acl.SetAccessRuleProtection(true,false);
        acl.AddAccessRule(new(system,FileSystemRights.FullControl,AccessControlType.Allow));
        acl.AddAccessRule(new(users,FileSystemRights.ReadAndExecute,AccessControlType.Allow));
        WindowsProtectedPaths.VerifyRules(acl);
        acl.AddAccessRule(new(users,FileSystemRights.WriteData,AccessControlType.Allow));
        Assert.Throws<UnauthorizedAccessException>(()=>WindowsProtectedPaths.VerifyRules(acl));
        var wrongOwner=new DirectorySecurity(); wrongOwner.SetOwner(users);
        Assert.Throws<UnauthorizedAccessException>(()=>WindowsProtectedPaths.VerifyRules(wrongOwner));
    }
}
