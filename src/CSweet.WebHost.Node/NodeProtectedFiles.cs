using System.Security.AccessControl;
using System.Security.Principal;
namespace CSweet.WebHost.Node;

internal static class NodeProtectedFiles
{
    public static void Verify(string path, bool secret = false)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        if (!Path.IsPathFullyQualified(path)) throw new InvalidDataException("Node identity and configuration paths must be absolute.");
        var file = new FileInfo(path);
        if (!file.Exists) throw new InvalidDataException("The installed Node identity or configuration is missing.");
        VerifyRules(file.GetAccessControl(), parent: false);
        if (secret) VerifySecret(file.GetAccessControl());
        if (file.LinkTarget is not null) throw new InvalidDataException("Node configuration cannot use links.");
        for (var parent = file.Directory; parent is not null; parent = parent.Parent)
        {
            if (parent.LinkTarget is not null) throw new InvalidDataException("Node configuration ancestors cannot use links.");
            VerifyRules(parent.GetAccessControl(), parent: true);
        }
    }

    private static void VerifySecret(FileSystemSecurity security)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        var current = WindowsIdentity.GetCurrent().User;
        foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
        {
            if ((rule.PropagationFlags & PropagationFlags.InheritOnly) != 0 || rule.AccessControlType != AccessControlType.Allow) continue;
            var sid = (SecurityIdentifier)rule.IdentityReference;
            if (sid == current || sid.IsWellKnown(WellKnownSidType.LocalSystemSid) ||
                sid.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid)) continue;
            if ((rule.FileSystemRights & FileSystemRights.ReadData) != 0)
                throw new UnauthorizedAccessException("Only the installed Node identity, SYSTEM and administrators may read the private key.");
        }
    }
    private static void VerifyRules(FileSystemSecurity security, bool parent)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var installer = new SecurityIdentifier("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464");
        bool Trusted(IdentityReference? sid) => sid == system || sid == admins || sid == installer;
        if (!Trusted(security.GetOwner(typeof(SecurityIdentifier))))
            throw new UnauthorizedAccessException("Node configuration and identity must be installed by an administrator.");
        var writes = parent ? FileSystemRights.DeleteSubdirectoriesAndFiles | FileSystemRights.Delete |
            FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership :
            FileSystemRights.Write | FileSystemRights.Delete | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership;
        foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
        {
            if ((rule.PropagationFlags & PropagationFlags.InheritOnly) != 0 || Trusted(rule.IdentityReference)) continue;
            if (rule.AccessControlType == AccessControlType.Allow && (rule.FileSystemRights & writes) != 0)
                throw new UnauthorizedAccessException("Untrusted accounts can replace the installed Node identity or configuration.");
        }
    }
}
