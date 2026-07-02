using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

namespace HostsGuard.Windows;

/// <summary>
/// Native ACL hardening for the hosts file (replaces shelling out to <c>icacls</c>).
/// Detects a weak DACL where a broad principal can write, and enforces an
/// inheritance-disabled DACL granting only SYSTEM and Administrators full control.
/// </summary>
[SupportedOSPlatform("windows")]
public static class HostsAcl
{
    private static readonly SecurityIdentifier System = new(WellKnownSidType.LocalSystemSid, null);
    private static readonly SecurityIdentifier Admins = new(WellKnownSidType.BuiltinAdministratorsSid, null);
    private static readonly SecurityIdentifier Users = new(WellKnownSidType.BuiltinUsersSid, null);
    private static readonly SecurityIdentifier AuthedUsers = new(WellKnownSidType.AuthenticatedUserSid, null);
    private static readonly SecurityIdentifier Everyone = new(WellKnownSidType.WorldSid, null);

    private const FileSystemRights WriteMask =
        FileSystemRights.WriteData | FileSystemRights.AppendData | FileSystemRights.Write
        | FileSystemRights.Modify | FileSystemRights.FullControl | FileSystemRights.ChangePermissions
        | FileSystemRights.TakeOwnership | FileSystemRights.Delete;

    /// <summary>True if a broad principal (Users / Authenticated Users / Everyone) can write.</summary>
    public static bool HasWeakAcl(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        var acl = new FileInfo(path).GetAccessControl();
        foreach (FileSystemAccessRule rule in acl.GetAccessRules(true, true, typeof(SecurityIdentifier)))
        {
            if (rule.AccessControlType != AccessControlType.Allow)
            {
                continue;
            }

            var id = rule.IdentityReference;
            var broad = id.Equals(Users) || id.Equals(AuthedUsers) || id.Equals(Everyone);
            if (broad && (rule.FileSystemRights & WriteMask) != 0)
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Enforce an inheritance-disabled DACL: SYSTEM + Administrators full control,
    /// nothing else. Requires the caller to own/have WRITE_DAC on the file.
    /// </summary>
    public static void Harden(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        var info = new FileInfo(path);
        var security = new FileSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new FileSystemAccessRule(System, FileSystemRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(Admins, FileSystemRights.FullControl, AccessControlType.Allow));
        info.SetAccessControl(security);
    }

    /// <summary>SIDs granted any access by the current DACL (for verification).</summary>
    public static IReadOnlyList<SecurityIdentifier> GrantedSids(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        var acl = new FileInfo(path).GetAccessControl();
        var result = new List<SecurityIdentifier>();
        foreach (FileSystemAccessRule rule in acl.GetAccessRules(true, true, typeof(SecurityIdentifier)))
        {
            if (rule.AccessControlType == AccessControlType.Allow && rule.IdentityReference is SecurityIdentifier sid)
            {
                result.Add(sid);
            }
        }

        return result;
    }
}
