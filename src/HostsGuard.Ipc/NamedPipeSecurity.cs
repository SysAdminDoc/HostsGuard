using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Security.Principal;

namespace HostsGuard.Ipc;

/// <summary>
/// Builds the ACL for the HostsGuard control pipe: full control for the current
/// (interactive) user and BUILTIN\Administrators only. No world/Everyone ACE, so
/// an out-of-ACL process is refused by the OS before any request is parsed.
/// </summary>
[SupportedOSPlatform("windows")]
public static class NamedPipeSecurity
{
    public const string PipeName = "HostsGuard.Control.v1";

    public static PipeSecurity CreateForCurrentUserAndAdmins()
    {
        var security = new PipeSecurity();

        var currentUser = WindowsIdentity.GetCurrent().User
            ?? throw new InvalidOperationException("Cannot determine current user SID.");
        security.AddAccessRule(new PipeAccessRule(
            currentUser,
            PipeAccessRights.FullControl,
            System.Security.AccessControl.AccessControlType.Allow));

        var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        security.AddAccessRule(new PipeAccessRule(
            admins,
            PipeAccessRights.FullControl,
            System.Security.AccessControl.AccessControlType.Allow));

        return security;
    }

    /// <summary>The SIDs granted access by <see cref="CreateForCurrentUserAndAdmins"/> (for verification).</summary>
    public static IReadOnlyList<SecurityIdentifier> GrantedSids(PipeSecurity security)
    {
        ArgumentNullException.ThrowIfNull(security);
        var rules = security.GetAccessRules(true, true, typeof(SecurityIdentifier));
        var sids = new List<SecurityIdentifier>();
        foreach (System.Security.AccessControl.AuthorizationRule rule in rules)
        {
            if (rule is PipeAccessRule { AccessControlType: System.Security.AccessControl.AccessControlType.Allow } par
                && par.IdentityReference is SecurityIdentifier sid)
            {
                sids.Add(sid);
            }
        }

        return sids;
    }
}
