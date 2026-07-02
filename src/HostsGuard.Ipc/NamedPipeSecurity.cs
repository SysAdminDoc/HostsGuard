using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Security.Principal;

namespace HostsGuard.Ipc;

/// <summary>
/// Builds the ACL for the HostsGuard control pipe. Two shapes:
/// per-user (dev/console runs) grants the current user + Administrators; the
/// cross-session shape (WFCP-000b, production LocalSystem service) keeps full
/// control with SYSTEM + Administrators and grants Authenticated Users
/// read-write so the unelevated user-session UI can connect — the per-session
/// token interceptor stays the authentication layer on top. No world/Everyone
/// ACE in either shape.
/// </summary>
[SupportedOSPlatform("windows")]
public static class NamedPipeSecurity
{
    public const string PipeName = "HostsGuard.Control.v1";

    /// <summary>Pick the shape for this process: cross-session under LocalSystem.</summary>
    public static PipeSecurity CreateDefault()
        => WindowsIdentity.GetCurrent().IsSystem ? CreateCrossSession() : CreateForCurrentUserAndAdmins();

    /// <summary>
    /// LocalSystem service ↔ unelevated UI: SYSTEM/Administrators own the pipe,
    /// Authenticated Users may connect (read-write only); the session token is
    /// what actually authorizes a caller.
    /// </summary>
    public static PipeSecurity CreateCrossSession()
    {
        var security = new PipeSecurity();
        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            PipeAccessRights.FullControl,
            System.Security.AccessControl.AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            PipeAccessRights.FullControl,
            System.Security.AccessControl.AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null),
            PipeAccessRights.ReadWrite,
            System.Security.AccessControl.AccessControlType.Allow));
        return security;
    }

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
