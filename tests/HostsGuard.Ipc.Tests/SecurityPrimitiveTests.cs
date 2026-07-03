using System.Runtime.Versioning;
using System.Security.Principal;
using FluentAssertions;
using HostsGuard.Ipc;
using Xunit;

namespace HostsGuard.Ipc.Tests;

[SupportedOSPlatform("windows")]
public class SecurityPrimitiveTests
{
    [Fact]
    public void PipeAcl_grants_only_current_user_and_admins()
    {
        var security = NamedPipeSecurity.CreateForCurrentUserAndAdmins();
        var sids = NamedPipeSecurity.GrantedSids(security);

        var currentUser = WindowsIdentity.GetCurrent().User!;
        var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var everyone = new SecurityIdentifier(WellKnownSidType.WorldSid, null);

        sids.Should().Contain(currentUser);
        sids.Should().Contain(admins);
        sids.Should().NotContain(everyone);
        sids.Should().HaveCount(2);
    }

    [Fact]
    public void CrossSession_acl_lets_interactive_users_connect_but_not_own()
    {
        // WFCP-000b + NET-087: the LocalSystem service and the unelevated
        // user-session UI share the pipe — SYSTEM/Admins keep full control, the
        // INTERACTIVE group gets read-write only, nobody else appears. INTERACTIVE
        // (not Authenticated Users) excludes service accounts and remote/NETWORK
        // logons.
        var security = NamedPipeSecurity.CreateCrossSession();
        var rules = security.GetAccessRules(true, true, typeof(SecurityIdentifier))
            .Cast<System.IO.Pipes.PipeAccessRule>()
            .ToDictionary(r => (SecurityIdentifier)r.IdentityReference, r => r.PipeAccessRights);

        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var interactive = new SecurityIdentifier(WellKnownSidType.InteractiveSid, null);
        var authenticated = new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null);
        var network = new SecurityIdentifier(WellKnownSidType.NetworkSid, null);
        var everyone = new SecurityIdentifier(WellKnownSidType.WorldSid, null);

        rules.Should().HaveCount(3);
        rules[system].Should().HaveFlag(System.IO.Pipes.PipeAccessRights.FullControl);
        rules[admins].Should().HaveFlag(System.IO.Pipes.PipeAccessRights.FullControl);
        // The ACL layer appends Synchronize to usable grants — assert the
        // contract: connectable, but no ownership/permission rights.
        rules[interactive].Should().HaveFlag(System.IO.Pipes.PipeAccessRights.ReadWrite);
        rules[interactive].Should().NotHaveFlag(System.IO.Pipes.PipeAccessRights.ChangePermissions);
        rules[interactive].Should().NotHaveFlag(System.IO.Pipes.PipeAccessRights.TakeOwnership);
        // The over-broad principals are gone.
        rules.Should().NotContainKey(authenticated);
        rules.Should().NotContainKey(network);
        rules.Should().NotContainKey(everyone);
    }

    [Fact]
    public void Default_acl_is_per_user_outside_the_service_context()
    {
        // Test processes never run as LocalSystem, so the default must be the
        // per-user shape here.
        WindowsIdentity.GetCurrent().IsSystem.Should().BeFalse();
        NamedPipeSecurity.GrantedSids(NamedPipeSecurity.CreateDefault())
            .Should().Contain(WindowsIdentity.GetCurrent().User!);
    }

    [Fact]
    public void Token_generate_is_256bit_hex_and_unique()
    {
        var a = SessionToken.Generate();
        var b = SessionToken.Generate();
        a.Should().HaveLength(64).And.MatchRegex("^[0-9a-f]{64}$");
        a.Should().NotBe(b);
    }

    [Fact]
    public void ConstantTimeEquals_matches_and_rejects()
    {
        var t = SessionToken.Generate();
        var replacement = t[^1] == '0' ? '1' : '0';
        SessionToken.ConstantTimeEquals(t, t).Should().BeTrue();
        SessionToken.ConstantTimeEquals(t, t[..^1] + replacement).Should().BeFalse();
        SessionToken.ConstantTimeEquals(t, null).Should().BeFalse();
        SessionToken.ConstantTimeEquals(null, t).Should().BeFalse();
    }

    [Fact]
    public void Handshake_file_roundtrips_and_is_acl_locked()
    {
        var dir = Path.Combine(Path.GetTempPath(), "hg_ipc_" + Guid.NewGuid().ToString("N"));
        var path = Path.Combine(dir, "session_token");
        try
        {
            var token = SessionToken.Generate();
            SessionToken.WriteHandshake(path, token);
            SessionToken.ReadHandshake(path).Should().Be(token);

            var acl = new FileInfo(path).GetAccessControl();
            var rules = acl.GetAccessRules(true, true, typeof(SecurityIdentifier));
            var everyone = new SecurityIdentifier(WellKnownSidType.WorldSid, null);
            rules.Cast<System.Security.AccessControl.FileSystemAccessRule>()
                .Any(r => r.IdentityReference.Equals(everyone)).Should().BeFalse();
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch { /* best effort */ }
        }
    }
}
