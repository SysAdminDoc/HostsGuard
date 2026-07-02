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
        SessionToken.ConstantTimeEquals(t, t).Should().BeTrue();
        SessionToken.ConstantTimeEquals(t, t[..^1] + "0").Should().BeFalse();
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
