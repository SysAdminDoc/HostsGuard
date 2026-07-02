using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using FluentAssertions;
using HostsGuard.Windows;
using Xunit;

namespace HostsGuard.Windows.Tests;

[SupportedOSPlatform("windows")]
public sealed class HostsAclTests : IDisposable
{
    private readonly string _dir;
    private readonly string _file;

    public HostsAclTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "hg_acl_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        _file = Path.Combine(_dir, "hosts");
        File.WriteAllText(_file, "# hosts\n");
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, true); } catch (IOException) { /* best effort */ }
    }

    [Fact]
    public void Detects_weak_acl_then_harden_removes_it()
    {
        // Add a broad Users:Write ACE to simulate a weak DACL.
        var info = new FileInfo(_file);
        var sec = info.GetAccessControl();
        var users = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);
        sec.AddAccessRule(new FileSystemAccessRule(users, FileSystemRights.Modify, AccessControlType.Allow));
        info.SetAccessControl(sec);

        HostsAcl.HasWeakAcl(_file).Should().BeTrue();

        HostsAcl.Harden(_file);

        HostsAcl.HasWeakAcl(_file).Should().BeFalse();
        var sids = HostsAcl.GrantedSids(_file);
        sids.Should().Contain(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null));
        sids.Should().Contain(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null));
        sids.Should().NotContain(new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null));
    }

    [Fact]
    public void Harden_disables_inheritance()
    {
        HostsAcl.Harden(_file);
        var acl = new FileInfo(_file).GetAccessControl();
        acl.AreAccessRulesProtected.Should().BeTrue(); // inheritance removed
    }
}
