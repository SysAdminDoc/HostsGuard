using System.Runtime.Versioning;
using FluentAssertions;
using HostsGuard.Core;
using HostsGuard.Data;
using HostsGuard.Windows;
using Microsoft.Data.Sqlite;
using Xunit;

namespace HostsGuard.Service.Tests;

/// <summary>
/// NET-093 child-process auto-allow: a direct child of an app with an existing HG
/// allow rule inherits that allow (bounded TTL) instead of prompting, but only
/// when the opt-in is on — deny-by-default is preserved otherwise.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class ChildInheritTests : IDisposable
{
    private readonly string _dir;
    private readonly ServiceState _state;
    private readonly FakeFirewallEngine _fw;

    private const string ParentPath = @"C:\apps\installer.exe";
    private const int ParentPid = 4242;

    public ChildInheritTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "hg_child_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        File.WriteAllText(Path.Combine(_dir, "hosts"), "# hosts\n");
        _fw = new FakeFirewallEngine();
        _state = new ServiceState(
            new HostsEngine(Path.Combine(_dir, "hosts")),
            new HostsDatabase(Path.Combine(_dir, "hostsguard.db")),
            _fw,
            new FirewallIdentity(Path.Combine(_dir, "fw_identities.json")),
            dataDir: _dir);
        _state.Consent.SetMode(ConsentBroker.ModeNotify);
        // A direct child (pid 9000) whose parent is the trusted installer.
        _state.Consent.LookupParent = pid => pid == 9000 ? (ParentPid, ParentPath) : null;
    }

    private void GiveParentAnAllowRule()
    {
        _fw.CreateRule(new FwRule("HG_Consent_Allow_installer_Out", "Out", "Allow", true, "Any", "Any", ParentPath, "hostsguard"));
    }

    private static BlockedConnection Child(string app, int pid = 9000)
        => new(DateTime.UtcNow, app, "Out", "203.0.113.9", 443, "TCP", pid, 5157);

    [Fact]
    public void Child_of_a_trusted_parent_is_auto_allowed_when_inherit_is_on()
    {
        GiveParentAnAllowRule();
        _state.Consent.SetChildInherit(true);

        _state.Consent.OnBlocked(Child(@"C:\apps\child.exe"));

        _state.Consent.PendingCount.Should().Be(0); // inherited, not prompted
        _fw.Rules.Keys.Should().Contain(k => k.StartsWith("HG_Child_child_Out", StringComparison.Ordinal));
    }

    [Fact]
    public void Child_still_prompts_when_inherit_is_off()
    {
        GiveParentAnAllowRule();
        // ChildInherit defaults off.

        _state.Consent.OnBlocked(Child(@"C:\apps\child2.exe"));

        _state.Consent.PendingCount.Should().Be(1); // deny-by-default preserved
        _fw.Rules.Keys.Should().NotContain(k => k.StartsWith("HG_Child_", StringComparison.Ordinal));
    }

    [Fact]
    public void Child_prompts_when_parent_has_no_allow_rule()
    {
        _state.Consent.SetChildInherit(true); // on, but the parent isn't trusted

        _state.Consent.OnBlocked(Child(@"C:\apps\child3.exe"));

        _state.Consent.PendingCount.Should().Be(1);
        _fw.Rules.Keys.Should().NotContain(k => k.StartsWith("HG_Child_", StringComparison.Ordinal));
    }

    [Fact]
    public void ChildInherit_setting_persists_across_broker_restart()
    {
        _state.Consent.SetChildInherit(true);
        _state.Consent.ChildInherit.Should().BeTrue();

        using var reloaded = new ConsentBroker(_state.Db, _state.Bus, _fw, null, _dir);
        reloaded.ChildInherit.Should().BeTrue();
    }

    public void Dispose()
    {
        _state.Dispose();
        SqliteConnection.ClearAllPools();
        try { Directory.Delete(_dir, true); } catch (IOException) { /* best effort */ }
    }
}
