using System.Runtime.Versioning;
using FluentAssertions;
using HostsGuard.Contracts;
using HostsGuard.Core;
using HostsGuard.Data;
using HostsGuard.Windows;
using Microsoft.Data.Sqlite;
using Xunit;

namespace HostsGuard.Service.Tests;

/// <summary>
/// NET-103: subscribable rule groups — assign HG_ rules to a named group, toggle
/// the group enable/disable atomically, and round-trip the groups through the
/// portable policy (NET-089).
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class RuleGroupTests : IDisposable
{
    private readonly string _dir;
    private readonly ServiceState _state;
    private readonly FakeFirewallEngine _fw;
    private readonly FirewallControlServiceImpl _svc;
    private static Grpc.Core.ServerCallContext Ctx => null!;

    public RuleGroupTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "hg_grp_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        File.WriteAllText(Path.Combine(_dir, "hosts"), "# hosts\n");
        _fw = new FakeFirewallEngine();
        _fw.CreateRule(new FwRule("HG_Block_1.2.3.4_Out", "Out", "Block", true, "1.2.3.4", "Any", "", "hostsguard"));
        _fw.CreateRule(new FwRule("HG_Block_5.6.7.8_Out", "Out", "Block", true, "5.6.7.8", "Any", "", "hostsguard"));
        _state = new ServiceState(
            new HostsEngine(Path.Combine(_dir, "hosts")),
            new HostsDatabase(Path.Combine(_dir, "hostsguard.db")), _fw, dataDir: _dir);
        _svc = new FirewallControlServiceImpl(_state);
    }

    [Fact]
    public async Task Assign_list_and_toggle_a_group_atomically()
    {
        (await _svc.AssignRuleGroup(new RuleGroupAssignment { RuleName = "HG_Block_1.2.3.4_Out", Group = "adblock" }, Ctx)).Ok.Should().BeTrue();
        (await _svc.AssignRuleGroup(new RuleGroupAssignment { RuleName = "HG_Block_5.6.7.8_Out", Group = "adblock" }, Ctx)).Ok.Should().BeTrue();

        var groups = await _svc.ListRuleGroups(new Empty(), Ctx);
        var adblock = groups.Groups.Single(g => g.Name == "adblock");
        adblock.Total.Should().Be(2);
        adblock.EnabledCount.Should().Be(2);

        // Disable the whole group in one call.
        (await _svc.ToggleRuleGroup(new RuleGroupToggle { Group = "adblock", Enabled = false }, Ctx)).Ok.Should().BeTrue();
        _fw.Rules["HG_Block_1.2.3.4_Out"].Enabled.Should().BeFalse();
        _fw.Rules["HG_Block_5.6.7.8_Out"].Enabled.Should().BeFalse();
        (await _svc.ListRuleGroups(new Empty(), Ctx)).Groups.Single(g => g.Name == "adblock").EnabledCount.Should().Be(0);

        // Re-enable.
        await _svc.ToggleRuleGroup(new RuleGroupToggle { Group = "adblock", Enabled = true }, Ctx);
        _fw.Rules["HG_Block_1.2.3.4_Out"].Enabled.Should().BeTrue();
    }

    [Fact]
    public async Task Only_hg_rules_can_be_grouped()
    {
        var ack = await _svc.AssignRuleGroup(new RuleGroupAssignment { RuleName = "SomeSystemRule", Group = "x" }, Ctx);
        ack.Ok.Should().BeFalse();
        ack.ErrorCode.Should().Be("hostsguard.error.v1/not_ours");
    }

    [Fact]
    public void Groups_round_trip_through_the_portable_policy()
    {
        _state.Db.AssignRuleToGroup("HG_Block_1.2.3.4_Out", "vpn");
        _state.Db.AssignRuleToGroup("HG_Block_5.6.7.8_Out", "vpn");

        var policy = PortablePolicy.FromJson(PolicyPortability.Export(_state).ToJson());
        policy.RuleGroups.Should().ContainSingle(g => g.Name == "vpn" && g.Rules.Count == 2);

        // Import onto a fresh machine reconstructs the group memberships.
        var dir2 = Path.Combine(Path.GetTempPath(), "hg_grp2_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir2);
        File.WriteAllText(Path.Combine(dir2, "hosts"), "# hosts\n");
        using var dst = new ServiceState(new HostsEngine(Path.Combine(dir2, "hosts")),
            new HostsDatabase(Path.Combine(dir2, "hostsguard.db")), new FakeFirewallEngine(), dataDir: dir2);
        PolicyPortability.Import(dst, policy);
        dst.Db.GetRulesInGroup("vpn").Should().HaveCount(2);
        try { Directory.Delete(dir2, true); } catch (IOException) { /* best effort */ }
    }

    public void Dispose()
    {
        _state.Dispose();
        SqliteConnection.ClearAllPools();
        try { Directory.Delete(_dir, true); } catch (IOException) { /* best effort */ }
    }
}
