using System.Runtime.Versioning;
using System.Security.Principal;
using FluentAssertions;
using HostsGuard.Core;
using HostsGuard.Windows;
using Xunit;

namespace HostsGuard.Windows.Tests;

[SupportedOSPlatform("windows")]
public class FirewallEngineTests
{
    private static bool IsElevated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    [Fact]
    public void ListRules_maps_without_throwing()
    {
        // Reading rules does not require elevation; verify the COM→FwRule projection
        // works against the real firewall on any dev box.
        var engine = new FirewallEngine();
        var rules = engine.ListRules();
        rules.Should().NotBeNull();
        rules.Should().OnlyContain(r =>
            (r.Direction == "In" || r.Direction == "Out") && (r.Action == "Block" || r.Action == "Allow"));
    }

    [Fact]
    public void Create_then_delete_round_trip_when_elevated()
    {
        if (!IsElevated())
        {
            // Admin-gated: mutation requires elevation. No-op pass in a standard-user run.
            return;
        }

        var engine = new FirewallEngine();
        var name = "HG_Test_" + Guid.NewGuid().ToString("N")[..8];
        try
        {
            var rule = new FwRule(name, "Out", "Block", true, "203.0.113.5", "TCP", string.Empty, "hostsguard");
            engine.CreateRule(rule).Should().BeTrue();
            engine.RuleExists(name).Should().BeTrue();
            engine.ListRules().Should().Contain(r => r.Name == name && r.Action == "Block" && r.Direction == "Out");
            engine.DeleteRule(name).Should().BeTrue();
            engine.RuleExists(name).Should().BeFalse();
        }
        finally
        {
            try { engine.DeleteRule(name); } catch { /* best effort cleanup */ }
        }
    }
}
