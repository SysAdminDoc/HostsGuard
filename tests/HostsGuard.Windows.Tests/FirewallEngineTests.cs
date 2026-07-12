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
            (r.Direction == "In" || r.Direction == "Out") && (r.Action == "Block" || r.Action == "Allow") &&
            r.Profiles.Length != 0 && r.LocalAddresses.Length != 0);

        engine.GetActiveInboundProfiles().Should().OnlyContain(profile =>
            profile.Name == "Domain" || profile.Name == "Private" || profile.Name == "Public");
    }

    [Fact]
    public void Posture_reads_three_profiles_and_round_trips_when_elevated()
    {
        var engine = new FirewallEngine();
        var posture = engine.GetPosture(); // reading posture needs no elevation
        posture.Select(p => p.Name).Should().Equal("Domain", "Private", "Public");

        if (!IsElevated())
        {
            return;
        }

        // Only flip when the current posture is uniform — the all-profiles
        // setter cannot faithfully restore a mixed per-profile state.
        if (posture.Select(p => p.OutboundBlock).Distinct().Count() != 1)
        {
            return;
        }

        var original = posture[0].OutboundBlock;
        try
        {
            engine.SetDefaultOutboundBlock(!original);
            engine.GetPosture().Should().OnlyContain(p => p.OutboundBlock == !original);
        }
        finally
        {
            engine.SetDefaultOutboundBlock(original);
        }

        engine.GetPosture().Should().OnlyContain(p => p.OutboundBlock == original);
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
