using System.Runtime.Versioning;
using System.Security.Principal;
using System.Reflection;
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
        engine.ListInterfaceAliases().Should().OnlyHaveUniqueItems(item => item.Alias)
            .And.OnlyContain(item => item.Alias.Length != 0 && item.InterfaceType.Length != 0);
    }

    [Fact]
    public void Lightweight_package_metadata_is_cached_without_binary_inventories()
    {
        var now = new DateTime(2026, 7, 13, 12, 0, 0, DateTimeKind.Utc);
        var calls = new List<bool>();
        var package = new FwAppPackage("Family", "S-1-15-2-1", "Display", "Full", "large.exe;other.exe");
        var engine = new FirewallEngine(includeBinaries =>
        {
            calls.Add(includeBinaries);
            return [includeBinaries ? package : package with { Binaries = string.Empty }];
        }, () => now);

        engine.GetMemorySnapshot().LightweightPackageCount.Should().Be(0);
        var method = typeof(FirewallEngine).GetMethod(
            "ListLightweightPackages", BindingFlags.Instance | BindingFlags.NonPublic)!;
        var first = (IReadOnlyList<FwAppPackage>)method.Invoke(engine, null)!;
        var second = (IReadOnlyList<FwAppPackage>)method.Invoke(engine, null)!;

        first.Should().BeSameAs(second);
        first.Should().ContainSingle().Which.Binaries.Should().BeEmpty();
        calls.Should().Equal(false);
        engine.GetMemorySnapshot().LightweightPackageCount.Should().Be(1);

        now = now.AddMinutes(16);
        _ = method.Invoke(engine, null);
        calls.Should().Equal(false, false);
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
            var selectedInterface = engine.ListInterfaceAliases().FirstOrDefault()?.Alias ?? "Any";
            var rule = new FwRule(name, "In", "Allow", true, "Any", "TCP", string.Empty, "hostsguard",
                RemotePorts: "443", LocalPorts: "8000-8010", Interfaces: selectedInterface);
            engine.CreateRule(rule).Should().BeTrue();
            engine.RuleExists(name).Should().BeTrue();
            engine.ListRules().Should().Contain(r => r.Name == name && r.Action == "Allow" && r.Direction == "In" &&
                r.RemotePorts == "443" && r.LocalPorts == "8000-8010" && r.Interfaces == selectedInterface);
            engine.ReplaceRule(rule with { LocalPorts = "9000" }).Should().BeTrue();
            engine.ListRules().Should().Contain(r => r.Name == name && r.LocalPorts == "9000");
            engine.DeleteRule(name).Should().BeTrue();
            engine.RuleExists(name).Should().BeFalse();
        }
        finally
        {
            try { engine.DeleteRule(name); } catch { /* best effort cleanup */ }
        }
    }
}
