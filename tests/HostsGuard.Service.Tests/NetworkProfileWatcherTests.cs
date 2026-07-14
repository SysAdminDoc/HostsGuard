using System.Runtime.Versioning;
using FluentAssertions;
using HostsGuard.Core;
using HostsGuard.Data;
using HostsGuard.Windows;
using Microsoft.Data.Sqlite;
using Xunit;

namespace HostsGuard.Service.Tests;

/// <summary>NET-083: network fingerprint → profile mapping and auto-switch evaluation.</summary>
[SupportedOSPlatform("windows")]
public sealed class NetworkProfileWatcherTests : IDisposable
{
    private sealed class FakeIdentity : INetworkIdentity
    {
        public NetworkFingerprint? Value { get; set; }

        public NetworkFingerprint? Current() => Value;
    }

    private readonly string _dir;
    private readonly ServiceState _state;
    private readonly HostsDatabase _db;
    private readonly FakeIdentity _identity = new();
    private readonly List<string> _applied = new();
    private readonly NetworkProfileWatcher _watcher;

    public NetworkProfileWatcherTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "hg_net_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        var hostsPath = Path.Combine(_dir, "hosts");
        File.WriteAllText(hostsPath, "# hosts\n");
        _db = new HostsDatabase(Path.Combine(_dir, "hostsguard.db"));
        _state = new ServiceState(new HostsEngine(hostsPath), _db, dataDir: _dir) { NetworkIdentity = _identity };
        _watcher = new NetworkProfileWatcher(_state, _identity, p => _applied.Add(p));

        // Two saved profiles to switch between.
        _db.AddDomain("home-only.example", "blocked");
        _db.SaveProfile("Home");
        _db.SaveProfile("Public");
    }

    public void Dispose()
    {
        _watcher.Dispose();
        _state.Dispose();
        try
        {
            Directory.Delete(_dir, true);
        }
        catch (IOException)
        {
            // best effort
        }
    }

    [Fact]
    public void Mapping_round_trips_and_removes_on_empty_profile()
    {
        _db.SetNetworkProfile("AA:BB:CC", "Public", "Cafe WiFi");
        _db.GetProfileForNetwork("AA:BB:CC").Should().Be("Public");
        _db.GetNetworkProfiles().Should().ContainSingle();

        _db.SetNetworkProfile("AA:BB:CC", "", "Cafe WiFi");
        _db.GetProfileForNetwork("AA:BB:CC").Should().BeNull();
    }

    [Fact]
    public void Evaluate_activates_the_mapped_profile_for_the_joined_network()
    {
        _db.SetNetworkProfile("gw-mac-public", "Public", "Cafe");
        _identity.Value = new NetworkFingerprint("gw-mac-public", "Wi-Fi");

        _watcher.Evaluate();

        _applied.Should().ContainSingle().Which.Should().Be("Public");
    }

    [Fact]
    public void Evaluate_ignores_networks_with_no_mapping()
    {
        _identity.Value = new NetworkFingerprint("unmapped-network", "Wi-Fi");

        _watcher.Evaluate();

        _applied.Should().BeEmpty();
        _db.GetAlerts(new AlertFilter(Type: "unknown_lan")).Rows
            .Should().ContainSingle(a => a.Subject == "Wi-Fi" && a.Action == "unknown_network");
    }

    [Fact]
    public void Evaluate_does_not_reswitch_when_already_active()
    {
        _db.SetNetworkProfile("gw-mac-home", "Home", "Home");
        _db.SetMeta("active_profile", "Home");
        _identity.Value = new NetworkFingerprint("gw-mac-home", "Ethernet");

        _watcher.Evaluate();

        _applied.Should().BeEmpty(); // already on Home
    }

    [Fact]
    public void Evaluate_switches_only_once_per_network_change()
    {
        _db.SetNetworkProfile("gw-mac-public", "Public", "Cafe");
        _identity.Value = new NetworkFingerprint("gw-mac-public", "Wi-Fi");

        _watcher.Evaluate();
        _watcher.Evaluate(); // same fingerprint — no repeat

        _applied.Should().ContainSingle();
    }

    [Fact]
    public void Evaluate_uses_multi_signal_matcher_precedence()
    {
        _db.SetNetworkProfile(
            NetworkProfileSelectorCodec.Encode(new("Home", "SSID", Ssid: "Office")),
            "Home",
            "SSID");
        _db.SetNetworkProfile(
            NetworkProfileSelectorCodec.Encode(new("Public", "Exact", Ssid: "Office", DnsSuffix: "guest.example")),
            "Public",
            "Exact");
        _identity.Value = new NetworkFingerprint("gateway", "Wi-Fi")
        {
            Ssid = "Office",
            InterfaceName = "Wi-Fi",
            DnsSuffix = "guest.example",
        };

        _watcher.Evaluate();

        _applied.Should().ContainSingle().Which.Should().Be("Public");
    }

    [Fact]
    public void Evaluate_rechecks_when_vpn_changes_without_fingerprint_change()
    {
        _db.SetNetworkProfile("same-gateway", "Home", "Home");
        _db.SetNetworkProfile(
            NetworkProfileSelectorCodec.Encode(new("Public", "VPN", Fingerprint: "same-gateway", VpnPresent: true)),
            "Public",
            "VPN");
        _identity.Value = new NetworkFingerprint("same-gateway", "Wi-Fi") { VpnPresent = false };

        _watcher.Evaluate();
        _identity.Value = _identity.Value with { VpnPresent = true };
        _watcher.Evaluate();

        _applied.Should().Equal("Home", "Public");
    }

    [Fact]
    public void Evaluate_ignores_stale_rules_instead_of_masking_a_valid_fallback()
    {
        _db.SetNetworkProfile("same-gateway", "Home", "Home");
        _db.SetNetworkProfile(
            NetworkProfileSelectorCodec.Encode(new("Deleted", "Stale", Fingerprint: "same-gateway", VpnPresent: true)),
            "Deleted",
            "Stale");
        _identity.Value = new NetworkFingerprint("same-gateway", "Wi-Fi") { VpnPresent = true };

        _watcher.Evaluate();

        _applied.Should().ContainSingle().Which.Should().Be("Home");
    }
}
