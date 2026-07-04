using System.Runtime.Versioning;
using FluentAssertions;
using HostsGuard.Data;
using Microsoft.Data.Sqlite;
using Xunit;

namespace HostsGuard.Service.Tests;

/// <summary>
/// NET-119 VPN-presence kill-switch: when armed and the chosen adapter is down,
/// default-outbound Block is enforced on every profile; when it returns, the exact
/// prior posture is restored. Off by default, and an engaged state survives a
/// service restart without capturing its own block-all as the "prior".
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class KillSwitchTests : IDisposable
{
    private readonly string _dir;
    private readonly FakeFirewallEngine _fw;
    private readonly HostsDatabase _db;
    private bool _vpnUp;

    public KillSwitchTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "hg_ks_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        _fw = new FakeFirewallEngine();
        _db = new HostsDatabase(Path.Combine(_dir, "hostsguard.db"));
        _vpnUp = true;
    }

    private KillSwitchMonitor NewMonitor() => new(_fw, _db, _ => _vpnUp, _dir);

    [Fact]
    public void Disabled_by_default_never_blocks()
    {
        using var ks = NewMonitor();
        ks.Enabled.Should().BeFalse();

        ks.Evaluate();

        ks.IsEngaged.Should().BeFalse();
        _fw.OutboundBlock.Should().BeFalse();
    }

    [Fact]
    public void Enabling_while_the_vpn_is_up_does_not_engage()
    {
        using var ks = NewMonitor();
        _vpnUp = true;

        ks.Configure(true, "WireGuard").Ok.Should().BeTrue();

        ks.IsEngaged.Should().BeFalse();
        _fw.OutboundBlock.Should().BeFalse();
    }

    [Fact]
    public void Vpn_down_engages_block_all()
    {
        using var ks = NewMonitor();
        ks.Configure(true, "WireGuard");

        _vpnUp = false;
        ks.Evaluate();

        ks.IsEngaged.Should().BeTrue();
        _fw.OutboundBlock.Should().BeTrue();
    }

    [Fact]
    public void Vpn_back_up_restores_the_prior_posture()
    {
        _fw.OutboundBlock = false; // user's normal posture: outbound allowed
        using var ks = NewMonitor();
        ks.Configure(true, "wg");

        _vpnUp = false;
        ks.Evaluate();
        _fw.OutboundBlock.Should().BeTrue(); // leaked-prevention engaged

        _vpnUp = true;
        ks.Evaluate();
        ks.IsEngaged.Should().BeFalse();
        _fw.OutboundBlock.Should().BeFalse(); // exact prior restored
    }

    [Fact]
    public void Restore_targets_the_captured_prior_per_profile_not_blindly_allow()
    {
        // User already runs Public=Block, Domain/Private=Allow before the VPN drops.
        _fw.SetDefaultOutboundBlock(new Dictionary<string, bool>(StringComparer.Ordinal)
        {
            ["Domain"] = false,
            ["Private"] = false,
            ["Public"] = true,
        });
        using var ks = NewMonitor();
        ks.Configure(true, "wg");

        _vpnUp = false;
        ks.Evaluate();
        _fw.PerProfileBlock.Values.Should().OnlyContain(v => v); // all blocked while down

        _vpnUp = true;
        ks.Evaluate();
        _fw.PerProfileBlock["Domain"].Should().BeFalse();
        _fw.PerProfileBlock["Private"].Should().BeFalse();
        _fw.PerProfileBlock["Public"].Should().BeTrue(); // restored, not flattened to Allow
    }

    [Fact]
    public void Disabling_while_engaged_lifts_the_block()
    {
        _fw.OutboundBlock = false;
        using var ks = NewMonitor();
        ks.Configure(true, "wg");
        _vpnUp = false;
        ks.Evaluate();
        _fw.OutboundBlock.Should().BeTrue();

        ks.Configure(false, "wg"); // turn the kill-switch off

        ks.IsEngaged.Should().BeFalse();
        _fw.OutboundBlock.Should().BeFalse();
    }

    [Fact]
    public void Engaged_state_survives_a_restart_and_restores_on_reconnect()
    {
        _fw.OutboundBlock = false;
        using (var ks1 = NewMonitor())
        {
            ks1.Configure(true, "wg");
            _vpnUp = false;
            ks1.Evaluate();
            _fw.OutboundBlock.Should().BeTrue();
        }

        // New monitor instance = service restart. Block-all is still live on the OS.
        using var ks2 = NewMonitor();
        ks2.IsEngaged.Should().BeTrue(); // reloaded as engaged from persisted state

        _vpnUp = true;
        ks2.Evaluate();
        ks2.IsEngaged.Should().BeFalse();
        _fw.OutboundBlock.Should().BeFalse(); // prior (allow) restored
    }

    [Fact]
    public void Restart_while_still_down_never_captures_its_own_block_all_as_prior()
    {
        _fw.OutboundBlock = false; // real prior = allow
        using (var ks1 = NewMonitor())
        {
            ks1.Configure(true, "wg");
            _vpnUp = false;
            ks1.Evaluate(); // engage, capture prior=allow
        }

        // Restart while the VPN is STILL down: must not re-capture the block-all.
        using var ks2 = NewMonitor();
        ks2.IsEngaged.Should().BeTrue();
        _vpnUp = false;
        ks2.Evaluate(); // still down — stays engaged, prior untouched

        _vpnUp = true;
        ks2.Evaluate();
        _fw.OutboundBlock.Should().BeFalse(); // restored to the ORIGINAL allow, not block
    }

    [Fact]
    public void Configure_rejects_enabling_without_an_adapter()
    {
        using var ks = NewMonitor();

        var ack = ks.Configure(true, "   ");

        ack.Ok.Should().BeFalse();
        ack.ErrorCode.Should().Be("hostsguard.error.v1/invalid_adapter");
        ks.Enabled.Should().BeFalse();
    }

    public void Dispose()
    {
        _db.Dispose();
        SqliteConnection.ClearAllPools();
        try { Directory.Delete(_dir, true); } catch (IOException) { /* best effort */ }
    }
}
