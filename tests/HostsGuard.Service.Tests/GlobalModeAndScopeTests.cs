using System.Runtime.Versioning;
using FluentAssertions;
using HostsGuard.Contracts;
using HostsGuard.Core;
using HostsGuard.Data;
using HostsGuard.Windows;
using Microsoft.Data.Sqlite;
using Xunit;

namespace HostsGuard.Service.Tests;

/// <summary>NET-076: global outbound posture selector and per-app scope blocks.</summary>
[SupportedOSPlatform("windows")]
public sealed class GlobalModeAndScopeTests : IDisposable
{
    private readonly string _dir;
    private readonly ServiceState _state;
    private readonly FakeFirewallEngine _fw = new();
    private readonly FirewallControlServiceImpl _impl;

    public GlobalModeAndScopeTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "hg_scope_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        var hostsPath = Path.Combine(_dir, "hosts");
        File.WriteAllText(hostsPath, "# hosts\n");
        _state = new ServiceState(new HostsEngine(hostsPath), new HostsDatabase(Path.Combine(_dir, "hostsguard.db")),
            firewall: _fw, dataDir: _dir);
        _impl = new FirewallControlServiceImpl(_state);
    }

    public void Dispose()
    {
        _state.Dispose();
        SqliteConnection.ClearAllPools();
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
    public async Task Global_block_all_sets_default_outbound_block_on_every_profile()
    {
        var ack = await _impl.SetGlobalMode(new GlobalModeRequest { Mode = "block-all" }, null!);

        ack.Ok.Should().BeTrue();
        _fw.PerProfileBlock.Values.Should().OnlyContain(v => v);

        (await _impl.SetGlobalMode(new GlobalModeRequest { Mode = "allow-all" }, null!)).Ok.Should().BeTrue();
        _fw.PerProfileBlock.Values.Should().OnlyContain(v => !v);
    }

    [Fact]
    public async Task Global_mode_rejects_unknown_values()
    {
        var ack = await _impl.SetGlobalMode(new GlobalModeRequest { Mode = "disable-firewall" }, null!);
        ack.Ok.Should().BeFalse();
        ack.ErrorCode.Should().Contain("invalid_mode");
    }

    [Theory]
    [InlineData("internet", "Out")]
    [InlineData("lan", "Out")]
    [InlineData("localhost", "Out")]
    [InlineData("inbound", "In")]
    public async Task Scope_block_creates_a_scoped_rule(string scope, string direction)
    {
        var ack = await _impl.BlockAppScope(
            new AppScopeRequest { ProgramPath = @"C:\apps\p2p.exe", Scope = scope }, null!);

        ack.Ok.Should().BeTrue();
        var rule = _fw.Rules.Values.Should().ContainSingle().Subject;
        rule.Action.Should().Be("Block");
        rule.Direction.Should().Be(direction);
        rule.Program.Should().Be(@"C:\apps\p2p.exe");
        rule.Name.Should().Contain("Scope");
        NetworkScopes.TryParse(scope, out var parsed).Should().BeTrue();
        rule.RemoteAddr.Should().Be(NetworkScopes.RemoteAddresses(parsed));
    }

    [Fact]
    public async Task Scope_block_rejects_unknown_scope()
    {
        var ack = await _impl.BlockAppScope(
            new AppScopeRequest { ProgramPath = @"C:\apps\p2p.exe", Scope = "moon" }, null!);
        ack.Ok.Should().BeFalse();
        ack.ErrorCode.Should().Contain("invalid_scope");
    }

    [Fact]
    public async Task Scope_block_round_trips_with_unblock()
    {
        await _impl.BlockAppScope(new AppScopeRequest { ProgramPath = @"C:\apps\p2p.exe", Scope = "internet" }, null!);
        _fw.Rules.Should().ContainSingle();

        var ack = await _impl.UnblockAppScope(new AppScopeRequest { ProgramPath = @"C:\apps\p2p.exe", Scope = "internet" }, null!);
        ack.Ok.Should().BeTrue();
        _fw.Rules.Should().BeEmpty();
    }

    [Fact]
    public void Direct_ip_connection_is_flagged_in_the_stream()
    {
        using var sub = _state.Bus.Subscribe<ConnectionEvent>();
        // 203.0.113.7 was never resolved → direct-to-IP.
        _state.PublishConnection(new ConnectionInfo("TCP", "0.0.0.0", 1, "203.0.113.7", 6881, "ESTABLISHED", 10, "p2p.exe"));

        sub.Reader.TryRead(out var ev).Should().BeTrue();
        ev!.FwStatus.Should().Be("DIRECT-IP");
    }

    [Fact]
    public void Resolved_ip_connection_is_not_flagged_direct()
    {
        _state.DirectIp.RecordResolved("93.184.216.34", DateTime.Now);
        using var sub = _state.Bus.Subscribe<ConnectionEvent>();
        _state.PublishConnection(new ConnectionInfo("TCP", "0.0.0.0", 1, "93.184.216.34", 443, "ESTABLISHED", 10, "browser.exe"));

        sub.Reader.TryRead(out var ev).Should().BeTrue();
        ev!.FwStatus.Should().BeEmpty();
    }
}
