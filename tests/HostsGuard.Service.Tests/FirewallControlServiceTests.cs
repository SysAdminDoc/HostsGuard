using System.Runtime.Versioning;
using FluentAssertions;
using HostsGuard.Contracts;
using HostsGuard.Core;
using HostsGuard.Data;
using HostsGuard.Ipc;
using HostsGuard.Windows;
using Microsoft.AspNetCore.Builder;
using Microsoft.Data.Sqlite;
using Xunit;

namespace HostsGuard.Service.Tests;

/// <summary>In-memory firewall engine so the service impl is testable unelevated.</summary>
internal sealed class FakeFirewallEngine : IFirewallEngine
{
    public Dictionary<string, FwRule> Rules { get; } = new(StringComparer.Ordinal);

    public IReadOnlyList<FwRule> ListRules() => Rules.Values.ToList();

    public bool CreateRule(FwRule rule)
    {
        if (Rules.ContainsKey(rule.Name))
        {
            return false;
        }

        Rules[rule.Name] = rule;
        return true;
    }

    public bool DeleteRule(string name) => Rules.Remove(name);

    public bool SetRuleEnabled(string name, bool enabled)
    {
        if (!Rules.TryGetValue(name, out var rule))
        {
            return false;
        }

        Rules[name] = rule with { Enabled = enabled };
        return true;
    }

    public bool RuleExists(string name) => Rules.ContainsKey(name);
}

/// <summary>
/// NET-022 service surface: quick-block, HG_-only mutation guard, custom rule
/// creation with prefix enforcement, drift + orphan flags, and the live
/// connection stream — over the real pipe transport.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class FirewallControlServiceTests : IAsyncLifetime
{
    private string _dir = null!;
    private WebApplication _app = null!;
    private ServiceState _state = null!;
    private FakeFirewallEngine _fw = null!;
    private string _pipe = null!;
    private string _token = null!;

    public async Task InitializeAsync()
    {
        _dir = Path.Combine(Path.GetTempPath(), "hg_fw_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        var hostsPath = Path.Combine(_dir, "hosts");
        File.WriteAllText(hostsPath, "# hosts\n");

        _fw = new FakeFirewallEngine();
        _state = new ServiceState(
            new HostsEngine(hostsPath),
            new HostsDatabase(Path.Combine(_dir, "hostsguard.db")),
            _fw,
            new FirewallIdentity(Path.Combine(_dir, "fw_identities.json")));
        _token = SessionToken.Generate();
        _pipe = "HostsGuard.FwTest." + Guid.NewGuid().ToString("N");
        _app = ServiceHost.Build(_state, _token, _pipe);
        await _app.StartAsync();
    }

    public async Task DisposeAsync()
    {
        await _app.DisposeAsync();
        _state.Dispose();
        SqliteConnection.ClearAllPools();
        try { Directory.Delete(_dir, true); } catch (IOException) { /* best effort */ }
    }

    private FirewallControl.FirewallControlClient Client(Grpc.Net.Client.GrpcChannel ch) => new(ch);

    [Fact]
    public async Task Quick_block_ip_creates_visible_hg_rule_and_tracks_state()
    {
        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var fw = Client(channel);

        var ack = await fw.BlockIpAsync(new FirewallIpRequest { Address = "203.0.113.7", Direction = "Outbound" });

        ack.Ok.Should().BeTrue();
        _fw.Rules.Should().ContainKey("HG_Block_203.0.113.7_Out");
        _fw.Rules["HG_Block_203.0.113.7_Out"].Action.Should().Be("Block");
        _state.Db.GetFwStateNames().Should().Contain("HG_Block_203.0.113.7_Out");

        var list = await fw.ListRulesAsync(new Empty());
        list.Rules.Should().Contain(r => r.Name == "HG_Block_203.0.113.7_Out" && r.Source == "hostsguard");
    }

    [Fact]
    public async Task Invalid_address_is_rejected_before_touching_the_engine()
    {
        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var ack = await Client(channel).BlockIpAsync(new FirewallIpRequest { Address = "not-an-ip; Remove-Item" });

        ack.Ok.Should().BeFalse();
        ack.ErrorCode.Should().Be("hostsguard.error.v1/invalid_address");
        _fw.Rules.Should().BeEmpty();
    }

    [Fact]
    public async Task Custom_rule_gets_hg_prefix_enforced()
    {
        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var ack = await Client(channel).CreateRuleAsync(new FirewallRule
        {
            Name = "MyRule",
            Direction = "Out",
            Action = "Block",
            RemoteAddr = "198.51.100.0/24",
            Protocol = "TCP",
            Enabled = true,
        });

        ack.Ok.Should().BeTrue();
        _fw.Rules.Should().ContainKey("HG_MyRule");
    }

    [Fact]
    public async Task Mutation_is_refused_for_system_rules()
    {
        _fw.Rules["Core Networking - DNS (UDP-Out)"] = new FwRule(
            "Core Networking - DNS (UDP-Out)", "Out", "Allow", true, "Any", "UDP", "", "system");

        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var fw = Client(channel);

        var del = await fw.DeleteRuleAsync(new RuleNameRequest { Name = "Core Networking - DNS (UDP-Out)" });
        var toggle = await fw.SetRuleEnabledAsync(new RuleEnabledRequest { Name = "Core Networking - DNS (UDP-Out)", Enabled = false });

        del.Ok.Should().BeFalse();
        del.ErrorCode.Should().Be("hostsguard.error.v1/not_ours");
        toggle.Ok.Should().BeFalse();
        _fw.Rules["Core Networking - DNS (UDP-Out)"].Enabled.Should().BeTrue();
    }

    [Fact]
    public async Task Toggle_and_delete_work_for_hg_rules()
    {
        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var fw = Client(channel);
        await fw.BlockIpAsync(new FirewallIpRequest { Address = "203.0.113.9" });
        var name = "HG_Block_203.0.113.9_Out";

        (await fw.SetRuleEnabledAsync(new RuleEnabledRequest { Name = name, Enabled = false })).Ok.Should().BeTrue();
        _fw.Rules[name].Enabled.Should().BeFalse();

        (await fw.DeleteRuleAsync(new RuleNameRequest { Name = name })).Ok.Should().BeTrue();
        _fw.Rules.Should().NotContainKey(name);
        _state.Db.GetFwStateNames().Should().NotContain(name);
    }

    [Fact]
    public async Task Tracked_rule_missing_live_surfaces_as_drift()
    {
        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var fw = Client(channel);
        await fw.BlockIpAsync(new FirewallIpRequest { Address = "203.0.113.11" });
        _fw.Rules.Clear(); // deleted behind our back

        var list = await fw.ListRulesAsync(new Empty());

        list.Rules.Should().Contain(r => r.Name == "HG_Block_203.0.113.11_Out" && r.Drifted);
    }

    [Fact]
    public async Task Hg_program_rule_with_missing_binary_is_orphaned()
    {
        _fw.Rules["HG_BlockApp_ghost_Out"] = new FwRule(
            "HG_BlockApp_ghost_Out", "Out", "Block", true, "Any", "Any",
            Path.Combine(_dir, "ghost.exe"), "hostsguard");

        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var list = await Client(channel).ListRulesAsync(new Empty());

        list.Rules.Should().Contain(r => r.Name == "HG_BlockApp_ghost_Out" && r.Orphaned);
    }

    [Fact]
    public async Task WatchConnections_streams_published_sightings()
    {
        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var monitoring = new Monitoring.MonitoringClient(channel);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var call = monitoring.WatchConnections(new Empty(), cancellationToken: cts.Token);

        await Task.Delay(250, cts.Token);
        _state.PublishConnection(new ConnectionInfo("TCP", "10.0.0.5", 51000, "93.184.216.34", 443, "ESTABLISHED", 4242, "edge.exe"));

        (await call.ResponseStream.MoveNext(cts.Token)).Should().BeTrue();
        var ev = call.ResponseStream.Current;
        ev.RemoteAddr.Should().Be("93.184.216.34");
        ev.RemotePort.Should().Be(443);
        ev.Process.Should().Be("edge.exe");
        ev.State.Should().Be("ESTABLISHED");
    }
}
