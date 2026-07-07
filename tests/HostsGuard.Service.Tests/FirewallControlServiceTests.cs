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

    private bool _outboundBlock;

    public bool OutboundBlock
    {
        get => _outboundBlock;
        set
        {
            _outboundBlock = value;
            PerProfileBlock = new Dictionary<string, bool>(StringComparer.Ordinal)
            {
                ["Domain"] = value,
                ["Private"] = value,
                ["Public"] = value,
            };
        }
    }

    public IReadOnlyList<FwProfilePosture> GetPosture() =>
        PerProfileBlock.Select(kv => new FwProfilePosture(kv.Key, true, kv.Value)).ToList();

    public void SetDefaultOutboundBlock(bool block) => OutboundBlock = block;

    public Dictionary<string, bool> PerProfileBlock { get; private set; } = new(StringComparer.Ordinal)
    {
        ["Domain"] = false,
        ["Private"] = false,
        ["Public"] = false,
    };

    public void SetDefaultOutboundBlock(IReadOnlyDictionary<string, bool> perProfile)
    {
        // Set the per-profile map directly (bypass the OutboundBlock setter,
        // which would collapse it to a uniform value).
        PerProfileBlock = new Dictionary<string, bool>(perProfile, StringComparer.Ordinal);
        _outboundBlock = PerProfileBlock.Values.All(v => v);
    }

    public bool SetRuleProgram(string name, string programPath)
    {
        if (!Rules.TryGetValue(name, out var rule))
        {
            return false;
        }

        Rules[name] = rule with { Program = programPath };
        return true;
    }
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
            new FirewallIdentity(Path.Combine(_dir, "fw_identities.json")),
            dataDir: _dir);
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
    public async Task Posture_round_trip_flips_lockdown_and_logs_it()
    {
        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var fw = Client(channel);

        var before = await fw.GetPostureAsync(new Empty());
        before.Available.Should().BeTrue();
        before.Lockdown.Should().BeFalse();
        before.Profiles.Should().HaveCount(3);

        (await fw.SetDefaultOutboundAsync(new OutboundRequest { Block = true })).Ok.Should().BeTrue();
        var after = await fw.GetPostureAsync(new Empty());
        after.Lockdown.Should().BeTrue();
        after.Profiles.Should().OnlyContain(p => p.OutboundBlock);

        (await fw.SetDefaultOutboundAsync(new OutboundRequest { Block = false })).Ok.Should().BeTrue();
        (await fw.GetPostureAsync(new Empty())).Lockdown.Should().BeFalse();
    }

    [Fact]
    public async Task Rebind_updates_program_state_and_identity_for_hg_rules_only()
    {
        var newBinary = Path.Combine(_dir, "moved-app.exe");
        File.WriteAllText(newBinary, "binary");
        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var fw = Client(channel);

        await fw.BlockProgramAsync(new FirewallProgramRequest
        {
            ProgramPath = Path.Combine(_dir, "old-app.exe"),
            Direction = "Outbound",
        });
        var name = _fw.Rules.Keys.Single(k => k.Contains("BlockApp_old-app"));

        var ack = await fw.RebindRuleAsync(new RebindRequest { Name = name, NewProgram = newBinary });

        ack.Ok.Should().BeTrue();
        _fw.Rules[name].Program.Should().Be(newBinary);
        _state.Identity!.Get(name).Should().Contain(i => i.Path == newBinary);

        (await fw.RebindRuleAsync(new RebindRequest { Name = "SystemRule", NewProgram = newBinary }))
            .ErrorCode.Should().Be("hostsguard.error.v1/not_ours");
        (await fw.RebindRuleAsync(new RebindRequest { Name = name, NewProgram = Path.Combine(_dir, "ghost.exe") }))
            .ErrorCode.Should().Be("hostsguard.error.v1/invalid_program");
    }

    [Fact]
    public async Task Suggest_rebind_returns_empty_for_unknown_rules()
    {
        using var channel = NamedPipeChannel.Create(_token, _pipe);

        var suggestions = await Client(channel).SuggestRebindAsync(new RuleNameRequest { Name = "HG_NotThere" });

        suggestions.OldPath.Should().BeEmpty();
        suggestions.Candidates.Should().BeEmpty();
    }

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
    public async Task ExplainDecision_reports_hosts_block_before_firewall_policy()
    {
        _state.Db.AddDomain("ads.example.test", "blocked", "manual");
        using var channel = NamedPipeChannel.Create(_token, _pipe);

        var explanation = await Client(channel).ExplainDecisionAsync(new DecisionExplainRequest
        {
            Domain = "ads.example.test",
            RemoteAddr = "203.0.113.20",
            RemotePort = 443,
            Protocol = "TCP",
        });

        explanation.Verdict.Should().Be("Blocked");
        explanation.Steps.Should().Contain(s => s.Layer == "Hosts" && s.Outcome == "Block" && s.Owner == "manual");
        explanation.NextSafeAction.Should().Contain("Allow");
    }

    [Fact]
    public async Task ExplainDecision_reports_matching_firewall_block_and_allow_rules()
    {
        var program = Path.Combine(_dir, "browser.exe");
        _fw.Rules["HG_Block_Test_Out"] = new FwRule(
            "HG_Block_Test_Out", "Out", "Block", true, "203.0.113.0/24", "TCP", program, "hostsguard", "443");
        _state.Db.AssignRuleToGroup("HG_Block_Test_Out", "Browser lockdown");
        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var fw = Client(channel);

        var blocked = await fw.ExplainDecisionAsync(new DecisionExplainRequest
        {
            RemoteAddr = "203.0.113.21",
            RemotePort = 443,
            Protocol = "TCP",
            ProgramPath = program,
        });

        blocked.Verdict.Should().Be("Blocked");
        blocked.Steps.Should().Contain(s => s.Layer == "Firewall rule" && s.Owner.Contains("HG_Block_Test_Out"));

        _fw.Rules.Clear();
        _fw.SetDefaultOutboundBlock(true);
        _fw.Rules["HG_Allow_Test_Out"] = new FwRule(
            "HG_Allow_Test_Out", "Out", "Allow", true, "Any", "Any", program, "hostsguard");

        var allowed = await fw.ExplainDecisionAsync(new DecisionExplainRequest
        {
            RemoteAddr = "198.51.100.9",
            ProgramPath = program,
        });

        allowed.Verdict.Should().Be("Allowed");
        allowed.Steps.Should().Contain(s => s.Layer == "Firewall rule" && s.Outcome == "Allow");
    }

    [Fact]
    public async Task ExplainDecision_reports_trusted_publisher_and_folder()
    {
        var trustedRoot = Path.Combine(_dir, "trusted");
        var program = Path.Combine(trustedRoot, "tool.exe");
        _state.Consent.SetTrustedPublishers(new[] { "Trusted Corp" });
        _state.Consent.SetTrustedFolders(new[] { trustedRoot });
        using var channel = NamedPipeChannel.Create(_token, _pipe);

        var explanation = await Client(channel).ExplainDecisionAsync(new DecisionExplainRequest
        {
            ProgramPath = program,
            Signer = "CN=Trusted Corp, O=Trusted Corp",
            RemoteAddr = "198.51.100.22",
        });

        explanation.Verdict.Should().Be("Allowed");
        explanation.Steps.Should().Contain(s => s.Owner == "trusted publisher:Trusted Corp" && s.Outcome == "Allow");
        explanation.Steps.Should().Contain(s => s.Owner.StartsWith("trusted folder:", StringComparison.Ordinal) && s.Outcome == "Allow");
    }

    [Fact]
    public async Task ExplainDecision_reports_profile_default_block()
    {
        _fw.SetDefaultOutboundBlock(true);
        _fw.Rules["System package allow"] = new FwRule(
            "System package allow", "Out", "Allow", true, "Any", "Any", "", "system");
        using var channel = NamedPipeChannel.Create(_token, _pipe);

        var explanation = await Client(channel).ExplainDecisionAsync(new DecisionExplainRequest
        {
            RemoteAddr = "198.51.100.23",
            Protocol = "TCP",
            RemotePort = 443,
        });

        explanation.Verdict.Should().Be("Blocked");
        explanation.Steps.Should().NotContain(s => s.Owner == "System package allow");
        explanation.Steps.Should().Contain(s => s.Layer == "Profile default" && s.Outcome == "Block");
        explanation.NextSafeAction.Should().Contain("allow rule");
    }

    [Fact]
    public async Task ExplainDecision_reports_engaged_kill_switch()
    {
        using var killSwitch = new KillSwitchMonitor(_fw, _state.Db, _ => false, _dir);
        _state.KillSwitch = killSwitch;
        killSwitch.Configure(true, "Test VPN").Ok.Should().BeTrue();
        using var channel = NamedPipeChannel.Create(_token, _pipe);

        var explanation = await Client(channel).ExplainDecisionAsync(new DecisionExplainRequest
        {
            RemoteAddr = "198.51.100.24",
            Protocol = "UDP",
            RemotePort = 443,
        });

        explanation.Verdict.Should().Be("Blocked");
        explanation.Steps.Should().Contain(s => s.Layer == "Posture" && s.Owner == "VPN kill-switch" && s.Outcome == "Block");
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
