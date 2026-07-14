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

    public List<FwAppPackage> Packages { get; } = new();

    public List<FwInterfaceAlias> InterfaceAliases { get; } = new();

    public int ListRulesCalls { get; private set; }

    public IReadOnlyList<FwRule> ListRules()
    {
        ListRulesCalls++;
        return Rules.Values.ToList();
    }

    public IReadOnlyList<FwAppPackage> ListPackages() => Packages.ToList();

    public IReadOnlyList<FwInterfaceAlias> ListInterfaceAliases() => InterfaceAliases.ToList();

    public List<InboundFirewallProfile> ActiveInboundProfiles { get; } = new();

    public IReadOnlyList<InboundFirewallProfile> GetActiveInboundProfiles() => ActiveInboundProfiles.ToList();

    public FirewallLocalPolicyModifyState LocalPolicyModifyState { get; set; } = FirewallLocalPolicyModifyState.Ok;

    public FirewallLocalPolicyModifyState GetLocalPolicyModifyState() => LocalPolicyModifyState;

    public HashSet<string> CreateFailures { get; } = new(StringComparer.Ordinal);

    public bool CreateRule(FwRule rule)
    {
        if (CreateFailures.Contains(rule.Name) || Rules.ContainsKey(rule.Name))
        {
            return false;
        }

        Rules[rule.Name] = rule;
        return true;
    }

    public bool ReplaceRule(FwRule rule)
    {
        if (!Rules.ContainsKey(rule.Name)) return false;
        Rules[rule.Name] = rule;
        return true;
    }

    public HashSet<string> DeleteFailures { get; } = new(StringComparer.Ordinal);

    public bool DeleteRule(string name) => !DeleteFailures.Contains(name) && Rules.Remove(name);

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

    public bool SetRuleRemoteAddresses(string name, string remoteAddresses)
    {
        if (!Rules.TryGetValue(name, out var rule))
        {
            return false;
        }

        Rules[name] = rule with { RemoteAddr = remoteAddresses };
        return true;
    }
}

internal sealed class FakeFlowTerminator : IFlowTerminator
{
    public List<FlowTuple> Closed { get; } = new();

    public FlowTerminationResult CloseTcp4(FlowTuple flow)
    {
        Closed.Add(flow);
        return new FlowTerminationResult(true, "closed IPv4 TCP flow");
    }
}

internal sealed class FakeLanAttackSurfaceStore : ILanAttackSurfaceStore
{
    public HashSet<string> Blocked { get; } = new(StringComparer.Ordinal);

    public bool IsBlocked(string key) => Blocked.Contains(key);

    public void SetBlocked(string key, bool blocked)
    {
        if (blocked)
        {
            Blocked.Add(key);
        }
        else
        {
            Blocked.Remove(key);
        }
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
    private FakeFlowTerminator _flows = null!;
    private FakeLanAttackSurfaceStore _lan = null!;
    private List<ConnectionInfo> _connections = null!;
    private Dictionary<string, IReadOnlyList<string>> _domainAnswers = null!;
    private string _pipe = null!;
    private string _token = null!;

    public async Task InitializeAsync()
    {
        _dir = Path.Combine(Path.GetTempPath(), "hg_fw_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        var hostsPath = Path.Combine(_dir, "hosts");
        File.WriteAllText(hostsPath, "# hosts\n");

        _fw = new FakeFirewallEngine();
        _flows = new FakeFlowTerminator();
        _lan = new FakeLanAttackSurfaceStore();
        _connections = new List<ConnectionInfo>();
        _domainAnswers = new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal);
        _state = new ServiceState(
            new HostsEngine(hostsPath),
            new HostsDatabase(Path.Combine(_dir, "hostsguard.db")),
            _fw,
            new FirewallIdentity(Path.Combine(_dir, "fw_identities.json")),
            dataDir: _dir,
            flowTerminator: _flows,
            connectionSnapshot: () => _connections,
            domainResolver: (domain, _) => Task.FromResult(
                _domainAnswers.TryGetValue(domain, out var ips)
                    ? ips
                    : (IReadOnlyList<string>)Array.Empty<string>()),
            lanSurfaceStore: _lan);
        _token = SessionToken.Generate();
        _pipe = "HostsGuard.FwTest." + Guid.NewGuid().ToString("N");
        _app = ServiceHost.Build(_state, _token, _pipe);
        await _app.StartAsync();
    }

    public async Task DisposeAsync()
    {
        await _app.DisposeAsync();
        _state.Dispose();
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
    public async Task Secure_rules_rpc_surfaces_evidence_and_rearms_a_quarantined_rule()
    {
        const string name = "HG_Block_rpc_loop";
        _fw.CreateRule(new FwRule(name, "Out", "Block", true, "203.0.113.25", "Any", string.Empty, "hostsguard"));
        _state.Db.UpsertFwState(name, "Out", "Block", "203.0.113.25", "Any", string.Empty);
        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var client = Client(channel);
        (await client.SetSecureRulesAsync(new SecureRulesRequest { Enabled = true })).Ok.Should().BeTrue();

        for (var i = 0; i < SecureRulesGuard.RestoreLimit; i++)
        {
            _fw.Rules.Remove(name);
            _state.SecureRules.Reconcile();
        }

        _fw.Rules.Remove(name);
        _state.SecureRules.Reconcile();

        var status = await client.GetSecureRulesAsync(new Empty());
        status.Tracked.Should().Be(0, "a quarantined rule is not receiving automatic protection");
        status.Quarantined.Should().Be(1);
        var conflict = status.Conflicts.Should().ContainSingle().Subject;
        conflict.Name.Should().Be(name);
        conflict.LiveEvidence.Should().Be("missing");
        conflict.TrackedEvidence.Should().Contain("203.0.113.25");
        (await client.ResolveSecureRuleConflictAsync(new SecureRuleConflictRequest { Name = name, Action = "invalid" }))
            .ErrorCode.Should().Be("hostsguard.error.v1/invalid_action");

        (await client.ResolveSecureRuleConflictAsync(new SecureRuleConflictRequest { Name = name, Action = "rearm" }))
            .Ok.Should().BeTrue();
        _fw.Rules.Should().ContainKey(name);
        (await client.GetSecureRulesAsync(new Empty())).Quarantined.Should().Be(0);
    }

    [Fact]
    public async Task Secure_rules_rearm_requires_the_guard_to_be_armed()
    {
        const string name = "HG_Block_rpc_off";
        _fw.CreateRule(new FwRule(name, "Out", "Block", true, "203.0.113.26", "Any", string.Empty, "hostsguard"));
        _state.Db.UpsertFwState(name, "Out", "Block", "203.0.113.26", "Any", string.Empty);
        _state.SecureRules.SetEnabled(true);
        for (var i = 0; i < SecureRulesGuard.RestoreLimit; i++)
        {
            _fw.Rules.Remove(name);
            _state.SecureRules.Reconcile();
        }

        _fw.Rules.Remove(name);
        _state.SecureRules.Reconcile();
        _state.SecureRules.SetEnabled(false);
        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var client = Client(channel);

        var ack = await client.ResolveSecureRuleConflictAsync(new SecureRuleConflictRequest
        {
            Name = name,
            Action = "rearm",
        });

        ack.ErrorCode.Should().Be("hostsguard.error.v1/secure_rules_disabled");
        _state.SecureRules.Conflicts.Should().ContainSingle();
        _fw.Rules.Should().NotContainKey(name);
    }

    [Fact]
    public async Task Secure_rules_accept_rpc_keeps_foreign_state_and_removes_tracking()
    {
        const string name = "HG_Block_rpc_accept";
        _fw.CreateRule(new FwRule(name, "Out", "Block", true, "198.51.100.9", "Any", string.Empty, "hostsguard"));
        _state.Db.UpsertFwState(name, "Out", "Block", "198.51.100.9", "Any", string.Empty);
        _state.SecureRules.SetEnabled(true);
        for (var i = 0; i < SecureRulesGuard.RestoreLimit; i++)
        {
            _fw.Rules.Remove(name);
            _state.SecureRules.Reconcile();
        }

        _fw.Rules.Remove(name);
        _state.SecureRules.Reconcile();
        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var client = Client(channel);

        (await client.ResolveSecureRuleConflictAsync(new SecureRuleConflictRequest { Name = name, Action = "accept" }))
            .Ok.Should().BeTrue();

        _fw.Rules.Should().NotContainKey(name);
        _state.Db.GetFwStateNames().Should().NotContain(name);
        (await client.GetSecureRulesAsync(new Empty())).Conflicts.Should().BeEmpty();
    }

    [Fact]
    public async Task Full_firewall_drift_logs_foreign_changes_and_surfaces_vanished_rows()
    {
        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var fw = Client(channel);
        _state.FirewallDrift.CaptureNow(Array.Empty<FwRule>());

        _fw.Rules["Steam Inbound"] = new FwRule("Steam Inbound", "In", "Allow", true, "Any", "TCP", @"C:\Steam\steam.exe", "system", "27015");
        var added = await fw.ListRulesAsync(new Empty());

        added.Rules.Single(r => r.Name == "Steam Inbound").DriftStatus.Should().Be("added");
        _state.Db.GetEvents(new EventLogFilter(Action: EventTaxonomy.FwRuleAdded)).Rows
            .Should().ContainSingle(e => e.Domain == "Steam Inbound");
        _state.Db.GetAlerts(new AlertFilter(Type: "firewall_drift", SurfaceOnly: false)).Rows
            .Should().ContainSingle(a => a.Subject == "Steam Inbound" && a.Action == "added");

        _fw.Rules["Steam Inbound"] = _fw.Rules["Steam Inbound"] with { Enabled = false };
        var changed = await fw.ListRulesAsync(new Empty());

        changed.Rules.Single(r => r.Name == "Steam Inbound").DriftStatus.Should().Be("changed");
        changed.Rules.Single(r => r.Name == "Steam Inbound").DriftDetail.Should().Contain("enabled: on -> off");

        _fw.Rules.Remove("Steam Inbound");
        var vanished = await fw.ListRulesAsync(new Empty());

        var row = vanished.Rules.Single(r => r.Name == "Steam Inbound");
        row.Source.Should().Be("system");
        row.DriftStatus.Should().Be("vanished");
        _fw.Rules.Should().NotContainKey("Steam Inbound");
        _state.Db.GetEvents(new EventLogFilter(Action: EventTaxonomy.FwRuleVanished)).Rows
            .Should().ContainSingle(e => e.Domain == "Steam Inbound");
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
    public async Task Close_connection_terminates_ipv4_tcp_tuple_and_logs()
    {
        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var fw = Client(channel);

        var ack = await fw.CloseConnectionAsync(new FlowCloseRequest
        {
            Protocol = "TCP",
            LocalAddr = "10.0.0.5",
            LocalPort = 51000,
            RemoteAddr = "93.184.216.34",
            RemotePort = 443,
            Process = "edge.exe",
        });

        ack.Ok.Should().BeTrue();
        _flows.Closed.Should().ContainSingle(f => f.RemoteAddress == "93.184.216.34" && f.RemotePort == 443);
        _state.Db.GetEvents(new EventLogFilter(Action: EventTaxonomy.FwFlowTeardown)).Rows
            .Should().ContainSingle(e => e.Process == "edge.exe" && e.Domain == "93.184.216.34:443");
    }

    [Fact]
    public async Task Flow_teardown_opt_in_closes_matching_ipv4_tcp_after_ip_block()
    {
        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var fw = Client(channel);
        await fw.SetFlowTeardownAsync(new FlowTeardownRequest { Enabled = true });
        _connections.Add(new ConnectionInfo("TCP", "10.0.0.5", 51000, "203.0.113.7", 443, "ESTABLISHED", 42, "browser"));
        _connections.Add(new ConnectionInfo("TCP", "10.0.0.5", 51001, "203.0.113.8", 443, "ESTABLISHED", 42, "browser"));
        _connections.Add(new ConnectionInfo("UDP", "10.0.0.5", 51002, "203.0.113.7", 53, "", 42, "browser"));

        var ack = await fw.BlockIpAsync(new FirewallIpRequest { Address = "203.0.113.7", Direction = "Outbound" });

        ack.Ok.Should().BeTrue();
        ack.Message.Should().Contain("closed 1 IPv4 TCP flow");
        _flows.Closed.Should().ContainSingle(f => f.RemoteAddress == "203.0.113.7" && f.Protocol == "TCP");
    }

    [Fact]
    public async Task Flow_teardown_stays_off_until_enabled()
    {
        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var fw = Client(channel);
        _connections.Add(new ConnectionInfo("TCP", "10.0.0.5", 51000, "203.0.113.7", 443, "ESTABLISHED", 42, "browser"));

        var ack = await fw.BlockIpAsync(new FirewallIpRequest { Address = "203.0.113.7", Direction = "Outbound" });

        ack.Ok.Should().BeTrue();
        ack.Message.Should().NotContain("closed");
        _flows.Closed.Should().BeEmpty();
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
    public async Task ListAppPackages_returns_package_identity_metadata()
    {
        _fw.Packages.Add(new FwAppPackage(
            "Contoso.Reader_123abc",
            "S-1-15-2-123",
            "Contoso Reader",
            "Contoso.Reader_1.0.0.0_x64__123abc",
            @"C:\Program Files\WindowsApps\Contoso.Reader\reader.exe"));
        using var channel = NamedPipeChannel.Create(_token, _pipe);

        var list = await Client(channel).ListAppPackagesAsync(new Empty());

        list.Packages.Should().ContainSingle(p =>
            p.PackageFamilyName == "Contoso.Reader_123abc" &&
            p.PackageSid == "S-1-15-2-123" &&
            p.DisplayName == "Contoso Reader" &&
            p.PackageFullName.Contains("Contoso.Reader", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Custom_rule_can_target_msix_package_family()
    {
        _fw.Packages.Add(new FwAppPackage(
            "Contoso.Reader_123abc",
            "S-1-15-2-123",
            "Contoso Reader",
            "Contoso.Reader_1.0.0.0_x64__123abc",
            @"C:\Program Files\WindowsApps\Contoso.Reader\reader.exe"));
        using var channel = NamedPipeChannel.Create(_token, _pipe);

        var ack = await Client(channel).CreateRuleAsync(new FirewallRule
        {
            Name = "ReaderPackageBlock",
            Direction = "Out",
            Action = "Block",
            RemoteAddr = "Any",
            Protocol = "TCP",
            PackageFamilyName = "Contoso.Reader_123abc",
            Enabled = true,
        });

        ack.Ok.Should().BeTrue();
        _fw.Rules.Should().ContainKey("HG_ReaderPackageBlock");
        _fw.Rules["HG_ReaderPackageBlock"].Program.Should().BeEmpty();
        _fw.Rules["HG_ReaderPackageBlock"].PackageSid.Should().Be("S-1-15-2-123");
        _fw.Rules["HG_ReaderPackageBlock"].PackageDisplayName.Should().Be("Contoso Reader");
        _state.Db.GetFwState().Should().ContainSingle(r =>
            r.Name == "HG_ReaderPackageBlock" &&
            r.PackageFamilyName == "Contoso.Reader_123abc" &&
            r.PackageSid == "S-1-15-2-123");

        var list = await Client(channel).ListRulesAsync(new Empty());
        list.Rules.Should().ContainSingle(r =>
            r.Name == "HG_ReaderPackageBlock" &&
            r.PackageFamilyName == "Contoso.Reader_123abc" &&
            r.PackageSid == "S-1-15-2-123" &&
            r.PackageDisplayName == "Contoso Reader");
    }

    [Fact]
    public async Task Custom_rule_rejects_program_and_package_target_together()
    {
        using var channel = NamedPipeChannel.Create(_token, _pipe);

        var ack = await Client(channel).CreateRuleAsync(new FirewallRule
        {
            Name = "Ambiguous",
            Direction = "Out",
            Action = "Block",
            Program = Path.Combine(_dir, "app.exe"),
            PackageFamilyName = "Contoso.Reader_123abc",
            Enabled = true,
        });

        ack.Ok.Should().BeFalse();
        ack.ErrorCode.Should().Be("hostsguard.error.v1/ambiguous_target");
        _fw.Rules.Should().BeEmpty();
    }

    [Fact]
    public async Task Rule_authoring_round_trips_local_remote_ports_and_selected_interface_aliases()
    {
        _fw.InterfaceAliases.Add(new FwInterfaceAlias("Ethernet", "Intel adapter", true, "Ethernet"));
        _fw.InterfaceAliases.Add(new FwInterfaceAlias("Wi-Fi", "Wireless adapter", false, "Wireless80211"));
        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var client = Client(channel);

        var aliases = await client.ListInterfaceAliasesAsync(new Empty());
        aliases.Interfaces.Should().Contain(row => row.Alias == "Ethernet" && row.IsUp && row.Description == "Intel adapter")
            .And.Contain(row => row.Alias == "Wi-Fi" && !row.IsUp);

        var created = await client.CreateRuleAsync(new FirewallRule
        {
            Name = "ScopedWeb",
            Direction = "In",
            Action = "Allow",
            Protocol = "TCP",
            LocalPorts = "8000-8010",
            RemotePorts = "443",
            Interfaces = "wi-fi, Ethernet,WI-FI",
            RemoteAddr = "Any",
            Enabled = true,
        });

        created.Ok.Should().BeTrue();
        var rule = _fw.Rules["HG_ScopedWeb"];
        rule.LocalPorts.Should().Be("8000-8010");
        rule.RemotePorts.Should().Be("443");
        rule.Interfaces.Should().Be("Ethernet,Wi-Fi");

        var updated = await client.UpdateRuleAsync(new FirewallRule
        {
            Name = "HG_ScopedWeb",
            Direction = "In",
            Action = "Allow",
            Protocol = "TCP",
            LocalPorts = "8000-8005,8006-8010",
            RemotePorts = "443",
            Interfaces = "Ethernet",
            RemoteAddr = "Any",
            Enabled = true,
        });

        updated.Ok.Should().BeTrue();
        _fw.Rules["HG_ScopedWeb"].LocalPorts.Should().Be("8000-8010");
        _fw.Rules["HG_ScopedWeb"].Interfaces.Should().Be("Ethernet");
        _state.Db.GetFwState().Should().ContainSingle(row =>
            row.Name == "HG_ScopedWeb" && row.LocalPorts == "8000-8010" &&
            row.RemotePorts == "443" && row.Interfaces == "Ethernet");
    }

    [Fact]
    public async Task Rule_authoring_rejects_ports_on_incompatible_protocol_unknown_alias_and_foreign_edit()
    {
        _fw.InterfaceAliases.Add(new FwInterfaceAlias("Ethernet", "Adapter", true, "Ethernet"));
        _fw.Rules["System rule"] = new FwRule("System rule", "In", "Allow", true, "Any", "TCP", "", "system");
        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var client = Client(channel);

        var incompatible = await client.CreateRuleAsync(new FirewallRule
        {
            Name = "BadProtocol", Direction = "In", Action = "Allow", Protocol = "Any",
            LocalPorts = "8000-8010", RemotePorts = "443", Enabled = true,
        });
        var typo = await client.CreateRuleAsync(new FirewallRule
        {
            Name = "BadAlias", Direction = "In", Action = "Allow", Protocol = "TCP",
            LocalPorts = "8000-8010", Interfaces = "Etherneet", Enabled = true,
        });
        var foreign = await client.UpdateRuleAsync(new FirewallRule
        {
            Name = "System rule", Direction = "In", Action = "Allow", Protocol = "TCP", Enabled = true,
        });

        incompatible.Ok.Should().BeFalse();
        incompatible.ErrorCode.Should().EndWith("/invalid_rule");
        incompatible.Message.Should().Contain("cannot specify").And.Contain("ports");
        typo.Ok.Should().BeFalse();
        typo.Message.Should().Contain("not available");
        foreign.Ok.Should().BeFalse();
        foreign.ErrorCode.Should().EndWith("/not_ours");
        _fw.Rules.Should().ContainKey("System rule").And.NotContainKey("HG_BadProtocol").And.NotContainKey("HG_BadAlias");
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
    public async Task CreateDomainFirewallRule_tracks_per_app_rule_and_explainer_reports_domain_layer()
    {
        var program = Path.Combine(_dir, "browser.exe");
        _domainAnswers["api.example.com"] = new[] { "203.0.113.44" };
        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var fw = Client(channel);

        var ack = await fw.CreateDomainFirewallRuleAsync(new DomainFirewallRuleRequest
        {
            Domain = "api.example.com",
            ProgramPath = program,
        });

        ack.Ok.Should().BeTrue();
        var ruleName = _fw.Rules.Keys.Single(k => k.StartsWith("HG_Domain_api_example_com_", StringComparison.Ordinal));
        _fw.Rules[ruleName].Program.Should().Be(program);
        _fw.Rules[ruleName].RemoteAddr.Should().Be("203.0.113.44");

        var rules = await fw.ListDomainFirewallRulesAsync(new Empty());
        rules.Rules.Should().ContainSingle(r =>
            r.RuleName == ruleName &&
            r.Domain == "api.example.com" &&
            r.Program == program &&
            r.RemoteAddr == "203.0.113.44");

        var explanation = await fw.ExplainDecisionAsync(new DecisionExplainRequest
        {
            Domain = "api.example.com",
            RemoteAddr = "203.0.113.44",
            ProgramPath = program,
        });

        explanation.Verdict.Should().Be("Blocked");
        explanation.Steps.Should().Contain(s => s.Layer == "Domain firewall" && s.Owner == ruleName);
    }

    [Fact]
    public async Task RememberResolution_refreshes_domain_firewall_remote_addresses()
    {
        var program = Path.Combine(_dir, "browser.exe");
        _domainAnswers["api.example.com"] = new[] { "203.0.113.44" };
        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var fw = Client(channel);
        await fw.CreateDomainFirewallRuleAsync(new DomainFirewallRuleRequest
        {
            Domain = "api.example.com",
            ProgramPath = program,
        });
        var ruleName = _fw.Rules.Keys.Single(k => k.StartsWith("HG_Domain_api_example_com_", StringComparison.Ordinal));

        _state.RememberResolution("api.example.com", new[] { "203.0.113.56", "203.0.113.55" });

        _fw.Rules[ruleName].RemoteAddr.Should().Be("203.0.113.55,203.0.113.56");
        _state.Db.ListDomainFirewallRules().Single(r => r.RuleName == ruleName).RemoteAddr
            .Should().Be("203.0.113.55,203.0.113.56");
    }

    [Fact]
    public async Task CreateDomainFirewallRule_rejects_global_domain_blocks_without_program_path()
    {
        using var channel = NamedPipeChannel.Create(_token, _pipe);

        var ack = await Client(channel).CreateDomainFirewallRuleAsync(new DomainFirewallRuleRequest
        {
            Domain = "api.example.com",
        });

        ack.Ok.Should().BeFalse();
        ack.ErrorCode.Should().Be("hostsguard.error.v1/invalid_program");
        _fw.Rules.Should().BeEmpty();
        _state.Db.ListDomainFirewallRules().Should().BeEmpty();
    }

    [Fact]
    public async Task LanAttackSurface_toggle_creates_reversible_registry_and_firewall_controls()
    {
        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var fw = Client(channel);

        var initial = await fw.GetLanAttackSurfaceAsync(new Empty());
        initial.Toggles.Should().HaveCount(6);
        initial.Toggles.Should().Contain(t => t.Key == "mdns" && !t.Blocked && t.BreakNote.Contains("AirPrint", StringComparison.Ordinal));

        var blockMdns = await fw.SetLanAttackSurfaceAsync(new LanAttackSurfaceRequest { Key = "mdns", Blocked = true });
        blockMdns.Ok.Should().BeTrue();
        _lan.Blocked.Should().Contain("mdns");
        _fw.Rules["HG_LAN_MDNS_In"].LocalPorts.Should().Be("5353");
        _fw.Rules["HG_LAN_MDNS_In"].RemoteAddr.Should().Be("LocalSubnet");
        _fw.Rules["HG_LAN_MDNS_Out"].RemotePorts.Should().Be("5353");
        _state.Db.GetFwStateNames().Should().Contain("HG_LAN_MDNS_In");
        _state.Db.GetFwStateNames().Should().Contain("HG_LAN_MDNS_Out");

        var blockSmb = await fw.SetLanAttackSurfaceAsync(new LanAttackSurfaceRequest { Key = "inbound-smb", Blocked = true });
        blockSmb.Ok.Should().BeTrue();
        _fw.Rules["HG_LAN_SMB_In"].Direction.Should().Be("In");
        _fw.Rules["HG_LAN_SMB_In"].LocalPorts.Should().Be("139,445");
        _fw.Rules["HG_LAN_SMB_In"].RemoteAddr.Should().Be("Any");

        (await fw.GetLanAttackSurfaceAsync(new Empty())).Toggles
            .Should().Contain(t => t.Key == "mdns" && t.Blocked && t.Status == "Blocked");

        var unblock = await fw.SetLanAttackSurfaceAsync(new LanAttackSurfaceRequest { Key = "mdns", Blocked = false });
        unblock.Ok.Should().BeTrue();
        _lan.Blocked.Should().NotContain("mdns");
        _fw.Rules.Should().NotContainKey("HG_LAN_MDNS_In");
        _fw.Rules.Should().NotContainKey("HG_LAN_MDNS_Out");
    }

    [Fact]
    public async Task LanAttackSurface_rejects_unknown_toggle()
    {
        using var channel = NamedPipeChannel.Create(_token, _pipe);

        var ack = await Client(channel).SetLanAttackSurfaceAsync(new LanAttackSurfaceRequest { Key = "bogus", Blocked = true });

        ack.Ok.Should().BeFalse();
        ack.ErrorCode.Should().Be("hostsguard.error.v1/invalid_lan_surface");
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
    public async Task Rule_analysis_filters_findings_and_cleanup_requires_unchanged_preview_binding()
    {
        _fw.ActiveInboundProfiles.Add(new InboundFirewallProfile("Public", true, true));
        _fw.LocalPolicyModifyState = FirewallLocalPolicyModifyState.GroupPolicyOverride;
        _fw.Rules["System DNS"] = AnalysisRule("System DNS", "system");
        _fw.Rules["HG_DuplicateDns"] = AnalysisRule("HG_DuplicateDns", "hostsguard");
        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var client = Client(channel);

        var analysis = await client.AnalyzeRulesAsync(new FirewallRuleAnalysisRequest
        {
            Kind = "exact_duplicate",
            CleanupEligibleOnly = true,
        });

        analysis.AnalysisHash.Should().HaveLength(64);
        analysis.LocalPolicyModifyState.Should().Be("group_policy_override");
        analysis.ActiveProfiles.Should().Equal("Public");
        analysis.RulesAnalyzed.Should().Be(2);
        analysis.Findings.Should().ContainSingle(finding =>
            finding.RuleName == "HG_DuplicateDns" && finding.RelatedRuleName == "System DNS" &&
            finding.CleanupEligible && finding.Remediation == "delete_duplicate");

        var unsafePreview = await client.ApplyRuleCleanupAsync(new FirewallRuleCleanupRequest
        {
            Preview = true,
            AnalysisHash = analysis.AnalysisHash,
            SelectedNames = { "System DNS" },
        });
        unsafePreview.Ok.Should().BeFalse();
        unsafePreview.ErrorCode.Should().EndWith("/unsafe_selection");
        unsafePreview.RejectedNames.Should().Equal("System DNS");

        var preview = await client.ApplyRuleCleanupAsync(new FirewallRuleCleanupRequest
        {
            Preview = true,
            AnalysisHash = analysis.AnalysisHash,
            SelectedNames = { "HG_DuplicateDns" },
        });
        preview.Ok.Should().BeTrue();
        preview.PreviewHash.Should().HaveLength(64);
        _fw.Rules.Should().ContainKey("HG_DuplicateDns");

        _fw.Rules["Unrelated"] = AnalysisRule("Unrelated", "system") with { LocalPorts = "8443" };
        var stale = await client.ApplyRuleCleanupAsync(new FirewallRuleCleanupRequest
        {
            AnalysisHash = analysis.AnalysisHash,
            PreviewHash = preview.PreviewHash,
            SelectedNames = { "HG_DuplicateDns" },
        });
        stale.Ok.Should().BeFalse();
        stale.ErrorCode.Should().EndWith("/analysis_changed");
        _fw.Rules.Should().ContainKey("HG_DuplicateDns");

        _fw.Rules.Remove("Unrelated");
        analysis = await client.AnalyzeRulesAsync(new FirewallRuleAnalysisRequest());
        preview = await client.ApplyRuleCleanupAsync(new FirewallRuleCleanupRequest
        {
            Preview = true,
            AnalysisHash = analysis.AnalysisHash,
            SelectedNames = { "HG_DuplicateDns" },
        });
        var applied = await client.ApplyRuleCleanupAsync(new FirewallRuleCleanupRequest
        {
            AnalysisHash = analysis.AnalysisHash,
            PreviewHash = preview.PreviewHash,
            SelectedNames = { "HG_DuplicateDns" },
        });

        applied.Ok.Should().BeTrue();
        applied.Deleted.Should().Be(1);
        _fw.Rules.Should().ContainKey("System DNS").And.NotContainKey("HG_DuplicateDns");
    }

    [Fact]
    public async Task Rule_cleanup_rolls_back_live_deletes_when_selected_batch_cannot_complete()
    {
        _fw.Rules["System DNS"] = AnalysisRule("System DNS", "system");
        _fw.Rules["HG_DuplicateA"] = AnalysisRule("HG_DuplicateA", "hostsguard");
        _fw.Rules["HG_DuplicateB"] = AnalysisRule("HG_DuplicateB", "hostsguard");
        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var client = Client(channel);
        var analysis = await client.AnalyzeRulesAsync(new FirewallRuleAnalysisRequest());
        var singlePreview = await client.ApplyRuleCleanupAsync(new FirewallRuleCleanupRequest
        {
            Preview = true,
            AnalysisHash = analysis.AnalysisHash,
            SelectedNames = { "HG_DuplicateA" },
        });
        var selectionMismatch = await client.ApplyRuleCleanupAsync(new FirewallRuleCleanupRequest
        {
            AnalysisHash = analysis.AnalysisHash,
            PreviewHash = singlePreview.PreviewHash,
            SelectedNames = { "HG_DuplicateA", "HG_DuplicateB" },
        });
        selectionMismatch.Ok.Should().BeFalse();
        selectionMismatch.ErrorCode.Should().EndWith("/preview_mismatch");
        _fw.Rules.Should().ContainKey("HG_DuplicateA").And.ContainKey("HG_DuplicateB");

        var preview = await client.ApplyRuleCleanupAsync(new FirewallRuleCleanupRequest
        {
            Preview = true,
            AnalysisHash = analysis.AnalysisHash,
            SelectedNames = { "HG_DuplicateA", "HG_DuplicateB" },
        });
        _fw.DeleteFailures.Add("HG_DuplicateB");

        var applied = await client.ApplyRuleCleanupAsync(new FirewallRuleCleanupRequest
        {
            AnalysisHash = analysis.AnalysisHash,
            PreviewHash = preview.PreviewHash,
            SelectedNames = { "HG_DuplicateA", "HG_DuplicateB" },
        });

        applied.Ok.Should().BeFalse();
        applied.ErrorCode.Should().EndWith("/delete_failed");
        _fw.Rules.Should().ContainKey("HG_DuplicateA").And.ContainKey("HG_DuplicateB");
    }

    private static FwRule AnalysisRule(string name, string source) => new(
        name, "In", "Allow", true, "Any", "TCP", @"C:\Apps\dns.exe", source,
        LocalPorts: "53", Profiles: "Public");

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
