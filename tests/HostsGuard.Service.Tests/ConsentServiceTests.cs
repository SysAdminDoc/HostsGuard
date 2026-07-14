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

/// <summary>
/// WFC-parity consent loop (WFCP-010/012/020/021/022): dedup + trust checks,
/// learning auto-allow, decision → rule write with identity, once-rule reaping,
/// pending timeout, posture rails on mode switches, and persistence across
/// broker restarts — over the real pipe transport where it matters.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class ConsentServiceTests : IAsyncLifetime
{
    private string _dir = null!;
    private WebApplication _app = null!;
    private ServiceState _state = null!;
    private FakeFirewallEngine _fw = null!;
    private TestClock _clock = null!;
    private string _pipe = null!;
    private string _token = null!;

    public async Task InitializeAsync()
    {
        _dir = Path.Combine(Path.GetTempPath(), "hg_consent_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        var hostsPath = Path.Combine(_dir, "hosts");
        File.WriteAllText(hostsPath, "# hosts\n");

        _fw = new FakeFirewallEngine();
        _clock = new TestClock(DateTime.UtcNow);
        _state = new ServiceState(
            new HostsEngine(hostsPath),
            new HostsDatabase(Path.Combine(_dir, "hostsguard.db")),
            _fw,
            new FirewallIdentity(Path.Combine(_dir, "fw_identities.json")),
            dataDir: _dir,
            clock: _clock);
        _token = SessionToken.Generate();
        _pipe = "HostsGuard.ConsentTest." + Guid.NewGuid().ToString("N");
        _app = ServiceHost.Build(_state, _token, _pipe);
        await _app.StartAsync();
    }

    public async Task DisposeAsync()
    {
        await _app.DisposeAsync();
        _state.Dispose();
        try { Directory.Delete(_dir, true); } catch (IOException) { /* best effort */ }
    }

    private string WriteExe(string name)
    {
        var path = Path.Combine(_dir, name);
        File.WriteAllText(path, "binary " + name);
        return path;
    }

    private static BlockedConnection Blocked(
        string app,
        DateTime tsUtc,
        string direction = "Out",
        string remote = "203.0.113.7",
        string protocol = "TCP",
        string filterOrigin = "",
        int interfaceIndex = 0,
        string interfaceName = "",
        string localAddress = "",
        int localPort = 0)
        => new(
            tsUtc,
            app,
            direction,
            remote,
            443,
            protocol,
            4711,
            5157,
            "67338",
            filterOrigin,
            "%%14611",
            "48",
            interfaceIndex,
            interfaceName,
            localAddress,
            localPort);

    [Fact]
    public void Normal_mode_drops_everything_and_notify_dedups_bursts()
    {
        var now = DateTime.UtcNow;
        _state.Consent.OnBlocked(Blocked(@"C:\apps\a.exe", now));
        _state.Consent.PendingCount.Should().Be(0); // normal mode: no prompts

        _state.Consent.SetMode("notify").Ok.Should().BeTrue();
        _state.Consent.OnBlocked(Blocked(@"C:\apps\a.exe", now));
        _state.Consent.OnBlocked(Blocked(@"C:\apps\a.exe", now.AddSeconds(2)));  // burst dup
        _state.Consent.OnBlocked(Blocked(@"C:\apps\a.exe", now.AddSeconds(10))); // outside window
        _state.Consent.OnBlocked(Blocked(@"C:\apps\b.exe", now.AddSeconds(2)));  // distinct app

        _state.Consent.PendingCount.Should().Be(3);
    }

    [Fact]
    public void Baseline_os_binary_is_auto_allowed_never_prompted()
    {
        _state.Consent.SetMode("notify");
        using var sub = _state.Bus.Subscribe<ConnectionDecisionRequest>();

        _state.Consent.OnBlocked(Blocked(@"C:\Windows\System32\MoUsoCoreWorker.exe", DateTime.UtcNow));

        _state.Consent.PendingCount.Should().Be(0); // never prompted
        _fw.Rules.Keys.Should().Contain(k => k.StartsWith("HG_Base_MoUsoCoreWorker_"));
        _fw.Rules.Values.Should().Contain(r => r.Action == "Allow" && r.Program.EndsWith("MoUsoCoreWorker.exe"));
        sub.Reader.TryRead(out _).Should().BeFalse(); // no decision request published
    }

    [Fact]
    public async Task Baseline_is_inspectable_and_appliable_over_the_pipe()
    {
        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var consent = new Consent.ConsentClient(channel);

        var list = await consent.GetBaselineAsync(new Empty());
        list.Items.Should().HaveCount(HostsGuard.Core.KnownSafeBaseline.Entries.Count);
        list.Items.Should().Contain(i => i.FileName == "System");

        (await consent.ApplyBaselineAsync(new Empty())).Ok.Should().BeTrue();
    }

    [Fact]
    public void Covering_rule_checks_reuse_one_cached_snapshot_across_a_burst()
    {
        _state.Consent.SetMode("notify");
        var app = WriteExe("burst.exe");
        var before = _fw.ListRulesCalls;
        var now = DateTime.UtcNow;

        // Three blocked events outside the dedup window each run the
        // covering-rule check; the COM-expensive enumeration must run once.
        _state.Consent.OnBlocked(Blocked(app, now));
        _state.Consent.OnBlocked(Blocked(app, now.AddSeconds(10)));
        _state.Consent.OnBlocked(Blocked(app, now.AddSeconds(20)));

        (_fw.ListRulesCalls - before).Should().Be(1);
    }

    [Fact]
    public void Covering_rule_cache_refreshes_exactly_at_injected_ttl_boundary()
    {
        _state.Consent.SetMode("notify");
        var before = _fw.ListRulesCalls;

        _state.Consent.OnBlocked(Blocked(@"C:\apps\clock-a.exe", _clock.UtcNow));
        _clock.Advance(ConsentBroker.RuleCacheTtl - TimeSpan.FromTicks(1));
        _state.Consent.OnBlocked(Blocked(@"C:\apps\clock-b.exe", _clock.UtcNow));
        (_fw.ListRulesCalls - before).Should().Be(1);

        _clock.Advance(TimeSpan.FromTicks(1));
        _state.Consent.OnBlocked(Blocked(@"C:\apps\clock-c.exe", _clock.UtcNow));
        (_fw.ListRulesCalls - before).Should().Be(2);
    }

    [Fact]
    public void A_fresh_decision_is_visible_to_covering_rule_checks_immediately()
    {
        _state.Consent.SetMode("notify");
        var app = WriteExe("decided.exe");
        var now = DateTime.UtcNow;

        _state.Consent.OnBlocked(Blocked(app, now)); // primes the rule cache (no rule yet)
        _state.Consent.PendingCount.Should().Be(1);

        _state.Consent.Decide(new ConnectionDecision { Application = app, Verdict = "allow", Duration = "always" })
            .Ok.Should().BeTrue();

        // The decision's rule write invalidated the cache, so a follow-up
        // blocked event inside the TTL sees the new rule and never re-prompts.
        // (The original id-less pending stays until its timeout — the point is
        // that no SECOND prompt appears.)
        _state.Consent.OnBlocked(Blocked(app, now.AddSeconds(10)));
        _state.Consent.PendingCount.Should().Be(1);
    }

    [Fact]
    public void Apps_with_a_covering_rule_are_never_reprompted()
    {
        _state.Consent.SetMode("notify");
        var app = WriteExe("ruled.exe");
        _fw.CreateRule(new FwRule("HG_Consent_Allow_ruled_Out", "Out", "Allow", true, "Any", "Any", app, "hostsguard"));

        _state.Consent.OnBlocked(Blocked(app, DateTime.UtcNow));

        _state.Consent.PendingCount.Should().Be(0);
    }

    [Fact]
    public void Renamed_impostor_at_a_whitelisted_path_is_re_prompted()
    {
        var app = WriteExe("realapp.exe");
        // Allow the real binary permanently — this remembers its identity.
        _state.Consent.Decide(new ConnectionDecision { Application = app, Verdict = "allow", Duration = "always" })
            .Ok.Should().BeTrue();
        _state.Identity!.Get("HG_Consent_Allow_realapp_Out").Should().NotBeEmpty();

        _state.Consent.SetMode("notify");
        using var sub = _state.Bus.Subscribe<ConnectionDecisionRequest>();

        // Same path, unchanged binary → covered, no prompt.
        _state.Consent.OnBlocked(Blocked(app, DateTime.UtcNow));
        _state.Consent.PendingCount.Should().Be(0);

        // An impostor overwrites the file at the same whitelisted path.
        File.WriteAllText(app, "malware-different-content");
        _state.Consent.OnBlocked(Blocked(app, DateTime.UtcNow.AddSeconds(10)));

        // Identity no longer matches → the rule doesn't cover it → re-prompted.
        _state.Consent.PendingCount.Should().Be(1);
        _state.Db.GetAlerts(new AlertFilter(Type: "binary_identity")).Rows
            .Should().ContainSingle(a => a.Subject == app && a.Action == "identity_mismatch");
    }

    [Fact]
    public void Notify_publishes_a_decision_request_on_the_bus()
    {
        _state.Consent.SetMode("notify");
        using var sub = _state.Bus.Subscribe<ConnectionDecisionRequest>();

        _state.Consent.OnBlocked(Blocked(@"C:\apps\push.exe", DateTime.UtcNow));

        sub.Reader.TryRead(out var request).Should().BeTrue();
        request!.Application.Should().Be(@"C:\apps\push.exe");
        request.RemoteAddress.Should().Be("203.0.113.7");
        request.Id.Should().NotBeEmpty();
    }

    [Fact]
    public void Notify_publishes_wfp_provenance_and_alerts_external_filters()
    {
        _state.Consent.SetMode("notify");
        _fw.ActiveInboundProfiles.Add(new InboundFirewallProfile("Private", true, true));
        using var sub = _state.Bus.Subscribe<ConnectionDecisionRequest>();

        _state.Consent.OnBlocked(Blocked(
            @"C:\apps\external.exe",
            DateTime.UtcNow,
            filterOrigin: "VendorBlockRule",
            interfaceIndex: 12,
            interfaceName: "Ethernet",
            localAddress: "192.168.1.10",
            localPort: 53117));

        sub.Reader.TryRead(out var request).Should().BeTrue();
        request!.FilterRuntimeId.Should().Be("67338");
        request.FilterOrigin.Should().Be("VendorBlockRule");
        request.LayerName.Should().Be("%%14611");
        request.LayerRuntimeId.Should().Be("48");
        request.InterfaceIndex.Should().Be(12);
        request.InterfaceName.Should().Be("Ethernet");
        request.FilterOwner.Should().Be("External firewall rule");
        request.ExternalFilter.Should().BeTrue();
        request.LocalAddress.Should().Be("192.168.1.10");
        request.LocalPort.Should().Be(53117);
        request.ActiveFirewallProfiles.Should().Equal("Private");

        _state.Db.GetAlerts(new AlertFilter(Type: "wfp_external_filter")).Rows.Should()
            .ContainSingle(a => a.Subject == "VendorBlockRule" && a.Process == @"C:\apps\external.exe");
    }

    [Fact]
    public void Notify_enriches_the_prompt_with_country_threat_and_signer()
    {
        _state.Consent.LookupCountry = _ => "US";
        _state.Consent.LookupThreat = ip => ip == "203.0.113.7";
        _state.Consent.SetMode("notify");
        using var sub = _state.Bus.Subscribe<ConnectionDecisionRequest>();

        _state.Consent.OnBlocked(Blocked(@"C:\apps\enrich.exe", DateTime.UtcNow, remote: "203.0.113.7"));

        sub.Reader.TryRead(out var req).Should().BeTrue();
        req!.Country.Should().Be("US");
        req.Threat.Should().BeTrue();
        req.Signer.Should().NotBeNull(); // best-effort: empty for an unsigned/missing path
    }

    [Fact]
    public void Interpreter_prompt_carries_script_identity_and_allow_is_not_a_broad_interpreter_rule()
    {
        var app = WriteExe("node.exe");
        var script = Path.Combine(_dir, "scraper", "index.js");
        var otherScript = Path.Combine(_dir, "scraper", "other.js");
        Directory.CreateDirectory(Path.GetDirectoryName(script)!);
        _state.Consent.LookupCommandLine = _ => $"\"{app}\" \"{script}\"";
        _state.Consent.SetMode("notify");
        using var sub = _state.Bus.Subscribe<ConnectionDecisionRequest>();
        var now = DateTime.UtcNow;

        _state.Consent.OnBlocked(Blocked(app, now, remote: "203.0.113.44"));

        sub.Reader.TryRead(out var req).Should().BeTrue();
        req!.CommandLine.Should().Be($"node {script}");
        req.ScriptPath.Should().Be(script);
        req.ScriptBindingKey.Should().NotBeEmpty();

        _state.Consent.Decide(new ConnectionDecision
        {
            Id = req.Id,
            Application = req.Application,
            Direction = req.Direction,
            RemoteAddress = req.RemoteAddress,
            RemotePort = req.RemotePort,
            Protocol = req.Protocol,
            Verdict = "allow",
            Duration = "always",
            ScopeCommandLine = true,
            CommandLine = req.CommandLine,
            ScriptPath = req.ScriptPath,
            ScriptBindingKey = req.ScriptBindingKey,
        }).Ok.Should().BeTrue();

        var ruleName = _fw.Rules.Keys.Single(k => k.StartsWith("HG_Cmd_Allow_node_", StringComparison.Ordinal));
        _fw.Rules.Keys.Should().NotContain("HG_Consent_Allow_node_Out");
        _fw.Rules[ruleName].Program.Should().Be(app);
        _fw.Rules[ruleName].RemoteAddr.Should().Be("203.0.113.44");
        _fw.Rules[ruleName].Protocol.Should().Be("TCP");
        _fw.Rules[ruleName].RemotePorts.Should().Be("443");

        _state.Consent.OnBlocked(Blocked(app, now.AddSeconds(10), remote: "203.0.113.44"));
        _state.Consent.PendingCount.Should().Be(0);

        _state.Consent.LookupCommandLine = _ => $"\"{app}\" \"{otherScript}\"";
        _state.Consent.OnBlocked(Blocked(app, now.AddSeconds(20), remote: "203.0.113.44"));
        _state.Consent.PendingCount.Should().Be(1);
    }

    [Fact]
    public void Interpreter_block_is_broker_enforced_without_writing_a_broad_block_rule()
    {
        var app = WriteExe("node.exe");
        var script = Path.Combine(_dir, "job.js");
        _state.Consent.LookupCommandLine = _ => $"\"{app}\" \"{script}\"";
        _state.Consent.SetMode("notify");
        using var sub = _state.Bus.Subscribe<ConnectionDecisionRequest>();
        var now = DateTime.UtcNow;

        _state.Consent.OnBlocked(Blocked(app, now, remote: "203.0.113.45"));

        sub.Reader.TryRead(out var req).Should().BeTrue();
        _state.Consent.Decide(new ConnectionDecision
        {
            Id = req!.Id,
            Application = req.Application,
            Direction = req.Direction,
            RemoteAddress = req.RemoteAddress,
            RemotePort = req.RemotePort,
            Protocol = req.Protocol,
            Verdict = "block",
            Duration = "always",
            ScopeCommandLine = true,
            CommandLine = req.CommandLine,
            ScriptPath = req.ScriptPath,
            ScriptBindingKey = req.ScriptBindingKey,
        }).Ok.Should().BeTrue();

        _fw.Rules.Keys.Should().NotContain(k => k.StartsWith("HG_Consent_Block_node_", StringComparison.Ordinal));
        _fw.Rules.Keys.Should().NotContain(k => k.StartsWith("HG_Cmd_Block_node_", StringComparison.Ordinal));

        _state.Consent.OnBlocked(Blocked(app, now.AddSeconds(10), remote: "203.0.113.99"));
        _state.Consent.PendingCount.Should().Be(0);

        _state.Consent.LookupCommandLine = _ => $"\"{app}\" \"{Path.Combine(_dir, "other.js")}\"";
        _state.Consent.OnBlocked(Blocked(app, now.AddSeconds(20), remote: "203.0.113.99"));
        _state.Consent.PendingCount.Should().Be(1);
    }

    [Fact]
    public void Learning_auto_allows_records_and_remembers_identity()
    {
        _state.Consent.SetMode("learning");
        var app = WriteExe("learned.exe");

        _state.Consent.OnBlocked(Blocked(app, DateTime.UtcNow));

        _state.Consent.PendingCount.Should().Be(0);
        _fw.Rules.Should().ContainKey("HG_Learn_learned_Out");
        _fw.Rules["HG_Learn_learned_Out"].Action.Should().Be("Allow");
        _state.Identity!.Get("HG_Learn_learned_Out").Should().NotBeEmpty();
        _state.Consent.History(10).Entries.Should().Contain(e => e.Application == app && e.Verdict == "learn");
    }

    [Fact]
    public async Task Decide_writes_permanent_rule_with_identity_over_the_pipe()
    {
        var app = WriteExe("decided.exe");
        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var consent = new Consent.ConsentClient(channel);

        var ack = await consent.DecideAsync(new ConnectionDecision
        {
            Application = app,
            Direction = "Out",
            RemoteAddress = "203.0.113.9",
            Protocol = "TCP",
            Verdict = "allow",
            Permanent = true,
        });

        ack.Ok.Should().BeTrue();
        _fw.Rules.Should().ContainKey("HG_Consent_Allow_decided_Out");
        _fw.Rules["HG_Consent_Allow_decided_Out"].RemoteAddr.Should().Be("Any"); // not scoped
        _state.Db.GetFwStateNames().Should().Contain("HG_Consent_Allow_decided_Out");
        _state.Identity!.Get("HG_Consent_Allow_decided_Out").Should().NotBeEmpty();

        var history = await consent.GetDecisionHistoryAsync(new HistoryRequest { Limit = 10 });
        history.Entries.Should().Contain(e => e.Application == app && e.Verdict == "allow" && e.Permanent);
    }

    [Fact]
    public void Pending_decision_history_preserves_wfp_provenance()
    {
        var app = WriteExe("triaged.exe");
        _state.Consent.SetMode("notify");
        using var sub = _state.Bus.Subscribe<ConnectionDecisionRequest>();

        _state.Consent.OnBlocked(Blocked(
            app,
            DateTime.UtcNow,
            filterOrigin: "VendorBlockRule",
            interfaceIndex: 12,
            interfaceName: "Ethernet"));
        sub.Reader.TryRead(out var req).Should().BeTrue();

        _state.Consent.Decide(new ConnectionDecision
        {
            Id = req!.Id,
            Application = req.Application,
            Direction = req.Direction,
            RemoteAddress = req.RemoteAddress,
            RemotePort = req.RemotePort,
            Protocol = req.Protocol,
            Verdict = "block",
            Duration = "always",
        }).Ok.Should().BeTrue();

        _state.Consent.History(10).Entries.Should().ContainSingle(e =>
            e.Application == app &&
            e.Verdict == "block" &&
            e.FilterOrigin == "VendorBlockRule" &&
            e.FilterRuntimeId == "67338" &&
            e.LayerName == "%%14611" &&
            e.LayerRuntimeId == "48" &&
            e.InterfaceIndex == 12 &&
            e.InterfaceName == "Ethernet" &&
            e.FilterOwner == "External firewall rule" &&
            e.ExternalFilter);
    }

    [Fact]
    public void Remote_scoped_decisions_validate_the_address()
    {
        var app = WriteExe("scoped.exe");

        var bad = _state.Consent.Decide(new ConnectionDecision
        {
            Application = app,
            Verdict = "block",
            Permanent = true,
            ScopeRemote = true,
            RemoteAddress = "not-an-ip; Remove-Item",
        });
        bad.ErrorCode.Should().Be("hostsguard.error.v1/invalid_address");

        var good = _state.Consent.Decide(new ConnectionDecision
        {
            Application = app,
            Verdict = "block",
            Permanent = true,
            ScopeRemote = true,
            RemoteAddress = "203.0.113.9",
        });
        good.Ok.Should().BeTrue();
        _fw.Rules["HG_Consent_Block_scoped_Out"].RemoteAddr.Should().Be("203.0.113.9");
    }

    [Fact]
    public void Decision_scopes_the_rule_to_port_and_protocol()
    {
        var app = WriteExe("scoped.exe");

        _state.Consent.Decide(new ConnectionDecision
        {
            Application = app,
            Direction = "Out",
            Verdict = "block",
            Duration = "always",
            Protocol = "TCP",
            RemotePort = 8080,
            ScopePort = true,
            ScopeProtocol = true,
        }).Ok.Should().BeTrue();

        var rule = _fw.Rules["HG_Consent_Block_scoped_Out"];
        rule.Protocol.Should().Be("TCP");
        rule.RemotePorts.Should().Be("8080");
    }

    [Fact]
    public void Duration_1h_reaps_the_rule_after_an_hour_not_before()
    {
        var app = WriteExe("hourly.exe");
        _state.Consent.Decide(new ConnectionDecision { Application = app, Verdict = "allow", Duration = "1h" }).Ok.Should().BeTrue();
        var name = _fw.Rules.Keys.Single(k => k.StartsWith("HG_Once_Allow_hourly_Out_"));

        _state.Consent.Sweep(DateTime.UtcNow + TimeSpan.FromMinutes(30));
        _fw.Rules.Should().ContainKey(name);

        _state.Consent.Sweep(DateTime.UtcNow + TimeSpan.FromHours(1) + TimeSpan.FromMinutes(1));
        _fw.Rules.Should().NotContainKey(name);
    }

    [Fact]
    public void Session_duration_survives_the_timer_but_startup_reaps_it()
    {
        var app = WriteExe("sessioned.exe");
        _state.Consent.Decide(new ConnectionDecision { Application = app, Verdict = "allow", Duration = "session" }).Ok.Should().BeTrue();
        var name = _fw.Rules.Keys.Single(k => k.StartsWith("HG_Once_Allow_sessioned_Out_"));

        _state.Consent.Sweep(DateTime.UtcNow + TimeSpan.FromDays(365)); // never timer-reaped
        _fw.Rules.Should().ContainKey(name);

        // A fresh broker (service restart) reaps all HG_Once_ rules.
        using var restarted = new ConsentBroker(_state.Db, _state.Bus, _fw, _state.Identity, _dir);
        _fw.Rules.Should().NotContainKey(name);
    }

    [Fact]
    public void Once_rules_exist_immediately_and_are_reaped_after_their_window()
    {
        var app = WriteExe("once.exe");

        _state.Consent.Decide(new ConnectionDecision
        {
            Application = app,
            Verdict = "allow",
            Permanent = false,
        }).Ok.Should().BeTrue();

        var onceRule = _fw.Rules.Keys.Single(k => k.StartsWith("HG_Once_Allow_once_Out_"));
        _state.Consent.Sweep(DateTime.UtcNow); // not due yet
        _fw.Rules.Should().ContainKey(onceRule);

        _state.Consent.Sweep(DateTime.UtcNow + ConsentBroker.OnceRuleLifetime + TimeSpan.FromSeconds(1));
        _fw.Rules.Should().NotContainKey(onceRule);
        _state.Db.GetFwStateNames().Should().NotContain(onceRule);
    }

    [Fact]
    public void Pending_prompts_expire_to_a_recorded_timeout()
    {
        _state.Consent.SetMode("notify");
        var now = DateTime.UtcNow;
        _state.Consent.OnBlocked(Blocked(@"C:\apps\slow.exe", now));
        _state.Consent.PendingCount.Should().Be(1);

        _state.Consent.Sweep(now + ConsentBroker.PendingTtl + TimeSpan.FromSeconds(1));

        _state.Consent.PendingCount.Should().Be(0);
        _state.Consent.History(10).Entries.Should().Contain(e =>
            e.Application == @"C:\apps\slow.exe" && e.Verdict == "timeout");
        _fw.Rules.Should().BeEmpty(); // timeout writes no rule — default-deny holds
    }

    [Fact]
    public void Inbound_decisions_create_inbound_rules()
    {
        var app = WriteExe("inbound.exe");

        _state.Consent.Decide(new ConnectionDecision
        {
            Application = app,
            Direction = "In",
            Verdict = "allow",
            Permanent = true,
        }).Ok.Should().BeTrue();

        _fw.Rules.Should().ContainKey("HG_Consent_Allow_inbound_In");
        _fw.Rules["HG_Consent_Allow_inbound_In"].Direction.Should().Be("In");
    }

    [Fact]
    public async Task Mode_rails_set_and_restore_posture_over_the_pipe()
    {
        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var consent = new Consent.ConsentClient(channel);
        _fw.OutboundBlock.Should().BeFalse();

        (await consent.SetModeAsync(new FilteringMode { Mode = "notify" })).Ok.Should().BeTrue();
        _fw.OutboundBlock.Should().BeTrue(); // armed: default-outbound Block
        (await consent.GetModeAsync(new Empty())).Mode.Should().Be("notify");

        (await consent.SetModeAsync(new FilteringMode { Mode = "normal" })).Ok.Should().BeTrue();
        _fw.OutboundBlock.Should().BeFalse(); // prior posture restored

        (await consent.SetModeAsync(new FilteringMode { Mode = "sideways" }))
            .ErrorCode.Should().Be("hostsguard.error.v1/invalid_mode");
    }

    [Fact]
    public void Prior_block_posture_survives_a_notify_round_trip()
    {
        _fw.OutboundBlock = true; // user already ran lockdown before notify

        _state.Consent.SetMode("notify");
        _fw.OutboundBlock.Should().BeTrue();
        _state.Consent.SetMode("normal");

        _fw.OutboundBlock.Should().BeTrue(); // restored to Block, not blindly Allow
    }

    [Fact]
    public void Mixed_prior_posture_round_trips_per_profile()
    {
        // Public=Block, Domain/Private=Allow before arming.
        _fw.SetDefaultOutboundBlock(new Dictionary<string, bool>(StringComparer.Ordinal)
        {
            ["Domain"] = false,
            ["Private"] = false,
            ["Public"] = true,
        });

        _state.Consent.SetMode("notify");   // arms: all profiles → Block
        _fw.PerProfileBlock.Values.Should().OnlyContain(v => v);

        _state.Consent.SetMode("normal");   // must restore the exact mix, not collapse

        _fw.PerProfileBlock["Domain"].Should().BeFalse();
        _fw.PerProfileBlock["Private"].Should().BeFalse();
        _fw.PerProfileBlock["Public"].Should().BeTrue();
    }

    [Fact]
    public void Mode_persists_and_resume_rearms_detection()
    {
        _state.Consent.SetMode("notify");

        using var restarted = new ConsentBroker(_state.Db, _state.Bus, _fw, _state.Identity, _dir);
        restarted.Mode.Should().Be("notify");

        var armed = false;
        restarted.ArmDetection = () => armed = true;
        restarted.ResumeFromPersistedMode();
        armed.Should().BeTrue();
        restarted.DetectionArmed.Should().BeTrue();
    }

    [Fact]
    public void Shutdown_restores_posture_but_keeps_mode_for_restart()
    {
        _fw.OutboundBlock.Should().BeFalse();
        _state.Consent.SetMode("notify");
        _fw.OutboundBlock.Should().BeTrue(); // armed

        _state.Consent.RestorePostureOnShutdown();

        _fw.OutboundBlock.Should().BeFalse(); // posture restored on stop
        _state.Consent.Mode.Should().Be("notify"); // mode persists

        // A fresh broker over the same state re-arms (crash/restart path).
        using var restarted = new ConsentBroker(_state.Db, _state.Bus, _fw, _state.Identity, _dir);
        restarted.ArmDetection = () => true;
        restarted.ResumeFromPersistedMode();
        restarted.Mode.Should().Be("notify");
    }

    [Fact]
    public void Shutdown_restore_is_a_noop_in_normal_mode()
    {
        _fw.OutboundBlock = true; // user's own lockdown, unrelated to consent
        _state.Consent.RestorePostureOnShutdown();
        _fw.OutboundBlock.Should().BeTrue(); // untouched
    }

    [Fact]
    public void Startup_reaps_leftover_once_rules_from_a_prior_run()
    {
        var app = WriteExe("stale.exe");
        _fw.CreateRule(new FwRule("HG_Once_Allow_stale_Out_deadbeef", "Out", "Allow", true, "Any", "Any", app, "hostsguard"));
        _state.Db.UpsertFwState("HG_Once_Allow_stale_Out_deadbeef", "Out", "Allow", "Any", "Any", app);

        using var restarted = new ConsentBroker(_state.Db, _state.Bus, _fw, _state.Identity, _dir);

        _fw.Rules.Should().NotContainKey("HG_Once_Allow_stale_Out_deadbeef");
        _state.Db.GetFwStateNames().Should().NotContain("HG_Once_Allow_stale_Out_deadbeef");
    }
}
