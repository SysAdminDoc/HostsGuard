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
/// NET-089 portable-policy export/import: a full snapshot round-trips to JSON and
/// reconstructs domains, HG_ firewall rules, schedules, profiles, the settings
/// lock, network profiles, and subscriptions on a clean machine — idempotently.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class PolicyPortabilityTests : IDisposable
{
    private readonly List<string> _dirs = new();

    private (ServiceState State, FakeFirewallEngine Fw) NewMachine()
    {
        var dir = Path.Combine(Path.GetTempPath(), "hg_pol_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        _dirs.Add(dir);
        var hostsPath = Path.Combine(dir, "hosts");
        File.WriteAllText(hostsPath, "# hosts\n");
        var fw = new FakeFirewallEngine();
        var state = new ServiceState(
            new HostsEngine(hostsPath),
            new HostsDatabase(Path.Combine(dir, "hostsguard.db")),
            firewall: fw,
            dataDir: dir);
        return (state, fw);
    }

    private (ServiceState State, FakeFirewallEngine Fw, FakeLanAttackSurfaceStore Lan) NewMachineWithLan()
    {
        var dir = Path.Combine(Path.GetTempPath(), "hg_pol_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        _dirs.Add(dir);
        var hostsPath = Path.Combine(dir, "hosts");
        File.WriteAllText(hostsPath, "# hosts\n");
        var fw = new FakeFirewallEngine();
        var lan = new FakeLanAttackSurfaceStore();
        var state = new ServiceState(
            new HostsEngine(hostsPath),
            new HostsDatabase(Path.Combine(dir, "hostsguard.db")),
            firewall: fw,
            dataDir: dir,
            lanSurfaceStore: lan);
        return (state, fw, lan);
    }

    [Fact]
    public void Export_import_reconstructs_every_section_on_a_clean_machine()
    {
        var (src, srcFw) = NewMachine();

        // Populate a rich policy on the source machine.
        src.Hosts.Block("ads.example.com");
        src.Db.AddDomain("ads.example.com", "blocked", "manual");
        src.Db.SetCategory("ads.example.com", "Advertising");
        src.Db.SetNotes("ads.example.com", "known ad host");
        src.Db.AddDomain("safe.example.com", "whitelisted", "manual");

        new FirewallControlServiceImpl(src).CreateRule(new FirewallRule
        {
            Name = "HG_BlockApp_evil_Out",
            Direction = "Out",
            Action = "Block",
            Enabled = true,
            RemoteAddr = "Any",
            Protocol = "Any",
            Program = @"C:\evil\evil.exe",
        }, TestContext());
        src.Db.UpsertDomainFirewallRule(
            "api.example.com",
            @"C:\Browser\browser.exe",
            "HG_Domain_api_example_com_ABCDEF123456",
            "Block",
            enabled: true,
            remoteAddr: "203.0.113.44");

        src.Db.SetSchedules(new[] { ("games.example.com", "5,6", "22:00", "23:59") });
        src.Db.AddDomain("work.example.com", "blocked", "manual");
        src.Db.SaveProfile("Work");
        src.Db.SetNetworkProfile("gw-mac-abc", "Work", "Home Wi-Fi");
        src.Db.UpsertBlocklistSub("StevenBlack", "https://example.com/hosts", 1000);
        src.Db.SetAllowlistSubs(new[] { "https://example.com/allow.txt" });
        src.Db.SetMeta("history_retention_days", "45");
        src.Lock.Enable("s3cret");

        // Export → JSON → parse (proves the wire shape survives).
        var exported = PolicyPortability.Export(src);
        var json = exported.ToJson();
        var policy = PortablePolicy.FromJson(json);
        policy.Version.Should().Be(PortablePolicy.CurrentVersion);
        policy.FirewallRules.Should().NotContain(r => r.Name.StartsWith("HG_Domain_", StringComparison.Ordinal));
        policy.DomainFirewallRules.Should().ContainSingle(r => r.Domain == "api.example.com");

        // Import onto a fresh, empty machine.
        var (dst, dstFw) = NewMachine();
        var summary = PolicyPortability.Import(dst, policy);
        summary.Should().NotBeEmpty();

        dst.Db.GetDomainStatus("ads.example.com").Should().Be("blocked");
        dst.Db.GetDomainStatus("safe.example.com").Should().Be("whitelisted");
        dst.Db.GetDomains(status: "blocked").Should().Contain(d => d.Domain == "ads.example.com" && d.Category == "Advertising" && d.Notes == "known ad host");
        dst.Hosts.GetBlocked().Should().Contain("ads.example.com");

        dstFw.Rules.Should().ContainKey("HG_BlockApp_evil_Out");
        dstFw.Rules["HG_BlockApp_evil_Out"].Program.Should().Be(@"C:\evil\evil.exe");
        dst.Db.ListDomainFirewallRules().Should().ContainSingle(r =>
            r.RuleName == "HG_Domain_api_example_com_ABCDEF123456" &&
            r.Program == @"C:\Browser\browser.exe" &&
            r.RemoteAddr == "203.0.113.44");
        dstFw.Rules.Should().ContainKey("HG_Domain_api_example_com_ABCDEF123456");

        dst.Db.GetSchedules().Should().ContainSingle(s => s.Target == "games.example.com" && s.Start == "22:00");
        dst.Db.ListProfiles().Should().Contain("Work");
        dst.Db.LoadProfile("Work").Should().Contain(r => r.Domain == "work.example.com");
        dst.Db.GetNetworkProfiles().Should().Contain(n => n.Fingerprint == "gw-mac-abc" && n.Profile == "Work");
        dst.Db.GetBlocklistSubs().Should().Contain(b => b.Name == "StevenBlack");
        dst.Db.GetAllowlistSubs().Should().Contain("https://example.com/allow.txt");
        dst.Db.GetMeta("history_retention_days").Should().Be("45");
        dst.Lock.Enabled.Should().BeTrue();
    }

    [Fact]
    public void Export_import_carries_non_secret_mutable_policy_state()
    {
        var (src, srcFw) = NewMachine();
        using var srcKillSwitch = new KillSwitchMonitor(srcFw, src.Db, _ => true, src.DataDir);
        src.KillSwitch = srcKillSwitch;

        src.Consent.SetMode(ConsentBroker.ModeNotify);
        src.Consent.SetChildInherit(true);
        src.Consent.SetInboundConsent(true);
        src.Consent.SetTrustedPublishers(new[] { "Acme Corp" });
        src.Consent.SetTrustedFolders(new[] { @"C:\Tools" });
        src.CnameCloak.SetEnabled(true);
        src.Db.SetMeta("sni_capture", "on");
        src.Doh.Import(new DohState
        {
            Updated = "2026-07-07T00:00:00.0000000Z",
            Source = "test-list",
            Sha256 = "abc123",
            Ips = { "9.9.9.9" },
        });
        var fw = new FirewallControlServiceImpl(src);
        fw.BlockQuic(new Empty(), TestContext());
        fw.BlockEncryptedDns(new DohBlockRequest(), TestContext());
        srcKillSwitch.Configure(true, "WireGuard");
        src.FlowTeardown.Enabled = true;

        src.Ai.SaveSettings("sk-secret", "test-model", "https://api.example.test", enabled: true);
        src.Db.SetMeta("ai_last_run", "2026-07-07T01:00:00.0000000Z");
        src.Db.SetMeta("ai_last_result", "categorized 1 domains");
        src.Db.SetMeta("ai_knowledge_reviewed_at", "2026-07-07T02:00:00.0000000Z");
        src.Db.UpsertAiKnowledge("purpose", "ads.example.com", "Ad delivery", "test-model");
        src.Db.UpsertUserOverride("category", "ads.example.com", "Advertising");
        src.Webhooks.Urls.Add("https://1.1.1.1/hook");
        src.Webhooks.Secret = "webhook-secret";
        src.Webhooks.Save(src.DataDir);

        var json = PolicyPortability.Export(src).ToJson();
        json.Should().NotContain("sk-secret").And.NotContain("webhook-secret");
        var policy = PortablePolicy.FromJson(json);
        policy.Ai!.ApiKeyConfigured.Should().BeTrue();
        policy.Webhooks!.SecretConfigured.Should().BeTrue();

        var (dst, dstFw) = NewMachine();
        using var dstKillSwitch = new KillSwitchMonitor(dstFw, dst.Db, _ => true, dst.DataDir);
        dst.KillSwitch = dstKillSwitch;

        var summary = PolicyPortability.Import(dst, policy);

        summary.Should().Contain(s => s.Contains("API key omitted", StringComparison.Ordinal));
        summary.Should().Contain(s => s.Contains("secret omitted", StringComparison.Ordinal));
        dst.Consent.Mode.Should().Be(ConsentBroker.ModeNotify);
        dst.Consent.ChildInherit.Should().BeTrue();
        dst.Consent.InboundConsent.Should().BeTrue();
        dst.Consent.TrustedPublishers.Should().ContainSingle().Which.Should().Be("Acme Corp");
        dst.Consent.TrustedFolders.Should().ContainSingle().Which.Should().Be(@"C:\Tools");
        dst.CnameCloak.Enabled.Should().BeTrue();
        dst.Db.GetMeta("sni_capture").Should().Be("on");
        dst.Doh.Load().Ips.Should().Contain("9.9.9.9");
        dstFw.Rules.Should().ContainKey(FirewallControlServiceImpl.QuicRuleName);
        dstFw.Rules.Should().ContainKey("HG_DoT_TCP");
        dst.KillSwitch!.Enabled.Should().BeTrue();
        dst.KillSwitch.Adapter.Should().Be("WireGuard");
        dst.FlowTeardown.Enabled.Should().BeTrue();

        dst.Ai.Settings.Should().Be(new AiSettings(string.Empty, "test-model", "https://api.example.test", true));
        dst.Db.GetMeta("ai_last_result").Should().Be("categorized 1 domains");
        dst.Db.GetMeta("ai_knowledge_reviewed_at").Should().Be("2026-07-07T02:00:00.0000000Z");
        dst.Db.GetAiKnowledge("purpose", new[] { "ads.example.com" })["ads.example.com"].Should().Be("Ad delivery");
        dst.Db.GetUserOverride("category", "ads.example.com").Should().Be("Advertising");
        dst.Webhooks.Urls.Should().ContainSingle().Which.Should().Be("https://1.1.1.1/hook");
        dst.Webhooks.Secret.Should().BeEmpty();
    }

    [Fact]
    public void Import_is_idempotent()
    {
        var (src, _) = NewMachine();
        src.Hosts.Block("a.example.com");
        src.Db.AddDomain("a.example.com", "blocked", "manual");
        new FirewallControlServiceImpl(src).CreateRule(new FirewallRule { Name = "HG_Block_1.2.3.4_Out", Action = "Block", Direction = "Out", RemoteAddr = "1.2.3.4" }, TestContext());

        var policy = PortablePolicy.FromJson(PolicyPortability.Export(src).ToJson());

        var (dst, dstFw) = NewMachine();
        PolicyPortability.Import(dst, policy);
        PolicyPortability.Import(dst, policy); // second apply must not duplicate/diverge.

        dst.Db.GetDomains(status: "blocked").Count(d => d.Domain == "a.example.com").Should().Be(1);
        dst.Hosts.GetBlocked().Count(d => d == "a.example.com").Should().Be(1);
        dstFw.Rules.Keys.Count(k => k == "HG_Block_1.2.3.4_Out").Should().Be(1);
    }

    [Fact]
    public void Export_import_round_trips_lan_attack_surface_toggles()
    {
        var (src, _, srcLan) = NewMachineWithLan();
        src.LanAttackSurface.Set("llmnr", true).Ok.Should().BeTrue();
        src.LanAttackSurface.Set("inbound-smb", true).Ok.Should().BeTrue();
        srcLan.Blocked.Should().Contain("llmnr");

        var policy = PortablePolicy.FromJson(PolicyPortability.Export(src).ToJson());
        policy.LanAttackSurface!.Toggles.Should().Contain(t => t.Key == "llmnr" && t.Blocked);
        policy.LanAttackSurface.Toggles.Should().Contain(t => t.Key == "inbound-smb" && t.Blocked);

        var (dst, dstFw, dstLan) = NewMachineWithLan();
        var summary = PolicyPortability.Import(dst, policy);

        summary.Should().Contain(s => s.Contains("LAN attack-surface", StringComparison.Ordinal));
        dstLan.Blocked.Should().Contain("llmnr");
        dstFw.Rules["HG_LAN_LLMNR_In"].LocalPorts.Should().Be("5355");
        dstFw.Rules["HG_LAN_SMB_In"].LocalPorts.Should().Be("139,445");
    }

    [Fact]
    public async Task ExportPolicy_and_ImportPolicy_round_trip_over_grpc()
    {
        var (src, _) = NewMachine();
        src.Hosts.Block("rpc.example.com");
        src.Db.AddDomain("rpc.example.com", "blocked", "manual");

        var token = SessionToken.Generate();
        var pipe = "HostsGuard.PolTest." + Guid.NewGuid().ToString("N");
        var app = ServiceHost.Build(src, token, pipe);
        await app.StartAsync();
        try
        {
            using var channel = NamedPipeChannel.Create(token, pipe);
            var policyClient = new Policy.PolicyClient(channel);
            var doc = await policyClient.ExportPolicyAsync(new Empty());
            doc.Json.Should().Contain("rpc.example.com");

            var (dst, _) = NewMachine();
            var dstToken = SessionToken.Generate();
            var dstPipe = "HostsGuard.PolTest2." + Guid.NewGuid().ToString("N");
            var dstApp = ServiceHost.Build(dst, dstToken, dstPipe);
            await dstApp.StartAsync();
            try
            {
                using var dstChannel = NamedPipeChannel.Create(dstToken, dstPipe);
                var result = await new Policy.PolicyClient(dstChannel).ImportPolicyAsync(new ImportPolicyRequest { Json = doc.Json });
                result.Ok.Should().BeTrue();
                result.Summary.Should().NotBeEmpty();
                dst.Db.GetDomainStatus("rpc.example.com").Should().Be("blocked");
            }
            finally
            {
                await dstApp.DisposeAsync();
            }
        }
        finally
        {
            await app.DisposeAsync();
        }
    }

    [Fact]
    public void Malformed_policy_json_throws_a_readable_error()
    {
        var act = () => PortablePolicy.FromJson("{ not valid json");
        act.Should().Throw<System.Text.Json.JsonException>();
    }

    private static Grpc.Core.ServerCallContext TestContext() => null!;

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        foreach (var dir in _dirs)
        {
            try { Directory.Delete(dir, true); } catch (IOException) { /* best effort */ }
        }
    }
}
