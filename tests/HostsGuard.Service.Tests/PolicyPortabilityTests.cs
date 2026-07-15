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
    private readonly List<ServiceState> _states = new();

    private (ServiceState State, FakeFirewallEngine Fw) NewMachine(IDnsConfig? dns = null)
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
            dns: dns,
            dataDir: dir);
        _states.Add(state);
        return (state, fw);
    }

    private (ServiceState State, FakeFirewallEngine Fw, FakeListFetcher Fetcher) NewMachineWithFetcher()
    {
        var dir = Path.Combine(Path.GetTempPath(), "hg_pol_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        _dirs.Add(dir);
        var hostsPath = Path.Combine(dir, "hosts");
        File.WriteAllText(hostsPath, "# hosts\n");
        var fw = new FakeFirewallEngine();
        var fetcher = new FakeListFetcher();
        var state = new ServiceState(
            new HostsEngine(hostsPath),
            new HostsDatabase(Path.Combine(dir, "hostsguard.db")),
            firewall: fw,
            dataDir: dir,
            listFetcher: fetcher);
        _states.Add(state);
        return (state, fw, fetcher);
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
        _states.Add(state);
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
        srcFw.Packages.Add(new FwAppPackage(
            "Contoso.Reader_123abc",
            "S-1-15-2-123",
            "Contoso Reader",
            "Contoso.Reader_1.0.0.0_x64__123abc",
            @"C:\Program Files\WindowsApps\Contoso.Reader\reader.exe"));
        new FirewallControlServiceImpl(src).CreateRule(new FirewallRule
        {
            Name = "HG_Package_Block_Contoso_Reader_Out",
            Direction = "Out",
            Action = "Block",
            Enabled = true,
            RemoteAddr = "Any",
            Protocol = "Any",
            PackageFamilyName = "Contoso.Reader_123abc",
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
        src.Db.UpsertBlocklistSub("StevenBlack", "https://example.com/hosts", 1000,
            mirrors: ["https://1.1.1.1/hosts", "https://8.8.8.8/hosts"]);
        src.Db.UpsertIpBlocklistSource(
            "hagezi-doh-ips", "https://example.com/doh-ips.txt",
            new[] { "1.2.3.4", "203.0.113.0/24" }, "hash-a", "", 0,
            Array.Empty<string>(), ruleCount: 1, truncated: false);
        src.Db.SetIpBlocklistEnabled("hagezi-doh-ips", false);
        src.Db.SetAllowlistSubs(new[] { "https://example.com/allow.txt" });
        src.Db.SetMeta("history_retention_days", "45");
        src.Lock.Enable("s3cret");

        // Export → JSON → parse (proves the wire shape survives).
        var exported = PolicyPortability.Export(src);
        var json = exported.ToJson();
        json.Should().NotContain("\"Hash\"").And.NotContain("pbkdf2_sha256");
        var policy = PortablePolicy.FromJson(json);
        policy.Version.Should().Be(PortablePolicy.CurrentVersion);
        policy.Lock.Enabled.Should().BeTrue();
        policy.Lock.LegacyHash.Should().BeNull();
        policy.FirewallRules.Should().NotContain(r => r.Name.StartsWith("HG_Domain_", StringComparison.Ordinal));
        policy.FirewallRules.Should().ContainSingle(r =>
            r.Name == "HG_Package_Block_Contoso_Reader_Out" &&
            r.PackageFamilyName == "Contoso.Reader_123abc" &&
            r.PackageSid == "S-1-15-2-123" &&
            r.PackageDisplayName == "Contoso Reader");
        policy.DomainFirewallRules.Should().ContainSingle(r => r.Domain == "api.example.com");

        // Import onto a fresh, empty machine.
        var (dst, dstFw) = NewMachine();
        var summary = PolicyPortability.Import(dst, policy);
        summary.Should().NotBeEmpty();
        summary[0].Should().Contain("credential omitted", "CLI and bounded WPF summaries must surface the omission");

        dst.Db.GetDomainStatus("ads.example.com").Should().Be("blocked");
        dst.Db.GetDomainStatus("safe.example.com").Should().Be("whitelisted");
        dst.Db.GetDomains(status: "blocked").Should().Contain(d => d.Domain == "ads.example.com" && d.Category == "Advertising" && d.Notes == "known ad host");
        dst.Hosts.GetBlocked().Should().Contain("ads.example.com");

        dstFw.Rules.Should().ContainKey("HG_BlockApp_evil_Out");
        dstFw.Rules["HG_BlockApp_evil_Out"].Program.Should().Be(@"C:\evil\evil.exe");
        dstFw.Rules.Should().ContainKey("HG_Package_Block_Contoso_Reader_Out");
        dstFw.Rules["HG_Package_Block_Contoso_Reader_Out"].Program.Should().BeEmpty();
        dstFw.Rules["HG_Package_Block_Contoso_Reader_Out"].PackageSid.Should().Be("S-1-15-2-123");
        dst.Db.ListDomainFirewallRules().Should().ContainSingle(r =>
            r.RuleName == "HG_Domain_api_example_com_ABCDEF123456" &&
            r.Program == @"C:\Browser\browser.exe" &&
            r.RemoteAddr == "203.0.113.44");
        dstFw.Rules.Should().ContainKey("HG_Domain_api_example_com_ABCDEF123456");

        dst.Db.GetSchedules().Should().ContainSingle(s => s.Target == "games.example.com" && s.Start == "22:00");
        dst.Db.ListProfiles().Should().Contain("Work");
        dst.Db.LoadProfile("Work").Should().Contain(r => r.Domain == "work.example.com");
        dst.Db.GetNetworkProfiles().Should().Contain(n => n.Fingerprint == "gw-mac-abc" && n.Profile == "Work");
        dst.Db.GetBlocklistSubs().Should().Contain(b =>
            b.Name == "StevenBlack"
            && b.Mirrors.SequenceEqual(new[] { "https://1.1.1.1/hosts", "https://8.8.8.8/hosts" }));
        dst.Db.GetIpBlocklistSources().Should().ContainSingle(b =>
            b.Name == "hagezi-doh-ips" && b.Url == "https://example.com/doh-ips.txt" && !b.Enabled);
        dst.Db.GetAllowlistSubs().Should().Contain("https://example.com/allow.txt");
        dst.Db.GetMeta("history_retention_days").Should().Be("45");
        dst.Lock.Enabled.Should().BeFalse("portable policy must not copy a password verifier between machines");
    }

    [Fact]
    public void Legacy_v1_lock_verifier_is_scrubbed_and_never_imported()
    {
        const string legacyHash = "pbkdf2_sha256$210000$AAECAwQFBgcICQoLDA0ODw==$dwuexifK4Fe/1NquYoJuiWZKOFaR+Cy7JI8GAbc+U/4=";
        var policy = PortablePolicy.FromJson($$"""
            {
              "Version": 1,
              "Lock": { "Enabled": true, "Hash": "{{legacyHash}}" }
            }
            """);

        policy.Lock.Enabled.Should().BeTrue();
        policy.Lock.LegacyHash.Should().BeNull();
        policy.ToJson().Should().NotContain("\"Hash\"").And.NotContain(legacyHash);

        var (target, _) = NewMachine();
        var summary = PolicyPortability.Import(target, policy);
        target.Lock.Enabled.Should().BeFalse();
        summary.Should().Contain(item => item.Contains("credential omitted", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Ambiguous_policy_is_rejected_before_preview_or_mutation()
    {
        var (target, _) = NewMachine();
        var service = new PolicyServiceImpl(target);
        const string duplicate = """
            { "Version": 1, "Domains": [
              { "Domain": "duplicate.example", "Status": "blocked" },
              { "Domain": "DUPLICATE.EXAMPLE", "Status": "whitelisted" }
            ] }
            """;

        var preview = await service.PreviewPolicyImport(
            new ImportPolicyRequest { Json = duplicate, Preview = true }, TestContext());

        preview.Ok.Should().BeFalse();
        preview.ErrorCode.Should().Be("hostsguard.error.v1/invalid_policy");
        preview.Message.Should().Contain("duplicate identity");
        target.Db.GetDomainStatus("duplicate.example").Should().BeNull();
        target.Hosts.GetBlocked().Should().NotContain("duplicate.example");
    }

    [Fact]
    public void Export_import_carries_non_secret_mutable_policy_state()
    {
        var (src, srcFw) = NewMachine();
        using var srcKillSwitch = new KillSwitchMonitor(srcFw, src.Db, _ => true, src.DataDir);
        src.KillSwitch = srcKillSwitch;
        src.AppVpnBindings = new AppVpnBindingCoordinator(srcFw, src.Db, () => new[]
        {
            new AdapterInfo("WireGuard", "Wintun Userspace Tunnel", true, true),
            new AdapterInfo("Ethernet", "Intel Ethernet", true, false),
        });

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
        src.AppVpnBindings.Set(@"C:\Apps\sync.exe", "WireGuard", enabled: true);
        src.Db.UpsertUsageQuotaRule("app", "sync.exe", 1073741824, 14, enabled: true);
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
        policy.AppVpnBindings.Should().ContainSingle(b => b.Program == @"C:\Apps\sync.exe" && b.Adapter == "WireGuard");
        policy.UsageQuotas.Should().ContainSingle(q =>
            q.Scope == "app" && q.Match == "sync.exe" && q.LimitBytes == 1073741824 && q.WindowDays == 14 && q.Enabled);

        var (dst, dstFw) = NewMachine();
        using var dstKillSwitch = new KillSwitchMonitor(dstFw, dst.Db, _ => true, dst.DataDir);
        dst.KillSwitch = dstKillSwitch;
        dst.AppVpnBindings = new AppVpnBindingCoordinator(dstFw, dst.Db, () => new[]
        {
            new AdapterInfo("WireGuard", "Wintun Userspace Tunnel", true, true),
            new AdapterInfo("Ethernet", "Intel Ethernet", true, false),
        });

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
        dst.Db.ListAppVpnBindings().Should().ContainSingle(b => b.Program == @"C:\Apps\sync.exe" && b.Adapter == "WireGuard");
        dstFw.Rules.Values.Should().Contain(r => r.Name.StartsWith("HG_VPNBind_", StringComparison.Ordinal) && r.Interfaces == "Ethernet");
        dst.Db.GetUsageQuotaRules().Should().ContainSingle(q =>
            q.Scope == "app" && q.Match == "sync.exe" && q.LimitBytes == 1073741824 && q.WindowDays == 14 && q.Enabled);
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
    public void Import_refuses_to_repoint_the_ai_endpoint_at_a_private_target()
    {
        var (dst, _) = NewMachine();
        var before = dst.Ai.Settings.Endpoint; // default public endpoint

        // A malicious shared policy tries to steer the Bearer-authenticated AI
        // endpoint at the cloud-metadata address to exfiltrate the stored key.
        var policy = new PortablePolicy
        {
            Ai = new PolicyAiSettings { Endpoint = "https://169.254.169.254/v1", Model = "evil", Enabled = true },
        };

        var summary = PolicyPortability.Import(dst, policy);

        dst.Ai.Settings.Endpoint.Should().Be(before);
        summary.Should().Contain(s => s.Contains("not a public https URL", StringComparison.Ordinal));
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
                var dstPolicy = new Policy.PolicyClient(dstChannel);
                var preview = await dstPolicy.PreviewPolicyImportAsync(new ImportPolicyRequest { Json = doc.Json, Preview = true });
                preview.Ok.Should().BeTrue();
                preview.Preview.Should().BeTrue();
                preview.Added.Should().BeGreaterThan(0);
                preview.Summary.Should().Contain(s => s.StartsWith("domains:", StringComparison.Ordinal));

                var result = await dstPolicy.ImportPolicyAsync(new ImportPolicyRequest { Json = doc.Json });
                result.Ok.Should().BeTrue();
                result.CheckpointId.Should().BeGreaterThan(0);
                result.Summary.Should().NotBeEmpty();
                dst.Db.GetDomainStatus("rpc.example.com").Should().Be("blocked");

                var restore = await dstPolicy.RestorePolicyCheckpointAsync(new Empty());
                restore.Ok.Should().BeTrue();
                restore.CheckpointId.Should().Be(result.CheckpointId);
                dst.Db.GetDomainStatus("rpc.example.com").Should().BeNull();
                dst.Hosts.GetBlocked().Should().NotContain("rpc.example.com");
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
    public async Task Policy_subscription_previews_applies_pins_and_rolls_back_over_grpc()
    {
        var (src, _) = NewMachine();
        src.Hosts.Block("subscribed.example.com");
        src.Db.AddDomain("subscribed.example.com", "blocked", "manual");
        var originalJson = PolicyPortability.Export(src).ToJson();

        src.Hosts.Block("changed.example.com");
        src.Db.AddDomain("changed.example.com", "blocked", "manual");
        var changedJson = PolicyPortability.Export(src).ToJson();

        var (dst, _, fetcher) = NewMachineWithFetcher();
        var url = "https://policies.example.test/base.json";
        fetcher.Responses[url] = originalJson;

        var token = SessionToken.Generate();
        var pipe = "HostsGuard.PolicySub." + Guid.NewGuid().ToString("N");
        var app = ServiceHost.Build(dst, token, pipe);
        await app.StartAsync();
        try
        {
            using var channel = NamedPipeChannel.Create(token, pipe);
            var client = new Policy.PolicyClient(channel);
            var request = new PolicySubscriptionRequest
            {
                Name = "Test policy",
                Url = url,
                Enabled = true,
                AutoApply = false,
                PinCurrentHash = true,
            };

            var preview = await client.PreviewPolicySubscriptionAsync(request);
            preview.Ok.Should().BeTrue();
            preview.Preview.Should().BeTrue();
            preview.Summary.Should().Contain(s => s.StartsWith("sha256:", StringComparison.Ordinal));
            dst.Db.GetDomainStatus("subscribed.example.com").Should().BeNull("preview must not mutate policy");

            var applied = await client.ApplyPolicySubscriptionAsync(request);
            applied.Ok.Should().BeTrue();
            applied.CheckpointId.Should().BeGreaterThan(0);
            dst.Db.GetDomainStatus("subscribed.example.com").Should().Be("blocked");

            var list = await client.ListPolicySubscriptionsAsync(new Empty());
            var saved = list.Subscriptions.Should().ContainSingle().Subject;
            saved.Name.Should().Be("Test policy");
            saved.AutoApply.Should().BeFalse();
            saved.PinHash.Should().Be(saved.LastHash);
            saved.LastCheckpointId.Should().Be(applied.CheckpointId);

            fetcher.Responses[url] = changedJson;
            var refresh = await client.RefreshPolicySubscriptionsAsync(new Empty());
            refresh.Ok.Should().BeTrue();
            refresh.Message.Should().Contain("no policy subscriptions have auto-apply enabled");
            dst.Db.GetDomainStatus("changed.example.com").Should().BeNull("manual subscriptions must not auto-apply");

            var mismatch = await client.PreviewPolicySubscriptionAsync(new PolicySubscriptionRequest { Id = saved.Id });
            mismatch.Ok.Should().BeFalse();
            mismatch.ErrorCode.Should().Be("hostsguard.error.v1/policy_subscription_pin_mismatch");

            var rollback = await client.RollbackPolicySubscriptionAsync(new PolicySubscriptionRequest { Id = saved.Id });
            rollback.Ok.Should().BeTrue();
            rollback.CheckpointId.Should().Be(applied.CheckpointId);
            dst.Db.GetDomainStatus("subscribed.example.com").Should().BeNull();
            dst.Hosts.GetBlocked().Should().NotContain("subscribed.example.com");
        }
        finally
        {
            await app.DisposeAsync();
        }
    }

    [Fact]
    public void Multi_signal_network_profile_round_trips_without_a_schema_migration()
    {
        var (src, _) = NewMachine();
        src.Db.AddDomain("work.example", "blocked");
        src.Db.SaveProfile("Work");
        var rule = new NetworkProfileMatchRule(
            "Work",
            "Corporate Wi-Fi",
            GatewayMac: "AA:BB:CC:DD:EE:FF",
            Ssid: "Office",
            InterfaceName: "Wi-Fi",
            DnsSuffix: "corp.example",
            VpnPresent: true);
        src.Db.SetNetworkProfile(NetworkProfileSelectorCodec.Encode(rule), rule.Profile, rule.Label);

        var exported = PortablePolicy.FromJson(PolicyPortability.Export(src).ToJson());
        exported.NetworkProfiles.Should().ContainSingle(n =>
            n.Profile == "Work"
            && n.GatewayMac == "AA:BB:CC:DD:EE:FF"
            && n.Ssid == "Office"
            && n.InterfaceName == "Wi-Fi"
            && n.DnsSuffix == "corp.example"
            && n.VpnPresent == true);

        var (dst, _) = NewMachine();
        PolicyPortability.Import(dst, exported);
        var stored = dst.Db.GetNetworkProfiles().Should().ContainSingle().Which;
        NetworkProfileSelectorCodec.Decode(stored.Fingerprint, stored.Profile, stored.Label)
            .Should().Be(rule);
    }

    [Fact]
    public void Per_adapter_resolver_and_doh_intent_round_trips_through_portable_policy()
    {
        var sourceDns = new FakeDnsConfig();
        sourceDns.ResolverAdapters.Clear();
        sourceDns.ResolverAdapters.AddRange(
        [
            new DnsAdapterState("ethernet-id", "Ethernet0", "Ethernet", true, false, false,
                ["1.1.1.1", "1.0.0.1"], ["1.1.1.1", "1.0.0.1"]),
            new DnsAdapterState("vpn-id", "Work VPN", "WireGuard tunnel", true, true, true,
                [], ["10.0.0.53"]),
        ]);
        var (source, _) = NewMachine(sourceDns);

        var policy = PortablePolicy.FromJson(PolicyPortability.Export(source).ToJson());

        policy.DnsPrivacy!.ResolverAdapters.Should().BeEquivalentTo(
        [
            new PolicyDnsResolver { Adapter = "Ethernet0", IsVpn = false, Servers = ["1.1.1.1", "1.0.0.1"] },
            new PolicyDnsResolver { Adapter = "Work VPN", IsVpn = true, Servers = [] },
        ]);

        var targetDns = new FakeDnsConfig();
        var (target, _) = NewMachine(targetDns);
        var summary = PolicyPortability.Import(target, policy);

        targetDns.ResolverSets.Should().HaveCount(2);
        targetDns.ResolverSets[0].Should().Equal("1.1.1.1", "1.0.0.1");
        targetDns.ResolverAdapterSets[0].Should().Equal("ethernet-id");
        targetDns.ResolverSets[1].Should().BeEmpty("the portable VPN snapshot restores DHCP");
        targetDns.ResolverAdapterSets[1].Should().Equal("vpn-id");
        summary.Should().Contain(line => line.Contains("2 applied, 0 unmatched", StringComparison.Ordinal));
        summary.Should().Contain(line => line.Contains("2 DoH auto-upgraded", StringComparison.Ordinal));
    }

    [Fact]
    public void Malformed_policy_json_throws_a_readable_error()
    {
        var act = () => PortablePolicy.FromJson("{ not valid json");
        act.Should().Throw<System.Text.Json.JsonException>();
    }

    [Fact]
    public void History_privacy_exclusions_round_trip_and_replace_idempotently()
    {
        var (source, _) = NewMachine();
        source.Db.UpsertHistoryPrivacyExclusion("app", "private.exe");
        source.Db.UpsertHistoryPrivacyExclusion("domain", "example.com");

        var json = PolicyPortability.Export(source).ToJson();
        var (target, _) = NewMachine();
        var policy = PortablePolicy.FromJson(json);
        PolicyPortability.Import(target, policy);
        PolicyPortability.Import(target, policy);

        target.Db.GetHistoryPrivacyExclusions().Select(x => $"{x.Scope}:{x.Match}")
            .Should().BeEquivalentTo("app:private.exe", "domain:example.com");
    }

    [Fact]
    public void Hosts_redirects_round_trip_and_restore_exactly()
    {
        var (source, _) = NewMachine();
        source.Db.UpsertHostsRedirect("router.example.com", "192.168.1.1");
        source.Hosts.ReconcileRedirects(new[] { ("router.example.com", "192.168.1.1") });

        var policy = PortablePolicy.FromJson(PolicyPortability.Export(source).ToJson());
        policy.HostsRedirects.Should().ContainSingle(row =>
            row.Domain == "router.example.com" && row.Ip == "192.168.1.1");

        var (target, _) = NewMachine();
        PolicyPortability.Import(target, policy);
        target.Db.GetHostsRedirects().Should().ContainSingle(row => row.Domain == "router.example.com");
        File.ReadAllText(target.Hosts.HostsPath).Should().Contain(
            $"192.168.1.1 router.example.com {HostsEngine.ManagedRedirectMarker}");

        target.Db.UpsertHostsRedirect("stale.example.com", "10.0.0.2");
        target.Hosts.ReconcileRedirects(target.Db.GetHostsRedirects().Select(row => (row.Domain, row.Ip)));
        PolicyPortability.Restore(target, policy);
        target.Db.GetHostsRedirects().Should().ContainSingle(row => row.Domain == "router.example.com");
        File.ReadAllText(target.Hosts.HostsPath).Should().NotContain("stale.example.com");
    }

    private static Grpc.Core.ServerCallContext TestContext() => null!;

    public void Dispose()
    {
        foreach (var state in _states)
        {
            state.Dispose();
        }

        foreach (var dir in _dirs)
        {
            try { Directory.Delete(dir, true); } catch (IOException) { /* best effort */ }
        }
    }
}
