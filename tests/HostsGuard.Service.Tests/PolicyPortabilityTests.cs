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
