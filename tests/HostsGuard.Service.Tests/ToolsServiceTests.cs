using System.IO.Compression;
using System.Runtime.Versioning;
using FluentAssertions;
using HostsGuard.Contracts;
using HostsGuard.Data;
using HostsGuard.Ipc;
using HostsGuard.Windows;
using Microsoft.AspNetCore.Builder;
using Microsoft.Data.Sqlite;
using Xunit;

namespace HostsGuard.Service.Tests;

internal sealed class FakeDnsConfig : IDnsConfig
{
    public int Flushes { get; private set; }

    public List<IReadOnlyList<string>> ResolverSets { get; } = new();

    public bool FlushCache()
    {
        Flushes++;
        return true;
    }

    public IReadOnlyList<string> SetResolvers(IReadOnlyList<string> servers)
    {
        ResolverSets.Add(servers);
        return new[] { "Ethernet0" };
    }
}

/// <summary>
/// NET-023 service surface: DNS flush/resolver, scheduled blocking (editor +
/// enforcement), hosts backup, ACL hardening, and the redacted support bundle.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class ToolsServiceTests : IAsyncLifetime
{
    private string _dir = null!;
    private WebApplication _app = null!;
    private ServiceState _state = null!;
    private FakeDnsConfig _dns = null!;
    private string _pipe = null!;
    private string _token = null!;

    public async Task InitializeAsync()
    {
        _dir = Path.Combine(Path.GetTempPath(), "hg_tools_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        var hostsPath = Path.Combine(_dir, "hosts");
        File.WriteAllText(hostsPath, "# hosts\n");

        _dns = new FakeDnsConfig();
        _state = new ServiceState(
            new HostsEngine(hostsPath),
            new HostsDatabase(Path.Combine(_dir, "hostsguard.db")),
            dns: _dns,
            dataDir: _dir);
        _token = SessionToken.Generate();
        _pipe = "HostsGuard.ToolsTest." + Guid.NewGuid().ToString("N");
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

    [Fact]
    public async Task Flush_and_resolver_switch_round_trip()
    {
        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var dns = new DnsControl.DnsControlClient(channel);

        (await dns.FlushCacheAsync(new Empty())).Ok.Should().BeTrue();
        _dns.Flushes.Should().Be(1);

        var request = new ResolverRequest();
        request.Servers.Add("1.1.1.1");
        request.Servers.Add("1.0.0.1");
        var ack = await dns.SetResolverAsync(request);
        ack.Ok.Should().BeTrue();
        _dns.ResolverSets.Should().ContainSingle().Which.Should().Equal("1.1.1.1", "1.0.0.1");

        var bad = new ResolverRequest();
        bad.Servers.Add("dns.example.com");
        (await dns.SetResolverAsync(bad)).ErrorCode.Should().Be("hostsguard.error.v1/invalid_resolver");
    }

    [Fact]
    public async Task Inspect_reports_engine_block_state()
    {
        _state.Hosts.Block("ads.inspect-me.test");
        using var channel = NamedPipeChannel.Create(_token, _pipe);

        var result = await new DnsControl.DnsControlClient(channel)
            .InspectAsync(new DomainRequest { Domain = "ads.inspect-me.test" });

        result.Blocked.Should().BeTrue();
    }

    [Fact]
    public async Task Schedules_validate_and_round_trip()
    {
        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var policy = new Policy.PolicyClient(channel);

        var bad = new ScheduleList();
        bad.Schedules.Add(new Schedule { Target = "youtube.com", Start = "25:99", End = "06:00" });
        bad.Schedules[0].Days.Add(0);
        (await policy.SetSchedulesAsync(bad)).ErrorCode.Should().Be("hostsguard.error.v1/invalid_schedule");

        var good = new ScheduleList();
        var s = new Schedule { Target = "youtube.com", Start = "22:00", End = "06:00" };
        s.Days.Add(0);
        s.Days.Add(4);
        good.Schedules.Add(s);
        (await policy.SetSchedulesAsync(good)).Ok.Should().BeTrue();

        var loaded = await policy.GetSchedulesAsync(new Empty());
        loaded.Schedules.Should().ContainSingle();
        loaded.Schedules[0].Target.Should().Be("youtube.com");
        loaded.Schedules[0].Days.Should().Equal(0, 4);
    }

    [Fact]
    public void Enforcer_blocks_in_window_and_self_reverts_after()
    {
        _state.Db.SetSchedules(new[] { ("distract.example.com", "0,1,2,3,4,5,6", "09:00", "17:00") });

        _state.Schedules.SweepAt(new DateTime(2026, 7, 1, 12, 0, 0)); // Wednesday noon
        _state.Hosts.GetBlocked().Should().Contain("distract.example.com");
        _state.Db.GetDomainSource("distract.example.com").Should().Be("schedule");

        _state.Schedules.SweepAt(new DateTime(2026, 7, 1, 18, 0, 0)); // after the window
        _state.Hosts.GetBlocked().Should().NotContain("distract.example.com");
        _state.Db.GetDomainStatus("distract.example.com").Should().BeNull(); // row removed
    }

    [Fact]
    public void Enforcer_never_reverts_a_manual_block()
    {
        _state.Hosts.Block("manual.example.com");
        _state.Db.AddDomain("manual.example.com", "blocked", "manual");
        _state.Db.SetSchedules(Array.Empty<(string, string, string, string)>());

        _state.Schedules.SweepAt(new DateTime(2026, 7, 1, 18, 0, 0));

        _state.Hosts.GetBlocked().Should().Contain("manual.example.com");
    }

    [Fact]
    public void Enforcer_respects_a_manual_whitelist()
    {
        _state.Db.AddDomain("allowed.example.com", "whitelisted", "manual");
        _state.Db.SetSchedules(new[] { ("allowed.example.com", "0,1,2,3,4,5,6", "00:00", "23:59") });

        _state.Schedules.SweepAt(new DateTime(2026, 7, 1, 12, 0, 0));

        _state.Hosts.GetBlocked().Should().NotContain("allowed.example.com");
    }

    [Fact]
    public void Enforcer_handles_overnight_windows()
    {
        _state.Db.SetSchedules(new[] { ("night.example.com", "2", "22:00", "06:00") }); // Wednesday
        var wednesdayNight = new DateTime(2026, 7, 1, 23, 0, 0);
        _state.Schedules.SweepAt(wednesdayNight);

        _state.Hosts.GetBlocked().Should().Contain("night.example.com");
    }

    [Fact]
    public async Task Backup_writes_timestamped_copy_under_data_dir()
    {
        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var ack = await new HostsControl.HostsControlClient(channel).BackupHostsAsync(new Empty());

        ack.Ok.Should().BeTrue();
        File.Exists(ack.Message).Should().BeTrue();
        ack.Message.Should().StartWith(Path.Combine(_dir, "backups"));
    }

    [Fact]
    public async Task Harden_acl_reports_typed_result()
    {
        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var ack = await new HostsControl.HostsControlClient(channel).HardenAclAsync(new Empty());

        // Typed either way: success, or a hostsguard.error.v1 code when the
        // unelevated test session cannot rewrite the ACL.
        if (!ack.Ok)
        {
            ack.ErrorCode.Should().StartWith("hostsguard.error.v1/");
        }
    }

    [Fact]
    public async Task Support_bundle_is_written_and_redacts_public_ips()
    {
        _state.Db.LogEvent("93.184.216.34", "fw_blocked", details: "remote 93.184.216.34 contacted");
        using var channel = NamedPipeChannel.Create(_token, _pipe);

        var ack = await new HostsGuard.Contracts.Diagnostics.DiagnosticsClient(channel)
            .ExportSupportBundleAsync(new Empty());

        ack.Ok.Should().BeTrue();
        File.Exists(ack.Message).Should().BeTrue();

        using var zip = ZipFile.OpenRead(ack.Message);
        zip.Entries.Select(e => e.Name).Should().Contain(new[] { "status.json", "events.log", "firewall_rules.tsv", "schedules.tsv" });
        using var reader = new StreamReader(zip.GetEntry("events.log")!.Open());
        var log = await reader.ReadToEndAsync();
        log.Should().NotContain("93.184.216.34"); // redaction pipeline applied
    }
}
