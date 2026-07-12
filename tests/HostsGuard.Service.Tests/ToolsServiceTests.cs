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

    public List<string> EntryFlushes { get; } = new();

    public List<DnsCacheRecord> CacheEntries { get; } = new();

    public List<IReadOnlyList<string>> ResolverSets { get; } = new();

    public List<IReadOnlyList<string>> ResolverAdapterSets { get; } = new();

    public List<DnsResolverSnapshot> RestoredSnapshots { get; } = new();

    public List<DnsAdapterState> ResolverAdapters { get; } =
    [
        new("ethernet-id", "Ethernet0", "Ethernet", true, false, true, [], ["192.168.1.1"]),
        new("vpn-id", "Work VPN", "WireGuard tunnel", true, true, false, ["10.0.0.53"], ["10.0.0.53"]),
    ];

    public DnsProbeResult ProbeResult { get; set; } = new(true, TimeSpan.FromMilliseconds(12), 1, 1, string.Empty);

    public bool FlushCache()
    {
        Flushes++;
        return true;
    }

    public bool FlushCacheEntry(string name)
    {
        EntryFlushes.Add(name);
        return true;
    }

    public IReadOnlyList<DnsCacheRecord> GetCacheEntries(int limit, string? search)
    {
        var needle = (search ?? string.Empty).Trim();
        return CacheEntries
            .Where(e => needle.Length == 0 ||
                        e.Name.Contains(needle, StringComparison.OrdinalIgnoreCase) ||
                        e.Type.Contains(needle, StringComparison.OrdinalIgnoreCase))
            .Take(limit)
            .ToList();
    }

    public IReadOnlyList<string> SetResolvers(IReadOnlyList<string> servers)
    {
        ResolverSets.Add(servers);
        return new[] { "Ethernet0" };
    }

    public IReadOnlyList<DnsAdapterState> ListResolverAdapters() => ResolverAdapters;

    public DnsResolverChange SetResolvers(IReadOnlyList<string> servers, IReadOnlyList<string> adapterIds)
    {
        ResolverSets.Add(servers);
        ResolverAdapterSets.Add(adapterIds);
        var selected = ResolverAdapters.Where(adapter => adapterIds.Contains(adapter.Id)).ToList();
        return new DnsResolverChange(new DnsResolverSnapshot(selected), selected);
    }

    public void RestoreResolvers(DnsResolverSnapshot snapshot) => RestoredSnapshots.Add(snapshot);

    public Task<DnsProbeResult> ProbeAsync(string host, TimeSpan timeout, CancellationToken cancellationToken)
        => Task.FromResult(ProbeResult);
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
        _dns.ResolverAdapterSets.Should().ContainSingle().Which.Should().Equal("ethernet-id");
        ack.Message.Should().Contain("12 ms");

        var bad = new ResolverRequest();
        bad.Servers.Add("dns.example.com");
        (await dns.SetResolverAsync(bad)).ErrorCode.Should().Be("hostsguard.error.v1/invalid_resolver");
    }

    [Fact]
    public async Task Resolver_adapter_preview_includes_vpn_and_failed_probe_restores_exact_snapshot()
    {
        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var dns = new DnsControl.DnsControlClient(channel);
        var adapters = await dns.ListResolverAdaptersAsync(new Empty());
        adapters.Adapters.Should().HaveCount(2);
        adapters.Adapters.Should().Contain(adapter => adapter.Id == "vpn-id" && adapter.IsVpn && !adapter.UsesDhcp);

        _dns.ProbeResult = new DnsProbeResult(true, TimeSpan.FromMilliseconds(8), 1, 0, string.Empty);
        var request = new ResolverRequest();
        request.Servers.Add("9.9.9.9");
        request.AdapterIds.Add("vpn-id");

        var ack = await dns.SetResolverAsync(request);

        ack.Ok.Should().BeFalse();
        ack.ErrorCode.Should().Be("hostsguard.error.v1/resolver_probe_failed");
        _dns.ResolverAdapterSets.Should().ContainSingle().Which.Should().Equal("vpn-id");
        _dns.RestoredSnapshots.Should().ContainSingle().Which.Adapters.Should()
            .ContainSingle(adapter => adapter.Id == "vpn-id");
        _state.Db.GetLog().Should().Contain(entry => entry.Action == "resolver_rollback");
    }

    [Fact]
    public async Task Dns_cache_listing_and_targeted_flush_round_trip()
    {
        _dns.CacheEntries.Add(new DnsCacheRecord("ads.example.com", "A", 4, 8));
        _dns.CacheEntries.Add(new DnsCacheRecord("cdn.example.net", "AAAA", 16, 0));
        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var dns = new DnsControl.DnsControlClient(channel);

        var list = await dns.ListCacheAsync(new DnsCacheRequest { Limit = 10, Search = "ads" });

        list.Available.Should().BeTrue();
        list.Entries.Should().ContainSingle();
        list.Entries[0].Name.Should().Be("ads.example.com");
        list.Entries[0].Type.Should().Be("A");
        list.Entries[0].DataLength.Should().Be(4);
        list.Entries[0].Flags.Should().Be(8);
        list.Entries[0].ServiceBinding.Should().BeFalse();
        list.Entries[0].PrivacyRole.Should().BeEmpty();

        var ack = await dns.FlushCacheEntryAsync(new DnsCacheEntryRequest { Name = "ADS.EXAMPLE.COM." });

        ack.Ok.Should().BeTrue();
        _dns.EntryFlushes.Should().Equal("ads.example.com");
        _state.Db.GetLog().Should().Contain(e => e.Domain == "ads.example.com" && e.Action == "cache_entry_flush");
    }

    [Fact]
    public async Task Dns_cache_entry_flush_rejects_invalid_names()
    {
        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var dns = new DnsControl.DnsControlClient(channel);

        var ack = await dns.FlushCacheEntryAsync(new DnsCacheEntryRequest { Name = "bad name" });

        ack.Ok.Should().BeFalse();
        ack.ErrorCode.Should().Be("hostsguard.error.v1/invalid_cache_entry");
        _dns.EntryFlushes.Should().BeEmpty();
    }

    [Fact]
    public async Task Dns_status_reports_https_svcb_cache_and_ech_observations()
    {
        _dns.CacheEntries.Add(new DnsCacheRecord("svc.example.com", "HTTPS", 32, 0));
        _dns.CacheEntries.Add(new DnsCacheRecord("_443._tcp.svc.example.com", "SVCB", 24, 0));
        _state.RecordSni(new SniObservation("203.0.113.44", "", EchUnavailable: true));
        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var status = await new DnsControl.DnsControlClient(channel).GetDohStatusAsync(new Empty());

        status.HttpsRecords.Should().Be(1);
        status.SvcbRecords.Should().Be(1);
        status.ServiceBindingObserved.Should().BeTrue();
        status.EchUnavailableObservations.Should().Be(1);
        status.EchState.Should().Be("ech-hidden");
        status.EchSummary.Should().Contain("real SNI was encrypted");
        status.EchRemediation.Should().Contain("No DNS or firewall blocking is changed automatically");
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
    public async Task Inspect_includes_domain_service_binding_cache_rows_and_posture()
    {
        _dns.CacheEntries.Add(new DnsCacheRecord("svc.inspect-me.test", "HTTPS", 48, 0));
        _dns.CacheEntries.Add(new DnsCacheRecord("_443._tcp.svc.inspect-me.test", "SVCB", 16, 0));
        _dns.CacheEntries.Add(new DnsCacheRecord("other.example.com", "HTTPS", 8, 0));
        using var channel = NamedPipeChannel.Create(_token, _pipe);

        var result = await new DnsControl.DnsControlClient(channel)
            .InspectAsync(new DomainRequest { Domain = "svc.inspect-me.test" });

        result.HttpsRecords.Should().Be(1);
        result.SvcbRecords.Should().Be(1);
        result.ServiceBindingObserved.Should().BeTrue();
        result.Records.Should().Contain(r => r.Type == "HTTPS" && r.Name == "svc.inspect-me.test");
        result.Records.Should().Contain(r => r.Type == "SVCB" && r.Name == "_443._tcp.svc.inspect-me.test");
        result.Records.Should().NotContain(r => r.Name == "other.example.com");
        result.EchState.Should().NotBeEmpty();
        result.EchSummary.Should().Contain("unobservable");
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
    public async Task Backup_restore_round_trip_replaces_hosts_content()
    {
        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var hosts = new HostsControl.HostsControlClient(channel);

        _state.Hosts.Block("restore-me.example.com");
        var backupAck = await hosts.BackupHostsAsync(new Empty());
        backupAck.Ok.Should().BeTrue();

        _state.Hosts.EmergencyReset();
        _state.Hosts.GetBlocked().Should().BeEmpty();

        var list = await hosts.ListBackupsAsync(new Empty());
        list.Entries.Should().NotBeEmpty();
        list.Entries.Should().OnlyContain(e => e.FileName.EndsWith(".bak") && !e.FileName.Contains('\\'));

        var restore = await hosts.RestoreBackupAsync(new BackupRequest { FileName = Path.GetFileName(backupAck.Message) });
        restore.Ok.Should().BeTrue();
        _state.Hosts.GetBlocked().Should().Contain("restore-me.example.com");
    }

    [Fact]
    public async Task Restore_rejects_traversal_and_unknown_names()
    {
        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var hosts = new HostsControl.HostsControlClient(channel);

        (await hosts.RestoreBackupAsync(new BackupRequest { FileName = @"..\hosts.bak" }))
            .ErrorCode.Should().Be("hostsguard.error.v1/invalid_backup");
        (await hosts.RestoreBackupAsync(new BackupRequest { FileName = "settings.json" }))
            .ErrorCode.Should().Be("hostsguard.error.v1/invalid_backup");
        (await hosts.RestoreBackupAsync(new BackupRequest { FileName = "hosts_never_written.bak" }))
            .ErrorCode.Should().Be("hostsguard.error.v1/backup_missing");
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
        _state.Db.RecordConnection(new ConnHistoryRow(DateTime.Now.ToString("o"), @"C:\Users\alice\apps\chrome.exe", 10, "TCP",
            "93.184.216.34", 443, "US", "blocked", "api.secret.example.com"));
        _state.Db.LogEvent("api.secret.example.com", "fw_blocked", process: @"C:\Users\alice\apps\chrome.exe",
            details: @"remote 93.184.216.34 contacted https://api.secret.example.com from C:\Users\alice\apps\chrome.exe");
        using var channel = NamedPipeChannel.Create(_token, _pipe);

        var ack = await new HostsGuard.Contracts.Diagnostics.DiagnosticsClient(channel)
            .ExportSupportBundleAsync(new SupportBundleRequest
            {
                Process = "chrome",
                Protocol = "tcp",
                Action = "fw_blocked",
                Limit = 10,
            });

        ack.Ok.Should().BeTrue();
        File.Exists(ack.Message).Should().BeTrue();

        using var zip = ZipFile.OpenRead(ack.Message);
        zip.Entries.Select(e => e.Name).Should().Contain(new[]
        {
            "status.json", "events.log", "firewall_rules.tsv", "schedules.tsv",
            "diagnostics.json", "consent_decisions.tsv", "traffic_profile_manifest.json",
            "traffic_profile.json", "traffic_profile.csv",
        });
        using var reader = new StreamReader(zip.GetEntry("events.log")!.Open());
        var log = await reader.ReadToEndAsync();
        log.Should().NotContain("93.184.216.34"); // redaction pipeline applied

        using var profileReader = new StreamReader(zip.GetEntry("traffic_profile.json")!.Open());
        var profile = await profileReader.ReadToEndAsync();
        profile.Should().Contain("no_payload_guarantee");
        profile.Should().Contain("tcp.port == 443");
        profile.Should().Contain("<REDACTED_IP:");
        profile.Should().Contain("<REDACTED_DOMAIN:");
        profile.Should().Contain("<REDACTED_PATH:");
        profile.Should().NotContain("93.184.216.34");
        profile.Should().NotContain("api.secret.example.com");
        profile.Should().NotContain(@"C:\Users\alice\apps\chrome.exe");

        using var manifestReader = new StreamReader(zip.GetEntry("traffic_profile_manifest.json")!.Open());
        var manifest = await manifestReader.ReadToEndAsync();
        manifest.Should().Contain("packet payloads").And.Contain("traffic_profile.csv");
    }

    [Fact]
    public async Task Support_bundle_repeated_exports_get_distinct_paths()
    {
        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var client = new HostsGuard.Contracts.Diagnostics.DiagnosticsClient(channel);

        var first = await client.ExportSupportBundleAsync(new SupportBundleRequest());
        var second = await client.ExportSupportBundleAsync(new SupportBundleRequest());

        first.Ok.Should().BeTrue();
        second.Ok.Should().BeTrue();
        first.Message.Should().NotBe(second.Message);
        Path.GetFileName(first.Message).Should().MatchRegex(@"^hostsguard_bundle_\d{8}_\d{6}_[a-f0-9]{8}\.zip$");
        File.Exists(first.Message).Should().BeTrue();
        File.Exists(second.Message).Should().BeTrue();
    }

    [Fact]
    public async Task Diagnostics_summary_reports_grouped_counts_and_consent_state_without_leaking()
    {
        _state.Db.LogEvent("203.0.113.9", "fw_blocked", details: "remote 203.0.113.9");
        _state.Db.LogEvent("ads.example.com", "blocked", details: "hosts file");
        _state.Consent.SetMode("notify");
        using var channel = NamedPipeChannel.Create(_token, _pipe);

        var ack = await new HostsGuard.Contracts.Diagnostics.DiagnosticsClient(channel)
            .ExportSupportBundleAsync(new SupportBundleRequest());

        using var zip = ZipFile.OpenRead(ack.Message);
        using var reader = new StreamReader(zip.GetEntry("diagnostics.json")!.Open());
        var json = await reader.ReadToEndAsync();

        json.Should().Contain("\"filtering_mode\": \"notify\"");
        json.Should().Contain("events_by_category");
        json.Should().Contain("firewall");   // fw_blocked bucketed
        json.Should().Contain("hosts");      // blocked bucketed
        json.Should().Contain("\"type\": \"port_scan\"");
        json.Should().Contain("\"surface\": true");
        json.Should().NotContain("203.0.113.9"); // counts only, no IPs
        json.Should().NotContain("ads.example.com");
    }
}
