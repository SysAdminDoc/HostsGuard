using System.Runtime.Versioning;
using FluentAssertions;
using HostsGuard.Contracts;
using HostsGuard.Data;
using HostsGuard.Windows;
using Microsoft.Data.Sqlite;
using Xunit;

namespace HostsGuard.Service.Tests;

/// <summary>
/// NET-070: the connection feed's first-sighting history recording, the
/// bandwidth aggregator's per-process minute buckets, and the Monitoring
/// history/bandwidth/settings RPC surface (impl-level, no pipe needed).
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class ConnectionHistoryAndBandwidthTests : IDisposable
{
    private sealed class FakeSource : IBandwidthSource
    {
        public bool Active { get; set; } = true;

        public Dictionary<int, (long Sent, long Recv)> Next { get; } = new();

        public IReadOnlyDictionary<int, (long Sent, long Recv)> Drain()
        {
            var snapshot = new Dictionary<int, (long, long)>(Next);
            Next.Clear();
            return snapshot;
        }
    }

    private readonly string _dir;
    private readonly ServiceState _state;
    private readonly HostsDatabase _db;

    public ConnectionHistoryAndBandwidthTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "hg_bw_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        var hostsPath = Path.Combine(_dir, "hosts");
        File.WriteAllText(hostsPath, "# hosts\n");
        _db = new HostsDatabase(Path.Combine(_dir, "hostsguard.db"));
        _state = new ServiceState(new HostsEngine(hostsPath), _db, dataDir: _dir);
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
    public void PublishConnection_records_history_only_for_first_sightings()
    {
        var info = new ConnectionInfo("TCP", "127.0.0.1", 5000, "93.184.216.34", 443, "ESTABLISHED", 42, "app.exe");

        _state.PublishConnection(info, recordHistory: true);
        _state.PublishConnection(info with { State = "CLOSE_WAIT" }, recordHistory: false);

        var rows = _db.GetConnectionHistory();
        var row = rows.Should().ContainSingle().Subject;
        row.Process.Should().Be("app.exe");
        row.RemoteAddr.Should().Be("93.184.216.34");
        row.RemotePort.Should().Be(443);
        row.Protocol.Should().Be("TCP");
    }

    [Fact]
    public void Aggregator_groups_drained_pids_by_process_into_minute_buckets()
    {
        var source = new FakeSource();
        source.Next[1] = (100, 10);
        source.Next[2] = (50, 5);    // same process name as pid 1
        source.Next[3] = (7, 7);
        using var aggregator = new BandwidthAggregator(_db, source,
            pid => pid == 3 ? "other.exe" : "app.exe");

        aggregator.FlushOnce(new DateTime(2026, 7, 2, 12, 0, 30));

        var rows = _db.GetBandwidth("2026-07-02T12:00");
        rows.Should().HaveCount(2);
        rows.Single(r => r.Process == "app.exe").Should().BeEquivalentTo(new { Sent = 150L, Recv = 15L });
        rows.Single(r => r.Process == "other.exe").Should().BeEquivalentTo(new { Sent = 7L, Recv = 7L });
    }

    [Fact]
    public void BuildBandwidth_zero_fills_aligns_and_ranks_series()
    {
        var now = new DateTime(2026, 7, 2, 12, 9, 0);
        _db.AddBandwidth("big.exe", "2026-07-02T12:05", 1000, 1000);
        _db.AddBandwidth("big.exe", "2026-07-02T12:09", 500, 0);
        _db.AddBandwidth("small.exe", "2026-07-02T12:09", 1, 1);
        _db.AddBandwidth("stale.exe", "2026-07-02T11:00", 9999, 9999); // outside the window
        var impl = new MonitoringServiceImpl(_state);

        var list = impl.BuildBandwidth(new BandwidthRequest { Minutes = 10, Top = 5 }, now);

        list.CountersActive.Should().BeFalse(); // no aggregator wired in this test
        list.Series.Should().HaveCount(2);
        list.Series[0].Process.Should().Be("big.exe");
        list.Series[0].Bytes.Should().HaveCount(10);
        list.Series[0].Bytes[5].Should().Be(2000); // 12:05 slot
        list.Series[0].Bytes[9].Should().Be(500);  // 12:09 slot
        list.Series[0].Bytes[0].Should().Be(0);    // zero-filled
        list.Series[0].TotalSent.Should().Be(1500);
        list.Series[0].TotalRecv.Should().Be(1000);
    }

    [Fact]
    public async Task History_settings_rpc_validates_and_persists_retention()
    {
        var impl = new MonitoringServiceImpl(_state);

        (await impl.SetHistorySettings(new HistorySettings { RetentionDays = 0 }, null!)).Ok.Should().BeFalse();
        (await impl.SetHistorySettings(new HistorySettings { RetentionDays = 14 }, null!)).Ok.Should().BeTrue();
        (await impl.GetHistorySettings(new Empty(), null!)).RetentionDays.Should().Be(14);
    }

    [Fact]
    public async Task List_events_filters_and_redacts_export_rows()
    {
        _db.LogEvent("repo.maven.apache.org", "blocked", process: @"C:\Users\me\app.exe",
            details: "called https://api.example.com/key/abcdef0123456789abcdef0123456789 at 93.184.216.34",
            reason: "manual");
        _db.LogEvent("firewall", "lockdown_on", details: "Public=block", reason: "manual");
        var impl = new MonitoringServiceImpl(_state);

        var filtered = await impl.ListEvents(new EventLogRequest
        {
            Limit = 10,
            Category = "hosts",
            Domain = "maven",
        }, null!);

        filtered.Total.Should().Be(1);
        filtered.Entries.Should().ContainSingle(e => e.Action == "blocked" && e.Category == "hosts");

        var redacted = await impl.ListEvents(new EventLogRequest
        {
            Limit = 10,
            Search = "api.example.com",
            Redact = true,
        }, null!);

        var row = redacted.Entries.Should().ContainSingle().Subject;
        redacted.Redacted.Should().BeTrue();
        row.Domain.Should().Contain("<REDACTED_DOMAIN:");
        row.Process.Should().Be("app.exe");
        row.Details.Should().Contain("<REDACTED_URL:").And.Contain("<REDACTED_IP:");
        row.Details.Should().NotContain("api.example.com");
    }
}
