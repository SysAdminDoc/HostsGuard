using FluentAssertions;
using HostsGuard.Data;
using Microsoft.Data.Sqlite;
using Xunit;

namespace HostsGuard.Data.Tests;

/// <summary>
/// NET-070: retention-bounded connection history and per-app bandwidth buckets.
/// </summary>
public sealed class ConnectionHistoryTests : IDisposable
{
    private readonly string _dir;
    private readonly HostsDatabase _db;

    public ConnectionHistoryTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "hg_hist_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        _db = new HostsDatabase(Path.Combine(_dir, "hostsguard.db"));
    }

    public void Dispose()
    {
        _db.Dispose();
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

    private static ConnHistoryRow Row(string ts, string process = "app.exe", string remote = "1.2.3.4") =>
        new(ts, process, 100, "TCP", remote, 443, "US", string.Empty);

    private static string Iso(DateTime dt) => dt.ToString("o", System.Globalization.CultureInfo.InvariantCulture);

    [Fact]
    public void History_records_and_queries_newest_first()
    {
        _db.RecordConnection(Row(Iso(DateTime.Now.AddMinutes(-2)), "old.exe"));
        _db.RecordConnection(Row(Iso(DateTime.Now), "new.exe"));

        var rows = _db.GetConnectionHistory();

        rows.Should().HaveCount(2);
        rows[0].Process.Should().Be("new.exe");
        rows[1].Process.Should().Be("old.exe");
    }

    [Fact]
    public void History_search_matches_process_remote_and_country()
    {
        _db.RecordConnection(Row(Iso(DateTime.Now), "chrome.exe", "8.8.8.8"));
        _db.RecordConnection(Row(Iso(DateTime.Now), "svchost.exe", "9.9.9.9"));

        _db.GetConnectionHistory(search: "chrome").Should().ContainSingle().Which.Process.Should().Be("chrome.exe");
        _db.GetConnectionHistory(search: "9.9.9").Should().ContainSingle().Which.Process.Should().Be("svchost.exe");
        _db.GetConnectionHistory(search: "US").Should().HaveCount(2);
        _db.GetConnectionHistory(search: "nomatch").Should().BeEmpty();
    }

    [Fact]
    public void History_prunes_rows_older_than_the_retention_window()
    {
        _db.HistoryRetentionDays = 7;
        _db.RecordConnection(Row(Iso(DateTime.Now.AddDays(-30)), "ancient.exe"));

        // The next insert prunes opportunistically.
        _db.RecordConnection(Row(Iso(DateTime.Now), "fresh.exe"));

        _db.GetConnectionHistory().Should().ContainSingle().Which.Process.Should().Be("fresh.exe");
    }

    [Fact]
    public void Retention_defaults_to_30_and_clamps_out_of_range_values()
    {
        _db.HistoryRetentionDays.Should().Be(30);

        _db.HistoryRetentionDays = 0;
        _db.HistoryRetentionDays.Should().Be(1);

        _db.HistoryRetentionDays = 9999;
        _db.HistoryRetentionDays.Should().Be(365);

        _db.HistoryRetentionDays = 14;
        _db.HistoryRetentionDays.Should().Be(14);
    }

    [Fact]
    public void Bandwidth_buckets_accumulate_per_process_per_minute()
    {
        _db.AddBandwidth("app.exe", "2026-07-02T12:00", 100, 50);
        _db.AddBandwidth("app.exe", "2026-07-02T12:00", 20, 5);
        _db.AddBandwidth("app.exe", "2026-07-02T12:01", 1, 1);
        _db.AddBandwidth("other.exe", "2026-07-02T12:00", 7, 7);

        var rows = _db.GetBandwidth("2026-07-02T12:00");

        rows.Should().HaveCount(3);
        rows.Single(r => r.Process == "app.exe" && r.Minute == "2026-07-02T12:00")
            .Should().BeEquivalentTo(new { Sent = 120L, Recv = 55L });
    }

    [Fact]
    public void Bandwidth_since_floor_and_prune_bound_the_table()
    {
        _db.AddBandwidth("app.exe", "2026-01-01T00:00", 1, 1);
        _db.AddBandwidth("app.exe", "2026-07-02T12:00", 2, 2);

        _db.GetBandwidth("2026-07-01T00:00").Should().ContainSingle();

        _db.HistoryRetentionDays = 30;
        _db.PruneBandwidth(new DateTime(2026, 7, 2, 12, 0, 0));
        _db.GetBandwidth("2020-01-01T00:00").Should().ContainSingle()
            .Which.Minute.Should().Be("2026-07-02T12:00");
    }

    [Fact]
    public void Schema_version_is_v8()
    {
        _db.SchemaVersionOnDisk().Should().Be(8);
    }
}
