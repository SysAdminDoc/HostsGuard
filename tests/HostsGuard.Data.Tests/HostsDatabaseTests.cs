using Dapper;
using FluentAssertions;
using HostsGuard.Data;
using Microsoft.Data.Sqlite;
using Xunit;

namespace HostsGuard.Data.Tests;

public sealed class HostsDatabaseTests : IDisposable
{
    private readonly string _dir;

    public HostsDatabaseTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "hg_db_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        try { Directory.Delete(_dir, true); } catch (IOException) { /* best effort */ }
    }

    private string DbPath(string name) => System.IO.Path.Combine(_dir, name);

    [Fact]
    public void Fresh_db_builds_schema_and_roundtrips_a_domain()
    {
        using var db = new HostsDatabase(DbPath("fresh.db"));
        db.SchemaVersionOnDisk().Should().Be(HostsDatabase.SchemaVersion);

        db.AddDomain("ads.example.com", "blocked", "list:foo");
        var rows = db.GetDomains();
        rows.Should().ContainSingle(r => r.Domain == "ads.example.com" && r.Status == "blocked");
        rows[0].Reason.Should().Be("blocklist"); // source list: → canonical blocklist
    }

    [Fact]
    public void Hourly_rollup_buckets_by_hour_and_zero_fills_the_window()
    {
        using var db = new HostsDatabase(DbPath("hourly.db"));
        var now = new DateTime(2026, 7, 2, 14, 30, 0);

        // 3 hits this hour, 1 two hours ago.
        db.RecordHourly("example.com", now);
        db.RecordHourly("example.com", now.AddMinutes(5));
        db.RecordHourly("example.com", now.AddMinutes(20));
        db.RecordHourly("example.com", now.AddHours(-2));
        db.RecordHourly("other.com", now); // distinct root, must not bleed in

        var hits = db.GetHourlyHits("example.com", now, hours: 24);

        hits.Should().HaveCount(24);
        hits[^1].Should().Be(3);   // current hour (newest)
        hits[^3].Should().Be(1);   // two hours ago
        hits[^2].Should().Be(0);   // one hour ago — zero-filled
        hits.Sum().Should().Be(4); // other.com excluded
    }

    [Fact]
    public void Hourly_rollup_prunes_buckets_older_than_48h()
    {
        using var db = new HostsDatabase(DbPath("prune.db"));
        var now = new DateTime(2026, 7, 2, 14, 0, 0);

        db.RecordHourly("example.com", now.AddHours(-72)); // stale
        db.RecordHourly("example.com", now);               // triggers prune

        using var conn = new SqliteConnection($"Data Source={DbPath("prune.db")}");
        conn.Open();
        conn.ExecuteScalar<long>("SELECT COUNT(*) FROM feed_hourly").Should().Be(1);
    }

    [Fact]
    public void Upsert_preserves_added_notes_hits_and_allowlist_wins()
    {
        var path = DbPath("upsert.db");
        using var db = new HostsDatabase(path);
        // Seed a row with notes/hits directly to simulate history.
        using (var conn = new SqliteConnection($"Data Source={path}"))
        {
            conn.Open();
            conn.Execute("INSERT INTO domains(domain,status,category,source,added,modified,hits,notes) VALUES('x.com','blocked','Ads','manual','2020','2020',7,'keep')");
        }

        // Re-block via UPSERT with empty category/source: must preserve.
        db.AddDomain("x.com", "whitelisted", "", "");
        var row = db.GetDomains().Single(r => r.Domain == "x.com");
        row.Status.Should().Be("whitelisted");
        row.Category.Should().Be("Ads");
        row.Source.Should().Be("manual");
        row.Added.Should().Be("2020");
        row.Hits.Should().Be(7);
        row.Notes.Should().Be("keep");

        // Blocklist import must NOT downgrade the whitelisted domain.
        db.AddDomainsBulk(new[] { ("x.com", "blocked", "list:bad") });
        db.GetDomains().Single(r => r.Domain == "x.com").Status.Should().Be("whitelisted");
    }

    [Fact]
    public void Legacy_v7_shaped_db_migrates_and_queries_succeed()
    {
        var path = DbPath("legacy.db");
        // Build a pre-versioning DB shape: old column names, no reason columns.
        using (var conn = new SqliteConnection($"Data Source={path}"))
        {
            conn.Open();
            conn.Execute("CREATE TABLE domains(domain TEXT PRIMARY KEY,status TEXT,category TEXT,source TEXT,date_added TEXT,date_modified TEXT,hit_count INTEGER,notes TEXT)");
            conn.Execute("INSERT INTO domains VALUES('legacy.com','blocked','ads','manual','2020','2020',9,'keep')");
            conn.Execute("CREATE TABLE log(id INTEGER PRIMARY KEY,timestamp TEXT,domain TEXT,action TEXT,process_name TEXT,details TEXT)");
            conn.Execute("INSERT INTO log(timestamp,domain,action,process_name,details) VALUES('2020','legacy.com','blocked','x.exe','d')");
        }
        SqliteConnection.ClearAllPools();

        using var db = new HostsDatabase(path);
        var rows = db.GetDomains();
        rows.Should().ContainSingle(r => r.Domain == "legacy.com" && r.Hits == 9 && r.Notes == "keep");

        var log = db.GetLog();
        log.Should().ContainSingle(e => e.Domain == "legacy.com" && e.Process == "x.exe");
    }

    [Fact]
    public void Event_ledger_filters_pages_and_derives_categories()
    {
        using var db = new HostsDatabase(DbPath("events.db"));
        db.LogEvent("ads.example.com", "blocked", process: "chrome.exe", details: "hosts file", reason: "manual");
        db.LogEvent("93.184.216.34", "fw_blocked", process: "app.exe", details: "remote 93.184.216.34 contacted", reason: "manual");
        db.LogEvent("C:\\Tools\\demo.exe", "consent_allow", details: "Out|1.1.1.1|TCP|permanent", reason: "consent");

        db.GetEvents(new EventLogFilter(Action: "blocked")).Rows.Should()
            .ContainSingle(e => e.Domain == "ads.example.com");
        db.GetEvents(new EventLogFilter(Reason: "consent")).Rows.Should()
            .ContainSingle(e => e.Action == "consent_allow");
        db.GetEvents(new EventLogFilter(Domain: "93.184")).Rows.Should()
            .ContainSingle(e => e.Action == "fw_blocked");
        db.GetEvents(new EventLogFilter(Process: "chrome")).Rows.Should()
            .ContainSingle(e => e.Domain == "ads.example.com");
        db.GetEvents(new EventLogFilter(Search: "remote")).Rows.Should()
            .ContainSingle(e => e.Action == "fw_blocked");
        db.GetEvents(new EventLogFilter(Category: "consent")).Rows.Should()
            .ContainSingle(e => e.Action == "consent_allow");
        db.GetEvents(new EventLogFilter(Category: "firewall")).Rows.Should()
            .ContainSingle(e => e.Action == "fw_blocked");

        var page = db.GetEvents(new EventLogFilter(Limit: 1, Offset: 1));
        page.Rows.Should().ContainSingle();
        page.Total.Should().Be(3);

        db.GetEvents(new EventLogFilter(Since: DateTime.Now.AddMinutes(-1).ToString("o"))).Total.Should().Be(3);
        db.GetEvents(new EventLogFilter(Until: DateTime.Now.AddMinutes(-1).ToString("o"))).Total.Should().Be(0);
    }

    [Fact]
    public void Migration_is_idempotent()
    {
        var path = DbPath("idem.db");
        using (var db1 = new HostsDatabase(path)) { db1.AddDomain("a.com"); }
        SqliteConnection.ClearAllPools();
        using var db2 = new HostsDatabase(path); // re-open: must not throw or lose data
        db2.GetDomains().Should().Contain(r => r.Domain == "a.com");
    }

    [Fact]
    public void Stats_counts_blocked_allowed_feed()
    {
        using var db = new HostsDatabase(DbPath("stats.db"));
        db.AddDomain("b1.com", "blocked", "manual");
        db.AddDomain("b2.com", "blocked", "manual");
        db.AddDomain("w1.com", "whitelisted", "manual");
        var stats = db.GetStats();
        stats.Blocked.Should().Be(2);
        stats.Whitelisted.Should().Be(1);
    }
}
