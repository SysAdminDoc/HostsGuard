using FluentAssertions;
using HostsGuard.Data;
using Dapper;
using Microsoft.Data.Sqlite;
using Xunit;

namespace HostsGuard.Data.Tests;

/// <summary>
/// NET-070: retention-bounded connection history and per-app bandwidth buckets.
/// </summary>
public sealed class ConnectionHistoryTests : IDisposable
{
    private readonly string _dir;
    private readonly string _path;
    private readonly HostsDatabase _db;

    public ConnectionHistoryTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "hg_hist_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        _path = Path.Combine(_dir, "hostsguard.db");
        _db = new HostsDatabase(_path);
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

    private static ConnHistoryRow Row(string ts, string process = "app.exe", string remote = "1.2.3.4", string host = "") =>
        new(ts, process, 100, "TCP", remote, 443, "US", string.Empty, host);

    private static string Iso(DateTime dt) => dt.ToString("o", System.Globalization.CultureInfo.InvariantCulture);

    private static string Minute(DateTime dt) =>
        dt.ToString("yyyy-MM-ddTHH:mm", System.Globalization.CultureInfo.InvariantCulture);

    private static string Hour(DateTime dt) =>
        dt.ToString("yyyy-MM-ddTHH", System.Globalization.CultureInfo.InvariantCulture);

    private static string Day(DateTime dt) =>
        dt.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture);

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
    public void History_search_matches_process_remote_country_and_host()
    {
        _db.RecordConnection(Row(Iso(DateTime.Now), "chrome.exe", "8.8.8.8", "dns.google"));
        _db.RecordConnection(Row(Iso(DateTime.Now), "svchost.exe", "9.9.9.9"));

        _db.GetConnectionHistory(search: "chrome").Should().ContainSingle().Which.Process.Should().Be("chrome.exe");
        _db.GetConnectionHistory(search: "9.9.9").Should().ContainSingle().Which.Process.Should().Be("svchost.exe");
        _db.GetConnectionHistory(search: "dns.google").Should().ContainSingle().Which.Host.Should().Be("dns.google");
        _db.GetConnectionHistory(search: "US").Should().HaveCount(2);
        _db.GetConnectionHistory(search: "nomatch").Should().BeEmpty();
    }

    [Fact]
    public void History_page_filters_by_app_host_ip_status_protocol_and_time()
    {
        var now = DateTime.Now;
        _db.RecordConnection(new ConnHistoryRow(Iso(now.AddMinutes(-2)), "chrome.exe", 100, "TCP",
            "203.0.113.9", 443, "US", "allowed", "cdn.example.com"));
        _db.RecordConnection(new ConnHistoryRow(Iso(now.AddMinutes(-1)), "curl.exe", 101, "UDP",
            "198.51.100.4", 53, "US", "blocked", "api.example.net"));
        _db.RecordConnection(new ConnHistoryRow(Iso(now), "chrome.exe", 102, "TCP",
            "203.0.113.10", 443, "US", "allowed", "static.example.com"));

        var page = _db.GetConnectionHistoryPage(new ConnectionHistoryFilter(
            Limit: 1,
            Offset: 1,
            Since: Iso(now.AddMinutes(-3)),
            Until: Iso(now.AddMinutes(1)),
            Process: "chrome",
            Host: "example.com",
            RemoteAddr: "203.0.113",
            FwStatus: "allow",
            Protocol: "tcp"));

        page.Total.Should().Be(2);
        page.Limit.Should().Be(1);
        page.Offset.Should().Be(1);
        page.Rows.Should().ContainSingle().Which.Host.Should().Be("cdn.example.com");
    }

    [Fact]
    public void History_filters_escape_like_wildcards()
    {
        _db.RecordConnection(Row(Iso(DateTime.Now), "literal.exe", "203.0.113.1", "weird%host.example"));
        _db.RecordConnection(Row(Iso(DateTime.Now), "wild.exe", "203.0.113.2", "weirdXhost.example"));

        var rows = _db.GetConnectionHistoryPage(new ConnectionHistoryFilter(Host: "weird%host")).Rows;

        rows.Should().ContainSingle().Which.Process.Should().Be("literal.exe");
    }

    [Fact]
    public void Clear_connection_history_deletes_only_history_rows()
    {
        _db.RecordConnection(Row(Iso(DateTime.Now), "chrome.exe"));
        _db.LogEvent("keep.example.com", "blocked");

        _db.ClearConnectionHistory().Should().Be(1);

        _db.GetConnectionHistory().Should().BeEmpty();
        _db.GetLog().Should().Contain(e => e.Domain == "keep.example.com");
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
    public void Usage_rollups_accumulate_and_filter_by_window_app_domain_and_search()
    {
        var now = new DateTime(2026, 7, 8, 12, 0, 0);
        _db.AddUsageRollup("cdn.example.com", "chrome.exe", now, 100, 50);
        _db.AddUsageRollup("cdn.example.com", "chrome.exe", now, 25, 25);
        _db.AddUsageRollup("api.example.net", "curl.exe", now.AddDays(-1), 5, 5);
        _db.AddUsageRollup("old.example.com", "chrome.exe", now.AddDays(-10), 999, 999);

        var rows = _db.GetUsageRollups(now.AddDays(-1), limit: 10);

        rows.Should().HaveCount(2);
        rows[0].Should().BeEquivalentTo(new
        {
            Day = "2026-07-08",
            Process = "chrome.exe",
            Domain = "cdn.example.com",
            Sent = 125L,
            Recv = 75L,
        });
        _db.GetUsageRollups(now.AddDays(-1), search: "api").Should().ContainSingle()
            .Which.Process.Should().Be("curl.exe");
        _db.GetUsageRollups(now.AddDays(-1), process: "chrome").Should().ContainSingle()
            .Which.Domain.Should().Be("cdn.example.com");
        _db.GetUsageRollups(now.AddDays(-1), domain: "example.net").Should().ContainSingle()
            .Which.Process.Should().Be("curl.exe");
    }

    [Fact]
    public void Usage_quota_rules_evaluate_reset_delete_and_export_history()
    {
        var now = new DateTime(2026, 7, 8, 12, 0, 0);
        _db.AddUsageRollup("cdn.example.com", "chrome.exe", now, 100, 50);
        _db.AddUsageRollup("api.example.com", "chrome.exe", now.AddDays(-1), 25, 25);
        _db.AddUsageRollup("cdn.example.com", "edge.exe", now, 5, 5);

        var appRule = _db.UpsertUsageQuotaRule("process", "chrome.exe", 180, 2, enabled: true);
        _db.UpsertUsageQuotaRule("domain", "CDN.Example.Com.", 500, 1, enabled: false);

        _db.GetUsageQuotaRules().Should().HaveCount(2);
        var appEval = _db.EvaluateUsageQuotas(now).Should().ContainSingle(e => e.Rule.Id == appRule.Id).Subject;
        appEval.UsedBytes.Should().Be(200);
        appEval.Triggered.Should().BeTrue();

        _db.EvaluateUsageQuotas(now, triggeredOnly: true).Should().ContainSingle(e => e.Rule.Id == appRule.Id);
        _db.MarkUsageQuotaAlerted(appRule.Id, appEval.UsedBytes, now);
        _db.EvaluateUsageQuotas(now, triggeredOnly: true).Should().BeEmpty();
        _db.ResetUsageQuotaHistory().Should().Be(2);
        _db.EvaluateUsageQuotas(now, triggeredOnly: true).Should().ContainSingle(e => e.Rule.Id == appRule.Id);

        _db.GetUsageQuotaHistory(now.AddDays(-1), "app", "chrome.exe").Should().Contain(r =>
            r.Day == "2026-07-08" && r.Scope == "app" && r.Match == "chrome.exe" && r.Sent == 100 && r.Recv == 50);
        _db.DeleteUsageQuotaRule(appRule.Id).Should().Be(1);
        _db.GetUsageQuotaRules().Should().ContainSingle(r => r.Scope == "domain" && r.Match == "cdn.example.com" && !r.Enabled);
    }

    [Fact]
    public void Retention_sweep_bounds_unbounded_tables_and_is_idempotent()
    {
        var now = new DateTime(2026, 7, 8, 12, 0, 0);
        var old = now.AddDays(-8);
        var fresh = now.AddDays(-1);
        _db.HistoryRetentionDays = 7;

        using (var conn = new SqliteConnection($"Data Source={_path}"))
        {
            conn.Open();
            conn.Execute(
                """
                INSERT INTO log(ts,domain,action,process,details,reason) VALUES
                    (@oldIso,'old-log.example','blocked','old.exe','','manual'),
                    (@freshIso,'fresh-log.example','blocked','fresh.exe','','manual');
                INSERT INTO resolved_hosts(ip,host,source,updated) VALUES
                    ('10.0.0.1','old-host.example','dns',@oldIso),
                    ('10.0.0.2','fresh-host.example','dns',@freshIso);
                INSERT INTO domain_usage(domain,process,sent,recv,updated) VALUES
                    ('old-usage.example','old.exe',1,1,@oldIso),
                    ('fresh-usage.example','fresh.exe',2,2,@freshIso);
                INSERT INTO app_bandwidth(process,minute,sent,recv) VALUES
                    ('old.exe',@oldMinute,1,1),
                    ('fresh.exe',@freshMinute,2,2);
                INSERT INTO usage_daily(day,process,domain,sent,recv) VALUES
                    (@oldDay,'old.exe','old-rollup.example',1,1),
                    (@freshDay,'fresh.exe','fresh-rollup.example',2,2);
                INSERT INTO feed_hourly(root,hour,hits) VALUES
                    ('old-hour.example',@oldHour,1),
                    ('fresh-hour.example',@freshHour,2);
                """,
                new
                {
                    oldIso = Iso(old),
                    freshIso = Iso(fresh),
                    oldMinute = Minute(old),
                    freshMinute = Minute(fresh),
                    oldDay = Day(old),
                    freshDay = Day(fresh),
                    oldHour = Hour(now.AddHours(-72)),
                    freshHour = Hour(now.AddHours(-1)),
                });
        }

        var first = _db.RunRetentionSweep(now, forceMaintenance: true);
        first.Should().BeEquivalentTo(new
        {
            LogRows = 1,
            ResolvedHosts = 1,
            DomainUsageRows = 1,
            BandwidthBuckets = 1,
            UsageDailyRows = 1,
            HourlyBuckets = 1,
            MaintenanceRan = true,
        });

        var second = _db.RunRetentionSweep(now);
        second.Should().BeEquivalentTo(new
        {
            LogRows = 0,
            ResolvedHosts = 0,
            DomainUsageRows = 0,
            BandwidthBuckets = 0,
            UsageDailyRows = 0,
            HourlyBuckets = 0,
            MaintenanceRan = false,
        });

        using var verify = new SqliteConnection($"Data Source={_path}");
        verify.Open();
        verify.ExecuteScalar<long>("SELECT COUNT(*) FROM log").Should().Be(1);
        verify.ExecuteScalar<long>("SELECT COUNT(*) FROM resolved_hosts").Should().Be(1);
        verify.ExecuteScalar<long>("SELECT COUNT(*) FROM domain_usage").Should().Be(1);
        verify.ExecuteScalar<long>("SELECT COUNT(*) FROM app_bandwidth").Should().Be(1);
        verify.ExecuteScalar<long>("SELECT COUNT(*) FROM usage_daily").Should().Be(1);
        verify.ExecuteScalar<long>("SELECT COUNT(*) FROM feed_hourly").Should().Be(1);
        verify.ExecuteScalar<string>("SELECT domain FROM log").Should().Be("fresh-log.example");
        verify.ExecuteScalar<string>("SELECT host FROM resolved_hosts").Should().Be("fresh-host.example");
        verify.ExecuteScalar<string>("SELECT domain FROM domain_usage").Should().Be("fresh-usage.example");
        verify.ExecuteScalar<string>("SELECT domain FROM usage_daily").Should().Be("fresh-rollup.example");
    }

    [Fact]
    public void Existing_database_enables_incremental_auto_vacuum_without_data_loss()
    {
        var path = Path.Combine(_dir, "existing-vacuum.db");
        using (var conn = new SqliteConnection($"Data Source={path}"))
        {
            conn.Open();
            conn.Execute("CREATE TABLE legacy(id INTEGER PRIMARY KEY, value TEXT)");
            conn.Execute("INSERT INTO legacy(value) VALUES('keep')");
            conn.ExecuteScalar<long>("PRAGMA auto_vacuum").Should().Be(0);
        }

        using (var db = new HostsDatabase(path))
        {
            db.SchemaVersionOnDisk().Should().Be(HostsDatabase.SchemaVersion);
        }

        SqliteConnection.ClearAllPools();
        using var verify = new SqliteConnection($"Data Source={path}");
        verify.Open();
        verify.ExecuteScalar<long>("PRAGMA auto_vacuum").Should().Be(2);
        verify.ExecuteScalar<string>("SELECT value FROM legacy").Should().Be("keep");
    }

    [Fact]
    public void Existing_connection_history_table_gains_host_column()
    {
        var path = Path.Combine(_dir, "existing-conn-history.db");
        using (var conn = new SqliteConnection($"Data Source={path}"))
        {
            conn.Open();
            conn.Execute(
                """
                CREATE TABLE conn_history(
                    id INTEGER PRIMARY KEY, ts TEXT, process TEXT, pid INTEGER, protocol TEXT,
                    remote_addr TEXT, remote_port INTEGER, country TEXT, fw_status TEXT)
                """);
            conn.Execute(
                """
                INSERT INTO conn_history(ts,process,pid,protocol,remote_addr,remote_port,country,fw_status)
                VALUES('2026-07-09T00:00:00Z','old.exe',1,'TCP','203.0.113.5',443,'US','')
                """);
        }

        using (var db = new HostsDatabase(path))
        {
            db.SchemaVersionOnDisk().Should().Be(HostsDatabase.SchemaVersion);
        }

        SqliteConnection.ClearAllPools();
        using var verify = new SqliteConnection($"Data Source={path}");
        verify.Open();
        verify.Query<string>("SELECT name FROM pragma_table_info('conn_history')")
            .Should().Contain("host");
        verify.ExecuteScalar<string>("SELECT host FROM conn_history WHERE process='old.exe'")
            .Should().BeEmpty();
    }

    [Fact]
    public void Schema_version_is_current()
    {
        _db.SchemaVersionOnDisk().Should().Be(HostsDatabase.SchemaVersion);
    }

    [Fact]
    public void History_privacy_exclusions_match_apps_and_domain_descendants_and_survive_restart()
    {
        _db.UpsertHistoryPrivacyExclusion("app", "private.exe");
        _db.UpsertHistoryPrivacyExclusion("domain", "example.com");

        _db.IsHistoryPersistenceExcluded("PRIVATE.EXE", null).Should().BeTrue();
        _db.IsHistoryPersistenceExcluded("other.exe", "api.example.com").Should().BeTrue();
        _db.IsHistoryPersistenceExcluded("other.exe", "notexample.com").Should().BeFalse();
        _db.GetHistoryPrivacyExclusions().Should().HaveCount(2);
    }

    [Fact]
    public void Adding_privacy_exclusion_purges_prior_connection_and_usage_history()
    {
        var now = DateTime.UtcNow;
        _db.RecordConnection(Row(Iso(now), "private.exe", host: "api.example.com"));
        _db.AddBandwidth("private.exe", Minute(now), 10, 20);
        _db.AddDomainUsage("api.example.com", "private.exe", 10, 20);
        _db.AddUsageRollup("api.example.com", "private.exe", now.Date, 10, 20);

        _db.UpsertHistoryPrivacyExclusion("domain", "example.com");
        _db.GetConnectionHistory().Should().BeEmpty();
        _db.GetDomainUsage("api.example.com").Should().BeEmpty();
        _db.GetUsageRollups(now.Date.AddDays(-1), 20).Should().BeEmpty();

        _db.UpsertHistoryPrivacyExclusion("app", "private.exe");
        _db.GetBandwidth(Minute(now.AddMinutes(-1))).Should().BeEmpty();
    }
}
