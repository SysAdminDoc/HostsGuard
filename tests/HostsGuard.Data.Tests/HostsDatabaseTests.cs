using Dapper;
using FluentAssertions;
using HostsGuard.Core;
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
        db.RecordHourly("example.com", now);
        db.RunRetentionSweep(now);                         // triggers prune

        using var conn = new SqliteConnection($"Data Source={DbPath("prune.db")};Pooling=False");
        conn.Open();
        conn.ExecuteScalar<long>("SELECT COUNT(*) FROM feed_hourly").Should().Be(1);
    }

    [Fact]
    public void Blocklist_source_stats_sum_exact_domain_hits_for_the_last_30_days()
    {
        using var db = new HostsDatabase(DbPath("source-stats.db"));
        var now = DateTime.Now;
        db.UpsertBlocklistSub("A", "https://lists.test/a.txt", 2);
        db.UpsertBlocklistSub("B", "https://lists.test/b.txt", 1);
        db.ReplaceBlocklistSourceDomains("A", new[] { "ads.example.com", "shared.example.net" });
        db.ReplaceBlocklistSourceDomains("B", new[] { "shared.example.net" });
        db.RecordDnsSightings(new[]
        {
            new DnsSightingWrite("ads.example.com", "browser", null, now),
            new DnsSightingWrite("ads.example.com", "browser", null, now.AddMinutes(1)),
            new DnsSightingWrite("shared.example.net", "browser", null, now.AddMinutes(2)),
            new DnsSightingWrite("ads.example.com", "browser", null, now.AddDays(-31)),
            new DnsSightingWrite("unlisted.example.org", "browser", null, now),
        });

        var rows = db.GetBlocklistSubs();

        rows.Single(r => r.Name == "A").Hits30d.Should().Be(3);
        rows.Single(r => r.Name == "B").Hits30d.Should().Be(1);
    }

    [Fact]
    public void Firewall_snapshot_seeds_silently_then_reports_add_change_and_vanish()
    {
        using var db = new HostsDatabase(DbPath("fw-snapshot.db"));
        var baseline = new FwRule("Core Networking", "In", "Allow", true, "Any", "TCP", string.Empty, "system", "Any");

        db.SnapshotFirewallRules(new[] { baseline }, new DateTime(2026, 7, 8, 10, 0, 0))
            .Should().BeEmpty();

        var changed = baseline with { Enabled = false };
        var added = new FwRule("Steam Installer", "In", "Allow", true, "Any", "TCP", @"C:\Steam\steam.exe", "system", "27015");
        var diffs = db.SnapshotFirewallRules(new[] { changed, added }, new DateTime(2026, 7, 8, 10, 5, 0));

        diffs.Should().ContainSingle(d => d.Name == "Core Networking" && d.ChangeKind == "changed")
            .Which.Details.Should().Contain("enabled: on -> off");
        diffs.Should().ContainSingle(d => d.Name == "Steam Installer" && d.ChangeKind == "added");

        var vanished = db.SnapshotFirewallRules(new[] { changed }, new DateTime(2026, 7, 8, 10, 10, 0));

        vanished.Should().ContainSingle(d => d.Name == "Steam Installer" && d.ChangeKind == "vanished");
        var snapshot = db.GetFirewallRuleSnapshots().Single(r => r.Name == "Steam Installer");
        snapshot.Present.Should().BeFalse();
        snapshot.ChangeDetail.Should().Contain("vanished system In Allow");
    }

    [Fact]
    public void Firewall_state_snapshot_and_app_vpn_bindings_preserve_interfaces()
    {
        using var db = new HostsDatabase(DbPath("fw-interfaces.db"));
        var rule = new FwRule(
            "HG_VPNBind_test",
            "Out",
            "Block",
            true,
            "Any",
            "Any",
            @"C:\Apps\sync.exe",
            "hostsguard",
            Interfaces: "Ethernet,Wi-Fi");

        db.UpsertFwState(rule.Name, rule.Direction, rule.Action, rule.RemoteAddr, rule.Protocol, rule.Program,
            rule.RemotePorts, rule.LocalPorts, rule.ServiceName, rule.Interfaces);
        db.GetFwState().Should().ContainSingle(r => r.Interfaces == "Ethernet,Wi-Fi");

        db.SnapshotFirewallRules(new[] { rule }, new DateTime(2026, 7, 8, 11, 0, 0)).Should().BeEmpty();
        var changed = rule with { Interfaces = "Ethernet" };
        db.SnapshotFirewallRules(new[] { changed }, new DateTime(2026, 7, 8, 11, 5, 0))
            .Should().ContainSingle(d => d.Details.Contains("interfaces: Ethernet,Wi-Fi -> Ethernet", StringComparison.Ordinal));

        db.UpsertAppVpnBinding(rule.Program, "WireGuard", rule.Name);
        db.ListAppVpnBindings().Should().ContainSingle(b =>
            b.Program == rule.Program && b.Adapter == "WireGuard" && b.RuleName == rule.Name);
        db.RemoveAppVpnBinding(rule.Program).Should().BeTrue();
        db.ListAppVpnBindings().Should().BeEmpty();
    }

    [Fact]
    public void Firewall_state_and_snapshot_preserve_package_identity()
    {
        using var db = new HostsDatabase(DbPath("fw-packages.db"));
        var rule = new FwRule(
            "HG_Package_Block_Contoso_Out",
            "Out",
            "Block",
            true,
            "Any",
            "Any",
            string.Empty,
            "hostsguard",
            PackageFamilyName: "Contoso.Reader_123abc",
            PackageSid: "S-1-15-2-123",
            PackageDisplayName: "Contoso Reader",
            PackageFullName: "Contoso.Reader_1.0.0.0_x64__123abc",
            PackageBinaries: @"C:\Program Files\WindowsApps\Contoso.Reader\reader.exe");

        db.UpsertFwState(
            rule.Name,
            rule.Direction,
            rule.Action,
            rule.RemoteAddr,
            rule.Protocol,
            rule.Program,
            rule.RemotePorts,
            rule.LocalPorts,
            rule.ServiceName,
            rule.Interfaces,
            rule.PackageFamilyName,
            rule.PackageSid,
            rule.PackageDisplayName,
            rule.PackageFullName,
            rule.PackageBinaries);

        db.GetFwState().Should().ContainSingle(r =>
            r.PackageFamilyName == "Contoso.Reader_123abc" &&
            r.PackageSid == "S-1-15-2-123" &&
            r.PackageDisplayName == "Contoso Reader");

        db.SnapshotFirewallRules(new[] { rule }, new DateTime(2026, 7, 8, 12, 0, 0)).Should().BeEmpty();
        var changed = rule with { PackageDisplayName = "Contoso Reader Preview" };
        db.SnapshotFirewallRules(new[] { changed }, new DateTime(2026, 7, 8, 12, 5, 0))
            .Should().ContainSingle(d =>
                d.PackageFamilyName == "Contoso.Reader_123abc" &&
                d.Details.Contains("package display: Contoso Reader -> Contoso Reader Preview", StringComparison.Ordinal));
    }

    [Fact]
    public void Firewall_snapshot_ignores_optional_package_binary_enrichment()
    {
        using var db = new HostsDatabase(DbPath("fw-package-binaries.db"));
        var full = new FwRule(
            "Package rule",
            "Out",
            "Block",
            true,
            "Any",
            "Any",
            string.Empty,
            "system",
            PackageFamilyName: "Contoso.Reader_123abc",
            PackageSid: "S-1-15-2-123",
            PackageDisplayName: "Contoso Reader",
            PackageFullName: "Contoso.Reader_1.0.0.0_x64__123abc",
            PackageBinaries: @"C:\Program Files\WindowsApps\Contoso.Reader\reader.exe");

        db.SnapshotFirewallRules(new[] { full }, new DateTime(2026, 7, 8, 12, 0, 0)).Should().BeEmpty();

        var lightweight = full with { PackageBinaries = string.Empty };
        db.SnapshotFirewallRules(new[] { lightweight }, new DateTime(2026, 7, 8, 12, 5, 0))
            .Should().BeEmpty();
        db.GetFirewallRuleSnapshots().Should().ContainSingle(r =>
            r.PackageBinaries == full.PackageBinaries);
    }

    [Fact]
    public void Upsert_preserves_added_notes_hits_and_allowlist_wins()
    {
        var path = DbPath("upsert.db");
        using var db = new HostsDatabase(path);
        // Seed a row with notes/hits directly to simulate history.
        using (var conn = new SqliteConnection($"Data Source={path};Pooling=False"))
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
        using (var conn = new SqliteConnection($"Data Source={path};Pooling=False"))
        {
            conn.Open();
            conn.Execute("CREATE TABLE domains(domain TEXT PRIMARY KEY,status TEXT,category TEXT,source TEXT,date_added TEXT,date_modified TEXT,hit_count INTEGER,notes TEXT)");
            conn.Execute("INSERT INTO domains VALUES('legacy.com','blocked','ads','manual','2020','2020',9,'keep')");
            conn.Execute("CREATE TABLE log(id INTEGER PRIMARY KEY,timestamp TEXT,domain TEXT,action TEXT,process_name TEXT,details TEXT)");
            conn.Execute("INSERT INTO log(timestamp,domain,action,process_name,details) VALUES('2020','legacy.com','blocked','x.exe','d')");
        }

        using var db = new HostsDatabase(path);
        var rows = db.GetDomains();
        rows.Should().ContainSingle(r => r.Domain == "legacy.com" && r.Hits == 9 && r.Notes == "keep");

        var log = db.GetLog();
        log.Should().ContainSingle(e => e.Domain == "legacy.com" && e.Process == "x.exe");
    }

    [Fact]
    public void Event_log_query_handles_empty_fresh_databases()
    {
        using var db = new HostsDatabase(DbPath("empty-log.db"));

        db.GetLog().Should().BeEmpty();
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
    public void Event_ledger_persists_wfp_provenance_columns()
    {
        using var db = new HostsDatabase(DbPath("wfp-events.db"));
        db.LogEvent(
            "C:\\Apps\\blocked.exe",
            "consent_block",
            details: "Out|203.0.113.9|TCP|permanent",
            reason: "consent",
            provenance: new WfpAuditProvenance(
                FilterRuntimeId: "67338",
                FilterOrigin: "VendorBlockRule",
                LayerName: "%%14611",
                LayerRuntimeId: "48",
                InterfaceIndex: 12,
                InterfaceName: "Ethernet"));

        var row = db.GetLog().Should().ContainSingle().Subject;
        row.FilterRuntimeId.Should().Be("67338");
        row.FilterOrigin.Should().Be("VendorBlockRule");
        row.LayerName.Should().Be("%%14611");
        row.LayerRuntimeId.Should().Be("48");
        row.InterfaceIndex.Should().Be(12);
        row.InterfaceName.Should().Be("Ethernet");

        db.GetEvents(new EventLogFilter(Search: "VendorBlockRule")).Rows.Should()
            .ContainSingle(e => e.FilterOrigin == "VendorBlockRule" && e.InterfaceName == "Ethernet");
    }

    [Fact]
    public void Alerts_dedupe_unread_rows_ack_and_honor_type_surface()
    {
        using var db = new HostsDatabase(DbPath("alerts.db"));

        var first = db.AddAlert("threat_hit", "critical", "Threat", "198.51.100.66", "first", action: "connect", process: "evil.exe");
        var second = db.AddAlert("threat_hit", "critical", "Threat", "198.51.100.66", "second", action: "connect", process: "evil.exe");
        second.Should().Be(first);

        var page = db.GetAlerts(new AlertFilter());
        page.Rows.Should().ContainSingle(r => r.Id == first && r.Details == "second" && !r.IsRead);
        page.Unread.Should().Be(1);
        db.GetAlertTypes().Should().Contain(t => t.Type == "threat_hit" && t.Surface && t.Unread == 1);

        db.SetAlertTypeSurface("threat_hit", false);
        db.GetAlerts(new AlertFilter()).Rows.Should().BeEmpty();
        db.GetAlerts(new AlertFilter(SurfaceOnly: false)).Rows.Should().ContainSingle(r => !r.Surfaced);

        db.AckAlerts(new[] { first }).Should().Be(1);
        db.GetAlerts(new AlertFilter(IncludeRead: true, SurfaceOnly: false)).Rows
            .Should().ContainSingle(r => r.IsRead);
        db.GetAlerts(new AlertFilter(SurfaceOnly: false)).Unread.Should().Be(0);

        db.TryAddAlertOnce("threat_hit", "critical", "Threat", "198.51.100.66", "retrospective",
            action: "connect", process: "evil.exe").Should().BeFalse();
        db.GetAlerts(new AlertFilter(IncludeRead: true, SurfaceOnly: false)).Rows.Should().ContainSingle();

        db.TryAddAlertOnce("threat_hit", "critical", "Threat", "203.0.113.99", "retrospective",
            action: "connect", process: "other.exe").Should().BeTrue();
        db.TryAddAlertOnce("threat_hit", "critical", "Threat", "203.0.113.99", "again",
            action: "connect", process: "other.exe").Should().BeFalse();
        db.GetAlerts(new AlertFilter(IncludeRead: true, SurfaceOnly: false)).Rows.Should().HaveCount(2);
    }

    [Fact]
    public void Port_scan_alert_type_is_operator_mutable_and_surfaced_by_default()
    {
        using var db = new HostsDatabase(DbPath("port-scan-alert-type.db"));

        db.GetAlertTypes().Should().ContainSingle(t =>
            t.Type == "port_scan" &&
            t.Label == "Blocked inbound port scans" &&
            t.Surface);

        db.SetAlertTypeSurface("port_scan", false);
        db.GetAlertTypes().Should().ContainSingle(t => t.Type == "port_scan" && !t.Surface);
    }

    [Fact]
    public void Dns_tunnel_alert_type_is_operator_mutable_and_off_by_default()
    {
        using var db = new HostsDatabase(DbPath("dns-tunnel-alert-type.db"));

        db.GetAlertTypes().Should().ContainSingle(t =>
            t.Type == "dns_tunnel" &&
            t.Label == "DNS-tunneling bursts" &&
            !t.Surface);

        db.SetAlertTypeSurface("dns_tunnel", true);
        db.GetAlertTypes().Should().ContainSingle(t => t.Type == "dns_tunnel" && t.Surface);
    }

    [Fact]
    public void Event_ledger_category_filter_pages_in_sql_equivalent_to_taxonomy()
    {
        using var db = new HostsDatabase(DbPath("event-category-sql.db"));
        var actions = new[]
        {
            EventTaxonomy.Blocked,
            EventTaxonomy.Whitelisted,
            EventTaxonomy.RawEdit,
            EventTaxonomy.FwBlocked,
            EventTaxonomy.PortScan,
            "FW_UNBLOCKED",
            EventTaxonomy.LockdownOn,
            EventTaxonomy.ConsentAllow,
            EventTaxonomy.ConsentTimeout,
            EventTaxonomy.ModeChanged,
            "doh_refreshed",
            "dns_blocklist_refresh",
            "resolver_changed",
            "blocklist_imported",
            "allowlist_refreshed",
            EventTaxonomy.ExclusionAdded,
            "defender_status",
            EventTaxonomy.BundleExport,
            "support_bundle_opened",
            "profile_applied",
            "schedule_window_started",
            "settings_lock_armed",
            "imported",
            "something_unmapped",
            string.Empty,
        };
        var rng = new Random(140);
        for (var i = 0; i < 300; i++)
        {
            var action = actions[rng.Next(actions.Length)];
            db.LogEvent($"event-{i:D3}.example.com", action, process: $"proc-{i % 7}.exe", details: $"row {i}");
        }

        var all = db.GetEvents(new EventLogFilter(Limit: 500)).Rows;
        all.Should().HaveCount(300);
        var categories = new[]
        {
            EventTaxonomy.Categories.Hosts,
            EventTaxonomy.Categories.Firewall,
            EventTaxonomy.Categories.Consent,
            EventTaxonomy.Categories.Dns,
            EventTaxonomy.Categories.Lists,
            EventTaxonomy.Categories.Defender,
            EventTaxonomy.Categories.Support,
            EventTaxonomy.Categories.Policy,
            EventTaxonomy.Categories.Other,
        };
        var pages = new[] { (Limit: 1, Offset: 0), (Limit: 7, Offset: 3), (Limit: 25, Offset: 20) };

        foreach (var category in categories)
        {
            var expected = all
                .Where(r => EventTaxonomy.Category(r.Action) == category)
                .ToList();
            foreach (var (limit, offset) in pages)
            {
                var actual = db.GetEvents(new EventLogFilter(Limit: limit, Offset: offset, Category: category));

                actual.Total.Should().Be(expected.Count, $"category {category} total should match taxonomy");
                actual.Rows.Select(r => r.Id).Should().Equal(
                    expected.Skip(offset).Take(limit).Select(r => r.Id),
                    $"category {category} page should be SQL-paged after filtering");
            }
        }
    }

    [Fact]
    public void Event_ledger_like_filters_treat_sqlite_wildcards_as_literals()
    {
        using var db = new HostsDatabase(DbPath("event-like-escape.db"));
        db.LogEvent("svc_host.example.com", "blocked", process: "svc_host.exe", details: "literal underscore");
        db.LogEvent("svcxhost.example.com", "blocked", process: "svcxhost.exe", details: "underscore control");
        db.LogEvent("percent.example.com", "blocked", process: "meter.exe", details: "loaded 100% of filter");
        db.LogEvent("percent-control.example.com", "blocked", process: "meter.exe", details: "loaded 1000 of filter");
        db.LogEvent("bracket.example.com", "blocked", process: "tagger.exe", details: "kept [tag] marker");

        db.GetEvents(new EventLogFilter(Search: "svc_host")).Rows.Should()
            .ContainSingle(e => e.Domain == "svc_host.example.com");
        db.GetEvents(new EventLogFilter(Search: "100%")).Rows.Should()
            .ContainSingle(e => e.Domain == "percent.example.com");
        db.GetEvents(new EventLogFilter(Search: "[tag]")).Rows.Should()
            .ContainSingle(e => e.Domain == "bracket.example.com");
    }

    [Fact]
    public void Migration_is_idempotent()
    {
        var path = DbPath("idem.db");
        using (var db1 = new HostsDatabase(path)) { db1.AddDomain("a.com"); }
        using var db2 = new HostsDatabase(path); // re-open: must not throw or lose data
        db2.GetDomains().Should().Contain(r => r.Domain == "a.com");
    }

    [Fact]
    public void Dispose_clears_only_this_database_pool()
    {
        var first = new HostsDatabase(DbPath("pool-a.db"));
        using var second = new HostsDatabase(DbPath("pool-b.db"));

        first.AddDomain("first.example.com");
        second.AddDomain("second.example.com");
        first.Dispose();

        second.AddDomain("still-live.example.com");
        second.GetDomains().Should().Contain(r => r.Domain == "still-live.example.com");
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

    [Fact]
    public void GetDomains_search_escapes_like_wildcards()
    {
        using var db = new HostsDatabase(DbPath("like-escape.db"));
        db.AddDomain("_dmarc.example.com", "blocked", "manual");
        db.AddDomain("xdmarcxexample.com", "blocked", "manual");

        var results = db.GetDomains(search: "_dmarc");
        results.Should().ContainSingle(r => r.Domain == "_dmarc.example.com");
    }

    [Fact]
    public void GetUsageRollups_search_escapes_like_wildcards()
    {
        using var db = new HostsDatabase(DbPath("rollup-escape.db"));
        var day = DateTime.Now.Date;
        db.AddUsageRollup("test.com", "my_app", day, 100, 200);
        db.AddUsageRollup("test.com", "myXapp", day, 100, 200);

        var results = db.GetUsageRollups(day, process: "my_app");
        results.Should().ContainSingle(r => r.Process == "my_app");
    }

    [Fact]
    public void GetTempAllows_skips_malformed_date_entries()
    {
        using var db = new HostsDatabase(DbPath("temp-malformed.db"));
        var future = DateTime.UtcNow.AddHours(1).ToString("o", System.Globalization.CultureInfo.InvariantCulture);
        using var conn = new SqliteConnection($"Data Source={DbPath("temp-malformed.db")};Pooling=False");
        conn.Open();
        conn.Execute("INSERT INTO temp_allows(domain, expires) VALUES('good.com', @f)", new { f = future });
        conn.Execute("INSERT INTO temp_allows(domain, expires) VALUES('bad.com', 'not-a-date')");

        var allows = db.GetTempAllows();
        allows.Should().ContainSingle(a => a.Domain == "good.com");
    }

    [Fact]
    public void OpenWithRecovery_opens_a_healthy_db_without_quarantine()
    {
        using var db = HostsDatabase.OpenWithRecovery(DbPath("healthy.db"), out var quarantined);
        quarantined.Should().BeNull();
        db.SchemaVersionOnDisk().Should().Be(HostsDatabase.SchemaVersion);
    }

    [Fact]
    public void OpenWithRecovery_quarantines_a_corrupt_db_and_rebuilds_fresh()
    {
        // NET-181: a power-loss-torn / disk-faulted database must never brick the
        // service. Write garbage where a SQLite file should be, then recover.
        var path = DbPath("corrupt.db");
        File.WriteAllBytes(path, System.Text.Encoding.ASCII.GetBytes("this is not a sqlite database at all"));

        using var db = HostsDatabase.OpenWithRecovery(path, out var quarantined);

        quarantined.Should().NotBeNull();
        File.Exists(quarantined!).Should().BeTrue("the bad file is moved aside, not deleted");
        quarantined!.Should().EndWith(".corrupt");
        db.SchemaVersionOnDisk().Should().Be(HostsDatabase.SchemaVersion); // fresh, usable schema
        db.GetLog(50).Should().Contain(e => e.Action == "db_recovered"); // recovery is auditable
    }

    [Fact]
    public void Corrupt_database_recovery_does_not_disrupt_an_unrelated_live_database()
    {
        using var healthy = new HostsDatabase(DbPath("live-during-recovery.db"));
        healthy.AddDomain("still-live.example", "blocked", "manual");

        var corruptPath = DbPath("unrelated-corrupt.db");
        File.WriteAllBytes(corruptPath, System.Text.Encoding.ASCII.GetBytes("not sqlite"));
        using var recovered = HostsDatabase.OpenWithRecovery(corruptPath, out var quarantined);

        quarantined.Should().NotBeNull();
        healthy.GetDomains().Should().ContainSingle(row => row.Domain == "still-live.example");
        healthy.LogEvent("still-live.example", "checked", reason: "test");
        healthy.GetLog(10).Should().Contain(row => row.Action == "checked");
    }

    [Fact]
    public void Dispose_is_idempotent()
    {
        var db = new HostsDatabase(DbPath("dispose-twice.db"));
        db.Dispose();
        Action second = () => db.Dispose();
        second.Should().NotThrow();
    }

    [Fact]
    public void Coordinator_path_reads_and_writes_throw_ObjectDisposedException_after_dispose()
    {
        // NET-167: the background coordinators (SecureRulesGuard/ScheduleEnforcer/
        // TempAllowScheduler) hit these methods; after dispose they must fail fast
        // with a typed exception that those coordinators swallow, not an opaque
        // SQLite error on a background thread.
        var db = new HostsDatabase(DbPath("disposed-guard.db"));
        db.Dispose();

        ((Action)(() => db.LogEvent("x.com", "blocked"))).Should().Throw<ObjectDisposedException>();
        ((Action)(() => db.GetFwState())).Should().Throw<ObjectDisposedException>();
        ((Action)(() => db.GetFwStateNames())).Should().Throw<ObjectDisposedException>();
        ((Action)(() => db.GetSchedules())).Should().Throw<ObjectDisposedException>();
        ((Action)(() => db.GetTempAllows())).Should().Throw<ObjectDisposedException>();
    }
}
