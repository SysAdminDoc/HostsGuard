using Dapper;
using FluentAssertions;
using HostsGuard.Data;
using Microsoft.Data.Sqlite;
using Xunit;

namespace HostsGuard.Data.Tests;

/// <summary>
/// NET-053: a real v3.x-shaped Python profile (legacy-column database +
/// config.json + doh_resolvers.json + backups) imports with zero data loss;
/// dry-run changes nothing; the import is one-shot; an existing target
/// database is never overwritten.
/// </summary>
public sealed class PythonMigrationTests : IDisposable
{
    private readonly string _root = Directory.CreateTempSubdirectory("hg_mig_").FullName;

    private string Source => Path.Combine(_root, "appdata");

    private string Target => Path.Combine(_root, "programdata");

    public PythonMigrationTests()
    {
        Directory.CreateDirectory(Source);
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        try { Directory.Delete(_root, true); } catch (IOException) { /* best effort */ }
    }

    /// <summary>A pre-versioning Python database with legacy column names.</summary>
    private void WritePythonDb()
    {
        var path = Path.Combine(Source, "hostsguard.db");
        using var conn = new SqliteConnection($"Data Source={path}");
        conn.Open();
        conn.Execute(
            """
            CREATE TABLE domains(
                domain TEXT PRIMARY KEY, status TEXT DEFAULT 'blocked', category TEXT, source TEXT,
                date_added TEXT, date_modified TEXT, hit_count INTEGER DEFAULT 0, notes TEXT);
            INSERT INTO domains(domain,status,source,date_added,date_modified,hit_count)
                VALUES('ads.legacy.com','blocked','manual','2025-01-01','2025-01-01',7);
            INSERT INTO domains(domain,status,source,date_added,date_modified,hit_count)
                VALUES('keep.legacy.com','whitelisted','manual','2025-01-01','2025-01-01',0);
            CREATE TABLE log(id INTEGER PRIMARY KEY, timestamp TEXT, domain TEXT, action TEXT, process_name TEXT, details TEXT);
            """);
        SqliteConnection.ClearAllPools();
    }

    private void WritePythonConfig()
        => File.WriteAllText(Path.Combine(Source, "config.json"),
            """
            {
              "theme": "dark",
              "schedules": [{"target": "youtube.com", "days": [0,1,2,3,4], "start": "09:00", "end": "17:00"}],
              "temp_allows": {"cdn.example.com": 1893456000},
              "allowlist_subscriptions": ["https://lists.example/allow.txt"],
              "blocklist_subscriptions": ["AdAway", "Unknown List"]
            }
            """);

    [Fact]
    public void Full_profile_imports_with_zero_data_loss()
    {
        WritePythonDb();
        WritePythonConfig();
        File.WriteAllText(Path.Combine(Source, "doh_resolvers.json"), """{"schema":1,"ips":["203.0.113.53"]}""");
        Directory.CreateDirectory(Path.Combine(Source, "backups"));
        File.WriteAllText(Path.Combine(Source, "backups", "hosts_20250101.bak"), "# old backup");

        var report = PythonMigration.Run(Source, Target, dryRun: false);

        report.AlreadyMigrated.Should().BeFalse();
        report.Domains.Should().Be(2);
        report.Schedules.Should().Be(1);
        report.TempAllows.Should().Be(1);
        report.AllowlistUrls.Should().Be(1);
        report.BlocklistSubs.Should().Be(1); // "Unknown List" isn't in the catalog
        report.BackupsCopied.Should().Be(1);

        using var db = new HostsDatabase(Path.Combine(Target, "hostsguard.db"));
        db.GetDomains().Should().HaveCount(2);
        db.GetDomains(status: "blocked").Should().ContainSingle(d => d.Domain == "ads.legacy.com" && d.Hits == 7);
        db.GetDomainStatus("keep.legacy.com").Should().Be("whitelisted");
        db.GetSchedules().Should().ContainSingle(s => s.Target == "youtube.com" && s.Days == "0,1,2,3,4");
        db.GetTempAllows().Should().ContainSingle(t => t.Domain == "cdn.example.com");
        db.GetAllowlistSubs().Should().ContainSingle().Which.Should().Be("https://lists.example/allow.txt");
        db.GetBlocklistSubs().Should().ContainSingle(b => b.Name == "AdAway");
        File.Exists(Path.Combine(Target, "doh_resolvers.json")).Should().BeTrue();
        File.Exists(Path.Combine(Target, "backups", "hosts_20250101.bak")).Should().BeTrue();
    }

    [Fact]
    public void Dry_run_reports_but_changes_nothing()
    {
        WritePythonDb();
        WritePythonConfig();

        var report = PythonMigration.Run(Source, Target, dryRun: true);

        report.Schedules.Should().Be(1);
        report.TempAllows.Should().Be(1);
        Directory.Exists(Target).Should().BeFalse();
    }

    [Fact]
    public void Migration_is_one_shot()
    {
        WritePythonDb();
        WritePythonConfig();
        PythonMigration.Run(Source, Target, dryRun: false);

        var second = PythonMigration.Run(Source, Target, dryRun: false);

        second.AlreadyMigrated.Should().BeTrue();
    }

    [Fact]
    public void Existing_target_database_is_never_overwritten()
    {
        WritePythonDb();
        Directory.CreateDirectory(Target);
        using (var existing = new HostsDatabase(Path.Combine(Target, "hostsguard.db")))
        {
            existing.AddDomain("mine.example.com", "blocked", "manual");
        }

        var report = PythonMigration.Run(Source, Target, dryRun: false);

        report.Actions.Should().Contain(a => a.Contains("already exists"));
        using var db = new HostsDatabase(Path.Combine(Target, "hostsguard.db"));
        db.GetDomainStatus("mine.example.com").Should().Be("blocked");
        db.GetDomainStatus("ads.legacy.com").Should().BeNull(); // source DB not merged over it
    }
}
