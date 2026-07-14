using System.Text.Json;
using HostsGuard.Core;
using Microsoft.Data.Sqlite;

namespace HostsGuard.Data;

/// <summary>What a migration run did (or would do, in dry-run).</summary>
public sealed record MigrationReport(
    bool DryRun,
    bool AlreadyMigrated,
    IReadOnlyList<string> Actions,
    int Domains,
    int Schedules,
    int TempAllows,
    int AllowlistUrls,
    int BlocklistSubs,
    int BackupsCopied);

/// <summary>
/// One-shot import of a Python-era HostsGuard profile (%APPDATA%\HostsGuard)
/// into the .NET service data dir (%ProgramData%\HostsGuard): hostsguard.db
/// (the schema migrator upgrades it in place), config.json schedules /
/// temp_allows / allowlist+blocklist subscriptions, doh_resolvers.json, and
/// backups. Firewall HG_ rules re-discover live via COM, so they carry over
/// automatically. The target database is never overwritten, and a completed
/// migration is recorded so the import can only run once.
/// </summary>
public static class PythonMigration
{
    public static MigrationReport Run(string sourceDir, string targetDir, bool dryRun)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sourceDir);
        ArgumentException.ThrowIfNullOrWhiteSpace(targetDir);
        var actions = new List<string>();
        var targetDb = Path.Combine(targetDir, "hostsguard.db");
        var sourceDb = Path.Combine(sourceDir, "hostsguard.db");

        // One-shot guard.
        if (File.Exists(targetDb))
        {
            using var probe = new HostsDatabase(targetDb);
            if (probe.GetMeta("migrated_from_python") is not null)
            {
                return new MigrationReport(dryRun, true, new[] { "already migrated — nothing to do" }, 0, 0, 0, 0, 0, 0);
            }
        }

        if (!dryRun)
        {
            Directory.CreateDirectory(targetDir);
        }

        // 1. Database: copy only when the target has none (never clobber).
        if (File.Exists(sourceDb) && !File.Exists(targetDb))
        {
            actions.Add($"copy {sourceDb} -> {targetDb} (schema auto-upgrades on open)");
            if (!dryRun)
            {
                File.Copy(sourceDb, targetDb);
                foreach (var suffix in new[] { "-wal", "-shm" })
                {
                    if (File.Exists(sourceDb + suffix))
                    {
                        File.Copy(sourceDb + suffix, targetDb + suffix, overwrite: true);
                    }
                }
            }
        }
        else if (File.Exists(targetDb))
        {
            actions.Add("target database already exists — importing config state only");
        }
        else
        {
            actions.Add("no Python database found — importing config state only");
        }

        // 2. Config-held state → DB tables.
        var schedules = 0;
        var tempAllows = 0;
        var allowlists = 0;
        var blocklists = 0;
        var configPath = Path.Combine(sourceDir, "config.json");
        JsonElement config = default;
        var hasConfig = false;
        if (File.Exists(configPath))
        {
            try
            {
                using var doc = JsonDocument.Parse(File.ReadAllText(configPath));
                config = doc.RootElement.Clone();
                hasConfig = config.ValueKind == JsonValueKind.Object;
            }
            catch (JsonException)
            {
                actions.Add("config.json is unreadable — skipped");
            }
        }

        HostsDatabase? db = null;
        try
        {
            if (!dryRun)
            {
                db = new HostsDatabase(targetDb);
            }

            if (hasConfig)
            {
                // schedules: [{target, days[], start, end}]
                if (config.TryGetProperty("schedules", out var sch) && sch.ValueKind == JsonValueKind.Array)
                {
                    var rows = new List<(string, string, string, string)>();
                    foreach (var s in sch.EnumerateArray())
                    {
                        var target = s.TryGetProperty("target", out var t) ? t.GetString() ?? "" : "";
                        if (target.Length == 0)
                        {
                            continue;
                        }

                        var days = s.TryGetProperty("days", out var d) && d.ValueKind == JsonValueKind.Array
                            ? string.Join(",", d.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.Number).Select(x => x.GetInt32()))
                            : "";
                        rows.Add((target,
                            days,
                            s.TryGetProperty("start", out var st) ? st.GetString() ?? "00:00" : "00:00",
                            s.TryGetProperty("end", out var en) ? en.GetString() ?? "00:00" : "00:00"));
                    }

                    schedules = rows.Count;
                    actions.Add($"import {schedules} schedules");
                    db?.SetSchedules(rows);
                }

                // temp_allows: {domain: unix_epoch_seconds}
                if (config.TryGetProperty("temp_allows", out var ta) && ta.ValueKind == JsonValueKind.Object)
                {
                    foreach (var kv in ta.EnumerateObject())
                    {
                        if (kv.Value.ValueKind == JsonValueKind.Number && Domains.LooksLikeDomain(kv.Name))
                        {
                            tempAllows++;
                            db?.SetTempAllow(kv.Name, DateTimeOffset.FromUnixTimeSeconds((long)kv.Value.GetDouble()).UtcDateTime);
                        }
                    }

                    actions.Add($"import {tempAllows} temp-allow windows (expiries re-arm on service start)");
                }

                // allowlist_subscriptions: [url]
                if (config.TryGetProperty("allowlist_subscriptions", out var al) && al.ValueKind == JsonValueKind.Array)
                {
                    var urls = al.EnumerateArray()
                        .Where(u => u.ValueKind == JsonValueKind.String)
                        .Select(u => u.GetString() ?? "")
                        .Where(u => u.StartsWith("https://", StringComparison.Ordinal))
                        .ToList();
                    allowlists = urls.Count;
                    actions.Add($"import {allowlists} allowlist subscriptions");
                    db?.SetAllowlistSubs(urls);
                }

                // blocklist_subscriptions: [catalog name] → resolved to catalog URLs
                if (config.TryGetProperty("blocklist_subscriptions", out var bl) && bl.ValueKind == JsonValueKind.Array)
                {
                    foreach (var n in bl.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.String))
                    {
                        var name = n.GetString() ?? "";
                        var source = BlocklistCatalog.Sources.FirstOrDefault(s => s.Name == name);
                        if (source is not null)
                        {
                            blocklists++;
                            db?.UpsertBlocklistSub(source.Name, source.Url, 0);
                        }
                    }

                    actions.Add($"import {blocklists} blocklist subscriptions");
                }
            }

            var domainCount = dryRun && File.Exists(sourceDb) && !File.Exists(targetDb)
                ? CountDomainsReadOnly(sourceDb)
                : 0;
            if (db is not null)
            {
                domainCount = db.GetDomains().Count;
                db.SetMeta("migrated_from_python", DateTime.Now.ToString("o", System.Globalization.CultureInfo.InvariantCulture));
            }

            // 3. doh_resolvers.json — copied verbatim (same schema).
            var dohSource = Path.Combine(sourceDir, "doh_resolvers.json");
            var dohTarget = Path.Combine(targetDir, "doh_resolvers.json");
            if (File.Exists(dohSource) && !File.Exists(dohTarget))
            {
                actions.Add("copy doh_resolvers.json");
                if (!dryRun)
                {
                    File.Copy(dohSource, dohTarget);
                }
            }

            // 4. Backups.
            var backups = 0;
            var backupSource = Path.Combine(sourceDir, "backups");
            if (Directory.Exists(backupSource))
            {
                var targetBackups = Path.Combine(targetDir, "backups");
                foreach (var file in Directory.EnumerateFiles(backupSource))
                {
                    var destination = Path.Combine(targetBackups, Path.GetFileName(file));
                    if (File.Exists(destination))
                    {
                        continue;
                    }

                    backups++;
                    if (!dryRun)
                    {
                        Directory.CreateDirectory(targetBackups);
                        File.Copy(file, destination);
                    }
                }

                actions.Add($"copy {backups} backups");
            }

            return new MigrationReport(dryRun, false, actions, domainCount, schedules, tempAllows, allowlists, blocklists, backups);
        }
        finally
        {
            db?.Dispose();
        }
    }

    private static int CountDomainsReadOnly(string databasePath)
    {
        var builder = new SqliteConnectionStringBuilder
        {
            DataSource = databasePath,
            Mode = SqliteOpenMode.ReadOnly,
            Pooling = false
        };
        using var connection = new SqliteConnection(builder.ConnectionString);
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM domains";
        return Convert.ToInt32(command.ExecuteScalar(), System.Globalization.CultureInfo.InvariantCulture);
    }
}
