using Dapper;
using HostsGuard.Core;
using Microsoft.Data.Sqlite;

namespace HostsGuard.Data;

/// <summary>A managed domain row.</summary>
public sealed record ManagedDomainRow(
    string Domain, string Status, string? Category, string? Source,
    string? Added, string? Modified, long Hits, string? Notes, string? Reason);

/// <summary>Aggregate counts for the dashboard.</summary>
public sealed record DomainStats(int Blocked, int Whitelisted, int FeedTotal, int TodayHits);

/// <summary>A DNS activity feed row, joined with the managed-domain status.</summary>
public sealed record FeedRow(
    string Domain, string? FirstSeen, string? LastSeen, long Hits,
    string? Process, long Hidden, string? Reason, string? Status);

/// <summary>A DNS sighting queued for batched feed/hourly persistence.</summary>
public sealed record DnsSightingWrite(string Domain, string Process, string? Reason, DateTime SeenAt);

/// <summary>A tracked HostsGuard firewall rule, for the Secure-Rules reconcile.</summary>
public sealed record FwStateRow(
    string Name,
    string? Direction,
    string? Action,
    string? RemoteAddr,
    string? Protocol,
    string? Program,
    string? RemotePorts,
    string? LocalPorts,
    string? ServiceName,
    string? Interfaces,
    string? PackageFamilyName,
    string? PackageSid,
    string? PackageDisplayName,
    string? PackageFullName,
    string? PackageBinaries);

/// <summary>An opt-in app-to-adapter policy (NET-157).</summary>
public sealed record AppVpnBindingRow(
    string Program,
    string Adapter,
    string RuleName,
    string Created,
    string Updated);

/// <summary>A domain-scoped firewall rule intent (reactive DNS answers -> HG_Domain_* rule).</summary>
public sealed record DomainFirewallRuleRow(
    string Domain,
    string Program,
    string RuleName,
    string Action,
    bool Enabled,
    string RemoteAddr,
    string Updated,
    string Created);

/// <summary>Current full Windows Firewall rule snapshot row (report-only baseline).</summary>
public sealed class FirewallRuleSnapshotRow
{
    public string Name { get; set; } = string.Empty;

    public string Direction { get; set; } = string.Empty;

    public string Action { get; set; } = string.Empty;

    public bool Enabled { get; set; }

    public string RemoteAddr { get; set; } = string.Empty;

    public string Protocol { get; set; } = string.Empty;

    public string Program { get; set; } = string.Empty;

    public string Source { get; set; } = string.Empty;

    public string RemotePorts { get; set; } = string.Empty;

    public string LocalPorts { get; set; } = string.Empty;

    public string ServiceName { get; set; } = string.Empty;

    public string Interfaces { get; set; } = string.Empty;

    public string PackageFamilyName { get; set; } = string.Empty;

    public string PackageSid { get; set; } = string.Empty;

    public string PackageDisplayName { get; set; } = string.Empty;

    public string PackageFullName { get; set; } = string.Empty;

    public string PackageBinaries { get; set; } = string.Empty;

    public string Hash { get; set; } = string.Empty;

    public bool Present { get; set; }

    public string FirstSeen { get; set; } = string.Empty;

    public string LastSeen { get; set; } = string.Empty;

    public string ChangedAt { get; set; } = string.Empty;

    public string ChangeKind { get; set; } = string.Empty;

    public string ChangeDetail { get; set; } = string.Empty;
}

/// <summary>One detected full-firewall baseline change.</summary>
public sealed record FirewallRuleDriftRow(
    string Name,
    string ChangeKind,
    string Source,
    string Direction,
    string Action,
    bool Enabled,
    string RemoteAddr,
    string Protocol,
    string Program,
    string RemotePorts,
    string LocalPorts,
    string ServiceName,
    string Interfaces,
    string PackageFamilyName,
    string PackageSid,
    string PackageDisplayName,
    string PackageFullName,
    string PackageBinaries,
    string Details);

/// <summary>A recorded (historical) connection sighting (NET-070).</summary>
public sealed record ConnHistoryRow(
    string Ts, string Process, long Pid, string Protocol,
    string RemoteAddr, long RemotePort, string Country, string FwStatus,
    string Host = "");

public sealed record ConnectionHistoryFilter(
    int Limit = 500,
    int Offset = 0,
    string? Search = null,
    string? Since = null,
    string? Until = null,
    string? Process = null,
    string? Host = null,
    string? RemoteAddr = null,
    string? FwStatus = null,
    string? Protocol = null);

public sealed record ConnectionHistoryPage(
    IReadOnlyList<ConnHistoryRow> Rows,
    int Total,
    int Limit,
    int Offset);

/// <summary>A per-process per-minute bandwidth bucket (NET-070).</summary>
public sealed record BandwidthRow(string Process, string Minute, long Sent, long Recv);

/// <summary>A per-day per-process per-domain data-usage rollup (NET-158).</summary>
public sealed record UsageRollupRow(string Day, string Process, string Domain, long Sent, long Recv);

/// <summary>A raw append-only ledger row.</summary>
public sealed record LogEventRow(
    string Ts,
    string Domain,
    string Action,
    string Process,
    string Details,
    string Reason,
    string FilterRuntimeId = "",
    string FilterOrigin = "",
    string LayerName = "",
    string LayerRuntimeId = "",
    long InterfaceIndex = 0,
    string InterfaceName = "")
{
    public void Deconstruct(
        out string Ts,
        out string Domain,
        out string Action,
        out string Process,
        out string Details,
        out string Reason)
    {
        Ts = this.Ts;
        Domain = this.Domain;
        Action = this.Action;
        Process = this.Process;
        Details = this.Details;
        Reason = this.Reason;
    }
}

/// <summary>A persisted event-log row with its derived taxonomy category.</summary>
public sealed record EventLogRow(
    long Id,
    string Ts,
    string Domain,
    string Action,
    string Process,
    string Details,
    string Reason,
    string Category,
    string FilterRuntimeId = "",
    string FilterOrigin = "",
    string LayerName = "",
    string LayerRuntimeId = "",
    int InterfaceIndex = 0,
    string InterfaceName = "");

/// <summary>Filter and paging shape for the persisted event ledger.</summary>
public sealed record EventLogFilter(
    int Limit = 200,
    int Offset = 0,
    string? Search = null,
    string? Since = null,
    string? Until = null,
    string? Action = null,
    string? Reason = null,
    string? Domain = null,
    string? Process = null,
    string? Category = null);

/// <summary>A page of filtered event-log rows plus the total matching count.</summary>
public sealed record EventLogPage(IReadOnlyList<EventLogRow> Rows, int Total);

/// <summary>A stateful operator alert row, distinct from the append-only event ledger.</summary>
public sealed record AlertRow(
    long Id,
    string Created,
    string Updated,
    string Type,
    string Severity,
    string Title,
    string Subject,
    string Details,
    string Action,
    string Process,
    bool IsRead,
    bool Surfaced);

/// <summary>Filter and paging shape for the stateful alert inbox.</summary>
public sealed record AlertFilter(
    int Limit = 200,
    int Offset = 0,
    bool IncludeRead = false,
    bool SurfaceOnly = true,
    string? Type = null);

/// <summary>A page of filtered alerts plus unread counts.</summary>
public sealed record AlertPage(IReadOnlyList<AlertRow> Rows, int Total, int Unread);

/// <summary>One alert type's current surfacing mode and unread count.</summary>
public sealed record AlertTypeRow(string Type, string Label, bool Surface, int Unread);

/// <summary>Rows deleted by a retention sweep plus whether SQLite maintenance ran.</summary>
public sealed record RetentionSweepResult(
    int LogRows,
    int ResolvedHosts,
    int DomainUsageRows,
    int BandwidthBuckets,
    int UsageDailyRows,
    int HourlyBuckets,
    bool MaintenanceRan);

/// <summary>A subscribed blocklist source plus source-owned domain count.</summary>
public sealed record BlocklistSubRow(
    string Name,
    string Url,
    string LastRefresh,
    long DomainCount,
    bool Enabled,
    long OwnedDomainCount,
    long Hits30d,
    string ContentHash,
    string PreviousHash,
    long PreviousDomainCount,
    string LastError,
    string LastErrorAt,
    string HealthStatus,
    long LastCheckpointId,
    string LastAttemptHash,
    long LastAttemptDomainCount);

/// <summary>Rollback result for removing one blocklist source.</summary>
public sealed record BlocklistRemoval(long Removed, long Preserved);

/// <summary>Stored pre-refresh checkpoint for one blocklist source.</summary>
public sealed record BlocklistCheckpointRow(
    long Id,
    string Source,
    string Created,
    string Url,
    string PreviousHash,
    long PreviousDomainCount,
    string NewHash,
    long NewDomainCount,
    string Reason);

/// <summary>Result of restoring a blocklist refresh checkpoint.</summary>
public sealed record BlocklistCheckpointRestore(long CheckpointId, long Restored, long Removed, long Preserved);

/// <summary>Checkpoint captured immediately before a broad portable-policy import.</summary>
public sealed record PolicyImportCheckpointRow(long Id, string Created, string Json, string Summary);

/// <summary>
/// SQLite persistence for HostsGuard (Microsoft.Data.Sqlite + Dapper). Schema v1
/// mirrors the Python schema v7 (domains/feed/log/fw_state/profiles + canonical
/// reason columns) and includes the legacy column-rename migration so a
/// pre-versioning database opens without data loss. WAL, busy_timeout, and an
/// integrity check run on open. The path is injectable for testability.
/// </summary>
public sealed partial class HostsDatabase : IDisposable
{
    public const int SchemaVersion = 27;

    /// <summary>Default connection-history / bandwidth retention (days).</summary>
    public const int DefaultHistoryRetentionDays = 30;

    private const int IncrementalVacuumPages = 256;
    private static readonly TimeSpan RetentionMaintenanceInterval = TimeSpan.FromHours(6);

    private readonly SqliteConnection _conn;
    private readonly object _gate = new();
    private bool _disposed;

    public HostsDatabase(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        var dir = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(dir))
        {
            Directory.CreateDirectory(dir);
        }

        _conn = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = path,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Shared,
        }.ToString());
        _conn.Open();
        _conn.Execute("PRAGMA busy_timeout=5000;");
        IntegrityCheck();
        EnsureIncrementalAutoVacuum();
        _conn.Execute("PRAGMA journal_mode=WAL;");
        Migrate();
    }

    private void IntegrityCheck()
    {
        var result = _conn.ExecuteScalar<string>("PRAGMA integrity_check");
        if (result is not null && result != "ok")
        {
            throw new InvalidOperationException($"Database integrity check failed: {result}");
        }
    }

    private void Migrate()
    {
        _conn.Execute("CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT)");
        RenameLegacyColumns();

        _conn.Execute(
            """
            CREATE TABLE IF NOT EXISTS domains(
                domain TEXT PRIMARY KEY, status TEXT DEFAULT 'blocked', category TEXT, source TEXT,
                added TEXT, modified TEXT, hits INTEGER DEFAULT 0, notes TEXT, reason TEXT);
            CREATE TABLE IF NOT EXISTS feed(
                domain TEXT PRIMARY KEY, first_seen TEXT, last_seen TEXT, hits INTEGER DEFAULT 1,
                process TEXT, hidden INTEGER DEFAULT 0, reason TEXT);
            CREATE TABLE IF NOT EXISTS log(
                id INTEGER PRIMARY KEY, ts TEXT, domain TEXT, action TEXT, process TEXT, details TEXT, reason TEXT,
                filter_runtime_id TEXT DEFAULT '', filter_origin TEXT DEFAULT '', layer_name TEXT DEFAULT '',
                layer_runtime_id TEXT DEFAULT '', interface_index INTEGER DEFAULT 0, interface_name TEXT DEFAULT '');
            CREATE INDEX IF NOT EXISTS idx_log_ts ON log(ts);
            CREATE INDEX IF NOT EXISTS idx_feed_ls ON feed(last_seen);
            CREATE TABLE IF NOT EXISTS fw_state(
                name TEXT PRIMARY KEY, direction TEXT, action TEXT, remote_addr TEXT, protocol TEXT,
                program TEXT, remote_ports TEXT, local_ports TEXT, service_name TEXT, interfaces TEXT,
                package_family_name TEXT, package_sid TEXT, package_display_name TEXT,
                package_full_name TEXT, package_binaries TEXT, created TEXT);
            CREATE TABLE IF NOT EXISTS app_vpn_bindings(
                program TEXT PRIMARY KEY, adapter TEXT NOT NULL, rule_name TEXT NOT NULL,
                created TEXT, updated TEXT);
            CREATE TABLE IF NOT EXISTS domain_firewall_rules(
                rule_name TEXT PRIMARY KEY, domain TEXT NOT NULL, program TEXT NOT NULL DEFAULT '',
                action TEXT NOT NULL DEFAULT 'Block', enabled INTEGER DEFAULT 1,
                remote_addr TEXT NOT NULL DEFAULT '', updated TEXT, created TEXT,
                UNIQUE(domain, program));
            CREATE INDEX IF NOT EXISTS idx_domain_firewall_rules_domain ON domain_firewall_rules(domain);
            CREATE TABLE IF NOT EXISTS firewall_rule_snapshot(
                name TEXT PRIMARY KEY, direction TEXT, action TEXT, enabled INTEGER DEFAULT 0,
                remote_addr TEXT, protocol TEXT, program TEXT, source TEXT, remote_ports TEXT, local_ports TEXT, service_name TEXT, interfaces TEXT,
                package_family_name TEXT, package_sid TEXT, package_display_name TEXT, package_full_name TEXT, package_binaries TEXT,
                hash TEXT, present INTEGER DEFAULT 1, first_seen TEXT, last_seen TEXT, changed_at TEXT,
                change_kind TEXT DEFAULT '', change_detail TEXT DEFAULT '');
            CREATE INDEX IF NOT EXISTS idx_firewall_rule_snapshot_present ON firewall_rule_snapshot(present);
            CREATE INDEX IF NOT EXISTS idx_firewall_rule_snapshot_changed ON firewall_rule_snapshot(changed_at);
            CREATE TABLE IF NOT EXISTS profiles(name TEXT PRIMARY KEY, created TEXT);
            CREATE TABLE IF NOT EXISTS profile_rules(
                id INTEGER PRIMARY KEY, profile TEXT, domain TEXT, status TEXT DEFAULT 'blocked', source TEXT);
            CREATE TABLE IF NOT EXISTS hidden_roots(root TEXT PRIMARY KEY, added TEXT);
            CREATE TABLE IF NOT EXISTS temp_allows(domain TEXT PRIMARY KEY, expires TEXT);
            CREATE TABLE IF NOT EXISTS schedules(
                id INTEGER PRIMARY KEY, target TEXT, days TEXT, start TEXT, end TEXT);
            CREATE TABLE IF NOT EXISTS blocklist_subs(
                name TEXT PRIMARY KEY, url TEXT, last_refresh TEXT, domain_count INTEGER DEFAULT 0,
                enabled INTEGER DEFAULT 1, content_hash TEXT DEFAULT '', previous_hash TEXT DEFAULT '',
                previous_domain_count INTEGER DEFAULT 0, last_error TEXT DEFAULT '',
                last_error_at TEXT DEFAULT '', health_status TEXT DEFAULT '',
                last_checkpoint_id INTEGER DEFAULT 0, last_attempt_hash TEXT DEFAULT '',
                last_attempt_domain_count INTEGER DEFAULT 0);
            CREATE TABLE IF NOT EXISTS blocklist_domain_sources(
                source TEXT NOT NULL, domain TEXT NOT NULL,
                PRIMARY KEY(source, domain)) WITHOUT ROWID;
            CREATE INDEX IF NOT EXISTS idx_blocklist_domain_sources_domain ON blocklist_domain_sources(domain);
            CREATE TABLE IF NOT EXISTS blocklist_refresh_checkpoints(
                id INTEGER PRIMARY KEY, source TEXT NOT NULL, created TEXT, url TEXT,
                previous_hash TEXT, previous_domain_count INTEGER DEFAULT 0,
                new_hash TEXT, new_domain_count INTEGER DEFAULT 0, reason TEXT);
            CREATE INDEX IF NOT EXISTS idx_blocklist_refresh_checkpoints_source ON blocklist_refresh_checkpoints(source, id DESC);
            CREATE TABLE IF NOT EXISTS blocklist_refresh_checkpoint_domains(
                checkpoint_id INTEGER NOT NULL, domain TEXT NOT NULL,
                PRIMARY KEY(checkpoint_id, domain)) WITHOUT ROWID;
            CREATE INDEX IF NOT EXISTS idx_blocklist_refresh_checkpoint_domains_domain ON blocklist_refresh_checkpoint_domains(domain);
            CREATE TABLE IF NOT EXISTS allowlist_subs(url TEXT PRIMARY KEY);
            CREATE TABLE IF NOT EXISTS feed_hourly(
                root TEXT, hour TEXT, hits INTEGER DEFAULT 0, PRIMARY KEY(root, hour));
            CREATE INDEX IF NOT EXISTS idx_feed_hourly_hour ON feed_hourly(hour);
            CREATE TABLE IF NOT EXISTS feed_domain_hourly(
                domain TEXT, hour TEXT, hits INTEGER DEFAULT 0, PRIMARY KEY(domain, hour)) WITHOUT ROWID;
            CREATE INDEX IF NOT EXISTS idx_feed_domain_hourly_hour ON feed_domain_hourly(hour);
            CREATE TABLE IF NOT EXISTS conn_history(
                id INTEGER PRIMARY KEY, ts TEXT, process TEXT, pid INTEGER, protocol TEXT,
                remote_addr TEXT, remote_port INTEGER, country TEXT, fw_status TEXT,
                host TEXT DEFAULT '');
            CREATE INDEX IF NOT EXISTS idx_conn_history_ts ON conn_history(ts);
            CREATE INDEX IF NOT EXISTS idx_conn_history_process ON conn_history(process);
            CREATE TABLE IF NOT EXISTS app_bandwidth(
                process TEXT, minute TEXT, sent INTEGER DEFAULT 0, recv INTEGER DEFAULT 0,
                PRIMARY KEY(process, minute));
            CREATE INDEX IF NOT EXISTS idx_app_bandwidth_minute ON app_bandwidth(minute);
            CREATE TABLE IF NOT EXISTS network_profiles(
                fingerprint TEXT PRIMARY KEY, profile TEXT, label TEXT);
            CREATE TABLE IF NOT EXISTS list_index(
                domain TEXT NOT NULL, list TEXT NOT NULL,
                PRIMARY KEY(domain, list)) WITHOUT ROWID;
            CREATE INDEX IF NOT EXISTS idx_list_index_list ON list_index(list);
            CREATE TABLE IF NOT EXISTS ai_knowledge(
                kind TEXT NOT NULL, key TEXT NOT NULL, value TEXT, model TEXT, created TEXT,
                PRIMARY KEY(kind, key)) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS resolved_hosts(
                ip TEXT PRIMARY KEY, host TEXT, source TEXT, updated TEXT) WITHOUT ROWID;
            CREATE INDEX IF NOT EXISTS idx_resolved_hosts_updated ON resolved_hosts(updated);
            CREATE TABLE IF NOT EXISTS user_overrides(
                kind TEXT NOT NULL, key TEXT NOT NULL, value TEXT, created TEXT,
                PRIMARY KEY(kind, key)) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS adopted_rules(
                name TEXT PRIMARY KEY, direction TEXT, action TEXT, remote_addr TEXT,
                protocol TEXT, program TEXT, enabled INTEGER DEFAULT 1, adopted_at TEXT);
            CREATE TABLE IF NOT EXISTS domain_usage(
                domain TEXT NOT NULL, process TEXT NOT NULL DEFAULT '',
                sent INTEGER DEFAULT 0, recv INTEGER DEFAULT 0, updated TEXT,
                PRIMARY KEY(domain, process)) WITHOUT ROWID;
            CREATE INDEX IF NOT EXISTS idx_domain_usage_updated ON domain_usage(updated);
            CREATE TABLE IF NOT EXISTS usage_daily(
                day TEXT NOT NULL, process TEXT NOT NULL DEFAULT '', domain TEXT NOT NULL,
                sent INTEGER DEFAULT 0, recv INTEGER DEFAULT 0,
                PRIMARY KEY(day, process, domain)) WITHOUT ROWID;
            CREATE INDEX IF NOT EXISTS idx_usage_daily_day ON usage_daily(day);
            CREATE INDEX IF NOT EXISTS idx_usage_daily_process ON usage_daily(process);
            CREATE INDEX IF NOT EXISTS idx_usage_daily_domain ON usage_daily(domain);
            CREATE TABLE IF NOT EXISTS rule_groups(
                grp TEXT NOT NULL, rule_name TEXT NOT NULL,
                PRIMARY KEY(grp, rule_name)) WITHOUT ROWID;
            CREATE INDEX IF NOT EXISTS idx_rule_groups_rule ON rule_groups(rule_name);
            CREATE TABLE IF NOT EXISTS alerts(
                id INTEGER PRIMARY KEY, created TEXT, updated TEXT, type TEXT, severity TEXT,
                title TEXT, subject TEXT, details TEXT, action TEXT, process TEXT,
                source_event_id INTEGER DEFAULT 0, is_read INTEGER DEFAULT 0, surfaced INTEGER DEFAULT 1);
            CREATE INDEX IF NOT EXISTS idx_alerts_read_created ON alerts(is_read, created);
            CREATE INDEX IF NOT EXISTS idx_alerts_type_subject ON alerts(type, subject, action, is_read);
            CREATE TABLE IF NOT EXISTS alert_type_settings(
                type TEXT PRIMARY KEY, label TEXT, surface INTEGER DEFAULT 1);
            CREATE TABLE IF NOT EXISTS policy_import_checkpoints(
                id INTEGER PRIMARY KEY, created TEXT, json TEXT NOT NULL, summary TEXT);
            """);

        // Add reason columns to tables that predate schema v7 but survived the rename.
        AddColumnIfMissing("domains", "reason", "TEXT");
        AddColumnIfMissing("feed", "reason", "TEXT");
        AddColumnIfMissing("log", "reason", "TEXT");
        AddColumnIfMissing("log", "filter_runtime_id", "TEXT DEFAULT ''");
        AddColumnIfMissing("log", "filter_origin", "TEXT DEFAULT ''");
        AddColumnIfMissing("log", "layer_name", "TEXT DEFAULT ''");
        AddColumnIfMissing("log", "layer_runtime_id", "TEXT DEFAULT ''");
        AddColumnIfMissing("log", "interface_index", "INTEGER DEFAULT 0");
        AddColumnIfMissing("log", "interface_name", "TEXT DEFAULT ''");
        AddColumnIfMissing("conn_history", "host", "TEXT DEFAULT ''");
        _conn.Execute("CREATE INDEX IF NOT EXISTS idx_conn_history_host ON conn_history(host);");
        _conn.Execute("CREATE INDEX IF NOT EXISTS idx_conn_history_remote ON conn_history(remote_addr);");
        AddColumnIfMissing("blocklist_subs", "enabled", "INTEGER DEFAULT 1");
        AddColumnIfMissing("blocklist_subs", "content_hash", "TEXT DEFAULT ''");
        AddColumnIfMissing("blocklist_subs", "previous_hash", "TEXT DEFAULT ''");
        AddColumnIfMissing("blocklist_subs", "previous_domain_count", "INTEGER DEFAULT 0");
        AddColumnIfMissing("blocklist_subs", "last_error", "TEXT DEFAULT ''");
        AddColumnIfMissing("blocklist_subs", "last_error_at", "TEXT DEFAULT ''");
        AddColumnIfMissing("blocklist_subs", "health_status", "TEXT DEFAULT ''");
        AddColumnIfMissing("blocklist_subs", "last_checkpoint_id", "INTEGER DEFAULT 0");
        AddColumnIfMissing("blocklist_subs", "last_attempt_hash", "TEXT DEFAULT ''");
        AddColumnIfMissing("blocklist_subs", "last_attempt_domain_count", "INTEGER DEFAULT 0");
        AddColumnIfMissing("fw_state", "remote_ports", "TEXT");
        AddColumnIfMissing("fw_state", "local_ports", "TEXT");
        AddColumnIfMissing("fw_state", "service_name", "TEXT");
        AddColumnIfMissing("fw_state", "interfaces", "TEXT");
        AddColumnIfMissing("fw_state", "package_family_name", "TEXT");
        AddColumnIfMissing("fw_state", "package_sid", "TEXT");
        AddColumnIfMissing("fw_state", "package_display_name", "TEXT");
        AddColumnIfMissing("fw_state", "package_full_name", "TEXT");
        AddColumnIfMissing("fw_state", "package_binaries", "TEXT");
        AddColumnIfMissing("firewall_rule_snapshot", "local_ports", "TEXT");
        AddColumnIfMissing("firewall_rule_snapshot", "interfaces", "TEXT");
        AddColumnIfMissing("firewall_rule_snapshot", "package_family_name", "TEXT");
        AddColumnIfMissing("firewall_rule_snapshot", "package_sid", "TEXT");
        AddColumnIfMissing("firewall_rule_snapshot", "package_display_name", "TEXT");
        AddColumnIfMissing("firewall_rule_snapshot", "package_full_name", "TEXT");
        AddColumnIfMissing("firewall_rule_snapshot", "package_binaries", "TEXT");
        _conn.Execute(
            """
            INSERT OR IGNORE INTO blocklist_domain_sources(source, domain)
            SELECT substr(source, 6), domain FROM domains
            WHERE source LIKE 'list:%' AND length(source) > 5
            """);

        _conn.Execute("INSERT OR REPLACE INTO meta(key,value) VALUES('schema_version',@v)", new { v = SchemaVersion.ToString() });
    }

    private void EnsureIncrementalAutoVacuum()
    {
        var mode = _conn.ExecuteScalar<long>("PRAGMA auto_vacuum");
        if (mode == 2)
        {
            return;
        }

        _conn.Execute("PRAGMA auto_vacuum=INCREMENTAL;");
        _conn.Execute("VACUUM;");

        mode = _conn.ExecuteScalar<long>("PRAGMA auto_vacuum");
        if (mode != 2)
        {
            throw new InvalidOperationException("SQLite incremental auto-vacuum could not be enabled.");
        }
    }

    private void RenameLegacyColumns()
    {
        // Pre-versioning databases used date_added/date_modified/hit_count (domains)
        // and timestamp/process_name (log). Rename in place so queries succeed.
        (string Table, string Old, string New)[] renames =
        {
            ("domains", "date_added", "added"),
            ("domains", "date_modified", "modified"),
            ("domains", "hit_count", "hits"),
            ("log", "timestamp", "ts"),
            ("log", "process_name", "process"),
        };

        foreach (var (table, oldCol, newCol) in renames)
        {
            var cols = Columns(table);
            if (cols.Contains(oldCol) && !cols.Contains(newCol))
            {
                _conn.Execute($"ALTER TABLE {table} RENAME COLUMN \"{oldCol}\" TO \"{newCol}\"");
            }
        }
    }

    private void AddColumnIfMissing(string table, string column, string type)
    {
        if (!Columns(table).Contains(column))
        {
            _conn.Execute($"ALTER TABLE {table} ADD COLUMN \"{column}\" {type}");
        }
    }

    private HashSet<string> Columns(string table)
    {
        var cols = _conn.Query<string>($"SELECT name FROM pragma_table_info(@t)", new { t = table });
        return new HashSet<string>(cols, StringComparer.Ordinal);
    }

    public DomainStats GetStats()
    {
        var today = DateTime.Now.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture);
        lock (_gate)
        {
            var blocked = _conn.ExecuteScalar<int>("SELECT COUNT(*) FROM domains WHERE status='blocked'");
            var wl = _conn.ExecuteScalar<int>("SELECT COUNT(*) FROM domains WHERE status='whitelisted'");
            var feed = _conn.ExecuteScalar<int>("SELECT COUNT(*) FROM feed WHERE hidden=0");
            var today_hits = _conn.ExecuteScalar<int>("SELECT COUNT(*) FROM log WHERE action='blocked' AND ts>=@t", new { t = today });
            return new DomainStats(blocked, wl, feed, today_hits);
        }
    }

    public int SchemaVersionOnDisk() =>
        int.TryParse(_conn.ExecuteScalar<string>("SELECT value FROM meta WHERE key='schema_version'"), out var v) ? v : 0;

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            _conn.Dispose();
            SqliteConnection.ClearPool(_conn);
            _disposed = true;
        }
    }
}
