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

/// <summary>
/// SQLite persistence for HostsGuard (Microsoft.Data.Sqlite + Dapper). Schema v1
/// mirrors the Python schema v7 (domains/feed/log/fw_state/profiles + canonical
/// reason columns) and includes the legacy column-rename migration so a
/// pre-versioning database opens without data loss. WAL, busy_timeout, and an
/// integrity check run on open. The path is injectable for testability.
/// </summary>
public sealed class HostsDatabase : IDisposable
{
    public const int SchemaVersion = 1;

    private readonly SqliteConnection _conn;
    private readonly object _gate = new();

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
        _conn.Execute("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;");
        IntegrityCheck();
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
                id INTEGER PRIMARY KEY, ts TEXT, domain TEXT, action TEXT, process TEXT, details TEXT, reason TEXT);
            CREATE INDEX IF NOT EXISTS idx_log_ts ON log(ts);
            CREATE INDEX IF NOT EXISTS idx_feed_ls ON feed(last_seen);
            CREATE TABLE IF NOT EXISTS fw_state(
                name TEXT PRIMARY KEY, direction TEXT, action TEXT, remote_addr TEXT, protocol TEXT,
                program TEXT, created TEXT);
            CREATE TABLE IF NOT EXISTS profiles(name TEXT PRIMARY KEY, created TEXT);
            CREATE TABLE IF NOT EXISTS profile_rules(
                id INTEGER PRIMARY KEY, profile TEXT, domain TEXT, status TEXT DEFAULT 'blocked', source TEXT);
            """);

        // Add reason columns to tables that predate schema v7 but survived the rename.
        AddColumnIfMissing("domains", "reason", "TEXT");
        AddColumnIfMissing("feed", "reason", "TEXT");
        AddColumnIfMissing("log", "reason", "TEXT");

        _conn.Execute("INSERT OR REPLACE INTO meta(key,value) VALUES('schema_version',@v)", new { v = SchemaVersion.ToString() });
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

    // ─── Domains ──────────────────────────────────────────────────────────────

    /// <summary>
    /// UPSERT a domain, preserving original added-date, notes, hits, and existing
    /// category, and never downgrading a whitelisted domain to blocked (allowlist wins).
    /// </summary>
    public void AddDomain(string domain, string status = "blocked", string source = "", string category = "", string? reason = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(domain);
        var now = DateTime.Now.ToString("o", System.Globalization.CultureInfo.InvariantCulture);
        var canonical = Reasons.Canonical(reason, source, status);
        lock (_gate)
        {
            _conn.Execute(
                """
                INSERT INTO domains(domain,status,category,source,added,modified,hits,reason)
                VALUES(@domain,@status,@category,@source,@now,@now,0,@reason)
                ON CONFLICT(domain) DO UPDATE SET
                    status=CASE WHEN domains.status='whitelisted' AND excluded.status='blocked' THEN 'whitelisted' ELSE excluded.status END,
                    modified=excluded.modified,
                    source=CASE WHEN excluded.source!='' THEN excluded.source ELSE domains.source END,
                    category=CASE WHEN excluded.category!='' THEN excluded.category ELSE domains.category END,
                    reason=excluded.reason
                """,
                new { domain = domain.ToLowerInvariant(), status, category, source, now, reason = canonical });
        }
    }

    /// <summary>Bulk UPSERT (domain,status,source) in one transaction; allowlist wins.</summary>
    public int AddDomainsBulk(IEnumerable<(string Domain, string Status, string Source)> rows)
    {
        ArgumentNullException.ThrowIfNull(rows);
        var list = rows.ToList();
        if (list.Count == 0)
        {
            return 0;
        }

        var now = DateTime.Now.ToString("o", System.Globalization.CultureInfo.InvariantCulture);
        lock (_gate)
        {
            using var tx = _conn.BeginTransaction();
            foreach (var (domain, status, source) in list)
            {
                _conn.Execute(
                    """
                    INSERT INTO domains(domain,status,category,source,added,modified,hits,reason)
                    VALUES(@domain,@status,'',@source,@now,@now,0,@reason)
                    ON CONFLICT(domain) DO UPDATE SET
                        status=CASE WHEN domains.status='whitelisted' AND excluded.status='blocked' THEN 'whitelisted' ELSE excluded.status END,
                        modified=excluded.modified,
                        source=CASE WHEN excluded.source!='' THEN excluded.source ELSE domains.source END
                    """,
                    new { domain = domain.ToLowerInvariant(), status, source, now, reason = Reasons.Canonical(null, source, status) },
                    tx);
            }

            tx.Commit();
        }

        return list.Count;
    }

    public IReadOnlyList<ManagedDomainRow> GetDomains(string? status = null, string? search = null, string? source = null)
    {
        var sql = "SELECT domain AS Domain, status AS Status, category AS Category, source AS Source, added AS Added, modified AS Modified, hits AS Hits, notes AS Notes, reason AS Reason FROM domains WHERE 1=1";
        var p = new DynamicParameters();
        if (!string.IsNullOrEmpty(status)) { sql += " AND status=@status"; p.Add("status", status); }
        if (!string.IsNullOrEmpty(source)) { sql += " AND source=@source"; p.Add("source", source); }
        if (!string.IsNullOrEmpty(search)) { sql += " AND domain LIKE @search"; p.Add("search", $"%{search}%"); }
        sql += " ORDER BY modified DESC";
        lock (_gate)
        {
            return _conn.Query<ManagedDomainRow>(sql, p).ToList();
        }
    }

    public void RemoveDomain(string domain)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(domain);
        lock (_gate)
        {
            _conn.Execute("DELETE FROM domains WHERE domain=@d", new { d = domain.ToLowerInvariant() });
        }
    }

    public void UpdateStatus(string domain, string status)
    {
        var now = DateTime.Now.ToString("o", System.Globalization.CultureInfo.InvariantCulture);
        lock (_gate)
        {
            _conn.Execute("UPDATE domains SET status=@status, modified=@now WHERE domain=@d",
                new { status, now, d = domain.ToLowerInvariant() });
        }
    }

    // ─── Log ──────────────────────────────────────────────────────────────────

    public void LogEvent(string domain, string action, string process = "", string details = "", string? reason = null)
    {
        var now = DateTime.Now.ToString("o", System.Globalization.CultureInfo.InvariantCulture);
        lock (_gate)
        {
            _conn.Execute(
                "INSERT INTO log(ts,domain,action,process,details,reason) VALUES(@now,@domain,@action,@process,@details,@reason)",
                new { now, domain, action, process, details, reason = Reasons.Canonical(reason, "", action, details) });
        }
    }

    public IReadOnlyList<(string Ts, string Domain, string Action, string Process, string Details, string Reason)> GetLog(int limit = 200)
    {
        lock (_gate)
        {
            return _conn.Query<(string, string, string, string, string, string)>(
                "SELECT ts, domain, action, process, details, reason FROM log ORDER BY ts DESC LIMIT @limit",
                new { limit }).ToList();
        }
    }

    // ─── Stats ────────────────────────────────────────────────────────────────

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
        _conn.Dispose();
        SqliteConnection.ClearAllPools();
    }
}
