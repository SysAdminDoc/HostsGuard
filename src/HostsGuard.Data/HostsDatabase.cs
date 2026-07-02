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

/// <summary>
/// SQLite persistence for HostsGuard (Microsoft.Data.Sqlite + Dapper). Schema v1
/// mirrors the Python schema v7 (domains/feed/log/fw_state/profiles + canonical
/// reason columns) and includes the legacy column-rename migration so a
/// pre-versioning database opens without data loss. WAL, busy_timeout, and an
/// integrity check run on open. The path is injectable for testability.
/// </summary>
public sealed class HostsDatabase : IDisposable
{
    public const int SchemaVersion = 2;

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
            CREATE TABLE IF NOT EXISTS hidden_roots(root TEXT PRIMARY KEY, added TEXT);
            CREATE TABLE IF NOT EXISTS temp_allows(domain TEXT PRIMARY KEY, expires TEXT);
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

    /// <summary>
    /// Direct status write, bypassing the allowlist-wins UPSERT rule — reserved
    /// for flows that legitimately downgrade a whitelisted row (temp-allow revert).
    /// </summary>
    public void UpdateStatus(string domain, string status, string? source = null)
    {
        var now = DateTime.Now.ToString("o", System.Globalization.CultureInfo.InvariantCulture);
        lock (_gate)
        {
            _conn.Execute(
                "UPDATE domains SET status=@status, modified=@now, source=COALESCE(@source, source) WHERE domain=@d",
                new { status, now, source, d = domain.ToLowerInvariant() });
        }
    }

    public string? GetDomainSource(string domain)
    {
        lock (_gate)
        {
            return _conn.ExecuteScalar<string?>("SELECT source FROM domains WHERE domain=@d",
                new { d = domain.ToLowerInvariant() });
        }
    }

    // ─── Activity feed ────────────────────────────────────────────────────────

    /// <summary>UPSERT a DNS sighting: bump hits + last_seen, keep first_seen.</summary>
    public void RecordFeed(string domain, string process = "", string? reason = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(domain);
        var now = DateTime.Now.ToString("o", System.Globalization.CultureInfo.InvariantCulture);
        lock (_gate)
        {
            _conn.Execute(
                """
                INSERT INTO feed(domain,first_seen,last_seen,hits,process,hidden,reason)
                VALUES(@domain,@now,@now,1,@process,0,@reason)
                ON CONFLICT(domain) DO UPDATE SET
                    last_seen=excluded.last_seen,
                    hits=feed.hits+1,
                    process=CASE WHEN excluded.process!='' THEN excluded.process ELSE feed.process END
                """,
                new { domain = domain.ToLowerInvariant(), now, process, reason });
        }
    }

    /// <summary>Recent feed rows (newest first), joined with managed-domain status.</summary>
    public IReadOnlyList<FeedRow> GetFeed(int limit = 500)
    {
        lock (_gate)
        {
            return _conn.Query<FeedRow>(
                """
                SELECT f.domain AS Domain, f.first_seen AS FirstSeen, f.last_seen AS LastSeen,
                       f.hits AS Hits, f.process AS Process, f.hidden AS Hidden, f.reason AS Reason,
                       d.status AS Status
                FROM feed f LEFT JOIN domains d ON d.domain = f.domain
                ORDER BY f.last_seen DESC LIMIT @limit
                """,
                new { limit }).ToList();
        }
    }

    // ─── Hidden roots ─────────────────────────────────────────────────────────

    public void HideRoot(string root)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(root);
        var now = DateTime.Now.ToString("o", System.Globalization.CultureInfo.InvariantCulture);
        lock (_gate)
        {
            _conn.Execute("INSERT OR IGNORE INTO hidden_roots(root,added) VALUES(@root,@now)",
                new { root = root.ToLowerInvariant(), now });
        }
    }

    public void UnhideRoot(string root)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(root);
        lock (_gate)
        {
            _conn.Execute("DELETE FROM hidden_roots WHERE root=@root", new { root = root.ToLowerInvariant() });
        }
    }

    public IReadOnlySet<string> GetHiddenRoots()
    {
        lock (_gate)
        {
            return _conn.Query<string>("SELECT root FROM hidden_roots").ToHashSet(StringComparer.Ordinal);
        }
    }

    // ─── Temp allows ──────────────────────────────────────────────────────────

    public void SetTempAllow(string domain, DateTime expiresUtc)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(domain);
        lock (_gate)
        {
            _conn.Execute(
                "INSERT OR REPLACE INTO temp_allows(domain,expires) VALUES(@d,@e)",
                new { d = domain.ToLowerInvariant(), e = expiresUtc.ToString("o", System.Globalization.CultureInfo.InvariantCulture) });
        }
    }

    public void RemoveTempAllow(string domain)
    {
        lock (_gate)
        {
            _conn.Execute("DELETE FROM temp_allows WHERE domain=@d", new { d = domain.ToLowerInvariant() });
        }
    }

    public IReadOnlyList<(string Domain, DateTime ExpiresUtc)> GetTempAllows()
    {
        lock (_gate)
        {
            return _conn.Query<(string, string)>("SELECT domain, expires FROM temp_allows")
                .Select(r => (r.Item1, DateTime.Parse(r.Item2, System.Globalization.CultureInfo.InvariantCulture,
                    System.Globalization.DateTimeStyles.AdjustToUniversal | System.Globalization.DateTimeStyles.AssumeUniversal)))
                .ToList();
        }
    }

    // ─── Firewall state (drift tracking) ──────────────────────────────────────

    /// <summary>Track a HostsGuard-created rule so drift (deleted-behind-our-back) is detectable.</summary>
    public void UpsertFwState(string name, string direction, string action, string remoteAddr, string protocol, string program)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        var now = DateTime.Now.ToString("o", System.Globalization.CultureInfo.InvariantCulture);
        lock (_gate)
        {
            _conn.Execute(
                """
                INSERT OR REPLACE INTO fw_state(name,direction,action,remote_addr,protocol,program,created)
                VALUES(@name,@direction,@action,@remoteAddr,@protocol,@program,
                       COALESCE((SELECT created FROM fw_state WHERE name=@name),@now))
                """,
                new { name, direction, action, remoteAddr, protocol, program, now });
        }
    }

    public void RemoveFwState(string name)
    {
        lock (_gate)
        {
            _conn.Execute("DELETE FROM fw_state WHERE name=@name", new { name });
        }
    }

    public IReadOnlySet<string> GetFwStateNames()
    {
        lock (_gate)
        {
            return _conn.Query<string>("SELECT name FROM fw_state").ToHashSet(StringComparer.Ordinal);
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
