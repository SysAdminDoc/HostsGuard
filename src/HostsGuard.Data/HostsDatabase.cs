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

/// <summary>A tracked HostsGuard firewall rule, for the Secure-Rules reconcile.</summary>
public sealed record FwStateRow(
    string Name, string? Direction, string? Action, string? RemoteAddr, string? Protocol, string? Program);

/// <summary>A recorded (historical) connection sighting (NET-070).</summary>
public sealed record ConnHistoryRow(
    string Ts, string Process, long Pid, string Protocol,
    string RemoteAddr, long RemotePort, string Country, string FwStatus);

/// <summary>A per-process per-minute bandwidth bucket (NET-070).</summary>
public sealed record BandwidthRow(string Process, string Minute, long Sent, long Recv);

/// <summary>A persisted event-log row with its derived taxonomy category.</summary>
public sealed record EventLogRow(
    long Id, string Ts, string Domain, string Action, string Process, string Details, string Reason, string Category);

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

/// <summary>Rows deleted by a retention sweep plus whether SQLite maintenance ran.</summary>
public sealed record RetentionSweepResult(
    int LogRows,
    int ResolvedHosts,
    int DomainUsageRows,
    int BandwidthBuckets,
    int HourlyBuckets,
    bool MaintenanceRan);

/// <summary>A subscribed blocklist source plus source-owned domain count.</summary>
public sealed record BlocklistSubRow(
    string Name, string Url, string LastRefresh, long DomainCount, bool Enabled, long OwnedDomainCount);

/// <summary>Rollback result for removing one blocklist source.</summary>
public sealed record BlocklistRemoval(long Removed, long Preserved);

/// <summary>
/// SQLite persistence for HostsGuard (Microsoft.Data.Sqlite + Dapper). Schema v1
/// mirrors the Python schema v7 (domains/feed/log/fw_state/profiles + canonical
/// reason columns) and includes the legacy column-rename migration so a
/// pre-versioning database opens without data loss. WAL, busy_timeout, and an
/// integrity check run on open. The path is injectable for testability.
/// </summary>
public sealed class HostsDatabase : IDisposable
{
    public const int SchemaVersion = 15;

    /// <summary>Default connection-history / bandwidth retention (days).</summary>
    public const int DefaultHistoryRetentionDays = 30;

    private const int IncrementalVacuumPages = 256;
    private static readonly TimeSpan RetentionMaintenanceInterval = TimeSpan.FromHours(6);

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
            CREATE TABLE IF NOT EXISTS schedules(
                id INTEGER PRIMARY KEY, target TEXT, days TEXT, start TEXT, end TEXT);
            CREATE TABLE IF NOT EXISTS blocklist_subs(
                name TEXT PRIMARY KEY, url TEXT, last_refresh TEXT, domain_count INTEGER DEFAULT 0,
                enabled INTEGER DEFAULT 1);
            CREATE TABLE IF NOT EXISTS blocklist_domain_sources(
                source TEXT NOT NULL, domain TEXT NOT NULL,
                PRIMARY KEY(source, domain)) WITHOUT ROWID;
            CREATE INDEX IF NOT EXISTS idx_blocklist_domain_sources_domain ON blocklist_domain_sources(domain);
            CREATE TABLE IF NOT EXISTS allowlist_subs(url TEXT PRIMARY KEY);
            CREATE TABLE IF NOT EXISTS feed_hourly(
                root TEXT, hour TEXT, hits INTEGER DEFAULT 0, PRIMARY KEY(root, hour));
            CREATE INDEX IF NOT EXISTS idx_feed_hourly_hour ON feed_hourly(hour);
            CREATE TABLE IF NOT EXISTS conn_history(
                id INTEGER PRIMARY KEY, ts TEXT, process TEXT, pid INTEGER, protocol TEXT,
                remote_addr TEXT, remote_port INTEGER, country TEXT, fw_status TEXT);
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
            CREATE TABLE IF NOT EXISTS rule_groups(
                grp TEXT NOT NULL, rule_name TEXT NOT NULL,
                PRIMARY KEY(grp, rule_name)) WITHOUT ROWID;
            CREATE INDEX IF NOT EXISTS idx_rule_groups_rule ON rule_groups(rule_name);
            """);

        // Add reason columns to tables that predate schema v7 but survived the rename.
        AddColumnIfMissing("domains", "reason", "TEXT");
        AddColumnIfMissing("feed", "reason", "TEXT");
        AddColumnIfMissing("log", "reason", "TEXT");
        AddColumnIfMissing("blocklist_subs", "enabled", "INTEGER DEFAULT 1");
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

    /// <summary>Assign a category only when the row doesn't have one yet.</summary>
    public void SetCategoryIfEmpty(string domain, string category)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(domain);
        if (string.IsNullOrWhiteSpace(category))
        {
            return;
        }

        lock (_gate)
        {
            _conn.Execute(
                "UPDATE domains SET category=@category WHERE domain=@domain AND (category IS NULL OR category='')",
                new { domain = domain.ToLowerInvariant(), category });
        }
    }

    /// <summary>Set a managed domain's notes (no-op when the row is absent).</summary>
    public void SetNotes(string domain, string notes)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(domain);
        lock (_gate)
        {
            _conn.Execute(
                "UPDATE domains SET notes=@notes WHERE domain=@domain",
                new { domain = domain.ToLowerInvariant(), notes = notes ?? string.Empty });
        }
    }

    /// <summary>Set (or clear with "") a managed domain's category.</summary>
    public void SetCategory(string domain, string category)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(domain);
        lock (_gate)
        {
            _conn.Execute(
                "UPDATE domains SET category=@category, modified=@now WHERE domain=@domain",
                new
                {
                    domain = domain.ToLowerInvariant(),
                    category = category ?? string.Empty,
                    now = DateTime.Now.ToString("o", System.Globalization.CultureInfo.InvariantCulture),
                });
        }
    }

    // ─── Persistent resolved-host store (IP → domain, remembered forever) ─────

    /// <summary>Remember an IP→host mapping (source: "dns" forward, "ptr" reverse).</summary>
    public void UpsertResolvedHost(string ip, string host, string source)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(ip);
        if (string.IsNullOrWhiteSpace(host))
        {
            return;
        }

        lock (_gate)
        {
            _conn.Execute(
                """
                INSERT INTO resolved_hosts(ip,host,source,updated) VALUES(@ip,@host,@source,@now)
                ON CONFLICT(ip) DO UPDATE SET host=excluded.host, source=excluded.source, updated=excluded.updated
                """,
                new
                {
                    ip,
                    host = host.ToLowerInvariant(),
                    source = source ?? string.Empty,
                    now = DateTime.Now.ToString("o", System.Globalization.CultureInfo.InvariantCulture),
                });
        }
    }

    /// <summary>Remember many IP→host mappings in one transaction.</summary>
    public void UpsertResolvedHosts(IEnumerable<(string Ip, string Host)> pairs, string source)
    {
        ArgumentNullException.ThrowIfNull(pairs);
        var now = DateTime.Now.ToString("o", System.Globalization.CultureInfo.InvariantCulture);
        lock (_gate)
        {
            using var tx = _conn.BeginTransaction();
            foreach (var (ip, host) in pairs)
            {
                if (string.IsNullOrWhiteSpace(ip) || string.IsNullOrWhiteSpace(host))
                {
                    continue;
                }

                _conn.Execute(
                    """
                    INSERT INTO resolved_hosts(ip,host,source,updated) VALUES(@ip,@host,@source,@now)
                    ON CONFLICT(ip) DO UPDATE SET host=excluded.host, source=excluded.source, updated=excluded.updated
                    """,
                    new { ip, host = host.ToLowerInvariant(), source = source ?? string.Empty, now }, tx);
            }

            tx.Commit();
        }
    }

    /// <summary>The remembered host for an IP, or "" when none is known.</summary>
    public string GetResolvedHost(string ip)
    {
        if (string.IsNullOrWhiteSpace(ip))
        {
            return string.Empty;
        }

        lock (_gate)
        {
            return _conn.ExecuteScalar<string?>("SELECT host FROM resolved_hosts WHERE ip=@ip", new { ip })
                ?? string.Empty;
        }
    }

    // ─── Blocklist intelligence index (domain → reference lists) ─────────────

    /// <summary>Replace one reference list's rows in the intelligence index.</summary>
    public void ReplaceListIndex(string list, IEnumerable<string> domains)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(list);
        ArgumentNullException.ThrowIfNull(domains);
        lock (_gate)
        {
            using var tx = _conn.BeginTransaction();
            _conn.Execute("DELETE FROM list_index WHERE list=@list", new { list }, tx);
            foreach (var chunk in domains.Chunk(2000))
            {
                _conn.Execute(
                    "INSERT OR IGNORE INTO list_index(domain,list) VALUES(@d,@list)",
                    chunk.Select(d => new { d, list }), tx);
            }

            tx.Commit();
        }
    }

    /// <summary>Reference-list membership for a batch of domains (chunked IN queries).</summary>
    public IReadOnlyDictionary<string, IReadOnlyList<string>> GetListMembership(IEnumerable<string> domains)
    {
        ArgumentNullException.ThrowIfNull(domains);
        var result = new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal);
        lock (_gate)
        {
            foreach (var chunk in domains.Distinct(StringComparer.Ordinal).Chunk(500))
            {
                var rows = _conn.Query<(string Domain, string List)>(
                    "SELECT domain, list FROM list_index WHERE domain IN @chunk ORDER BY list",
                    new { chunk });
                foreach (var group in rows.GroupBy(r => r.Domain, StringComparer.Ordinal))
                {
                    result[group.Key] = group.Select(r => r.List).ToList();
                }
            }
        }

        return result;
    }

    /// <summary>Reference lists that block one domain (ordered by list name).</summary>
    public IReadOnlyList<string> GetBlocklistsFor(string domain)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(domain);
        lock (_gate)
        {
            return _conn.Query<string>(
                "SELECT list FROM list_index WHERE domain=@d ORDER BY list",
                new { d = domain.ToLowerInvariant() }).ToList();
        }
    }

    /// <summary>Intelligence-index size: (distinct lists, total rows).</summary>
    public (int Lists, long Rows) GetListIndexStats()
    {
        lock (_gate)
        {
            var lists = _conn.ExecuteScalar<int>("SELECT COUNT(DISTINCT list) FROM list_index");
            var rows = _conn.ExecuteScalar<long>("SELECT COUNT(*) FROM list_index");
            return (lists, rows);
        }
    }

    // ─── AI knowledge store (learned purposes / categories / connection info) ─

    /// <summary>Record something the AI learned; kind ∈ purpose|category|connection.</summary>
    public void UpsertAiKnowledge(string kind, string key, string value, string model)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(kind);
        ArgumentException.ThrowIfNullOrWhiteSpace(key);
        lock (_gate)
        {
            _conn.Execute(
                """
                INSERT INTO ai_knowledge(kind,key,value,model,created)
                VALUES(@kind,@key,@value,@model,@now)
                ON CONFLICT(kind,key) DO UPDATE SET value=excluded.value, model=excluded.model
                """,
                new
                {
                    kind,
                    key = key.ToLowerInvariant(),
                    value = value ?? string.Empty,
                    model = model ?? string.Empty,
                    now = DateTime.Now.ToString("o", System.Globalization.CultureInfo.InvariantCulture),
                });
        }
    }

    /// <summary>Learned values for a batch of keys within one kind.</summary>
    public IReadOnlyDictionary<string, string> GetAiKnowledge(string kind, IEnumerable<string> keys)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(kind);
        ArgumentNullException.ThrowIfNull(keys);
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        lock (_gate)
        {
            foreach (var chunk in keys.Distinct(StringComparer.Ordinal).Chunk(500))
            {
                foreach (var row in _conn.Query<(string Key, string Value)>(
                    "SELECT key, value FROM ai_knowledge WHERE kind=@kind AND key IN @chunk",
                    new { kind, chunk }))
                {
                    result[row.Key] = row.Value;
                }
            }
        }

        return result;
    }

    /// <summary>Everything the AI has learned: (kind, key, value, model, created).</summary>
    public IReadOnlyList<(string Kind, string Key, string Value, string Model, string Created)> GetAllAiKnowledge()
    {
        lock (_gate)
        {
            return _conn.Query<(string, string, string, string, string)>(
                "SELECT kind, key, value, COALESCE(model,''), COALESCE(created,'') FROM ai_knowledge ORDER BY kind, key")
                .ToList();
        }
    }

    /// <summary>Remove a learned AI-knowledge entry (discarded during review; NET-107).</summary>
    public void RemoveAiKnowledge(string kind, string key)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(kind);
        ArgumentException.ThrowIfNullOrWhiteSpace(key);
        lock (_gate)
        {
            _conn.Execute("DELETE FROM ai_knowledge WHERE kind=@kind AND key=@key",
                new { kind, key = key.ToLowerInvariant() });
        }
    }

    // ─── User overrides (curated labels that BEAT the AI; NET-107) ────────────

    /// <summary>
    /// Persist a user-authoritative label (kind ∈ purpose|category) that wins over
    /// both the curated tables and the AI. An empty value clears the override.
    /// </summary>
    public void UpsertUserOverride(string kind, string key, string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(kind);
        ArgumentException.ThrowIfNullOrWhiteSpace(key);
        var k = key.ToLowerInvariant();
        lock (_gate)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                _conn.Execute("DELETE FROM user_overrides WHERE kind=@kind AND key=@k", new { kind, k });
                return;
            }

            _conn.Execute(
                """
                INSERT INTO user_overrides(kind,key,value,created) VALUES(@kind,@k,@value,@now)
                ON CONFLICT(kind,key) DO UPDATE SET value=excluded.value, created=excluded.created
                """,
                new { kind, k, value = value.Trim(), now = DateTime.Now.ToString("o", System.Globalization.CultureInfo.InvariantCulture) });
        }
    }

    /// <summary>The user override for one (kind,key), or "" when none.</summary>
    public string GetUserOverride(string kind, string key)
    {
        if (string.IsNullOrWhiteSpace(kind) || string.IsNullOrWhiteSpace(key))
        {
            return string.Empty;
        }

        lock (_gate)
        {
            return _conn.ExecuteScalar<string?>(
                "SELECT value FROM user_overrides WHERE kind=@kind AND key=@k",
                new { kind, k = key.ToLowerInvariant() }) ?? string.Empty;
        }
    }

    /// <summary>User overrides for a batch of keys within one kind (chunked IN queries).</summary>
    public IReadOnlyDictionary<string, string> GetUserOverrides(string kind, IEnumerable<string> keys)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(kind);
        ArgumentNullException.ThrowIfNull(keys);
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        lock (_gate)
        {
            foreach (var chunk in keys.Distinct(StringComparer.Ordinal).Chunk(500))
            {
                foreach (var row in _conn.Query<(string Key, string Value)>(
                    "SELECT key, value FROM user_overrides WHERE kind=@kind AND key IN @chunk",
                    new { kind, chunk }))
                {
                    result[row.Key] = row.Value;
                }
            }
        }

        return result;
    }

    /// <summary>All user overrides: (kind, key, value, created).</summary>
    public IReadOnlyList<(string Kind, string Key, string Value, string Created)> GetAllUserOverrides()
    {
        lock (_gate)
        {
            return _conn.Query<(string, string, string, string)>(
                "SELECT kind, key, value, COALESCE(created,'') FROM user_overrides ORDER BY kind, key")
                .ToList();
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
                        source=CASE
                            WHEN excluded.source='' THEN domains.source
                            WHEN domains.source IS NULL OR domains.source='' OR domains.source LIKE 'list:%' THEN excluded.source
                            ELSE domains.source
                        END
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

    public string? GetDomainStatus(string domain)
    {
        lock (_gate)
        {
            return _conn.ExecuteScalar<string?>("SELECT status FROM domains WHERE domain=@d",
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
    /// <summary>
    /// Increment the current-hour hit bucket for a domain root (NET-042
    /// sparkline source). Opportunistically prunes buckets older than 48 h so
    /// the table stays bounded without a scheduler.
    /// </summary>
    public void RecordHourly(string root, DateTime now)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(root);
        var hour = now.ToString("yyyy-MM-ddTHH", System.Globalization.CultureInfo.InvariantCulture);
        var cutoff = now.AddHours(-48).ToString("yyyy-MM-ddTHH", System.Globalization.CultureInfo.InvariantCulture);
        lock (_gate)
        {
            _conn.Execute(
                """
                INSERT INTO feed_hourly(root,hour,hits) VALUES(@root,@hour,1)
                ON CONFLICT(root,hour) DO UPDATE SET hits=hits+1
                """,
                new { root, hour });
            _conn.Execute("DELETE FROM feed_hourly WHERE hour < @cutoff", new { cutoff });
        }
    }

    /// <summary>
    /// 24-hour hourly hit histogram for a domain root, oldest→newest, ending at
    /// <paramref name="now"/>'s hour. Missing hours are zero-filled so the
    /// sparkline is always <paramref name="hours"/> points wide.
    /// </summary>
    public IReadOnlyList<int> GetHourlyHits(string root, DateTime now, int hours = 24)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(root);
        var buckets = new int[Math.Clamp(hours, 1, 168)];
        var top = new DateTime(now.Year, now.Month, now.Day, now.Hour, 0, 0, now.Kind);
        var byHour = new Dictionary<string, int>(StringComparer.Ordinal);
        lock (_gate)
        {
            var earliest = top.AddHours(-(buckets.Length - 1))
                .ToString("yyyy-MM-ddTHH", System.Globalization.CultureInfo.InvariantCulture);
            foreach (var row in _conn.Query<(string Hour, long Hits)>(
                "SELECT hour AS Hour, hits AS Hits FROM feed_hourly WHERE root=@root AND hour >= @earliest",
                new { root, earliest }))
            {
                byHour[row.Hour] = (int)row.Hits;
            }
        }

        for (var i = 0; i < buckets.Length; i++)
        {
            var hour = top.AddHours(-(buckets.Length - 1 - i))
                .ToString("yyyy-MM-ddTHH", System.Globalization.CultureInfo.InvariantCulture);
            buckets[i] = byHour.GetValueOrDefault(hour);
        }

        return buckets;
    }

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

    // ─── Connection history + per-app bandwidth (NET-070) ────────────────────

    /// <summary>History/bandwidth retention in days (meta-backed, clamped 1–365).</summary>
    public int HistoryRetentionDays
    {
        get => int.TryParse(GetMeta("history_retention_days"), out var d)
            ? Math.Clamp(d, 1, 365)
            : DefaultHistoryRetentionDays;
        set => SetMeta("history_retention_days", Math.Clamp(value, 1, 365)
            .ToString(System.Globalization.CultureInfo.InvariantCulture));
    }

    /// <summary>
    /// Record a first-sighting connection. Opportunistically prunes rows older
    /// than the retention window (indexed delete — cheap when there's nothing
    /// to remove), so the table stays bounded without a scheduler.
    /// </summary>
    public void RecordConnection(ConnHistoryRow row)
    {
        ArgumentNullException.ThrowIfNull(row);
        var cutoff = DateTime.Now.AddDays(-HistoryRetentionDays)
            .ToString("o", System.Globalization.CultureInfo.InvariantCulture);
        lock (_gate)
        {
            _conn.Execute(
                """
                INSERT INTO conn_history(ts,process,pid,protocol,remote_addr,remote_port,country,fw_status)
                VALUES(@Ts,@Process,@Pid,@Protocol,@RemoteAddr,@RemotePort,@Country,@FwStatus)
                """, row);
            _conn.Execute("DELETE FROM conn_history WHERE ts < @cutoff", new { cutoff });
        }
    }

    /// <summary>
    /// Query recorded connections, newest first. <paramref name="search"/> is a
    /// substring match across process, remote address, and country.
    /// </summary>
    public IReadOnlyList<ConnHistoryRow> GetConnectionHistory(int limit = 500, string? search = null, string? since = null)
    {
        var sql = """
            SELECT ts AS Ts, process AS Process, pid AS Pid, protocol AS Protocol,
                   remote_addr AS RemoteAddr, remote_port AS RemotePort,
                   country AS Country, fw_status AS FwStatus
            FROM conn_history WHERE 1=1
            """;
        var p = new DynamicParameters();
        if (!string.IsNullOrWhiteSpace(search))
        {
            sql += " AND (process LIKE @s OR remote_addr LIKE @s OR country LIKE @s)";
            p.Add("s", $"%{search.Trim()}%");
        }

        if (!string.IsNullOrWhiteSpace(since))
        {
            sql += " AND ts >= @since";
            p.Add("since", since);
        }

        sql += " ORDER BY ts DESC LIMIT @limit";
        p.Add("limit", Math.Clamp(limit, 1, 10_000));
        lock (_gate)
        {
            return _conn.Query<ConnHistoryRow>(sql, p).ToList();
        }
    }

    /// <summary>Accumulate bytes into a per-process per-minute bucket.</summary>
    public void AddBandwidth(string process, string minute, long sent, long recv)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(process);
        ArgumentException.ThrowIfNullOrWhiteSpace(minute);
        lock (_gate)
        {
            _conn.Execute(
                """
                INSERT INTO app_bandwidth(process,minute,sent,recv) VALUES(@process,@minute,@sent,@recv)
                ON CONFLICT(process,minute) DO UPDATE SET sent=sent+excluded.sent, recv=recv+excluded.recv
                """,
                new { process, minute, sent, recv });
        }
    }

    /// <summary>Bandwidth buckets at or after <paramref name="sinceMinute"/> ("yyyy-MM-ddTHH:mm").</summary>
    public IReadOnlyList<BandwidthRow> GetBandwidth(string sinceMinute)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sinceMinute);
        lock (_gate)
        {
            return _conn.Query<BandwidthRow>(
                """
                SELECT process AS Process, minute AS Minute, sent AS Sent, recv AS Recv
                FROM app_bandwidth WHERE minute >= @sinceMinute
                """,
                new { sinceMinute }).ToList();
        }
    }

    /// <summary>Prune bandwidth buckets older than the retention window.</summary>
    public void PruneBandwidth(DateTime now)
    {
        var cutoff = now.AddDays(-HistoryRetentionDays)
            .ToString("yyyy-MM-ddTHH:mm", System.Globalization.CultureInfo.InvariantCulture);
        lock (_gate)
        {
            _conn.Execute("DELETE FROM app_bandwidth WHERE minute < @cutoff", new { cutoff });
        }
    }

    /// <summary>
    /// Apply retention to all unbounded history tables, then periodically run
    /// SQLite planner and free-page maintenance. Safe to call from a frequent
    /// service sweep; deletes are indexed and the heavier work is throttled.
    /// </summary>
    public RetentionSweepResult RunRetentionSweep(DateTime now, bool forceMaintenance = false)
    {
        var historyCutoff = now.AddDays(-HistoryRetentionDays)
            .ToString("o", System.Globalization.CultureInfo.InvariantCulture);
        var bandwidthCutoff = now.AddDays(-HistoryRetentionDays)
            .ToString("yyyy-MM-ddTHH:mm", System.Globalization.CultureInfo.InvariantCulture);
        var hourlyCutoff = now.AddHours(-48)
            .ToString("yyyy-MM-ddTHH", System.Globalization.CultureInfo.InvariantCulture);

        lock (_gate)
        {
            using var tx = _conn.BeginTransaction();
            var logRows = _conn.Execute("DELETE FROM log WHERE ts IS NULL OR ts < @cutoff",
                new { cutoff = historyCutoff }, tx);
            var resolvedHosts = _conn.Execute(
                "DELETE FROM resolved_hosts WHERE updated IS NULL OR updated < @cutoff",
                new { cutoff = historyCutoff }, tx);
            var domainUsage = _conn.Execute(
                "DELETE FROM domain_usage WHERE updated IS NULL OR updated < @cutoff",
                new { cutoff = historyCutoff }, tx);
            var bandwidthBuckets = _conn.Execute("DELETE FROM app_bandwidth WHERE minute < @cutoff",
                new { cutoff = bandwidthCutoff }, tx);
            var hourlyBuckets = _conn.Execute("DELETE FROM feed_hourly WHERE hour < @cutoff",
                new { cutoff = hourlyCutoff }, tx);
            tx.Commit();

            var maintenanceRan = ShouldRunRetentionMaintenance(now, forceMaintenance);
            if (maintenanceRan)
            {
                _conn.Execute("PRAGMA optimize;");
                _conn.Execute($"PRAGMA incremental_vacuum({IncrementalVacuumPages});");
                SetMetaNoLock("retention_maintenance_at",
                    now.ToString("o", System.Globalization.CultureInfo.InvariantCulture));
            }

            return new RetentionSweepResult(
                logRows,
                resolvedHosts,
                domainUsage,
                bandwidthBuckets,
                hourlyBuckets,
                maintenanceRan);
        }
    }

    private bool ShouldRunRetentionMaintenance(DateTime now, bool forceMaintenance)
    {
        if (forceMaintenance)
        {
            return true;
        }

        var last = GetMetaNoLock("retention_maintenance_at");
        if (!DateTime.TryParse(
                last,
                System.Globalization.CultureInfo.InvariantCulture,
                System.Globalization.DateTimeStyles.RoundtripKind,
                out var lastRun))
        {
            return true;
        }

        var elapsed = now - lastRun;
        return elapsed < TimeSpan.Zero || elapsed >= RetentionMaintenanceInterval;
    }

    // ─── Per-domain data usage (NET-108: DNS → process → bytes) ──────────────

    /// <summary>Accumulate bytes attributed to a domain (via a resolved remote IP), keyed by requesting process.</summary>
    public void AddDomainUsage(string domain, string process, long sent, long recv)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(domain);
        if (sent == 0 && recv == 0)
        {
            return;
        }

        lock (_gate)
        {
            _conn.Execute(
                """
                INSERT INTO domain_usage(domain,process,sent,recv,updated)
                VALUES(@domain,@process,@sent,@recv,@now)
                ON CONFLICT(domain,process) DO UPDATE SET
                    sent=sent+excluded.sent, recv=recv+excluded.recv, updated=excluded.updated
                """,
                new
                {
                    domain = domain.ToLowerInvariant(),
                    process = process ?? string.Empty,
                    sent,
                    recv,
                    now = DateTime.Now.ToString("o", System.Globalization.CultureInfo.InvariantCulture),
                });
        }
    }

    /// <summary>Total bytes (sent+recv) per domain, for the feed's Data column.</summary>
    public IReadOnlyDictionary<string, long> GetDomainUsageTotals(IEnumerable<string> domains)
    {
        ArgumentNullException.ThrowIfNull(domains);
        var result = new Dictionary<string, long>(StringComparer.Ordinal);
        lock (_gate)
        {
            foreach (var chunk in domains.Select(d => d.ToLowerInvariant()).Distinct(StringComparer.Ordinal).Chunk(500))
            {
                foreach (var row in _conn.Query<(string Domain, long Bytes)>(
                    "SELECT domain, SUM(sent+recv) AS Bytes FROM domain_usage WHERE domain IN @chunk GROUP BY domain",
                    new { chunk }))
                {
                    result[row.Domain] = row.Bytes;
                }
            }
        }

        return result;
    }

    /// <summary>Per-domain usage rows (domain, process, sent, recv) — diagnostics/quota input.</summary>
    public IReadOnlyList<(string Domain, string Process, long Sent, long Recv)> GetDomainUsage(string domain)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(domain);
        lock (_gate)
        {
            return _conn.Query<(string, string, long, long)>(
                "SELECT domain, process, sent, recv FROM domain_usage WHERE domain=@d ORDER BY sent+recv DESC",
                new { d = domain.ToLowerInvariant() }).ToList();
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

    /// <summary>Hide specific exact domains from the feed (persisted on the feed row).</summary>
    public void HideDomains(IEnumerable<string> domains)
    {
        ArgumentNullException.ThrowIfNull(domains);
        lock (_gate)
        {
            using var tx = _conn.BeginTransaction();
            foreach (var domain in domains)
            {
                if (!string.IsNullOrWhiteSpace(domain))
                {
                    _conn.Execute("UPDATE feed SET hidden=1 WHERE domain=@d",
                        new { d = domain.ToLowerInvariant() }, tx);
                }
            }

            tx.Commit();
        }
    }

    /// <summary>Reveal specific exact domains previously hidden from the feed.</summary>
    public void UnhideDomains(IEnumerable<string> domains)
    {
        ArgumentNullException.ThrowIfNull(domains);
        lock (_gate)
        {
            using var tx = _conn.BeginTransaction();
            foreach (var domain in domains)
            {
                if (!string.IsNullOrWhiteSpace(domain))
                {
                    _conn.Execute("UPDATE feed SET hidden=0 WHERE domain=@d",
                        new { d = domain.ToLowerInvariant() }, tx);
                }
            }

            tx.Commit();
        }
    }

    /// <summary>
    /// True when a domain is hidden from the feed — either its exact feed row is
    /// marked hidden, or its <paramref name="root"/> is a hidden root. Single
    /// query for the live-event hot path.
    /// </summary>
    public bool IsHidden(string domain, string root)
    {
        if (string.IsNullOrWhiteSpace(domain))
        {
            return false;
        }

        lock (_gate)
        {
            return _conn.ExecuteScalar<long>(
                """
                SELECT CASE WHEN EXISTS(SELECT 1 FROM feed WHERE domain=@d AND hidden=1)
                              OR EXISTS(SELECT 1 FROM hidden_roots WHERE root=@r)
                            THEN 1 ELSE 0 END
                """,
                new { d = domain.ToLowerInvariant(), r = (root ?? string.Empty).ToLowerInvariant() }) == 1;
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

    // ─── Profiles ─────────────────────────────────────────────────────────────

    /// <summary>Snapshot the current managed-domain set as a named profile.</summary>
    public void SaveProfile(string name)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        var now = DateTime.Now.ToString("o", System.Globalization.CultureInfo.InvariantCulture);
        lock (_gate)
        {
            using var tx = _conn.BeginTransaction();
            _conn.Execute("INSERT OR REPLACE INTO profiles(name,created) VALUES(@name,@now)", new { name, now }, tx);
            _conn.Execute("DELETE FROM profile_rules WHERE profile=@name", new { name }, tx);
            _conn.Execute(
                "INSERT INTO profile_rules(profile,domain,status,source) SELECT @name, domain, status, source FROM domains",
                new { name }, tx);
            tx.Commit();
        }
    }

    /// <summary>
    /// Create/replace a profile from explicit rows (NET-089 policy import),
    /// rather than snapshotting the current domain set like <see cref="SaveProfile"/>.
    /// </summary>
    public void ImportProfile(string name, IEnumerable<(string Domain, string Status, string? Source)> rows)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        ArgumentNullException.ThrowIfNull(rows);
        var now = DateTime.Now.ToString("o", System.Globalization.CultureInfo.InvariantCulture);
        lock (_gate)
        {
            using var tx = _conn.BeginTransaction();
            _conn.Execute("INSERT OR REPLACE INTO profiles(name,created) VALUES(@name,@now)", new { name, now }, tx);
            _conn.Execute("DELETE FROM profile_rules WHERE profile=@name", new { name }, tx);
            foreach (var (domain, status, source) in rows)
            {
                if (string.IsNullOrWhiteSpace(domain))
                {
                    continue;
                }

                _conn.Execute(
                    "INSERT INTO profile_rules(profile,domain,status,source) VALUES(@name,@domain,@status,@source)",
                    new { name, domain = domain.ToLowerInvariant(), status, source = source ?? string.Empty }, tx);
            }

            tx.Commit();
        }
    }

    public IReadOnlyList<(string Domain, string Status, string? Source)> LoadProfile(string name)
    {
        lock (_gate)
        {
            return _conn.Query<(string, string, string?)>(
                "SELECT domain, status, source FROM profile_rules WHERE profile=@name", new { name }).ToList();
        }
    }

    public void DeleteProfile(string name)
    {
        lock (_gate)
        {
            using var tx = _conn.BeginTransaction();
            _conn.Execute("DELETE FROM profile_rules WHERE profile=@name", new { name }, tx);
            _conn.Execute("DELETE FROM profiles WHERE name=@name", new { name }, tx);
            tx.Commit();
        }
    }

    public IReadOnlyList<string> ListProfiles()
    {
        lock (_gate)
        {
            return _conn.Query<string>("SELECT name FROM profiles ORDER BY name").ToList();
        }
    }

    /// <summary>Replace the managed-domain set wholesale (profile switch).</summary>
    public void ReplaceDomains(IEnumerable<(string Domain, string Status, string? Source)> rows)
    {
        ArgumentNullException.ThrowIfNull(rows);
        var now = DateTime.Now.ToString("o", System.Globalization.CultureInfo.InvariantCulture);
        lock (_gate)
        {
            using var tx = _conn.BeginTransaction();
            _conn.Execute("DELETE FROM domains", transaction: tx);
            foreach (var (domain, status, source) in rows)
            {
                _conn.Execute(
                    """
                    INSERT INTO domains(domain,status,category,source,added,modified,hits,reason)
                    VALUES(@domain,@status,'',@source,@now,@now,0,@reason)
                    """,
                    new { domain = domain.ToLowerInvariant(), status, source = source ?? string.Empty, now, reason = Reasons.Canonical(null, source ?? string.Empty, status) },
                    tx);
            }

            tx.Commit();
        }
    }

    // ─── Network→profile auto-switch map (NET-083) ───────────────────────────

    /// <summary>Map a network fingerprint to a profile (label is the human network name).</summary>
    public void SetNetworkProfile(string fingerprint, string profile, string label)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(fingerprint);
        lock (_gate)
        {
            if (string.IsNullOrWhiteSpace(profile))
            {
                _conn.Execute("DELETE FROM network_profiles WHERE fingerprint=@fingerprint", new { fingerprint });
            }
            else
            {
                _conn.Execute(
                    "INSERT OR REPLACE INTO network_profiles(fingerprint,profile,label) VALUES(@fingerprint,@profile,@label)",
                    new { fingerprint, profile, label });
            }
        }
    }

    public IReadOnlyList<(string Fingerprint, string Profile, string Label)> GetNetworkProfiles()
    {
        lock (_gate)
        {
            return _conn.Query<(string, string, string)>(
                "SELECT fingerprint, profile, label FROM network_profiles ORDER BY label").ToList();
        }
    }

    /// <summary>The profile mapped to a fingerprint, or null.</summary>
    public string? GetProfileForNetwork(string fingerprint)
    {
        lock (_gate)
        {
            return _conn.ExecuteScalar<string?>(
                "SELECT profile FROM network_profiles WHERE fingerprint=@fingerprint", new { fingerprint });
        }
    }

    public string? GetMeta(string key)
    {
        lock (_gate)
        {
            return GetMetaNoLock(key);
        }
    }

    public void SetMeta(string key, string value)
    {
        lock (_gate)
        {
            SetMetaNoLock(key, value);
        }
    }

    private string? GetMetaNoLock(string key) =>
        _conn.ExecuteScalar<string?>("SELECT value FROM meta WHERE key=@key", new { key });

    private void SetMetaNoLock(string key, string value) =>
        _conn.Execute("INSERT OR REPLACE INTO meta(key,value) VALUES(@key,@value)", new { key, value });

    // ─── Blocklist / allowlist subscriptions ──────────────────────────────────

    public void UpsertBlocklistSub(string name, string url, long domainCount)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        var now = DateTime.Now.ToString("o", System.Globalization.CultureInfo.InvariantCulture);
        lock (_gate)
        {
            _conn.Execute(
                """
                INSERT INTO blocklist_subs(name,url,last_refresh,domain_count,enabled)
                VALUES(@name,@url,@now,@domainCount,1)
                ON CONFLICT(name) DO UPDATE SET
                    url=excluded.url,
                    last_refresh=excluded.last_refresh,
                    domain_count=excluded.domain_count,
                    enabled=1
                """,
                new { name, url, now, domainCount });
        }
    }

    public void SetBlocklistSubEnabled(string name, bool enabled)
    {
        lock (_gate)
        {
            _conn.Execute("UPDATE blocklist_subs SET enabled=@enabled WHERE name=@name", new { name, enabled = enabled ? 1 : 0 });
        }
    }

    public BlocklistRemoval RemoveBlocklistSub(string name)
    {
        lock (_gate)
        {
            using var tx = _conn.BeginTransaction();
            var src = $"list:{name}";
            var owned = _conn.Query<string>(
                """
                SELECT b.domain FROM blocklist_domain_sources b
                JOIN domains d ON d.domain=b.domain
                WHERE b.source=@name
                  AND d.status='blocked'
                  AND (d.source IS NULL OR d.source='' OR d.source=@src)
                  AND NOT EXISTS (
                      SELECT 1 FROM blocklist_domain_sources other
                      WHERE other.domain=b.domain AND other.source<>@name)
                """,
                new { name, src }, tx).ToList();
            var tracked = _conn.ExecuteScalar<long>(
                "SELECT COUNT(*) FROM blocklist_domain_sources WHERE source=@name",
                new { name }, tx);
            foreach (var chunk in owned.Chunk(500))
            {
                _conn.Execute("DELETE FROM domains WHERE domain IN @chunk AND status='blocked'", new { chunk }, tx);
            }

            _conn.Execute("DELETE FROM blocklist_domain_sources WHERE source=@name", new { name }, tx);
            _conn.Execute("DELETE FROM blocklist_subs WHERE name=@name", new { name }, tx);
            tx.Commit();
            return new BlocklistRemoval(owned.Count, Math.Max(0, tracked - owned.Count));
        }
    }

    public void ReplaceBlocklistSourceDomains(string name, IEnumerable<string> domains)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        ArgumentNullException.ThrowIfNull(domains);
        var cleaned = domains.Select(d => d.ToLowerInvariant()).Distinct(StringComparer.Ordinal).ToList();
        lock (_gate)
        {
            using var tx = _conn.BeginTransaction();
            _conn.Execute("DELETE FROM blocklist_domain_sources WHERE source=@name", new { name }, tx);
            foreach (var chunk in cleaned.Chunk(500))
            {
                foreach (var domain in chunk)
                {
                    _conn.Execute(
                        "INSERT OR IGNORE INTO blocklist_domain_sources(source,domain) VALUES(@name,@domain)",
                        new { name, domain }, tx);
                }
            }

            tx.Commit();
        }
    }

    public IReadOnlyList<BlocklistSubRow> GetBlocklistSubs()
    {
        lock (_gate)
        {
            return _conn.Query<(string Name, string Url, string LastRefresh, long DomainCount, long Enabled, long OwnedDomainCount)>(
                """
                SELECT s.name AS Name, s.url AS Url, COALESCE(s.last_refresh,'') AS LastRefresh,
                       COALESCE(s.domain_count,0) AS DomainCount, COALESCE(s.enabled,1) AS Enabled,
                       COUNT(b.domain) AS OwnedDomainCount
                FROM blocklist_subs s
                LEFT JOIN blocklist_domain_sources b ON b.source=s.name
                GROUP BY s.name, s.url, s.last_refresh, s.domain_count, s.enabled
                ORDER BY s.name
                """)
                .Select(r => new BlocklistSubRow(
                    r.Name,
                    r.Url,
                    r.LastRefresh,
                    r.DomainCount,
                    r.Enabled != 0,
                    r.OwnedDomainCount))
                .ToList();
        }
    }

    public void SetAllowlistSubs(IEnumerable<string> urls)
    {
        ArgumentNullException.ThrowIfNull(urls);
        lock (_gate)
        {
            using var tx = _conn.BeginTransaction();
            _conn.Execute("DELETE FROM allowlist_subs", transaction: tx);
            foreach (var url in urls)
            {
                _conn.Execute("INSERT OR IGNORE INTO allowlist_subs(url) VALUES(@url)", new { url }, tx);
            }

            tx.Commit();
        }
    }

    public IReadOnlyList<string> GetAllowlistSubs()
    {
        lock (_gate)
        {
            return _conn.Query<string>("SELECT url FROM allowlist_subs ORDER BY url").ToList();
        }
    }

    // ─── Schedules ────────────────────────────────────────────────────────────

    /// <summary>Replace the full schedule set (the editor saves atomically).</summary>
    public void SetSchedules(IEnumerable<(string Target, string Days, string Start, string End)> schedules)
    {
        ArgumentNullException.ThrowIfNull(schedules);
        lock (_gate)
        {
            using var tx = _conn.BeginTransaction();
            _conn.Execute("DELETE FROM schedules", transaction: tx);
            foreach (var (target, days, start, end) in schedules)
            {
                // Firewall-rule targets (fw:HG_…) are case-sensitive rule names;
                // domain targets are lowercased for case-insensitive matching.
                var stored = target.StartsWith("fw:", StringComparison.Ordinal) ? target : target.ToLowerInvariant();
                _conn.Execute(
                    "INSERT INTO schedules(target,days,start,end) VALUES(@target,@days,@start,@end)",
                    new { target = stored, days, start, end }, tx);
            }

            tx.Commit();
        }
    }

    public IReadOnlyList<(string Target, string Days, string Start, string End)> GetSchedules()
    {
        lock (_gate)
        {
            return _conn.Query<(string, string, string, string)>(
                "SELECT target, days, start, end FROM schedules ORDER BY id").ToList();
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

    // ─── Rule groups (NET-103): assign HG_ rules to named toggleable groups ───

    /// <summary>Assign a rule to a group (idempotent). Empty group removes all of the rule's group memberships.</summary>
    public void AssignRuleToGroup(string ruleName, string group)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(ruleName);
        lock (_gate)
        {
            if (string.IsNullOrWhiteSpace(group))
            {
                _conn.Execute("DELETE FROM rule_groups WHERE rule_name=@r", new { r = ruleName });
                return;
            }

            _conn.Execute("INSERT OR IGNORE INTO rule_groups(grp,rule_name) VALUES(@g,@r)",
                new { g = group.Trim(), r = ruleName });
        }
    }

    /// <summary>Remove a whole group (its rule memberships; the rules themselves stay).</summary>
    public void RemoveRuleGroup(string group)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(group);
        lock (_gate)
        {
            _conn.Execute("DELETE FROM rule_groups WHERE grp=@g", new { g = group.Trim() });
        }
    }

    /// <summary>Rule names in a group.</summary>
    public IReadOnlyList<string> GetRulesInGroup(string group)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(group);
        lock (_gate)
        {
            return _conn.Query<string>("SELECT rule_name FROM rule_groups WHERE grp=@g ORDER BY rule_name",
                new { g = group.Trim() }).ToList();
        }
    }

    /// <summary>All group→rule-name memberships (for listing + portable-policy export).</summary>
    public IReadOnlyList<(string Group, string RuleName)> GetRuleGroups()
    {
        lock (_gate)
        {
            return _conn.Query<(string, string)>(
                "SELECT grp, rule_name FROM rule_groups ORDER BY grp, rule_name").ToList();
        }
    }

    /// <summary>Full tracked-rule rows, for the Secure-Rules tamper reconcile.</summary>
    public IReadOnlyList<FwStateRow> GetFwState()
    {
        lock (_gate)
        {
            return _conn.Query<FwStateRow>(
                """
                SELECT name AS Name, direction AS Direction, action AS Action,
                       remote_addr AS RemoteAddr, protocol AS Protocol, program AS Program
                FROM fw_state
                """).ToList();
        }
    }

    // ─── Adopted (imported) Windows Firewall rules (NET-095) ─────────────────

    /// <summary>
    /// Record existing (non-HG_) Windows Firewall rules HostsGuard adopts into its
    /// view. Non-destructive: the live WF rules are never changed — this only
    /// remembers them so they persist in HostsGuard's model, tagged distinctly.
    /// Returns the number of newly-adopted rows.
    /// </summary>
    public int AdoptRules(IEnumerable<(string Name, string Direction, string Action, string RemoteAddr, string Protocol, string Program, bool Enabled)> rows)
    {
        ArgumentNullException.ThrowIfNull(rows);
        var now = DateTime.Now.ToString("o", System.Globalization.CultureInfo.InvariantCulture);
        var added = 0;
        lock (_gate)
        {
            using var tx = _conn.BeginTransaction();
            foreach (var r in rows)
            {
                if (string.IsNullOrWhiteSpace(r.Name))
                {
                    continue;
                }

                added += _conn.Execute(
                    """
                    INSERT INTO adopted_rules(name,direction,action,remote_addr,protocol,program,enabled,adopted_at)
                    VALUES(@Name,@Direction,@Action,@RemoteAddr,@Protocol,@Program,@Enabled,@now)
                    ON CONFLICT(name) DO UPDATE SET
                        direction=excluded.direction, action=excluded.action, remote_addr=excluded.remote_addr,
                        protocol=excluded.protocol, program=excluded.program, enabled=excluded.enabled
                    """,
                    new { r.Name, r.Direction, r.Action, r.RemoteAddr, r.Protocol, r.Program, Enabled = r.Enabled ? 1 : 0, now }, tx);
            }

            tx.Commit();
        }

        return added;
    }

    public IReadOnlySet<string> GetAdoptedRuleNames()
    {
        lock (_gate)
        {
            return _conn.Query<string>("SELECT name FROM adopted_rules").ToHashSet(StringComparer.Ordinal);
        }
    }

    public void RemoveAdoptedRule(string name)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        lock (_gate)
        {
            _conn.Execute("DELETE FROM adopted_rules WHERE name=@name", new { name });
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

    /// <summary>
    /// Paged/filterable persistent event ledger. Direct filters run in SQLite;
    /// the category filter is applied after deriving the canonical taxonomy
    /// bucket from the stored action.
    /// </summary>
    public EventLogPage GetEvents(EventLogFilter filter)
    {
        ArgumentNullException.ThrowIfNull(filter);
        var limit = Math.Clamp(filter.Limit <= 0 ? 200 : filter.Limit, 1, 2000);
        var offset = Math.Max(0, filter.Offset);
        var (where, args) = BuildEventWhere(filter);

        lock (_gate)
        {
            if (!string.IsNullOrWhiteSpace(filter.Category))
            {
                var all = _conn.Query<EventLogRowRaw>(
                        $"SELECT id, ts, domain, action, process, details, reason FROM log{where} ORDER BY ts DESC, id DESC",
                        args)
                    .Select(ToEventLogRow)
                    .Where(r => string.Equals(r.Category, filter.Category, StringComparison.OrdinalIgnoreCase))
                    .ToList();
                return new EventLogPage(all.Skip(offset).Take(limit).ToList(), all.Count);
            }

            var total = _conn.ExecuteScalar<int>($"SELECT COUNT(*) FROM log{where}", args);
            args.Add("limit", limit);
            args.Add("offset", offset);
            var rows = _conn.Query<EventLogRowRaw>(
                    $"SELECT id, ts, domain, action, process, details, reason FROM log{where} ORDER BY ts DESC, id DESC LIMIT @limit OFFSET @offset",
                    args)
                .Select(ToEventLogRow)
                .ToList();
            return new EventLogPage(rows, total);
        }
    }

    private static (string Where, DynamicParameters Args) BuildEventWhere(EventLogFilter filter)
    {
        var clauses = new List<string>();
        var args = new DynamicParameters();

        AddLike("search", filter.Search,
            "(domain LIKE @search ESCAPE '\\' OR action LIKE @search ESCAPE '\\' OR process LIKE @search ESCAPE '\\' OR details LIKE @search ESCAPE '\\' OR reason LIKE @search ESCAPE '\\')");
        if (!string.IsNullOrWhiteSpace(filter.Since))
        {
            clauses.Add("ts >= @since");
            args.Add("since", filter.Since.Trim());
        }

        if (!string.IsNullOrWhiteSpace(filter.Until))
        {
            clauses.Add("ts <= @until");
            args.Add("until", filter.Until.Trim());
        }

        AddExact("action", filter.Action, "action");
        AddExact("reason", filter.Reason, "reason");
        AddLike("domain", filter.Domain, "domain LIKE @domain ESCAPE '\\'");
        AddLike("process", filter.Process, "process LIKE @process ESCAPE '\\'");

        return (clauses.Count == 0 ? string.Empty : " WHERE " + string.Join(" AND ", clauses), args);

        void AddLike(string name, string? value, string clause)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return;
            }

            clauses.Add(clause);
            args.Add(name, "%" + EscapeLike(value.Trim()) + "%");
        }

        void AddExact(string name, string? value, string column)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return;
            }

            clauses.Add($"LOWER({column}) = LOWER(@{name})");
            args.Add(name, value.Trim());
        }
    }

    private static string EscapeLike(string value) => value
        .Replace("\\", "\\\\", StringComparison.Ordinal)
        .Replace("%", "\\%", StringComparison.Ordinal)
        .Replace("_", "\\_", StringComparison.Ordinal);

    private static EventLogRow ToEventLogRow(EventLogRowRaw row)
        => new(
            row.Id,
            row.Ts ?? string.Empty,
            row.Domain ?? string.Empty,
            row.Action ?? string.Empty,
            row.Process ?? string.Empty,
            row.Details ?? string.Empty,
            row.Reason ?? string.Empty,
            EventTaxonomy.Category(row.Action));

    private sealed record EventLogRowRaw(
        long Id, string? Ts, string? Domain, string? Action, string? Process, string? Details, string? Reason);

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
