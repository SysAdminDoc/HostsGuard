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

/// <summary>
/// SQLite persistence for HostsGuard (Microsoft.Data.Sqlite + Dapper). Schema v1
/// mirrors the Python schema v7 (domains/feed/log/fw_state/profiles + canonical
/// reason columns) and includes the legacy column-rename migration so a
/// pre-versioning database opens without data loss. WAL, busy_timeout, and an
/// integrity check run on open. The path is injectable for testability.
/// </summary>
public sealed class HostsDatabase : IDisposable
{
    public const int SchemaVersion = 6;

    /// <summary>Default connection-history / bandwidth retention (days).</summary>
    public const int DefaultHistoryRetentionDays = 30;

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
            CREATE TABLE IF NOT EXISTS schedules(
                id INTEGER PRIMARY KEY, target TEXT, days TEXT, start TEXT, end TEXT);
            CREATE TABLE IF NOT EXISTS blocklist_subs(
                name TEXT PRIMARY KEY, url TEXT, last_refresh TEXT, domain_count INTEGER DEFAULT 0);
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

    public string? GetMeta(string key)
    {
        lock (_gate)
        {
            return _conn.ExecuteScalar<string?>("SELECT value FROM meta WHERE key=@key", new { key });
        }
    }

    public void SetMeta(string key, string value)
    {
        lock (_gate)
        {
            _conn.Execute("INSERT OR REPLACE INTO meta(key,value) VALUES(@key,@value)", new { key, value });
        }
    }

    // ─── Blocklist / allowlist subscriptions ──────────────────────────────────

    public void UpsertBlocklistSub(string name, string url, long domainCount)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        var now = DateTime.Now.ToString("o", System.Globalization.CultureInfo.InvariantCulture);
        lock (_gate)
        {
            _conn.Execute(
                "INSERT OR REPLACE INTO blocklist_subs(name,url,last_refresh,domain_count) VALUES(@name,@url,@now,@domainCount)",
                new { name, url, now, domainCount });
        }
    }

    public void RemoveBlocklistSub(string name)
    {
        lock (_gate)
        {
            _conn.Execute("DELETE FROM blocklist_subs WHERE name=@name", new { name });
        }
    }

    public IReadOnlyList<(string Name, string Url, string LastRefresh, long DomainCount)> GetBlocklistSubs()
    {
        lock (_gate)
        {
            return _conn.Query<(string, string, string, long)>(
                "SELECT name, url, last_refresh, domain_count FROM blocklist_subs ORDER BY name").ToList();
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
                _conn.Execute(
                    "INSERT INTO schedules(target,days,start,end) VALUES(@target,@days,@start,@end)",
                    new { target = target.ToLowerInvariant(), days, start, end }, tx);
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
