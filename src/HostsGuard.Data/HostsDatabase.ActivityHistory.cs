using Dapper;
using HostsGuard.Core;

namespace HostsGuard.Data;

public sealed partial class HostsDatabase
{
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
                INSERT INTO conn_history(ts,process,pid,protocol,remote_addr,remote_port,country,fw_status,host,asn)
                VALUES(@Ts,@Process,@Pid,@Protocol,@RemoteAddr,@RemotePort,@Country,@FwStatus,@Host,@Asn)
                """, row);
            _conn.Execute("DELETE FROM conn_history WHERE ts < @cutoff", new { cutoff });
        }
    }

    /// <summary>
    /// Query recorded connections, newest first. <paramref name="search"/> is a
    /// substring match across process, remote address, and country.
    /// </summary>
    public IReadOnlyList<ConnHistoryRow> GetConnectionHistory(int limit = 500, string? search = null, string? since = null)
        => GetConnectionHistoryPage(new ConnectionHistoryFilter(
            Limit: limit,
            Search: search,
            Since: since)).Rows;

    public ConnectionHistoryPage GetConnectionHistoryPage(ConnectionHistoryFilter filter)
    {
        var limit = Math.Clamp(filter.Limit > 0 ? filter.Limit : 500, 1, 10_000);
        var offset = Math.Max(0, filter.Offset);
        var (where, p) = BuildConnectionHistoryWhere(filter);
        var sql = $"""
            SELECT ts AS Ts, process AS Process, pid AS Pid, protocol AS Protocol,
                   remote_addr AS RemoteAddr, remote_port AS RemotePort,
                   country AS Country, fw_status AS FwStatus, host AS Host, asn AS Asn
            FROM conn_history{where}
            ORDER BY ts DESC LIMIT @limit OFFSET @offset
            """;
        p.Add("limit", limit);
        p.Add("offset", offset);
        lock (_gate)
        {
            var total = _conn.ExecuteScalar<int>($"SELECT COUNT(*) FROM conn_history{where}", p);
            var rows = _conn.Query<ConnHistoryRow>(sql, p).ToList();
            return new ConnectionHistoryPage(rows, total, limit, offset);
        }
    }

    public int ClearConnectionHistory()
    {
        lock (_gate)
        {
            return _conn.Execute("DELETE FROM conn_history");
        }
    }

    private static (string Where, DynamicParameters Args) BuildConnectionHistoryWhere(ConnectionHistoryFilter filter)
    {
        var clauses = new List<string>();
        var args = new DynamicParameters();

        AddLike("search", filter.Search,
            "(process LIKE @search ESCAPE '\\' OR host LIKE @search ESCAPE '\\' OR remote_addr LIKE @search ESCAPE '\\' OR country LIKE @search ESCAPE '\\' OR asn LIKE @search ESCAPE '\\' OR fw_status LIKE @search ESCAPE '\\' OR protocol LIKE @search ESCAPE '\\')");
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

        AddLike("process", filter.Process, "process LIKE @process ESCAPE '\\'");
        AddLike("host", filter.Host, "host LIKE @host ESCAPE '\\'");
        AddLike("remoteAddr", filter.RemoteAddr, "remote_addr LIKE @remoteAddr ESCAPE '\\'");
        AddLike("fwStatus", filter.FwStatus, "fw_status LIKE @fwStatus ESCAPE '\\'");
        AddExact("protocol", filter.Protocol, "protocol");

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
        var usageDailyCutoff = now.AddDays(-HistoryRetentionDays)
            .ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture);
        var hourlyCutoff = now.AddHours(-48)
            .ToString("yyyy-MM-ddTHH", System.Globalization.CultureInfo.InvariantCulture);
        var domainHourlyCutoff = now.AddDays(-HistoryRetentionDays)
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
            var usageDailyRows = _conn.Execute("DELETE FROM usage_daily WHERE day < @cutoff",
                new { cutoff = usageDailyCutoff }, tx);
            var hourlyBuckets = _conn.Execute("DELETE FROM feed_hourly WHERE hour < @cutoff",
                new { cutoff = hourlyCutoff }, tx);
            hourlyBuckets += _conn.Execute("DELETE FROM feed_domain_hourly WHERE hour < @cutoff",
                new { cutoff = domainHourlyCutoff }, tx);
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
                usageDailyRows,
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

    /// <summary>Accumulate bytes into the durable daily app x domain rollup.</summary>
    public void AddUsageRollup(string domain, string process, DateTime day, long sent, long recv)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(domain);
        if (sent == 0 && recv == 0)
        {
            return;
        }

        var dayKey = day.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture);
        lock (_gate)
        {
            _conn.Execute(
                """
                INSERT INTO usage_daily(day,process,domain,sent,recv)
                VALUES(@day,@process,@domain,@sent,@recv)
                ON CONFLICT(day,process,domain) DO UPDATE SET
                    sent=sent+excluded.sent, recv=recv+excluded.recv
                """,
                new
                {
                    day = dayKey,
                    process = process ?? string.Empty,
                    domain = domain.ToLowerInvariant(),
                    sent,
                    recv,
                });
        }
    }

    /// <summary>Query daily per-app/per-domain rollups, newest window first and largest rows first.</summary>
    public IReadOnlyList<UsageRollupRow> GetUsageRollups(
        DateTime sinceDay,
        int limit = 200,
        string? search = null,
        string? process = null,
        string? domain = null)
    {
        var sql = """
            SELECT day AS Day, process AS Process, domain AS Domain, sent AS Sent, recv AS Recv
            FROM usage_daily
            WHERE day >= @since
            """;
        var p = new DynamicParameters();
        p.Add("since", sinceDay.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture));
        if (!string.IsNullOrWhiteSpace(search))
        {
            sql += " AND (domain LIKE @search ESCAPE '\\' OR process LIKE @search ESCAPE '\\')";
            p.Add("search", $"%{EscapeLike(search.Trim())}%");
        }

        if (!string.IsNullOrWhiteSpace(process))
        {
            sql += " AND process LIKE @process ESCAPE '\\'";
            p.Add("process", $"%{EscapeLike(process.Trim())}%");
        }

        if (!string.IsNullOrWhiteSpace(domain))
        {
            sql += " AND domain LIKE @domain ESCAPE '\\'";
            p.Add("domain", $"%{EscapeLike(domain.Trim().ToLowerInvariant())}%");
        }

        sql += " ORDER BY (sent+recv) DESC, day DESC, process COLLATE NOCASE, domain COLLATE NOCASE LIMIT @limit";
        p.Add("limit", Math.Clamp(limit, 1, 2000));
        lock (_gate)
        {
            return _conn.Query<UsageRollupRow>(sql, p).ToList();
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


}
