using System.Text;
using Dapper;

namespace HostsGuard.Data;

public sealed partial class HostsDatabase
{
    private const string UsageQuotaScopeApp = "app";
    private const string UsageQuotaScopeDomain = "domain";

    public IReadOnlyList<UsageQuotaRuleRow> GetUsageQuotaRules()
    {
        lock (_gate)
        {
            return _conn.Query<UsageQuotaRuleRaw>(
                    """
                    SELECT id AS Id, scope AS Scope, match AS Match,
                           limit_bytes AS LimitBytes, window_days AS WindowDays, enabled AS Enabled,
                           last_alerted_bytes AS LastAlertedBytes, last_alerted_at AS LastAlertedAt,
                           created AS Created, updated AS Updated
                    FROM usage_quota_rules
                    ORDER BY scope COLLATE NOCASE, match COLLATE NOCASE
                    """)
                .Select(ToUsageQuotaRule)
                .ToList();
        }
    }

    public UsageQuotaRuleRow UpsertUsageQuotaRule(string scope, string match, long limitBytes, int windowDays, bool enabled)
    {
        scope = NormalizeUsageQuotaScope(scope);
        match = CleanUsageQuotaMatch(scope, match);
        if (scope.Length == 0)
        {
            throw new ArgumentException("scope must be app or domain", nameof(scope));
        }

        if (match.Length == 0)
        {
            throw new ArgumentException("quota match is required", nameof(match));
        }

        if (limitBytes <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(limitBytes), "quota limit must be greater than zero");
        }

        windowDays = Math.Clamp(windowDays <= 0 ? 30 : windowDays, 1, 365);
        var now = DateTime.Now.ToString("o", System.Globalization.CultureInfo.InvariantCulture);
        lock (_gate)
        {
            _conn.Execute(
                """
                INSERT INTO usage_quota_rules(scope,match,limit_bytes,window_days,enabled,last_alerted_bytes,last_alerted_at,created,updated)
                VALUES(@scope,@match,@limitBytes,@windowDays,@enabled,0,'',@now,@now)
                ON CONFLICT(scope,match) DO UPDATE SET
                    limit_bytes=excluded.limit_bytes,
                    window_days=excluded.window_days,
                    enabled=excluded.enabled,
                    updated=excluded.updated,
                    last_alerted_bytes=CASE
                        WHEN usage_quota_rules.limit_bytes != excluded.limit_bytes THEN 0
                        ELSE usage_quota_rules.last_alerted_bytes
                    END,
                    last_alerted_at=CASE
                        WHEN usage_quota_rules.limit_bytes != excluded.limit_bytes THEN ''
                        ELSE usage_quota_rules.last_alerted_at
                    END
                """,
                new
                {
                    scope,
                    match,
                    limitBytes,
                    windowDays,
                    enabled = enabled ? 1 : 0,
                    now,
                });

            var row = _conn.QuerySingle<UsageQuotaRuleRaw>(
                    """
                    SELECT id AS Id, scope AS Scope, match AS Match,
                           limit_bytes AS LimitBytes, window_days AS WindowDays, enabled AS Enabled,
                           last_alerted_bytes AS LastAlertedBytes, last_alerted_at AS LastAlertedAt,
                           created AS Created, updated AS Updated
                    FROM usage_quota_rules
                    WHERE scope=@scope AND match=@match
                    """,
                    new { scope, match });
            return ToUsageQuotaRule(row);
        }
    }

    public int DeleteUsageQuotaRule(long id, string? scope = null, string? match = null)
    {
        lock (_gate)
        {
            if (id > 0)
            {
                return _conn.Execute("DELETE FROM usage_quota_rules WHERE id=@id", new { id });
            }

            var cleanScope = NormalizeUsageQuotaScope(scope ?? string.Empty);
            var cleanMatch = CleanUsageQuotaMatch(cleanScope, match ?? string.Empty);
            if (cleanScope.Length == 0 || cleanMatch.Length == 0)
            {
                return 0;
            }

            return _conn.Execute(
                "DELETE FROM usage_quota_rules WHERE scope=@scope AND match=@match",
                new { scope = cleanScope, match = cleanMatch });
        }
    }

    public int ResetUsageQuotaHistory()
    {
        lock (_gate)
        {
            return _conn.Execute("UPDATE usage_quota_rules SET last_alerted_bytes=0,last_alerted_at='',updated=@now",
                new { now = DateTime.Now.ToString("o", System.Globalization.CultureInfo.InvariantCulture) });
        }
    }

    public void ReplaceUsageQuotaRules(IEnumerable<(string Scope, string Match, long LimitBytes, int WindowDays, bool Enabled)> rules)
    {
        ArgumentNullException.ThrowIfNull(rules);
        lock (_gate)
        {
            using var tx = _conn.BeginTransaction();
            _conn.Execute("DELETE FROM usage_quota_rules", transaction: tx);
            foreach (var rule in rules)
            {
                var scope = NormalizeUsageQuotaScope(rule.Scope);
                var match = CleanUsageQuotaMatch(scope, rule.Match);
                if (scope.Length == 0 || match.Length == 0 || rule.LimitBytes <= 0)
                {
                    continue;
                }

                var now = DateTime.Now.ToString("o", System.Globalization.CultureInfo.InvariantCulture);
                _conn.Execute(
                    """
                    INSERT INTO usage_quota_rules(scope,match,limit_bytes,window_days,enabled,last_alerted_bytes,last_alerted_at,created,updated)
                    VALUES(@scope,@match,@limitBytes,@windowDays,@enabled,0,'',@now,@now)
                    """,
                    new
                    {
                        scope,
                        match,
                        limitBytes = rule.LimitBytes,
                        windowDays = Math.Clamp(rule.WindowDays <= 0 ? 30 : rule.WindowDays, 1, 365),
                        enabled = rule.Enabled ? 1 : 0,
                        now,
                    },
                    tx);
            }

            tx.Commit();
        }
    }

    public IReadOnlyList<UsageQuotaEvaluation> EvaluateUsageQuotas(DateTime now, bool triggeredOnly = false)
    {
        lock (_gate)
        {
            var rules = _conn.Query<UsageQuotaRuleRaw>(
                    """
                    SELECT id AS Id, scope AS Scope, match AS Match,
                           limit_bytes AS LimitBytes, window_days AS WindowDays, enabled AS Enabled,
                           last_alerted_bytes AS LastAlertedBytes, last_alerted_at AS LastAlertedAt,
                           created AS Created, updated AS Updated
                    FROM usage_quota_rules
                    WHERE enabled=1
                    ORDER BY scope COLLATE NOCASE, match COLLATE NOCASE
                    """)
                .Select(ToUsageQuotaRule)
                .ToList();
            var result = new List<UsageQuotaEvaluation>();
            foreach (var rule in rules)
            {
                var used = GetUsageBytesForRuleNoLock(rule, now);
                var crossed = used >= rule.LimitBytes && rule.LimitBytes > 0 && rule.LastAlertedBytes < rule.LimitBytes;
                if (!triggeredOnly || crossed)
                {
                    result.Add(new UsageQuotaEvaluation(rule, used, crossed));
                }
            }

            return result;
        }
    }

    public long GetUsageBytesForQuota(string scope, string match, int windowDays, DateTime now)
    {
        scope = NormalizeUsageQuotaScope(scope);
        match = CleanUsageQuotaMatch(scope, match);
        if (scope.Length == 0 || match.Length == 0)
        {
            return 0;
        }

        var rule = new UsageQuotaRuleRow(0, scope, match, 1, Math.Clamp(windowDays <= 0 ? 30 : windowDays, 1, 365),
            true, 0, string.Empty, string.Empty, string.Empty);
        lock (_gate)
        {
            return GetUsageBytesForRuleNoLock(rule, now);
        }
    }

    public void MarkUsageQuotaAlerted(long id, long usedBytes, DateTime now)
    {
        if (id <= 0)
        {
            return;
        }

        lock (_gate)
        {
            _conn.Execute(
                """
                UPDATE usage_quota_rules
                SET last_alerted_bytes=@used,
                    last_alerted_at=@now,
                    updated=@now
                WHERE id=@id
                """,
                new
                {
                    id,
                    used = Math.Max(0, usedBytes),
                    now = now.ToString("o", System.Globalization.CultureInfo.InvariantCulture),
                });
        }
    }

    public IReadOnlyList<UsageQuotaHistoryRow> GetUsageQuotaHistory(
        DateTime sinceDay,
        string? scope = null,
        string? match = null,
        int limit = 2000)
    {
        var cleanScope = NormalizeUsageQuotaScope(scope ?? string.Empty);
        var cleanMatch = CleanUsageQuotaMatch(cleanScope, match ?? string.Empty);
        var since = sinceDay.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture);
        var cappedLimit = Math.Clamp(limit <= 0 ? 2000 : limit, 1, 10000);
        var matchParam = string.Empty;
        var where = "WHERE day >= @since";
        if (cleanScope == UsageQuotaScopeApp && cleanMatch.Length != 0)
        {
            where += " AND lower(process)=@match";
            matchParam = cleanMatch.ToLowerInvariant();
        }
        else if (cleanScope == UsageQuotaScopeDomain && cleanMatch.Length != 0)
        {
            where += " AND lower(domain)=@match";
            matchParam = cleanMatch.ToLowerInvariant();
        }

        var sql = cleanScope switch
        {
            UsageQuotaScopeApp => $"""
                SELECT day AS Day, CAST('app' AS TEXT) AS Scope, process AS Match,
                       CAST(SUM(sent) AS INTEGER) AS Sent, CAST(SUM(recv) AS INTEGER) AS Recv
                FROM usage_daily
                {where}
                GROUP BY day, process
                ORDER BY day DESC, (SUM(sent)+SUM(recv)) DESC, process COLLATE NOCASE
                LIMIT @limit
                """,
            UsageQuotaScopeDomain => $"""
                SELECT day AS Day, CAST('domain' AS TEXT) AS Scope, domain AS Match,
                       CAST(SUM(sent) AS INTEGER) AS Sent, CAST(SUM(recv) AS INTEGER) AS Recv
                FROM usage_daily
                {where}
                GROUP BY day, domain
                ORDER BY day DESC, (SUM(sent)+SUM(recv)) DESC, domain COLLATE NOCASE
                LIMIT @limit
                """,
            _ => $"""
                SELECT day AS Day, CAST('app' AS TEXT) AS Scope, process AS Match,
                       CAST(SUM(sent) AS INTEGER) AS Sent, CAST(SUM(recv) AS INTEGER) AS Recv,
                       CAST(SUM(sent)+SUM(recv) AS INTEGER) AS Total
                FROM usage_daily
                {where}
                GROUP BY day, process
                UNION ALL
                SELECT day AS Day, CAST('domain' AS TEXT) AS Scope, domain AS Match,
                       CAST(SUM(sent) AS INTEGER) AS Sent, CAST(SUM(recv) AS INTEGER) AS Recv,
                       CAST(SUM(sent)+SUM(recv) AS INTEGER) AS Total
                FROM usage_daily
                {where}
                GROUP BY day, domain
                ORDER BY Day DESC, Total DESC, Scope COLLATE NOCASE, Match COLLATE NOCASE
                LIMIT @limit
                """,
        };

        lock (_gate)
        {
            using var cmd = _conn.CreateCommand();
            cmd.CommandText = sql;
            cmd.Parameters.AddWithValue("@since", since);
            cmd.Parameters.AddWithValue("@limit", cappedLimit);
            if (matchParam.Length != 0)
            {
                cmd.Parameters.AddWithValue("@match", matchParam);
            }

            using var reader = cmd.ExecuteReader();
            var rows = new List<UsageQuotaHistoryRow>();
            while (reader.Read())
            {
                rows.Add(new UsageQuotaHistoryRow(
                    ReadText(reader.GetValue(0)),
                    ReadText(reader.GetValue(1)),
                    ReadText(reader.GetValue(2)),
                    ReadLong(reader.GetValue(3)),
                    ReadLong(reader.GetValue(4))));
            }

            return rows;
        }
    }

    private static string ReadText(object value)
        => value switch
        {
            null or DBNull => string.Empty,
            string s => s,
            byte[] b => Encoding.UTF8.GetString(b),
            _ => Convert.ToString(value, System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty,
        };

    private static long ReadLong(object value)
        => value switch
        {
            null or DBNull => 0,
            long l => l,
            int i => i,
            byte[] b when long.TryParse(Encoding.UTF8.GetString(b), System.Globalization.NumberStyles.Integer,
                System.Globalization.CultureInfo.InvariantCulture, out var parsed) => parsed,
            _ => Convert.ToInt64(value, System.Globalization.CultureInfo.InvariantCulture),
        };

    private long GetUsageBytesForRuleNoLock(UsageQuotaRuleRow rule, DateTime now)
    {
        var since = now.Date.AddDays(-(Math.Clamp(rule.WindowDays <= 0 ? 30 : rule.WindowDays, 1, 365) - 1))
            .ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture);
        return rule.Scope switch
        {
            UsageQuotaScopeApp => _conn.ExecuteScalar<long>(
                "SELECT COALESCE(SUM(sent+recv),0) FROM usage_daily WHERE day >= @since AND lower(process)=@match",
                new { since, match = rule.Match.ToLowerInvariant() }),
            UsageQuotaScopeDomain => _conn.ExecuteScalar<long>(
                "SELECT COALESCE(SUM(sent+recv),0) FROM usage_daily WHERE day >= @since AND lower(domain)=@match",
                new { since, match = rule.Match.ToLowerInvariant() }),
            _ => 0,
        };
    }

    private static UsageQuotaRuleRow ToUsageQuotaRule(UsageQuotaRuleRaw row)
        => new(
            row.Id,
            row.Scope ?? string.Empty,
            row.Match ?? string.Empty,
            row.LimitBytes,
            (int)row.WindowDays,
            row.Enabled != 0,
            row.LastAlertedBytes,
            row.LastAlertedAt ?? string.Empty,
            row.Created ?? string.Empty,
            row.Updated ?? string.Empty);

    private static string NormalizeUsageQuotaScope(string scope)
    {
        var clean = (scope ?? string.Empty).Trim().ToLowerInvariant();
        return clean switch
        {
            "" => string.Empty,
            "app" or "process" => UsageQuotaScopeApp,
            "domain" or "host" => UsageQuotaScopeDomain,
            _ => string.Empty,
        };
    }

    private static string CleanUsageQuotaMatch(string scope, string match)
    {
        var clean = (match ?? string.Empty).Trim();
        return scope == UsageQuotaScopeDomain ? clean.TrimEnd('.').ToLowerInvariant() : clean;
    }

    private sealed record UsageQuotaRuleRaw(
        long Id,
        string? Scope,
        string? Match,
        long LimitBytes,
        long WindowDays,
        long Enabled,
        long LastAlertedBytes,
        string? LastAlertedAt,
        string? Created,
        string? Updated);
}
