using Dapper;

namespace HostsGuard.Data;

public sealed record HistoryPrivacyExclusionRow(string Scope, string Match, string Added);

public sealed partial class HostsDatabase
{
    public IReadOnlyList<HistoryPrivacyExclusionRow> GetHistoryPrivacyExclusions()
    {
        lock (_gate)
            return _conn.Query<HistoryPrivacyExclusionRow>(
                "SELECT scope,match,added FROM history_privacy_exclusions ORDER BY scope,match COLLATE NOCASE").ToList();
    }

    public void UpsertHistoryPrivacyExclusion(string scope, string match)
    {
        (scope, match) = NormalizeHistoryPrivacyExclusion(scope, match);
        lock (_gate)
        {
            _conn.Execute("""
                INSERT INTO history_privacy_exclusions(scope,match,added) VALUES(@scope,@match,@added)
                ON CONFLICT(scope,match) DO UPDATE SET added=excluded.added
                """, new { scope, match, added = DateTime.UtcNow.ToString("o", System.Globalization.CultureInfo.InvariantCulture) });
            PurgeHistoryForExclusionNoLock(scope, match);
        }
    }

    public int DeleteHistoryPrivacyExclusion(string scope, string match)
    {
        (scope, match) = NormalizeHistoryPrivacyExclusion(scope, match);
        lock (_gate)
            return _conn.Execute("DELETE FROM history_privacy_exclusions WHERE scope=@scope AND match=@match", new { scope, match });
    }

    public void ReplaceHistoryPrivacyExclusions(IEnumerable<(string Scope, string Match)> exclusions)
    {
        ArgumentNullException.ThrowIfNull(exclusions);
        var normalized = exclusions.Select(x => NormalizeHistoryPrivacyExclusion(x.Scope, x.Match)).Distinct().ToList();
        lock (_gate)
        using (var tx = _conn.BeginTransaction())
        {
            _conn.Execute("DELETE FROM history_privacy_exclusions", transaction: tx);
            foreach (var (scope, match) in normalized)
            {
                _conn.Execute("INSERT INTO history_privacy_exclusions(scope,match,added) VALUES(@scope,@match,@added)",
                    new { scope, match, added = DateTime.UtcNow.ToString("o", System.Globalization.CultureInfo.InvariantCulture) }, tx);
                PurgeHistoryForExclusionNoLock(scope, match, tx);
            }
            tx.Commit();
        }
    }

    public bool IsHistoryPersistenceExcluded(string? process, string? domain)
    {
        var app = (process ?? string.Empty).Trim();
        var host = (domain ?? string.Empty).Trim().TrimEnd('.').ToLowerInvariant();
        lock (_gate)
        {
            var rules = _conn.Query<(string Scope, string Match)>("SELECT scope,match FROM history_privacy_exclusions");
            return rules.Any(rule => rule.Scope == "app"
                ? app.Equals(rule.Match, StringComparison.OrdinalIgnoreCase)
                : host.Length != 0 && (host.Equals(rule.Match, StringComparison.OrdinalIgnoreCase)
                    || host.EndsWith('.' + rule.Match, StringComparison.OrdinalIgnoreCase)));
        }
    }

    private static (string Scope, string Match) NormalizeHistoryPrivacyExclusion(string scope, string match)
    {
        var cleanScope = (scope ?? string.Empty).Trim().ToLowerInvariant();
        if (cleanScope is not ("app" or "domain")) throw new ArgumentException("scope must be app or domain", nameof(scope));
        var cleanMatch = (match ?? string.Empty).Trim();
        if (cleanScope == "domain") cleanMatch = cleanMatch.TrimEnd('.').ToLowerInvariant();
        if (cleanMatch.Length == 0 || cleanMatch.Length > 512 || cleanMatch.IndexOfAny(['\r', '\n', '\0']) >= 0)
            throw new ArgumentException("match must be 1-512 safe characters", nameof(match));
        return (cleanScope, cleanMatch);
    }

    private void PurgeHistoryForExclusionNoLock(string scope, string match, System.Data.IDbTransaction? tx = null)
    {
        if (scope == "app")
        {
            _conn.Execute("DELETE FROM conn_history WHERE process=@match COLLATE NOCASE; DELETE FROM app_bandwidth WHERE process=@match COLLATE NOCASE; DELETE FROM domain_usage WHERE process=@match COLLATE NOCASE; DELETE FROM usage_daily WHERE process=@match COLLATE NOCASE; DELETE FROM feed WHERE process=@match COLLATE NOCASE;",
                new { match }, tx);
            return;
        }

        const string suffix = "%.";
        var like = suffix + match;
        _conn.Execute("""
            DELETE FROM conn_history WHERE host=@match COLLATE NOCASE OR host LIKE @like COLLATE NOCASE;
            DELETE FROM domain_usage WHERE domain=@match COLLATE NOCASE OR domain LIKE @like COLLATE NOCASE;
            DELETE FROM usage_daily WHERE domain=@match COLLATE NOCASE OR domain LIKE @like COLLATE NOCASE;
            DELETE FROM feed_domain_hourly WHERE domain=@match COLLATE NOCASE OR domain LIKE @like COLLATE NOCASE;
            DELETE FROM feed WHERE domain=@match COLLATE NOCASE OR domain LIKE @like COLLATE NOCASE;
            DELETE FROM resolved_hosts WHERE host=@match COLLATE NOCASE OR host LIKE @like COLLATE NOCASE;
            """, new { match, like }, tx);
    }
}
