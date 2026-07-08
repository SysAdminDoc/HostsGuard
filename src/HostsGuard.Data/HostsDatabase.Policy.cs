using Dapper;
using HostsGuard.Core;

namespace HostsGuard.Data;

public sealed partial class HostsDatabase
{
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


}
