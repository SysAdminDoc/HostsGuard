using Dapper;
using HostsGuard.Core;

namespace HostsGuard.Data;

public sealed partial class HostsDatabase
{
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

    /// <summary>Managed status for a bounded set of domain keys.</summary>
    public IReadOnlyDictionary<string, string> GetDomainStatuses(IEnumerable<string> domains)
    {
        ArgumentNullException.ThrowIfNull(domains);
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        lock (_gate)
        {
            foreach (var chunk in domains
                .Select(Domains.ToAscii)
                .Where(Domains.LooksLikeDomain)
                .Distinct(StringComparer.Ordinal)
                .Chunk(500))
            {
                foreach (var row in _conn.Query<(string Domain, string Status)>(
                    "SELECT domain, status FROM domains WHERE domain IN @chunk",
                    new { chunk }))
                {
                    result[row.Domain] = row.Status;
                }
            }
        }

        return result;
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
        if (!string.IsNullOrEmpty(search)) { sql += " AND domain LIKE @search ESCAPE '\\'"; p.Add("search", $"%{EscapeLike(search)}%"); }
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
        var seenAt = DateTime.Now;
        var now = seenAt.ToString("o", System.Globalization.CultureInfo.InvariantCulture);
        var hour = seenAt.ToString("yyyy-MM-ddTHH", System.Globalization.CultureInfo.InvariantCulture);
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
            _conn.Execute(
                """
                INSERT INTO feed_domain_hourly(domain,hour,hits) VALUES(@domain,@hour,1)
                ON CONFLICT(domain,hour) DO UPDATE SET hits=hits+1
                """,
                new { domain = domain.ToLowerInvariant(), hour });
        }
    }

    /// <summary>
    /// Persist a batch of DNS sightings in one transaction: feed rows are
    /// upserted by domain and hourly sparkline buckets by root/hour.
    /// </summary>
    public void RecordDnsSightings(IEnumerable<DnsSightingWrite> sightings)
    {
        ArgumentNullException.ThrowIfNull(sightings);
        var rows = sightings
            .Where(s => !string.IsNullOrWhiteSpace(s.Domain))
            .Select(s => new DnsSightingWrite(
                s.Domain.ToLowerInvariant().Trim(),
                s.Process ?? string.Empty,
                s.Reason,
                s.SeenAt,
                s.Pid,
                s.ParentPath ?? string.Empty))
            .ToList();
        if (rows.Count == 0)
        {
            return;
        }

        lock (_gate)
        {
            using var tx = _conn.BeginTransaction();
            foreach (var group in rows.GroupBy(r => r.Domain, StringComparer.Ordinal))
            {
                var first = group.Min(r => r.SeenAt)
                    .ToString("o", System.Globalization.CultureInfo.InvariantCulture);
                var last = group.Max(r => r.SeenAt)
                    .ToString("o", System.Globalization.CultureInfo.InvariantCulture);
                var identity = group.Last();
                var process = identity.Process.Length != 0
                    ? identity.Process
                    : group.LastOrDefault(r => !string.IsNullOrWhiteSpace(r.Process))?.Process ?? string.Empty;
                var reason = group.LastOrDefault(r => !string.IsNullOrWhiteSpace(r.Reason))?.Reason;
                _conn.Execute(
                    """
                    INSERT INTO feed(domain,first_seen,last_seen,hits,process,hidden,reason,pid,parent_path)
                    VALUES(@domain,@first,@last,@hits,@process,0,@reason,@pid,@parentPath)
                    ON CONFLICT(domain) DO UPDATE SET
                        last_seen=excluded.last_seen,
                        hits=feed.hits+excluded.hits,
                        process=CASE WHEN excluded.process!='' THEN excluded.process ELSE feed.process END,
                        reason=CASE WHEN excluded.reason IS NOT NULL AND excluded.reason!='' THEN excluded.reason ELSE feed.reason END,
                        pid=excluded.pid,
                        parent_path=excluded.parent_path
                    """,
                    new
                    {
                        domain = group.Key,
                        first,
                        last,
                        hits = group.Count(),
                        process,
                        reason,
                        pid = identity.Pid,
                        parentPath = new DbString
                        {
                            Value = identity.ParentPath,
                            IsAnsi = false,
                            Length = -1,
                        },
                    },
                    tx);
            }

            foreach (var group in rows
                         .Select(r => new
                         {
                             r.Domain,
                             Hour = r.SeenAt.ToString("yyyy-MM-ddTHH", System.Globalization.CultureInfo.InvariantCulture),
                         })
                         .GroupBy(r => (r.Domain, r.Hour)))
            {
                _conn.Execute(
                    """
                    INSERT INTO feed_domain_hourly(domain,hour,hits) VALUES(@domain,@hour,@hits)
                    ON CONFLICT(domain,hour) DO UPDATE SET hits=hits+excluded.hits
                    """,
                    new { domain = group.Key.Domain, hour = group.Key.Hour, hits = group.Count() },
                    tx);
            }

            foreach (var group in rows
                         .Select(r => new
                         {
                             Root = Domains.GetRoot(r.Domain),
                             Hour = r.SeenAt.ToString("yyyy-MM-ddTHH", System.Globalization.CultureInfo.InvariantCulture),
                         })
                         .Where(r => !string.IsNullOrWhiteSpace(r.Root))
                         .GroupBy(r => (r.Root, r.Hour)))
            {
                _conn.Execute(
                    """
                    INSERT INTO feed_hourly(root,hour,hits) VALUES(@root,@hour,@hits)
                    ON CONFLICT(root,hour) DO UPDATE SET hits=hits+excluded.hits
                    """,
                    new { root = group.Key.Root, hour = group.Key.Hour, hits = group.Count() },
                    tx);
            }

            tx.Commit();
        }
    }

    /// <summary>
    /// Increment the current-hour hit bucket for a domain root (NET-042
    /// sparkline source). Retention is handled by <see cref="RunRetentionSweep"/>.
    /// </summary>
    public void RecordHourly(string root, DateTime now)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(root);
        var hour = now.ToString("yyyy-MM-ddTHH", System.Globalization.CultureInfo.InvariantCulture);
        lock (_gate)
        {
            _conn.Execute(
                """
                INSERT INTO feed_hourly(root,hour,hits) VALUES(@root,@hour,1)
                ON CONFLICT(root,hour) DO UPDATE SET hits=hits+1
                """,
                new { root, hour });
        }
    }

    /// <summary>Recent feed rows (newest first), joined with managed-domain status.</summary>
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

    /// <summary>True if the domain already has a feed row (i.e. it has been observed before).</summary>
    public bool FeedContains(string domain)
    {
        if (string.IsNullOrWhiteSpace(domain))
        {
            return false;
        }

        lock (_gate)
        {
            ThrowIfDisposed();
            return _conn.ExecuteScalar<long>(
                "SELECT COUNT(1) FROM feed WHERE domain=@d",
                new { d = domain.ToLowerInvariant() }) != 0;
        }
    }

    public IReadOnlyList<FeedRow> GetFeed(int limit = 500)
    {
        lock (_gate)
        {
            return _conn.Query<FeedRow>(
                """
                SELECT f.domain AS Domain, f.first_seen AS FirstSeen, f.last_seen AS LastSeen,
                       f.hits AS Hits, f.process AS Process, f.hidden AS Hidden, f.reason AS Reason,
                       d.status AS Status, f.pid AS Pid, f.parent_path AS ParentPath
                FROM feed f LEFT JOIN domains d ON d.domain = f.domain
                ORDER BY f.last_seen DESC LIMIT @limit
                """,
                new { limit }).ToList();
        }
    }

    /// <summary>
    /// Frequently observed blocked domains with persisted direct-parent
    /// identity. CDN and trust evidence are evaluated by the service against
    /// current curated knowledge and explicit trust settings.
    /// </summary>
    public IReadOnlyList<AllowlistCandidateRow> GetAllowlistCandidates(int limit = 500)
    {
        lock (_gate)
        {
            return _conn.Query(
                """
                SELECT f.domain AS Domain, f.hits AS Hits,
                       COALESCE(f.process,'') AS Process,
                       COALESCE(f.parent_path,'') AS ParentPath,
                       COALESCE(d.category,'') AS Category
                FROM feed f
                JOIN domains d ON d.domain=f.domain
                WHERE d.status='blocked' AND f.hits>=@minimumHits
                      AND length(hex(f.parent_path))>0
                ORDER BY f.hits DESC, f.domain ASC
                LIMIT @limit
                """,
                new
                {
                    minimumHits = HostsGuard.Core.AllowlistRecommendationScorer.MinimumHits,
                    limit = Math.Clamp(limit, 1, 2000),
                })
                .Select(row =>
                {
                    var values = (IDictionary<string, object?>)row;
                    return new AllowlistCandidateRow(
                        ReadText(values["Domain"] ?? DBNull.Value),
                        ReadLong(values["Hits"] ?? DBNull.Value),
                        ReadText(values["Process"] ?? DBNull.Value).TrimEnd('\0'),
                        ReadText(values["ParentPath"] ?? DBNull.Value).TrimEnd('\0'),
                        ReadText(values["Category"] ?? DBNull.Value).TrimEnd('\0'));
                })
                .Where(row => row.ParentPath.Length != 0)
                .ToList();
        }
    }


}
