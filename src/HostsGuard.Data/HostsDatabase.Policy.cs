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
                .Where(r => DateTime.TryParse(r.Item2, System.Globalization.CultureInfo.InvariantCulture,
                    System.Globalization.DateTimeStyles.AdjustToUniversal | System.Globalization.DateTimeStyles.AssumeUniversal, out _))
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

    public long CreatePolicyImportCheckpoint(string json, IEnumerable<string> summary)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(json);
        ArgumentNullException.ThrowIfNull(summary);
        var now = DateTime.Now.ToString("o", System.Globalization.CultureInfo.InvariantCulture);
        lock (_gate)
        {
            return _conn.ExecuteScalar<long>(
                """
                INSERT INTO policy_import_checkpoints(created,json,summary)
                VALUES(@now,@json,@summary);
                SELECT last_insert_rowid();
                """,
                new { now, json, summary = string.Join("\n", summary) });
        }
    }

    public PolicyImportCheckpointRow? GetLatestPolicyImportCheckpoint()
    {
        lock (_gate)
        {
            return _conn.QuerySingleOrDefault<PolicyImportCheckpointRow>(
                """
                SELECT id AS Id, COALESCE(created,'') AS Created, json AS Json, COALESCE(summary,'') AS Summary
                FROM policy_import_checkpoints
                ORDER BY id DESC
                LIMIT 1
                """);
        }
    }

    public PolicyImportCheckpointRow? GetPolicyImportCheckpoint(long id)
    {
        if (id <= 0)
        {
            return null;
        }

        lock (_gate)
        {
            return _conn.QuerySingleOrDefault<PolicyImportCheckpointRow>(
                """
                SELECT id AS Id, COALESCE(created,'') AS Created, json AS Json, COALESCE(summary,'') AS Summary
                FROM policy_import_checkpoints
                WHERE id=@id
                LIMIT 1
                """,
                new { id });
        }
    }

    public IReadOnlyList<PolicySubscriptionRow> GetPolicySubscriptions()
    {
        lock (_gate)
        {
            return QueryPolicySubscriptionsNoLock(string.Empty, null);
        }
    }

    public PolicySubscriptionRow? GetPolicySubscription(long id)
    {
        if (id <= 0)
        {
            return null;
        }

        lock (_gate)
        {
            return QueryPolicySubscriptionsNoLock("WHERE id=@id", new { id }).FirstOrDefault();
        }
    }

    public PolicySubscriptionRow? GetPolicySubscriptionByUrl(string url)
    {
        if (string.IsNullOrWhiteSpace(url))
        {
            return null;
        }

        lock (_gate)
        {
            return QueryPolicySubscriptionsNoLock("WHERE url=@url", new { url = url.Trim() }).FirstOrDefault();
        }
    }

    public long SavePolicySubscription(long id, string name, string url, bool enabled, bool autoApply, string pinHash)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        ArgumentException.ThrowIfNullOrWhiteSpace(url);
        var now = DateTime.Now.ToString("o", System.Globalization.CultureInfo.InvariantCulture);
        lock (_gate)
        {
            if (id > 0)
            {
                var changed = _conn.Execute(
                    """
                    UPDATE policy_subscriptions SET
                        name=@name,
                        url=@url,
                        enabled=@enabled,
                        auto_apply=@autoApply,
                        pin_hash=@pinHash,
                        updated=@now
                    WHERE id=@id
                    """,
                    new
                    {
                        id,
                        name = name.Trim(),
                        url = url.Trim(),
                        enabled = enabled ? 1 : 0,
                        autoApply = autoApply ? 1 : 0,
                        pinHash = NormalizeHash(pinHash),
                        now,
                    });
                if (changed != 0)
                {
                    return id;
                }
            }

            _conn.Execute(
                """
                INSERT INTO policy_subscriptions(
                    name,url,enabled,auto_apply,pin_hash,created,updated)
                VALUES(@name,@url,@enabled,@autoApply,@pinHash,@now,@now)
                ON CONFLICT(url) DO UPDATE SET
                    name=excluded.name,
                    enabled=excluded.enabled,
                    auto_apply=excluded.auto_apply,
                    pin_hash=excluded.pin_hash,
                    updated=excluded.updated
                """,
                new
                {
                    name = name.Trim(),
                    url = url.Trim(),
                    enabled = enabled ? 1 : 0,
                    autoApply = autoApply ? 1 : 0,
                    pinHash = NormalizeHash(pinHash),
                    now,
                });
            return _conn.ExecuteScalar<long>(
                "SELECT id FROM policy_subscriptions WHERE url=@url",
                new { url = url.Trim() });
        }
    }

    public long RecordPolicySubscriptionApplied(
        long id,
        string name,
        string url,
        bool enabled,
        bool autoApply,
        string pinHash,
        string lastHash,
        long checkpointId,
        IEnumerable<string> summary)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        ArgumentException.ThrowIfNullOrWhiteSpace(url);
        ArgumentNullException.ThrowIfNull(summary);
        var now = DateTime.Now.ToString("o", System.Globalization.CultureInfo.InvariantCulture);
        lock (_gate)
        {
            var savedId = SavePolicySubscription(id, name, url, enabled, autoApply, pinHash);
            _conn.Execute(
                """
                UPDATE policy_subscriptions SET
                    last_hash=@lastHash,
                    last_checkpoint_id=@checkpointId,
                    last_applied_at=@now,
                    last_preview_summary=@summary,
                    last_error='',
                    last_error_at='',
                    updated=@now
                WHERE id=@savedId
                """,
                new
                {
                    savedId,
                    lastHash = NormalizeHash(lastHash),
                    checkpointId,
                    now,
                    summary = string.Join("\n", summary),
                });
            return savedId;
        }
    }

    public void RecordPolicySubscriptionFailure(long id, string url, string name, string error)
    {
        var message = (error ?? string.Empty).Trim();
        if (message.Length > 500)
        {
            message = message[..500];
        }

        var now = DateTime.Now.ToString("o", System.Globalization.CultureInfo.InvariantCulture);
        lock (_gate)
        {
            if (id > 0)
            {
                _conn.Execute(
                    """
                    UPDATE policy_subscriptions SET
                        last_error=@message,
                        last_error_at=@now,
                        updated=@now
                    WHERE id=@id
                    """,
                    new { id, message, now });
                return;
            }

            if (!string.IsNullOrWhiteSpace(url) && !string.IsNullOrWhiteSpace(name))
            {
                _conn.Execute(
                    """
                    INSERT INTO policy_subscriptions(name,url,enabled,auto_apply,last_error,last_error_at,created,updated)
                    VALUES(@name,@url,1,0,@message,@now,@now,@now)
                    ON CONFLICT(url) DO UPDATE SET
                        last_error=excluded.last_error,
                        last_error_at=excluded.last_error_at,
                        updated=excluded.updated
                    """,
                    new { name = name.Trim(), url = url.Trim(), message, now });
            }
        }
    }

    public bool DeletePolicySubscription(long id)
    {
        if (id <= 0)
        {
            return false;
        }

        lock (_gate)
        {
            return _conn.Execute("DELETE FROM policy_subscriptions WHERE id=@id", new { id }) != 0;
        }
    }

    private IReadOnlyList<PolicySubscriptionRow> QueryPolicySubscriptionsNoLock(string whereClause, object? args)
    {
        return _conn.Query<(
                long Id,
                string Name,
                string Url,
                long Enabled,
                long AutoApply,
                string PinHash,
                string LastHash,
                long LastCheckpointId,
                string LastAppliedAt,
                string LastPreviewSummary,
                string LastError,
                string LastErrorAt,
                string Created,
                string Updated)>(
            $"""
            SELECT id AS Id, name AS Name, url AS Url,
                   COALESCE(enabled,1) AS Enabled,
                   COALESCE(auto_apply,0) AS AutoApply,
                   COALESCE(pin_hash,'') AS PinHash,
                   COALESCE(last_hash,'') AS LastHash,
                   COALESCE(last_checkpoint_id,0) AS LastCheckpointId,
                   COALESCE(last_applied_at,'') AS LastAppliedAt,
                   COALESCE(last_preview_summary,'') AS LastPreviewSummary,
                   COALESCE(last_error,'') AS LastError,
                   COALESCE(last_error_at,'') AS LastErrorAt,
                   COALESCE(created,'') AS Created,
                   COALESCE(updated,'') AS Updated
            FROM policy_subscriptions
            {whereClause}
            ORDER BY name, id
            """,
            args)
            .Select(r => new PolicySubscriptionRow(
                r.Id,
                r.Name,
                r.Url,
                r.Enabled != 0,
                r.AutoApply != 0,
                r.PinHash,
                r.LastHash,
                r.LastCheckpointId,
                r.LastAppliedAt,
                r.LastPreviewSummary,
                r.LastError,
                r.LastErrorAt,
                r.Created,
                r.Updated))
            .ToList();
    }

    private static string NormalizeHash(string? value)
        => (value ?? string.Empty).Trim().ToLowerInvariant();

    // ─── Blocklist / allowlist subscriptions ──────────────────────────────────

    public void UpsertBlocklistSub(
        string name,
        string url,
        long domainCount,
        string contentHash = "",
        string previousHash = "",
        long previousDomainCount = 0,
        string healthStatus = "ok",
        long lastCheckpointId = 0,
        string lastAttemptHash = "",
        long lastAttemptDomainCount = 0)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        var now = DateTime.Now.ToString("o", System.Globalization.CultureInfo.InvariantCulture);
        lock (_gate)
        {
            _conn.Execute(
                """
                INSERT INTO blocklist_subs(
                    name,url,last_refresh,domain_count,enabled,content_hash,previous_hash,
                    previous_domain_count,last_error,last_error_at,health_status,last_checkpoint_id,
                    last_attempt_hash,last_attempt_domain_count)
                VALUES(
                    @name,@url,@now,@domainCount,1,@contentHash,@previousHash,
                    @previousDomainCount,'','',@healthStatus,@lastCheckpointId,
                    @lastAttemptHash,@lastAttemptDomainCount)
                ON CONFLICT(name) DO UPDATE SET
                    url=excluded.url,
                    last_refresh=excluded.last_refresh,
                    domain_count=excluded.domain_count,
                    enabled=1,
                    content_hash=excluded.content_hash,
                    previous_hash=excluded.previous_hash,
                    previous_domain_count=excluded.previous_domain_count,
                    last_error='',
                    last_error_at='',
                    health_status=excluded.health_status,
                    last_checkpoint_id=excluded.last_checkpoint_id,
                    last_attempt_hash=excluded.last_attempt_hash,
                    last_attempt_domain_count=excluded.last_attempt_domain_count
                """,
                new
                {
                    name,
                    url,
                    now,
                    domainCount,
                    contentHash = contentHash ?? string.Empty,
                    previousHash = previousHash ?? string.Empty,
                    previousDomainCount,
                    healthStatus = string.IsNullOrWhiteSpace(healthStatus) ? "ok" : healthStatus,
                    lastCheckpointId,
                    lastAttemptHash = lastAttemptHash ?? string.Empty,
                    lastAttemptDomainCount,
                });
        }
    }

    public void RecordBlocklistRefreshFailure(
        string name,
        string url,
        string error,
        string healthStatus = "error",
        string lastAttemptHash = "",
        long lastAttemptDomainCount = 0)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        var now = DateTime.Now.ToString("o", System.Globalization.CultureInfo.InvariantCulture);
        var message = (error ?? string.Empty).Trim();
        if (message.Length > 500)
        {
            message = message[..500];
        }

        lock (_gate)
        {
            _conn.Execute(
                """
                INSERT INTO blocklist_subs(
                    name,url,last_refresh,domain_count,enabled,last_error,last_error_at,
                    health_status,last_attempt_hash,last_attempt_domain_count)
                VALUES(@name,@url,'',0,1,@message,@now,@healthStatus,@lastAttemptHash,@lastAttemptDomainCount)
                ON CONFLICT(name) DO UPDATE SET
                    url=CASE WHEN @url!='' THEN @url ELSE blocklist_subs.url END,
                    last_error=excluded.last_error,
                    last_error_at=excluded.last_error_at,
                    health_status=excluded.health_status,
                    last_attempt_hash=excluded.last_attempt_hash,
                    last_attempt_domain_count=excluded.last_attempt_domain_count
                """,
                new
                {
                    name,
                    url = url ?? string.Empty,
                    message,
                    now,
                    healthStatus = string.IsNullOrWhiteSpace(healthStatus) ? "error" : healthStatus,
                    lastAttemptHash = lastAttemptHash ?? string.Empty,
                    lastAttemptDomainCount,
                });
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

    public BlocklistRemoval RemoveBlocklistSourceDomainsNotIn(string name, IEnumerable<string> replacementDomains)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        ArgumentNullException.ThrowIfNull(replacementDomains);
        var keep = replacementDomains.Select(d => d.ToLowerInvariant()).Distinct(StringComparer.Ordinal).ToHashSet(StringComparer.Ordinal);
        lock (_gate)
        {
            var current = _conn.Query<string>(
                "SELECT domain FROM blocklist_domain_sources WHERE source=@name",
                new { name }).ToList();
            var candidates = current.Where(d => !keep.Contains(d)).ToList();
            if (candidates.Count == 0)
            {
                return new BlocklistRemoval(0, 0);
            }

            using var tx = _conn.BeginTransaction();
            var src = $"list:{name}";
            long removed = 0;
            long preserved = 0;
            foreach (var chunk in candidates.Chunk(500))
            {
                var owned = _conn.Query<string>(
                    """
                    SELECT b.domain FROM blocklist_domain_sources b
                    JOIN domains d ON d.domain=b.domain
                    WHERE b.source=@name
                      AND b.domain IN @chunk
                      AND d.status='blocked'
                      AND (d.source IS NULL OR d.source='' OR d.source=@src)
                      AND NOT EXISTS (
                          SELECT 1 FROM blocklist_domain_sources other
                          WHERE other.domain=b.domain AND other.source<>@name)
                    """,
                    new { name, src, chunk }, tx).ToList();
                if (owned.Count != 0)
                {
                    _conn.Execute("DELETE FROM domains WHERE domain IN @owned AND status='blocked'", new { owned }, tx);
                }

                removed += owned.Count;
                preserved += chunk.Count() - owned.Count;
            }

            tx.Commit();
            return new BlocklistRemoval(removed, preserved);
        }
    }

    public IReadOnlyList<string> GetBlocklistSourceDomains(string name)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        lock (_gate)
        {
            return _conn.Query<string>(
                "SELECT domain FROM blocklist_domain_sources WHERE source=@name ORDER BY domain",
                new { name }).ToList();
        }
    }

    public BlocklistSubRow? GetBlocklistSub(string name)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        lock (_gate)
        {
            return QueryBlocklistSubs("WHERE s.name=@name", new { name }).FirstOrDefault();
        }
    }

    public long CreateBlocklistCheckpoint(
        string name,
        string url,
        string previousHash,
        long previousDomainCount,
        string newHash,
        long newDomainCount,
        string reason,
        IEnumerable<string> previousDomains)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        ArgumentNullException.ThrowIfNull(previousDomains);
        var cleaned = previousDomains.Select(d => d.ToLowerInvariant()).Distinct(StringComparer.Ordinal).ToList();
        var now = DateTime.Now.ToString("o", System.Globalization.CultureInfo.InvariantCulture);
        lock (_gate)
        {
            using var tx = _conn.BeginTransaction();
            var id = _conn.ExecuteScalar<long>(
                """
                INSERT INTO blocklist_refresh_checkpoints(
                    source,created,url,previous_hash,previous_domain_count,new_hash,new_domain_count,reason)
                VALUES(@name,@now,@url,@previousHash,@previousDomainCount,@newHash,@newDomainCount,@reason);
                SELECT last_insert_rowid();
                """,
                new
                {
                    name,
                    now,
                    url,
                    previousHash = previousHash ?? string.Empty,
                    previousDomainCount,
                    newHash = newHash ?? string.Empty,
                    newDomainCount,
                    reason = reason ?? string.Empty,
                },
                tx);
            foreach (var chunk in cleaned.Chunk(500))
            {
                _conn.Execute(
                    "INSERT OR IGNORE INTO blocklist_refresh_checkpoint_domains(checkpoint_id,domain) VALUES(@id,@domain)",
                    chunk.Select(domain => new { id, domain }),
                    tx);
            }

            tx.Commit();
            return id;
        }
    }

    public BlocklistCheckpointRestore RestoreLatestBlocklistCheckpoint(string name)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        lock (_gate)
        {
            var checkpoint = _conn.QuerySingleOrDefault<BlocklistCheckpointRow>(
                """
                SELECT id AS Id, source AS Source, created AS Created, url AS Url,
                       COALESCE(previous_hash,'') AS PreviousHash,
                       COALESCE(previous_domain_count,0) AS PreviousDomainCount,
                       COALESCE(new_hash,'') AS NewHash,
                       COALESCE(new_domain_count,0) AS NewDomainCount,
                       COALESCE(reason,'') AS Reason
                FROM blocklist_refresh_checkpoints
                WHERE source=@name
                ORDER BY id DESC
                LIMIT 1
                """,
                new { name });
            if (checkpoint is null)
            {
                throw new InvalidOperationException($"no checkpoint exists for {name}");
            }

            var previous = _conn.Query<string>(
                "SELECT domain FROM blocklist_refresh_checkpoint_domains WHERE checkpoint_id=@id ORDER BY domain",
                new { id = checkpoint.Id }).ToList();
            var previousSet = previous.ToHashSet(StringComparer.Ordinal);
            var current = _conn.Query<string>(
                "SELECT domain FROM blocklist_domain_sources WHERE source=@name ORDER BY domain",
                new { name }).ToList();
            var removedCandidates = current.Where(d => !previousSet.Contains(d)).ToList();
            var src = $"list:{name}";
            var now = DateTime.Now.ToString("o", System.Globalization.CultureInfo.InvariantCulture);
            long removed = 0;
            long preserved = 0;

            using var tx = _conn.BeginTransaction();
            foreach (var chunk in removedCandidates.Chunk(500))
            {
                var owned = _conn.Query<string>(
                    """
                    SELECT b.domain FROM blocklist_domain_sources b
                    JOIN domains d ON d.domain=b.domain
                    WHERE b.source=@name
                      AND b.domain IN @chunk
                      AND d.status='blocked'
                      AND (d.source IS NULL OR d.source='' OR d.source=@src)
                      AND NOT EXISTS (
                          SELECT 1 FROM blocklist_domain_sources other
                          WHERE other.domain=b.domain AND other.source<>@name)
                    """,
                    new { name, src, chunk }, tx).ToList();
                if (owned.Count != 0)
                {
                    _conn.Execute("DELETE FROM domains WHERE domain IN @owned AND status='blocked'", new { owned }, tx);
                }

                removed += owned.Count;
                preserved += chunk.Count() - owned.Count;
            }

            _conn.Execute("DELETE FROM blocklist_domain_sources WHERE source=@name", new { name }, tx);
            foreach (var chunk in previous.Chunk(500))
            {
                _conn.Execute(
                    "INSERT OR IGNORE INTO blocklist_domain_sources(source,domain) VALUES(@name,@domain)",
                    chunk.Select(domain => new { name, domain }),
                    tx);
                foreach (var domain in chunk)
                {
                    _conn.Execute(
                        """
                        INSERT INTO domains(domain,status,category,source,added,modified,hits,reason)
                        VALUES(@domain,'blocked','',@src,@now,@now,0,@reason)
                        ON CONFLICT(domain) DO UPDATE SET
                            status=CASE WHEN domains.status='whitelisted' THEN 'whitelisted' ELSE 'blocked' END,
                            modified=excluded.modified,
                            source=CASE
                                WHEN domains.source IS NULL OR domains.source='' OR domains.source LIKE 'list:%' THEN excluded.source
                                ELSE domains.source
                            END
                        """,
                        new { domain, src, now, reason = Reasons.Canonical(null, src, "blocked") },
                        tx);
                }
            }

            _conn.Execute(
                """
                UPDATE blocklist_subs SET
                    url=@url,
                    last_refresh=@now,
                    domain_count=@domainCount,
                    content_hash=@contentHash,
                    previous_hash=@previousHash,
                    previous_domain_count=@previousDomainCount,
                    last_error='',
                    last_error_at='',
                    health_status='restored',
                    last_checkpoint_id=@checkpointId,
                    last_attempt_hash=@contentHash,
                    last_attempt_domain_count=@domainCount
                WHERE name=@name
                """,
                new
                {
                    name,
                    url = checkpoint.Url,
                    now,
                    domainCount = previous.Count,
                    contentHash = checkpoint.PreviousHash,
                    previousHash = checkpoint.NewHash,
                    previousDomainCount = checkpoint.NewDomainCount,
                    checkpointId = checkpoint.Id,
                },
                tx);

            tx.Commit();
            return new BlocklistCheckpointRestore(checkpoint.Id, previous.Count, removed, preserved);
        }
    }

    public IReadOnlyList<BlocklistSubRow> GetBlocklistSubs()
    {
        return QueryBlocklistSubs(string.Empty, null);
    }

    private IReadOnlyList<BlocklistSubRow> QueryBlocklistSubs(string whereClause, object? args)
    {
        var cutoff = DateTime.Now.AddDays(-30)
            .ToString("yyyy-MM-ddTHH", System.Globalization.CultureInfo.InvariantCulture);
        lock (_gate)
        {
            return _conn.Query<(
                    string Name,
                    string Url,
                    string LastRefresh,
                    long DomainCount,
                    long Enabled,
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
                    long LastAttemptDomainCount)>(
                $"""
                SELECT s.name AS Name, s.url AS Url, COALESCE(s.last_refresh,'') AS LastRefresh,
                       COALESCE(s.domain_count,0) AS DomainCount, COALESCE(s.enabled,1) AS Enabled,
                       COUNT(b.domain) AS OwnedDomainCount, COALESCE(stats.hits_30d,0) AS Hits30d,
                       COALESCE(s.content_hash,'') AS ContentHash,
                       COALESCE(s.previous_hash,'') AS PreviousHash,
                       COALESCE(s.previous_domain_count,0) AS PreviousDomainCount,
                       COALESCE(s.last_error,'') AS LastError,
                       COALESCE(s.last_error_at,'') AS LastErrorAt,
                       COALESCE(NULLIF(s.health_status,''),'new') AS HealthStatus,
                       COALESCE(s.last_checkpoint_id,0) AS LastCheckpointId,
                       COALESCE(s.last_attempt_hash,'') AS LastAttemptHash,
                       COALESCE(s.last_attempt_domain_count,0) AS LastAttemptDomainCount
                FROM blocklist_subs s
                LEFT JOIN blocklist_domain_sources b ON b.source=s.name
                LEFT JOIN (
                    SELECT b.source, SUM(h.hits) AS hits_30d
                    FROM blocklist_domain_sources b
                    JOIN feed_domain_hourly h ON h.domain=b.domain
                    WHERE h.hour >= @cutoff
                    GROUP BY b.source
                ) stats ON stats.source=s.name
                {whereClause}
                GROUP BY s.name, s.url, s.last_refresh, s.domain_count, s.enabled,
                         s.content_hash, s.previous_hash, s.previous_domain_count,
                         s.last_error, s.last_error_at, s.health_status, s.last_checkpoint_id,
                         s.last_attempt_hash, s.last_attempt_domain_count
                ORDER BY s.name
                """,
                MergeArgs(args, cutoff))
                .Select(r => new BlocklistSubRow(
                    r.Name,
                    r.Url,
                    r.LastRefresh,
                    r.DomainCount,
                    r.Enabled != 0,
                    r.OwnedDomainCount,
                    r.Hits30d,
                    r.ContentHash,
                    r.PreviousHash,
                    r.PreviousDomainCount,
                    r.LastError,
                    r.LastErrorAt,
                    r.HealthStatus,
                    r.LastCheckpointId,
                    r.LastAttemptHash,
                    r.LastAttemptDomainCount))
                .ToList();
        }
    }

    private static DynamicParameters MergeArgs(object? args, string cutoff)
    {
        var parameters = new DynamicParameters(args);
        parameters.Add("cutoff", cutoff);
        return parameters;
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
