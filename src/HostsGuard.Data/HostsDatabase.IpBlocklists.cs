using Dapper;

namespace HostsGuard.Data;

/// <summary>One IP-format blocklist source's persisted state (NET-171).</summary>
public sealed record IpBlocklistSourceRow(
    string Name,
    string Url,
    bool Enabled,
    long AddressCount,
    long RuleCount,
    string ContentHash,
    string PreviousHash,
    long PreviousAddressCount,
    string HealthStatus,
    string LastError,
    string LastErrorAt,
    string LastRefresh,
    bool Truncated);

public sealed partial class HostsDatabase
{
    public IReadOnlyList<IpBlocklistSourceRow> GetIpBlocklistSources()
    {
        lock (_gate)
        {
            return _conn.Query<(string Name, string Url, long Enabled, long AddressCount, long RuleCount,
                    string ContentHash, string PreviousHash, long PreviousAddressCount, string HealthStatus,
                    string LastError, string LastErrorAt, string LastRefresh, long Truncated)>(
                """
                SELECT name, COALESCE(url,''), COALESCE(enabled,1), COALESCE(address_count,0),
                       COALESCE(rule_count,0), COALESCE(content_hash,''), COALESCE(previous_hash,''),
                       COALESCE(previous_address_count,0), COALESCE(health_status,''),
                       COALESCE(last_error,''), COALESCE(last_error_at,''), COALESCE(last_refresh,''),
                       COALESCE(truncated,0)
                FROM ip_blocklist_sources ORDER BY name
                """)
                .Select(r => new IpBlocklistSourceRow(r.Name, r.Url, r.Enabled != 0, r.AddressCount, r.RuleCount,
                    r.ContentHash, r.PreviousHash, r.PreviousAddressCount, r.HealthStatus,
                    r.LastError, r.LastErrorAt, r.LastRefresh, r.Truncated != 0))
                .ToList();
        }
    }

    public IpBlocklistSourceRow? GetIpBlocklistSource(string name) =>
        GetIpBlocklistSources().FirstOrDefault(r => string.Equals(r.Name, name, StringComparison.Ordinal));

    public IReadOnlyList<string> GetIpBlocklistAddresses(string name) => SplitAddresses(
        QueryScalarLocked("SELECT COALESCE(addresses,'') FROM ip_blocklist_sources WHERE name=@name", name));

    public IReadOnlyList<string> GetIpBlocklistPreviousAddresses(string name) => SplitAddresses(
        QueryScalarLocked("SELECT COALESCE(previous_addresses,'') FROM ip_blocklist_sources WHERE name=@name", name));

    /// <summary>Record a successful import/refresh: current + previous payloads and health.</summary>
    public void UpsertIpBlocklistSource(
        string name,
        string url,
        IReadOnlyList<string> addresses,
        string contentHash,
        string previousHash,
        long previousAddressCount,
        IReadOnlyList<string> previousAddresses,
        long ruleCount,
        bool truncated,
        string healthStatus = "ok")
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        var now = DateTime.Now.ToString("o", System.Globalization.CultureInfo.InvariantCulture);
        lock (_gate)
        {
            _conn.Execute(
                """
                INSERT INTO ip_blocklist_sources(
                    name,url,enabled,address_count,rule_count,content_hash,previous_hash,
                    previous_address_count,addresses,previous_addresses,health_status,
                    last_error,last_error_at,last_refresh,truncated)
                VALUES(@name,@url,1,@count,@ruleCount,@contentHash,@previousHash,
                    @previousAddressCount,@addresses,@previousAddresses,@healthStatus,'','',@now,@truncated)
                ON CONFLICT(name) DO UPDATE SET
                    url=excluded.url,
                    address_count=excluded.address_count,
                    rule_count=excluded.rule_count,
                    content_hash=excluded.content_hash,
                    previous_hash=excluded.previous_hash,
                    previous_address_count=excluded.previous_address_count,
                    addresses=excluded.addresses,
                    previous_addresses=excluded.previous_addresses,
                    health_status=excluded.health_status,
                    last_error='', last_error_at='',
                    last_refresh=excluded.last_refresh,
                    truncated=excluded.truncated
                """,
                new
                {
                    name,
                    url,
                    count = (long)addresses.Count,
                    ruleCount,
                    contentHash,
                    previousHash,
                    previousAddressCount,
                    addresses = string.Join('\n', addresses),
                    previousAddresses = string.Join('\n', previousAddresses),
                    healthStatus,
                    now,
                    truncated = truncated ? 1 : 0,
                });
        }
    }

    /// <summary>Subscription-only upsert (portable-policy import): keeps any applied payload.</summary>
    public void UpsertIpBlocklistSubscription(string name, string url, bool enabled)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        lock (_gate)
        {
            _conn.Execute(
                """
                INSERT INTO ip_blocklist_sources(name,url,enabled,health_status)
                VALUES(@name,@url,@enabled,'new')
                ON CONFLICT(name) DO UPDATE SET url=excluded.url, enabled=excluded.enabled
                """,
                new { name, url, enabled = enabled ? 1 : 0 });
        }
    }

    public void RecordIpBlocklistFailure(string name, string url, string error, string healthStatus = "error")
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
                INSERT INTO ip_blocklist_sources(name,url,enabled,last_error,last_error_at,health_status)
                VALUES(@name,@url,1,@message,@now,@healthStatus)
                ON CONFLICT(name) DO UPDATE SET
                    url=CASE WHEN @url!='' THEN @url ELSE ip_blocklist_sources.url END,
                    last_error=excluded.last_error,
                    last_error_at=excluded.last_error_at,
                    health_status=excluded.health_status
                """,
                new { name, url, message, now, healthStatus });
        }
    }

    public void SetIpBlocklistEnabled(string name, bool enabled)
    {
        lock (_gate)
        {
            _conn.Execute(
                "UPDATE ip_blocklist_sources SET enabled=@enabled WHERE name=@name",
                new { name, enabled = enabled ? 1 : 0 });
        }
    }

    public bool RemoveIpBlocklistSource(string name)
    {
        lock (_gate)
        {
            return _conn.Execute("DELETE FROM ip_blocklist_sources WHERE name=@name", new { name }) > 0;
        }
    }

    /// <summary>
    /// Roll the source back to its previous payload (swap current/previous), so a
    /// bad refresh is reversible. Throws when no previous payload exists.
    /// </summary>
    public IReadOnlyList<string> RollbackIpBlocklistSource(string name)
    {
        lock (_gate)
        {
            var previous = SplitAddresses(_conn.ExecuteScalar<string>(
                "SELECT COALESCE(previous_addresses,'') FROM ip_blocklist_sources WHERE name=@name", new { name }));
            if (previous.Count == 0)
            {
                throw new InvalidOperationException($"no previous refresh to roll back to for {name}");
            }

            var now = DateTime.Now.ToString("o", System.Globalization.CultureInfo.InvariantCulture);
            _conn.Execute(
                """
                UPDATE ip_blocklist_sources SET
                    addresses=previous_addresses, previous_addresses=addresses,
                    address_count=previous_address_count, previous_address_count=address_count,
                    content_hash=previous_hash, previous_hash=content_hash,
                    health_status='restored', last_refresh=@now, truncated=0
                WHERE name=@name
                """,
                new { name, now });
            return previous;
        }
    }

    public void SetIpBlocklistRuleCount(string name, long ruleCount)
    {
        lock (_gate)
        {
            _conn.Execute(
                "UPDATE ip_blocklist_sources SET rule_count=@ruleCount WHERE name=@name",
                new { name, ruleCount });
        }
    }

    private string QueryScalarLocked(string sql, string name)
    {
        lock (_gate)
        {
            return _conn.ExecuteScalar<string>(sql, new { name }) ?? string.Empty;
        }
    }

    private static IReadOnlyList<string> SplitAddresses(string? joined) =>
        (joined ?? string.Empty).Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
}
