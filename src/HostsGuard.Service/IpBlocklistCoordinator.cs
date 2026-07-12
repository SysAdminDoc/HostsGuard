using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using HostsGuard.Core;
using HostsGuard.Data;
using HostsGuard.Windows;

namespace HostsGuard.Service;

/// <summary>One IP-list import/refresh outcome (NET-171).</summary>
public sealed record IpImportOutcome(
    long Total, long Invalid, long Duplicates, long Unsafe,
    long Rules, bool Truncated, long Guarded = 0, long Failed = 0,
    string Warning = "");

/// <summary>
/// IP-format blocklist engine (NET-171): fetches opt-in sources of IPv4/IPv6/
/// CIDR entries (e.g. HaGeZi ips/doh, ips/tif) and enforces them as chunked
/// HG_IPBlock_* Windows Firewall outbound block rules, because hosts-file
/// blocking cannot stop hardcoded-IP C2 or DoH-bootstrap-IP bypass. The same
/// churn guard as domain blocklists protects scheduled refreshes, and every
/// refresh keeps the previous payload for one-step rollback. A daily timer
/// refreshes enabled sources.
/// </summary>
public sealed class IpBlocklistCoordinator : IDisposable
{
    private const int ChurnGuardMinimumPreviousCount = 100;
    private const double ChurnGuardDropRatio = 0.50;
    private const double ChurnGuardGrowthRatio = 2.00;

    private readonly HostsDatabase _db;
    private readonly IFirewallEngine? _firewall;
    private readonly IListFetcher _fetcher;
    private readonly int _maxAddressesPerRule;
    private readonly int _maxRules;
    private readonly Timer _refreshTimer;
    private readonly object _gate = new();
    private Task _scheduledRefresh = Task.CompletedTask;
    private bool _disposed;

    public IpBlocklistCoordinator(
        HostsDatabase db,
        IFirewallEngine? firewall,
        IListFetcher fetcher,
        TimeSpan? refreshInterval = null,
        int maxAddressesPerRule = 128,
        int maxRules = 256)
    {
        _db = db ?? throw new ArgumentNullException(nameof(db));
        _firewall = firewall;
        _fetcher = fetcher ?? throw new ArgumentNullException(nameof(fetcher));
        _maxAddressesPerRule = maxAddressesPerRule;
        _maxRules = maxRules;
        var interval = refreshInterval ?? TimeSpan.FromHours(24);
        _refreshTimer = new Timer(_ => KickScheduledRefresh(), null, interval, interval);
    }

    /// <summary>
    /// Timer tick: start a scheduled refresh and remember its Task so
    /// <see cref="Dispose"/> can drain an in-flight refresh (the callback
    /// fire-and-forgets an async task, so <c>Timer.Dispose(WaitHandle)</c> alone
    /// would not wait for the DB/firewall work to finish).
    /// </summary>
    internal void KickScheduledRefresh()
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            _scheduledRefresh = SafeScheduledRefreshAsync();
        }
    }

    public IReadOnlyList<IpBlocklistSourceRow> List() => _db.GetIpBlocklistSources();

    public async Task<IpImportOutcome> ImportAsync(string name, string url, CancellationToken ct)
        => await ImportAsync(name, url, ct, guardChurn: false);

    private async Task<IpImportOutcome> ImportAsync(string name, string url, CancellationToken ct, bool guardChurn)
    {
        var text = await _fetcher.FetchAsync(url, BlocklistCatalog.MaxBlocklistBytes, ct);
        var contentHash = Sha256(text);
        var scan = IpBlocklistParser.Scan(text);
        var existing = _db.GetIpBlocklistSource(name);

        if (guardChurn && existing is not null)
        {
            var guard = EvaluateChurn(existing, scan.Entries.Count, contentHash);
            if (guard.Guarded)
            {
                _db.RecordIpBlocklistFailure(name, url, guard.Message, healthStatus: "guarded");
                _db.LogEvent($"iplist:{name}", "refresh_guarded", details: guard.Message, reason: "ip_blocklist");
                return new IpImportOutcome(scan.Entries.Count, scan.Invalid, scan.Duplicates, scan.Unsafe,
                    Rules: existing.RuleCount, Truncated: false, Guarded: 1, Warning: guard.Message);
            }
        }

        var (entries, truncated) = Cap(scan.Entries);
        lock (_gate)
        {
            var previousAddresses = existing is null ? Array.Empty<string>() : _db.GetIpBlocklistAddresses(name);
            var ruleCount = ApplyRules(name, entries, enabled: existing?.Enabled ?? true,
                previousRuleCount: (int)(existing?.RuleCount ?? 0));
            _db.UpsertIpBlocklistSource(
                name, url, entries, contentHash,
                previousHash: existing?.ContentHash ?? string.Empty,
                previousAddressCount: existing?.AddressCount ?? 0,
                previousAddresses: previousAddresses,
                ruleCount: ruleCount,
                truncated: truncated);

            var warning = truncated
                ? $"list exceeds the {_maxRules * _maxAddressesPerRule:N0}-address rule cap; {scan.Entries.Count - entries.Count:N0} entries were not enforced"
                : string.Empty;
            _db.LogEvent($"iplist:{name}", "ip_blocklist_applied",
                details: $"{entries.Count:N0} addresses across {ruleCount} rules " +
                         $"({scan.Invalid} invalid, {scan.Duplicates} dup, {scan.Unsafe} unsafe refused" +
                         (truncated ? ", truncated" : string.Empty) + ")",
                reason: "ip_blocklist");
            return new IpImportOutcome(scan.Entries.Count, scan.Invalid, scan.Duplicates, scan.Unsafe,
                ruleCount, truncated, Warning: warning);
        }
    }

    public async Task<IpImportOutcome> RefreshAllAsync(CancellationToken ct)
    {
        long total = 0, invalid = 0, duplicates = 0, unsafeCount = 0, rules = 0, guarded = 0, failed = 0;
        var truncated = false;
        var warning = string.Empty;
        foreach (var source in _db.GetIpBlocklistSources().Where(s => s.Enabled))
        {
            IpImportOutcome outcome;
            try
            {
                outcome = await ImportAsync(source.Name, source.Url, ct, guardChurn: true);
            }
            catch (Exception ex) when (ex is HttpRequestException or InvalidOperationException or TaskCanceledException or IOException)
            {
                failed++;
                warning = $"refresh failed for {source.Name}: {ex.Message}";
                _db.RecordIpBlocklistFailure(source.Name, source.Url, ex.Message);
                _db.LogEvent($"iplist:{source.Name}", "refresh_failed", details: ex.GetType().Name, reason: "ip_blocklist");
                continue;
            }

            total += outcome.Total;
            invalid += outcome.Invalid;
            duplicates += outcome.Duplicates;
            unsafeCount += outcome.Unsafe;
            rules += outcome.Rules;
            guarded += outcome.Guarded;
            truncated |= outcome.Truncated;
            if (outcome.Warning.Length != 0)
            {
                warning = outcome.Warning;
            }
        }

        return new IpImportOutcome(total, invalid, duplicates, unsafeCount, rules, truncated, guarded, failed, warning);
    }

    public Contracts.Ack SetEnabled(string name, bool enabled)
    {
        lock (_gate)
        {
            var source = _db.GetIpBlocklistSource(name);
            if (source is null)
            {
                return Error("not_found", $"{name} is not a subscribed IP blocklist");
            }

            _db.SetIpBlocklistEnabled(name, enabled);
            for (var i = 0; i < source.RuleCount; i++)
            {
                _firewall?.SetRuleEnabled(RuleName(name, i), enabled);
            }

            _db.LogEvent($"iplist:{name}", enabled ? "ip_blocklist_enabled" : "ip_blocklist_disabled", reason: "ip_blocklist");
            return Ok($"{(enabled ? "enabled" : "disabled")} {name} ({source.RuleCount} rules)");
        }
    }

    public Contracts.Ack Remove(string name)
    {
        lock (_gate)
        {
            var source = _db.GetIpBlocklistSource(name);
            if (source is null)
            {
                return Error("not_found", $"{name} is not a subscribed IP blocklist");
            }

            for (var i = 0; i < source.RuleCount; i++)
            {
                var rule = RuleName(name, i);
                _firewall?.DeleteRule(rule);
                _db.RemoveFwState(rule);
            }

            _db.RemoveIpBlocklistSource(name);
            _db.LogEvent($"iplist:{name}", "ip_blocklist_removed",
                details: $"deleted {source.RuleCount} rules ({source.AddressCount:N0} addresses)", reason: "ip_blocklist");
            return Ok($"removed {name}: deleted {source.RuleCount} firewall rules");
        }
    }

    public IpImportOutcome Rollback(string name)
    {
        lock (_gate)
        {
            var source = _db.GetIpBlocklistSource(name)
                ?? throw new InvalidOperationException($"{name} is not a subscribed IP blocklist");
            var restored = _db.RollbackIpBlocklistSource(name);
            var ruleCount = ApplyRules(name, restored, source.Enabled, previousRuleCount: (int)source.RuleCount);
            _db.SetIpBlocklistRuleCount(name, ruleCount);
            _db.LogEvent($"iplist:{name}", "ip_blocklist_rolled_back",
                details: $"restored {restored.Count:N0} addresses across {ruleCount} rules", reason: "ip_blocklist");
            return new IpImportOutcome(restored.Count, 0, 0, 0, ruleCount, Truncated: false);
        }
    }

    private (IReadOnlyList<string> Entries, bool Truncated) Cap(IReadOnlyList<string> entries)
    {
        var cap = _maxRules * _maxAddressesPerRule;
        return entries.Count <= cap ? (entries, false) : (entries.Take(cap).ToList(), true);
    }

    private int ApplyRules(string name, IReadOnlyList<string> entries, bool enabled, int previousRuleCount)
    {
        var chunks = entries.Chunk(_maxAddressesPerRule).ToList();
        if (_firewall is { } fw)
        {
            for (var i = 0; i < chunks.Count; i++)
            {
                var ruleName = RuleName(name, i);
                var remote = string.Join(',', chunks[i]);
                var applied = fw.RuleExists(ruleName)
                    ? fw.SetRuleRemoteAddresses(ruleName, remote) && fw.SetRuleEnabled(ruleName, enabled)
                    : fw.CreateRule(new FwRule(ruleName, "Out", "Block", enabled, remote, "Any", string.Empty, "hostsguard"));
                if (applied)
                {
                    _db.UpsertFwState(ruleName, "Out", "Block", remote, "Any", string.Empty);
                }
            }

            for (var i = chunks.Count; i < previousRuleCount; i++)
            {
                var ruleName = RuleName(name, i);
                fw.DeleteRule(ruleName);
                _db.RemoveFwState(ruleName);
            }
        }

        return chunks.Count;
    }

    private async Task SafeScheduledRefreshAsync()
    {
        if (_disposed)
        {
            return;
        }

        try
        {
            await RefreshAllAsync(CancellationToken.None);
        }
        catch (Exception ex) when (ex is HttpRequestException or InvalidOperationException or TaskCanceledException or IOException)
        {
            _db.LogEvent("iplists", "refresh_failed", details: ex.GetType().Name, reason: "ip_blocklist");
        }
    }

    private static (bool Guarded, string Message) EvaluateChurn(IpBlocklistSourceRow existing, long newCount, string newHash)
    {
        if (existing.AddressCount <= 0 || string.Equals(existing.ContentHash, newHash, StringComparison.OrdinalIgnoreCase))
        {
            return (false, string.Empty);
        }

        if (newCount == 0)
        {
            return (true, $"refresh skipped for {existing.Name}: source returned 0 addresses after {existing.AddressCount:N0}");
        }

        if (existing.AddressCount >= ChurnGuardMinimumPreviousCount)
        {
            var ratio = newCount / (double)existing.AddressCount;
            if (ratio < ChurnGuardDropRatio)
            {
                return (true, $"refresh skipped for {existing.Name}: address count fell from {existing.AddressCount:N0} to {newCount:N0}");
            }

            if (ratio > ChurnGuardGrowthRatio)
            {
                return (true, $"refresh skipped for {existing.Name}: address count grew from {existing.AddressCount:N0} to {newCount:N0}");
            }
        }

        return (false, string.Empty);
    }

    internal static string RuleName(string source, int index)
    {
        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(source)))[..8];
        var slug = new string(source.Select(c => char.IsLetterOrDigit(c) ? c : '_').ToArray());
        if (slug.Length > 32)
        {
            slug = slug[..32];
        }

        return $"HG_IPBlock_{slug}_{hash}_{index:D4}";
    }

    private static string Sha256(string text) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text))).ToLowerInvariant();

    private static Contracts.Ack Ok(string message) => new() { Ok = true, Message = message };

    private static Contracts.Ack Error(string code, string message) =>
        new() { Ok = false, Message = message, ErrorCode = $"hostsguard.error.v1/{code}" };

    public void Dispose()
    {
        Task inFlight;
        lock (_gate)
        {
            _disposed = true;
            inFlight = _scheduledRefresh;
        }

        _refreshTimer.Dispose();
        // Drain a timer-driven refresh already running so it can never touch the
        // database or firewall after Db.Dispose (which runs last on shutdown).
        try
        {
            inFlight.Wait(TimeSpan.FromSeconds(5));
        }
        catch (AggregateException)
        {
            // SafeScheduledRefreshAsync swallows its own expected exceptions;
            // anything else surfacing here is benign during teardown.
        }
    }
}
