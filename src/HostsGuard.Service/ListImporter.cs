using System.Net.Http;
using System.Runtime.Versioning;
using HostsGuard.Core;
using HostsGuard.Data;
using HostsGuard.Windows;

namespace HostsGuard.Service;

/// <summary>One import's outcome.</summary>
public sealed record ImportOutcome(long Added, long Total, long HostsEntries, string Warning);

/// <summary>
/// Blocklist / allowlist import engine: fetch (byte-capped), parse, bulk block
/// in one hosts-file transaction, bulk UPSERT (allowlist wins), record the
/// subscription, and re-apply allowlists so a fresh blocklist can never
/// re-block a whitelisted domain. A daily timer refreshes subscriptions.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class ListImporter : IDisposable
{
    private readonly HostsEngine _hosts;
    private readonly HostsDatabase _db;
    private readonly IListFetcher _fetcher;
    private readonly Timer _refreshTimer;
    private bool _disposed;

    public ListImporter(HostsEngine hosts, HostsDatabase db, IListFetcher fetcher, TimeSpan? refreshInterval = null)
    {
        _hosts = hosts ?? throw new ArgumentNullException(nameof(hosts));
        _db = db ?? throw new ArgumentNullException(nameof(db));
        _fetcher = fetcher ?? throw new ArgumentNullException(nameof(fetcher));
        var interval = refreshInterval ?? TimeSpan.FromHours(24);
        _refreshTimer = new Timer(_ => _ = SafeScheduledRefreshAsync(), null, interval, interval);
    }

    public async Task<ImportOutcome> ImportBlocklistAsync(string name, string url, CancellationToken ct)
    {
        var text = await _fetcher.FetchAsync(url, BlocklistCatalog.MaxBlocklistBytes, ct);
        var domains = BlocklistCatalog.ParseDomains(text);

        var added = _hosts.BlockBulk(domains);
        _db.AddDomainsBulk(domains.Select(d => (d, "blocked", $"list:{name}")));
        _db.UpsertBlocklistSub(name, url, domains.Count);
        _db.LogEvent($"list:{name}", "blocked", details: $"Blocklist imported ({domains.Count} domains)", reason: "blocklist");

        // Whitelisted domains always win: re-apply allowlists after an import.
        ReapplyAllowlisted();

        var entries = _hosts.GetBlocked().Count;
        var warning = entries > BlocklistCatalog.LargeHostsWarn
            ? $"Hosts file now {entries:N0} entries — watch DNS Client CPU"
            : string.Empty;
        return new ImportOutcome(added, domains.Count, entries, warning);
    }

    public async Task<ImportOutcome> RefreshAllAsync(CancellationToken ct)
    {
        long added = 0, total = 0;
        var warning = string.Empty;
        foreach (var (name, url, _, _) in _db.GetBlocklistSubs())
        {
            var outcome = await ImportBlocklistAsync(name, url, ct);
            added += outcome.Added;
            total += outcome.Total;
            warning = outcome.Warning;
        }

        return new ImportOutcome(added, total, _hosts.GetBlocked().Count, warning);
    }

    public async Task<int> RefreshAllowlistsAsync(CancellationToken ct)
    {
        var domains = new HashSet<string>(StringComparer.Ordinal);
        foreach (var url in _db.GetAllowlistSubs())
        {
            var text = await _fetcher.FetchAsync(url, BlocklistCatalog.MaxAllowlistBytes, ct);
            foreach (var d in BlocklistCatalog.ParseDomains(text))
            {
                domains.Add(d);
            }
        }

        if (domains.Count != 0)
        {
            _db.AddDomainsBulk(domains.Select(d => (d, "whitelisted", "allowlist")));
            foreach (var d in domains)
            {
                _hosts.Unblock(d);
            }
        }

        return domains.Count;
    }

    /// <summary>Unblock every whitelisted domain that an import just re-added.</summary>
    private void ReapplyAllowlisted()
    {
        foreach (var row in _db.GetDomains(status: "whitelisted"))
        {
            _hosts.Unblock(row.Domain);
        }
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
            await RefreshAllowlistsAsync(CancellationToken.None);
        }
        catch (Exception ex) when (ex is HttpRequestException or InvalidOperationException or TaskCanceledException or IOException)
        {
            _db.LogEvent("lists", "refresh_failed", details: ex.GetType().Name);
        }
    }

    public void Dispose()
    {
        _disposed = true;
        _refreshTimer.Dispose();
    }
}
