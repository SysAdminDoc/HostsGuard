using System.Net.Http;
using System.Runtime.Versioning;
using HostsGuard.Core;
using HostsGuard.Data;
using HostsGuard.Windows;

namespace HostsGuard.Service;

/// <summary>One import's outcome, with the NET-077 health report.</summary>
public sealed record ImportOutcome(
    long Added, long Total, long HostsEntries, string Warning,
    long Duplicates = 0, long Invalid = 0, long HijackFlagged = 0,
    long AllowlistOverrides = 0, bool MirrorUsed = false,
    long Removed = 0, long Preserved = 0, bool Preview = false);

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
        // Mirror fallback (NET-077): if the primary URL fails and the catalog
        // knows a mirror for this source, retry the mirror before giving up.
        var (text, mirrorUsed) = await FetchWithMirrorAsync(name, url, ct);
        var scan = BlocklistCatalog.Scan(text);
        var domains = scan.Domains;

        var added = _hosts.BlockBulk(domains);
        _db.AddDomainsBulk(domains.Select(d => (d, "blocked", $"list:{name}")));
        _db.ReplaceBlocklistSourceDomains(name, domains);
        _db.UpsertBlocklistSub(name, url, domains.Count);

        // Whitelisted domains always win: re-apply allowlists after an import,
        // and report how many blocklist entries the allowlist overrode.
        var overrides = ReapplyAllowlisted(domains);

        var entries = _hosts.GetBlocked().Count;
        var warning = entries > BlocklistCatalog.LargeHostsWarn
            ? $"Hosts file now {entries:N0} entries — watch DNS Client CPU"
            : string.Empty;

        _db.LogEvent($"list:{name}", "blocked",
            details: $"imported {domains.Count} domains ({scan.Duplicates} dup, {scan.Invalid} invalid, " +
                     $"{scan.HijackFlagged} hijack-flagged, {overrides} allowlist-overridden" +
                     (mirrorUsed ? ", via mirror" : string.Empty) + ")",
            reason: "blocklist");

        return new ImportOutcome(added, domains.Count, entries, warning,
            scan.Duplicates, scan.Invalid, scan.HijackFlagged, overrides, mirrorUsed);
    }

    public async Task<ImportOutcome> PreviewBlocklistAsync(string name, string url, CancellationToken ct)
    {
        var (text, mirrorUsed) = await FetchWithMirrorAsync(name, url, ct);
        var scan = BlocklistCatalog.Scan(text);
        var blocked = _db.GetDomains(status: "blocked").Select(r => r.Domain).ToHashSet(StringComparer.Ordinal);
        var whitelisted = _db.GetDomains(status: "whitelisted").Select(r => r.Domain).ToHashSet(StringComparer.Ordinal);
        var wouldAdd = scan.Domains.Count(d => !blocked.Contains(d) && !whitelisted.Contains(d));
        var overrides = scan.Domains.Count(whitelisted.Contains);
        var entries = _hosts.GetBlocked().Count + wouldAdd;
        var warning = entries > BlocklistCatalog.LargeHostsWarn
            ? $"Hosts file would reach {entries:N0} entries - watch DNS Client CPU"
            : string.Empty;
        return new ImportOutcome(wouldAdd, scan.Domains.Count, entries, warning,
            scan.Duplicates, scan.Invalid, scan.HijackFlagged, overrides, mirrorUsed, Preview: true);
    }

    public ImportOutcome RemoveSource(string name)
    {
        var removal = _db.RemoveBlocklistSub(name);
        _hosts.Reconcile(_db.GetDomains(status: "blocked").Select(d => d.Domain));
        _db.LogEvent($"list:{name}", "blocklist_removed",
            details: $"removed {removal.Removed} domains; preserved {removal.Preserved}", reason: "blocklist");
        return new ImportOutcome(0, 0, _hosts.GetBlocked().Count, string.Empty,
            Removed: removal.Removed, Preserved: removal.Preserved);
    }

    /// <summary>Fetch a list, falling back to the catalog mirror on failure.</summary>
    private async Task<(string Text, bool MirrorUsed)> FetchWithMirrorAsync(string name, string url, CancellationToken ct)
    {
        try
        {
            return (await _fetcher.FetchAsync(url, BlocklistCatalog.MaxBlocklistBytes, ct), false);
        }
        catch (Exception ex) when (ex is HttpRequestException or InvalidOperationException or TaskCanceledException or IOException)
        {
            var mirror = BlocklistCatalog.Sources
                .FirstOrDefault(s => s.Name == name && s.Url == url && s.Mirror.Length != 0)?.Mirror;
            if (mirror is null)
            {
                throw;
            }

            _db.LogEvent($"list:{name}", "mirror_fallback", details: $"primary failed ({ex.GetType().Name}); trying mirror");
            return (await _fetcher.FetchAsync(mirror, BlocklistCatalog.MaxBlocklistBytes, ct), true);
        }
    }

    public async Task<ImportOutcome> RefreshAllAsync(CancellationToken ct)
    {
        long added = 0, total = 0;
        var warning = string.Empty;
        long duplicates = 0, invalid = 0, hijack = 0, overrides = 0;
        foreach (var sub in _db.GetBlocklistSubs().Where(s => s.Enabled))
        {
            var outcome = await ImportBlocklistAsync(sub.Name, sub.Url, ct);
            added += outcome.Added;
            total += outcome.Total;
            duplicates += outcome.Duplicates;
            invalid += outcome.Invalid;
            hijack += outcome.HijackFlagged;
            overrides += outcome.AllowlistOverrides;
            warning = outcome.Warning;
        }

        return new ImportOutcome(added, total, _hosts.GetBlocked().Count, warning,
            duplicates, invalid, hijack, overrides);
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

    /// <summary>
    /// Unblock every whitelisted domain that an import just re-added — in a
    /// single reconcile (one atomic write, one self-write hash) rather than N
    /// per-domain Unblock calls, so a large allowlist can't overflow the hosts
    /// engine's self-write hash window and trip a spurious tamper alert.
    /// </summary>
    /// <summary>Returns how many of <paramref name="imported"/> the allowlist overrode.</summary>
    private long ReapplyAllowlisted(IReadOnlyList<string> imported)
    {
        var whitelisted = _db.GetDomains(status: "whitelisted")
            .Select(r => r.Domain).ToHashSet(StringComparer.Ordinal);
        if (whitelisted.Count == 0)
        {
            return 0;
        }

        var overrides = imported.Count(whitelisted.Contains);
        var target = _hosts.GetBlocked().Where(d => !whitelisted.Contains(d)).ToList();
        _hosts.Reconcile(target);
        return overrides;
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
