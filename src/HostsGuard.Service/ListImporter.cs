using System.Net.Http;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using HostsGuard.Core;
using HostsGuard.Data;
using HostsGuard.Windows;

namespace HostsGuard.Service;

/// <summary>One import's outcome, with the NET-077 health report.</summary>
public sealed record ImportOutcome(
    long Added, long Total, long HostsEntries, string Warning,
    long Duplicates = 0, long Invalid = 0, long HijackFlagged = 0,
    long AllowlistOverrides = 0, bool MirrorUsed = false,
    long Removed = 0, long Preserved = 0, bool Preview = false,
    long Guarded = 0, long Failed = 0, long CheckpointId = 0,
    long ModifiersStripped = 0);

/// <summary>
/// Blocklist / allowlist import engine: fetch (byte-capped), parse, bulk block
/// in one hosts-file transaction, bulk UPSERT (allowlist wins), record the
/// subscription, and re-apply allowlists so a fresh blocklist can never
/// re-block a whitelisted domain. A daily timer refreshes subscriptions.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class ListImporter : IDisposable
{
    private const int ChurnGuardMinimumPreviousCount = 100;
    private const double ChurnGuardDropRatio = 0.50;
    private const double ChurnGuardGrowthRatio = 2.00;

    private readonly HostsEngine _hosts;
    private readonly HostsDatabase _db;
    private readonly IListFetcher _fetcher;
    private readonly Timer _refreshTimer;
    private readonly ScheduledTaskDrain _scheduledRefresh = new();

    public ListImporter(HostsEngine hosts, HostsDatabase db, IListFetcher fetcher, TimeSpan? refreshInterval = null)
    {
        _hosts = hosts ?? throw new ArgumentNullException(nameof(hosts));
        _db = db ?? throw new ArgumentNullException(nameof(db));
        _fetcher = fetcher ?? throw new ArgumentNullException(nameof(fetcher));
        var interval = refreshInterval ?? TimeSpan.FromHours(24);
        _refreshTimer = new Timer(_ => KickScheduledRefresh(), null, interval, interval);
    }

    public async Task<ImportOutcome> ImportBlocklistAsync(string name, string url, CancellationToken ct)
        => await ImportBlocklistAsync(name, url, ct, guardChurn: false, existing: null);

    private async Task<ImportOutcome> ImportBlocklistAsync(
        string name,
        string url,
        CancellationToken ct,
        bool guardChurn,
        BlocklistSubRow? existing)
    {
        // Mirror fallback (NET-077): if the primary URL fails and the catalog
        // knows a mirror for this source, retry the mirror before giving up.
        var (text, mirrorUsed) = await FetchWithMirrorAsync(name, url, ct);
        var contentHash = Sha256(text);
        var scan = BlocklistCatalog.Scan(text);
        var domains = scan.Domains;
        existing ??= _db.GetBlocklistSub(name);

        if (guardChurn && existing is not null)
        {
            var guard = EvaluateChurn(existing, domains.Count, contentHash);
            if (guard.Guarded)
            {
                _db.RecordBlocklistRefreshFailure(
                    name,
                    url,
                    guard.Message,
                    healthStatus: "guarded",
                    lastAttemptHash: contentHash,
                    lastAttemptDomainCount: domains.Count);
                _db.LogEvent($"list:{name}", "refresh_guarded", details: guard.Message, reason: "blocklist");
                return new ImportOutcome(0, domains.Count, _hosts.GetBlocked().Count, guard.Message,
                    scan.Duplicates, scan.Invalid, scan.HijackFlagged, MirrorUsed: mirrorUsed,
                    Guarded: 1, ModifiersStripped: scan.ModifiersStripped);
            }
        }

        var previousDomains = existing is null
            ? Array.Empty<string>()
            : _db.GetBlocklistSourceDomains(name);
        var checkpointId = existing is null || (existing.DomainCount == 0 && previousDomains.Count == 0)
            ? 0
            : _db.CreateBlocklistCheckpoint(
                name,
                existing.Url.Length != 0 ? existing.Url : url,
                existing.ContentHash,
                existing.DomainCount,
                contentHash,
                domains.Count,
                guardChurn ? "scheduled refresh" : "manual import",
                previousDomains);

        var dropped = existing is null
            ? new BlocklistRemoval(0, 0)
            : _db.RemoveBlocklistSourceDomainsNotIn(name, domains);
        var added = _hosts.BlockBulk(domains);
        _db.AddDomainsBulk(domains.Select(d => (d, "blocked", $"list:{name}")));
        _db.ReplaceBlocklistSourceDomains(name, domains);
        _db.UpsertBlocklistSub(
            name,
            url,
            domains.Count,
            contentHash,
            existing?.ContentHash ?? string.Empty,
            existing?.DomainCount ?? 0,
            healthStatus: checkpointId == 0 ? "ok" : "ok",
            lastCheckpointId: checkpointId,
            lastAttemptHash: contentHash,
            lastAttemptDomainCount: domains.Count);

        // Whitelisted domains always win: re-apply allowlists after an import,
        // and report how many blocklist entries the allowlist overrode.
        var overrides = ReapplyAllowlisted(domains);
        _hosts.Reconcile(_db.GetDomains(status: "blocked").Select(d => d.Domain));

        var entries = _hosts.GetBlocked().Count;
        var warning = entries > BlocklistCatalog.LargeHostsWarn
            ? $"Hosts file now {entries:N0} entries — watch DNS Client CPU"
            : string.Empty;

        _db.LogEvent($"list:{name}", "blocked",
            details: $"imported {domains.Count} domains ({scan.Duplicates} dup, {scan.Invalid} invalid, " +
                     $"{scan.HijackFlagged} hijack-flagged, {scan.ModifiersStripped} modifier-stripped, " +
                     $"{overrides} allowlist-overridden" +
                     (mirrorUsed ? ", via mirror" : string.Empty) + ")",
            reason: "blocklist");

        return new ImportOutcome(added, domains.Count, entries, warning,
            scan.Duplicates, scan.Invalid, scan.HijackFlagged, overrides, mirrorUsed,
            Removed: dropped.Removed, Preserved: dropped.Preserved,
            CheckpointId: checkpointId, ModifiersStripped: scan.ModifiersStripped);
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
            scan.Duplicates, scan.Invalid, scan.HijackFlagged, overrides, mirrorUsed, Preview: true,
            ModifiersStripped: scan.ModifiersStripped);
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

    public ImportOutcome RestoreCheckpoint(string name)
    {
        var restore = _db.RestoreLatestBlocklistCheckpoint(name);
        _hosts.Reconcile(_db.GetDomains(status: "blocked").Select(d => d.Domain));
        _db.LogEvent($"list:{name}", "blocklist_checkpoint_restored",
            details: $"checkpoint {restore.CheckpointId}: restored {restore.Restored}, removed {restore.Removed}, preserved {restore.Preserved}",
            reason: "blocklist");
        return new ImportOutcome(0, restore.Restored, _hosts.GetBlocked().Count, string.Empty,
            Removed: restore.Removed, Preserved: restore.Preserved, CheckpointId: restore.CheckpointId);
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
        long duplicates = 0, invalid = 0, hijack = 0, overrides = 0, guarded = 0, failed = 0, checkpointId = 0, stripped = 0;
        foreach (var sub in _db.GetBlocklistSubs().Where(s => s.Enabled))
        {
            ImportOutcome outcome;
            try
            {
                outcome = await ImportBlocklistAsync(sub.Name, sub.Url, ct, guardChurn: true, existing: sub);
            }
            catch (Exception ex) when (ex is HttpRequestException or InvalidOperationException or TaskCanceledException or IOException)
            {
                failed++;
                warning = $"refresh failed for {sub.Name}: {ex.Message}";
                _db.RecordBlocklistRefreshFailure(sub.Name, sub.Url, ex.Message);
                _db.LogEvent($"list:{sub.Name}", "refresh_failed", details: ex.GetType().Name, reason: "blocklist");
                continue;
            }

            added += outcome.Added;
            total += outcome.Total;
            duplicates += outcome.Duplicates;
            invalid += outcome.Invalid;
            hijack += outcome.HijackFlagged;
            overrides += outcome.AllowlistOverrides;
            stripped += outcome.ModifiersStripped;
            guarded += outcome.Guarded;
            if (outcome.CheckpointId != 0)
            {
                checkpointId = outcome.CheckpointId;
            }

            if (outcome.Warning.Length != 0)
            {
                warning = outcome.Warning;
            }
        }

        return new ImportOutcome(added, total, _hosts.GetBlocked().Count, warning,
            duplicates, invalid, hijack, overrides, Guarded: guarded, Failed: failed, CheckpointId: checkpointId,
            ModifiersStripped: stripped);
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

    internal void KickScheduledRefresh() => _scheduledRefresh.TryRun(SafeScheduledRefreshAsync);

    private async Task SafeScheduledRefreshAsync(CancellationToken cancellationToken)
    {
        try
        {
            await RefreshAllAsync(cancellationToken);
            await RefreshAllowlistsAsync(cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // Owner disposal cancels an in-flight scheduled refresh.
        }
        catch (Exception ex)
        {
            try
            {
                _db.LogEvent("lists", "refresh_failed", details: $"{ex.GetType().Name}: {ex.Message}");
            }
            catch (Exception)
            {
                // Teardown diagnostics must not fault the tracked task.
            }
        }
    }

    private static (bool Guarded, string Message) EvaluateChurn(BlocklistSubRow existing, long newCount, string newHash)
    {
        if (existing.DomainCount <= 0 || string.Equals(existing.ContentHash, newHash, StringComparison.OrdinalIgnoreCase))
        {
            return (false, string.Empty);
        }

        if (newCount == 0)
        {
            return (true, $"refresh skipped for {existing.Name}: source returned 0 domains after {existing.DomainCount:N0}");
        }

        if (existing.DomainCount >= ChurnGuardMinimumPreviousCount)
        {
            var ratio = newCount / (double)existing.DomainCount;
            if (ratio < ChurnGuardDropRatio)
            {
                return (true, $"refresh skipped for {existing.Name}: domain count fell from {existing.DomainCount:N0} to {newCount:N0}");
            }

            if (ratio > ChurnGuardGrowthRatio)
            {
                return (true, $"refresh skipped for {existing.Name}: domain count grew from {existing.DomainCount:N0} to {newCount:N0}");
            }
        }

        return (false, string.Empty);
    }

    private static string Sha256(string text)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(text));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    public void Dispose()
    {
        _refreshTimer.Dispose();
        _scheduledRefresh.Dispose();
    }
}
