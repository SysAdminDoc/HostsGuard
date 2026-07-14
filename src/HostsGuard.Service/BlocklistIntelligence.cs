using System.Globalization;
using System.Net.Http;
using System.Runtime.Versioning;
using HostsGuard.Core;
using HostsGuard.Data;

namespace HostsGuard.Service;

/// <summary>
/// Downloads every catalog blocklist into a local domain→list index — as
/// REFERENCE intelligence, never as active blocks. The activity feed uses the
/// index to flag domains the well-known lists would block (block candidates).
/// Refreshes in the background on first start (post-install) and weekly.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class BlocklistIntelligence : IDisposable
{
    /// <summary>Meta key holding the last successful refresh timestamp.</summary>
    public const string RefreshedMetaKey = "list_index_refreshed";

    private static readonly TimeSpan RefreshInterval = TimeSpan.FromDays(7);

    private readonly HostsDatabase _db;
    private readonly IListFetcher _fetcher;
    private readonly IClock _clock;
    private readonly Timer _timer;
    private readonly ScheduledTaskDrain _scheduledRefresh = new();
    private int _refreshing;

    public BlocklistIntelligence(HostsDatabase db, IListFetcher fetcher, IClock? clock = null)
    {
        _db = db ?? throw new ArgumentNullException(nameof(db));
        _fetcher = fetcher ?? throw new ArgumentNullException(nameof(fetcher));
        _clock = clock ?? SystemClock.Instance;
        _timer = new Timer(_ => KickScheduledRefresh(), null, RefreshInterval, RefreshInterval);
    }

    public bool IsRefreshing => Volatile.Read(ref _refreshing) == 1;

    public string LastRefreshed => _db.GetMeta(RefreshedMetaKey) ?? string.Empty;

    /// <summary>Kick a background refresh when the index is empty or older than a week.</summary>
    public void StartIfStale() => KickScheduledRefresh();

    internal void KickScheduledRefresh() => _scheduledRefresh.TryRun(RefreshIfStaleAsync);

    private async Task RefreshIfStaleAsync(CancellationToken cancellationToken)
    {
        try
        {
            var (lists, _) = _db.GetListIndexStats();
            var fresh = lists > 0 &&
                        DateTime.TryParse(LastRefreshed, CultureInfo.InvariantCulture,
                            DateTimeStyles.RoundtripKind, out var at) &&
                        _clock.UtcNow - at.ToUniversalTime() < RefreshInterval;
            if (!fresh)
            {
                await RefreshAsync(cancellationToken);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // Owner disposal cancels an in-flight scheduled refresh.
        }
        catch (Exception ex)
        {
            try
            {
                _db.LogEvent("intel", "index_failed", details: $"{ex.GetType().Name}: {ex.Message}");
            }
            catch (Exception)
            {
                // Teardown diagnostics must not fault the tracked task.
            }
        }
    }

    /// <summary>
    /// Download and index every catalog source. Per-list failures are logged
    /// and skipped; the refresh timestamp is written when at least one list
    /// landed. Returns (indexed lists, failed lists).
    /// </summary>
    public async Task<(int Indexed, int Failed)> RefreshAsync(CancellationToken ct)
    {
        if (Interlocked.Exchange(ref _refreshing, 1) == 1)
        {
            return (0, 0); // already running
        }

        try
        {
            int indexed = 0, failed = 0;
            foreach (var source in BlocklistCatalog.Sources)
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    var domains = (await FetchWithMirrorAsync(source, ct)).Domains;
                    _db.ReplaceListIndex(source.Name, domains);
                    indexed++;
                }
                catch (Exception ex) when (ex is HttpRequestException or InvalidOperationException
                    or TaskCanceledException or IOException)
                {
                    failed++;
                    _db.LogEvent($"intel:{source.Name}", "index_failed", details: ex.GetType().Name);
                }
            }

            if (indexed > 0)
            {
                _db.SetMeta(RefreshedMetaKey, _clock.UtcNow.ToString("o", CultureInfo.InvariantCulture));
                var (lists, rows) = _db.GetListIndexStats();
                _db.LogEvent("intel", "index_refreshed", details: $"{lists} lists, {rows:N0} domains, {failed} failed");
            }

            return (indexed, failed);
        }
        finally
        {
            Volatile.Write(ref _refreshing, 0);
        }
    }

    private async Task<BlocklistScan> FetchWithMirrorAsync(BlocklistSourceInfo source, CancellationToken ct)
    {
        try
        {
            return await ScanRemoteAsync(source.Url, ct);
        }
        catch (Exception ex) when (source.Mirror.Length != 0 &&
            ex is HttpRequestException or InvalidOperationException or TaskCanceledException or IOException)
        {
            return await ScanRemoteAsync(source.Mirror, ct);
        }
    }

    private Task<BlocklistScan> ScanRemoteAsync(string url, CancellationToken ct) =>
        _fetcher.ReadTextAsync(url, BlocklistCatalog.MaxBlocklistBytes, BlocklistCatalog.ScanAsync, ct);

    public void Dispose()
    {
        _timer.Dispose();
        _scheduledRefresh.Dispose();
    }
}
