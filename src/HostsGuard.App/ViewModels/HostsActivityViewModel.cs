using System.Collections.ObjectModel;
using System.IO;
using System.Runtime.Versioning;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Grpc.Core;
using HostsGuard.App.Services;
using HostsGuard.Contracts;

namespace HostsGuard.App.ViewModels;

/// <summary>
/// Hosts Activity tab: a snapshot of recent DNS sightings (GetActivity) kept
/// live by the WatchDns server-stream. Row actions round-trip through the
/// service. Collection mutations marshal to the captured UI context; in
/// headless tests (no context) they run inline.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed partial class HostsActivityViewModel : ObservableObject, IDisposable
{
    private const int MaxRows = 1000;

    private readonly HostsServiceClient _client;
    private readonly AppConfigStore? _config;
    private readonly SynchronizationContext? _ui;
    private CancellationTokenSource? _watchCts;
    private CancellationTokenSource? _filterCts;
    private bool _loading; // suppress refresh/save while applying persisted view flags

    /// <summary>Pause after the last filter keystroke before the service round-trip.</summary>
    public static TimeSpan FilterDebounce { get; set; } = TimeSpan.FromMilliseconds(350);

    [ObservableProperty]
    private string _filter = string.Empty;

    [ObservableProperty]
    private bool _showHidden;

    [ObservableProperty]
    private bool _hideBlocked;

    [ObservableProperty]
    private bool _hideReverseDns;

    [ObservableProperty]
    private string _statusText = "Ready";

    public HostsActivityViewModel(HostsServiceClient client, AppConfigStore? config = null)
    {
        _client = client ?? throw new ArgumentNullException(nameof(client));
        _config = config;
        _ui = SynchronizationContext.Current;

        // Restore the persisted view toggles without triggering a refresh/save.
        if (_config is not null)
        {
            _loading = true;
            _showHidden = _config.GetViewFlag("activity_show_hidden");
            _hideBlocked = _config.GetViewFlag("activity_hide_blocked");
            _hideReverseDns = _config.GetViewFlag("activity_hide_reverse_dns");
            _groupByRoot = _config.GetViewFlag("activity_group_by_root");
            _loading = false;
        }
    }

    /// <summary>Reverse-DNS PTR lookups (*.in-addr.arpa / *.ip6.arpa) — feed noise.</summary>
    private static bool IsReverseDns(string domain)
        => domain.EndsWith(".in-addr.arpa", StringComparison.OrdinalIgnoreCase)
        || domain.EndsWith(".ip6.arpa", StringComparison.OrdinalIgnoreCase);

    public ObservableCollection<ActivityRowViewModel> Rows { get; } = new();

    // ─── Group-by-root view (collapses CDN/subdomain noise) ──────────────────

    private System.ComponentModel.ICollectionView? _view;

    [ObservableProperty]
    private bool _groupByRoot;

    /// <summary>The feed view; grouped under expandable root headers when enabled.</summary>
    public System.ComponentModel.ICollectionView RowsView
    {
        get
        {
            if (_view is null)
            {
                _view = System.Windows.Data.CollectionViewSource.GetDefaultView(Rows);
                ApplyGrouping(_view);
            }

            return _view;
        }
    }

    partial void OnGroupByRootChanged(bool value)
    {
        if (_view is not null)
        {
            ApplyGrouping(_view);
        }

        Persist("activity_group_by_root", value);
    }

    private void Persist(string key, bool value)
    {
        if (!_loading)
        {
            _config?.SaveViewFlag(key, value);
        }
    }

    private void ApplyGrouping(System.ComponentModel.ICollectionView view)
    {
        view.GroupDescriptions.Clear();
        if (GroupByRoot)
        {
            view.GroupDescriptions.Add(
                new System.Windows.Data.PropertyGroupDescription(nameof(ActivityRowViewModel.Root)));
        }
    }

    partial void OnShowHiddenChanged(bool value)
    {
        Persist("activity_show_hidden", value);
        if (!_loading)
        {
            _ = GuardedRefreshAsync(CancellationToken.None);
        }
    }

    partial void OnHideBlockedChanged(bool value)
    {
        Persist("activity_hide_blocked", value);
        if (!_loading)
        {
            _ = GuardedRefreshAsync(CancellationToken.None);
        }
    }

    partial void OnHideReverseDnsChanged(bool value)
    {
        Persist("activity_hide_reverse_dns", value);
        if (!_loading)
        {
            _ = GuardedRefreshAsync(CancellationToken.None);
        }
    }

    /// <summary>Live search: re-query shortly after typing stops instead of waiting for Refresh.</summary>
    partial void OnFilterChanged(string value)
    {
        _filterCts?.Cancel();
        _filterCts?.Dispose();
        _filterCts = new CancellationTokenSource();
        _ = GuardedRefreshAsync(_filterCts.Token);
    }

    private async Task GuardedRefreshAsync(CancellationToken ct)
    {
        try
        {
            if (ct.CanBeCanceled)
            {
                await Task.Delay(FilterDebounce, ct);
            }

            await RefreshAsync();
        }
        catch (OperationCanceledException)
        {
            // Superseded by a newer keystroke.
        }
        catch (Exception ex) when (ex is RpcException or IOException)
        {
            StatusText = "Service unavailable — reconnect from the status bar";
        }
    }

    [RelayCommand]
    public async Task RefreshAsync()
    {
        var list = await _client.Hosts.GetActivityAsync(new ActivityRequest
        {
            Search = Filter,
            IncludeHidden = ShowHidden,
        });
        Rows.Clear();
        var hidden = 0;
        foreach (var row in list.Rows)
        {
            if ((HideBlocked && row.Status == "blocked") || (HideReverseDns && IsReverseDns(row.Domain)))
            {
                hidden++;
                continue;
            }

            Rows.Add(ActivityRowViewModel.From(row));
        }

        StatusText = hidden > 0
            ? $"{Rows.Count} domains in feed · {hidden} hidden"
            : $"{Rows.Count} domains in feed";
        await LoadSparklinesAsync();
    }

    /// <summary>
    /// Fetch the 24h hourly sparkline once per distinct root and fan it out to
    /// every row sharing that root (NET-042). Best-effort: a failed fetch just
    /// leaves the row's sparkline blank.
    /// </summary>
    public async Task LoadSparklinesAsync()
    {
        foreach (var group in Rows.GroupBy(r => r.Root, StringComparer.OrdinalIgnoreCase))
        {
            if (string.IsNullOrEmpty(group.Key))
            {
                continue;
            }

            try
            {
                var spark = await _client.Hosts.GetSparklineAsync(new DomainRequest { Domain = group.Key });
                var points = Sparklines.BuildPoints(spark.Hits);
                var total = spark.Hits.Sum();
                foreach (var row in group)
                {
                    row.SparklinePoints = points;
                    row.SparklineTip = $"{total} hits in the last 24h";
                }
            }
            catch (Exception ex) when (ex is RpcException or IOException)
            {
                // Sparkline is decorative — a fetch failure leaves it blank.
            }
        }
    }

    /// <summary>Start consuming the live DNS stream until disposed.</summary>
    public void StartWatching()
    {
        if (_watchCts is not null)
        {
            return;
        }

        _watchCts = new CancellationTokenSource();
        _ = WatchLoopAsync(_watchCts.Token);
    }

    private async Task WatchLoopAsync(CancellationToken ct)
    {
        try
        {
            using var call = _client.Monitoring.WatchDns(new Empty(), cancellationToken: ct);
            await foreach (var ev in call.ResponseStream.ReadAllAsync(ct))
            {
                OnUi(() => Upsert(ev));
            }
        }
        catch (Exception ex) when (ex is RpcException or OperationCanceledException or IOException)
        {
            OnUi(() => StatusText = ct.IsCancellationRequested ? StatusText : "Live feed disconnected");
        }
    }

    private void Upsert(DnsEvent ev)
    {
        var existing = Rows.FirstOrDefault(r => r.Domain == ev.Domain);
        if ((HideBlocked && ev.Blocked)
            || (HideReverseDns && IsReverseDns(ev.Domain))
            || (ev.Hidden && !ShowHidden))
        {
            // The feed is filtered — drop live events the active toggles or a
            // persisted hide exclude (and any row that just became excluded).
            // ev.Hidden is authoritative (exact-domain or hidden-root, from the
            // service), so hidden entries never bounce back into the feed.
            if (existing is not null)
            {
                Rows.Remove(existing);
            }

            return;
        }

        if (existing is not null)
        {
            existing.Hits++;
            existing.LastSeen = DateTime.Now.ToString("o", System.Globalization.CultureInfo.InvariantCulture);
            if (!string.IsNullOrEmpty(ev.Process))
            {
                existing.Process = ev.Process;
            }

            var idx = Rows.IndexOf(existing);
            if (idx > 0)
            {
                Rows.Move(idx, 0);
            }

            return;
        }

        Rows.Insert(0, new ActivityRowViewModel
        {
            Domain = ev.Domain,
            Root = Core.Domains.GetRoot(ev.Domain),
            Status = ev.Blocked ? "blocked" : string.Empty,
            Process = ev.Process,
            Hits = 1,
            LastSeen = DateTime.Now.ToString("o", System.Globalization.CultureInfo.InvariantCulture),
            Blocklists = ev.Blocklists.ToList(),
        });
        while (Rows.Count > MaxRows)
        {
            Rows.RemoveAt(Rows.Count - 1);
        }
    }

    private void OnUi(Action action)
    {
        if (_ui is null)
        {
            action();
        }
        else
        {
            _ui.Post(_ => action(), null);
        }
    }

    /// <summary>Context menus fire with a null parameter when no row is selected.</summary>
    private bool NoSelection(string? domain)
    {
        if (string.IsNullOrWhiteSpace(domain))
        {
            StatusText = "Select a row first";
            return true;
        }

        return false;
    }

    [RelayCommand]
    public async Task BlockAsync(string domain)
    {
        if (NoSelection(domain))
        {
            return;
        }

        var ack = await _client.Hosts.BlockAsync(new DomainRequest { Domain = domain, Source = "feed" });
        StatusText = ack.Message;
        await RefreshAsync();
    }

    [RelayCommand]
    public async Task AllowAsync(string domain)
    {
        if (NoSelection(domain))
        {
            return;
        }

        var ack = await _client.Hosts.AllowAsync(new DomainRequest { Domain = domain, Source = "feed" });
        StatusText = ack.Message;
        await RefreshAsync();
    }

    [RelayCommand]
    public async Task BlockRootAsync(string domain)
    {
        if (NoSelection(domain))
        {
            return;
        }

        var ack = await _client.Hosts.BlockRootAsync(new DomainRequest { Domain = domain, Source = "feed" });
        StatusText = ack.Message;
        await RefreshAsync();
    }

    [RelayCommand]
    public Task TempAllow15Async(string domain) => TempAllowAsync(domain, 15);

    [RelayCommand]
    public Task TempAllow60Async(string domain) => TempAllowAsync(domain, 60);

    [RelayCommand]
    public Task TempAllow480Async(string domain) => TempAllowAsync(domain, 480);

    private async Task TempAllowAsync(string domain, int minutes)
    {
        if (NoSelection(domain))
        {
            return;
        }

        var ack = await _client.Hosts.TempAllowAsync(new TempAllowRequest { Domain = domain, Minutes = minutes });
        StatusText = ack.Message;
        await RefreshAsync();
    }

    [RelayCommand]
    public async Task HideRootAsync(string domain)
    {
        if (NoSelection(domain))
        {
            return;
        }

        var ack = await _client.Hosts.HideRootAsync(new DomainRequest { Domain = domain });
        StatusText = ack.Message;
        await RefreshAsync();
    }

    /// <summary>Hide one exact domain from the feed (leaves the rest of the root).</summary>
    [RelayCommand]
    public async Task HideDomainAsync(string domain)
    {
        if (NoSelection(domain))
        {
            return;
        }

        var request = new HideDomainsRequest();
        request.Domains.Add(domain);
        var ack = await _client.Hosts.HideDomainsAsync(request);
        StatusText = ack.Message;
        await RefreshAsync();
    }

    /// <summary>
    /// Hide a whole group: store the exact domains currently listed under that
    /// root, not the root itself — so future new subdomains still surface.
    /// </summary>
    [RelayCommand]
    public async Task HideGroupAsync(string? root)
    {
        if (string.IsNullOrWhiteSpace(root))
        {
            return;
        }

        var domains = Rows
            .Where(r => string.Equals(r.Root, root, StringComparison.OrdinalIgnoreCase))
            .Select(r => r.Domain)
            .Distinct(StringComparer.Ordinal)
            .ToList();
        if (domains.Count == 0)
        {
            return;
        }

        var request = new HideDomainsRequest();
        request.Domains.AddRange(domains);
        var ack = await _client.Hosts.HideDomainsAsync(request);
        StatusText = ack.Message;
        await RefreshAsync();
    }

    [RelayCommand]
    public async Task UnhideRootAsync(string domain)
    {
        if (NoSelection(domain))
        {
            return;
        }

        var ack = await _client.Hosts.UnhideRootAsync(new DomainRequest { Domain = domain });
        StatusText = ack.Message;
        await RefreshAsync();
    }

    /// <summary>AI-research purpose descriptions for feed domains that have none.</summary>
    [RelayCommand]
    public async Task ResearchPurposesAsync()
    {
        StatusText = "Asking DeepSeek to research domain purposes…";
        var result = await _client.Hosts.ResearchPurposesAsync(new Empty());
        StatusText = result.Message;
        if (result.Ok && result.Categorized > 0)
        {
            await RefreshAsync();
        }
    }

    [RelayCommand]
    public void ResearchGoogle(string domain) => Research.Open(Research.Sites[0].UrlTemplate, domain);

    [RelayCommand]
    public void ResearchVirusTotal(string domain) => Research.Open(Research.Sites[1].UrlTemplate, domain);

    [RelayCommand]
    public void ResearchWhois(string domain) => Research.Open(Research.Sites[2].UrlTemplate, domain);

    public void Dispose()
    {
        _watchCts?.Cancel();
        _watchCts?.Dispose();
        _watchCts = null;
        _filterCts?.Cancel();
        _filterCts?.Dispose();
        _filterCts = null;
    }
}
