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
    private readonly IPrompt? _prompt;
    private readonly IConfirm? _confirm;
    private readonly SynchronizationContext? _ui;
    private CancellationTokenSource? _watchCts;
    private CancellationTokenSource? _filterCts;
    private bool _loading; // suppress refresh/save while applying persisted view flags
    private readonly Dictionary<string, ActivityRowViewModel> _rowByDomain = new(StringComparer.Ordinal);

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

    /// <summary>
    /// Troubleshooting view: show ONLY currently-blocked domains, overriding
    /// "Hide blocked". Lets you refresh a page, see exactly what HostsGuard
    /// blocked, and unblock it to test — the "did I block something I shouldn't
    /// have?" workflow.
    /// </summary>
    [ObservableProperty]
    private bool _blockedOnly;

    [ObservableProperty]
    private string _statusText = I18n.T("Status.Ready", "Ready");

    public HostsActivityViewModel(
        HostsServiceClient client,
        AppConfigStore? config = null,
        IPrompt? prompt = null,
        IConfirm? confirm = null)
    {
        _client = client ?? throw new ArgumentNullException(nameof(client));
        _config = config;
        _prompt = prompt;
        _confirm = confirm;
        _ui = SynchronizationContext.Current;

        // Restore the persisted view toggles without triggering a refresh/save.
        if (_config is not null)
        {
            _loading = true;
            _showHidden = _config.GetViewFlag("activity_show_hidden");
            _hideBlocked = _config.GetViewFlag("activity_hide_blocked");
            _hideReverseDns = _config.GetViewFlag("activity_hide_reverse_dns");
            _groupByRoot = _config.GetViewFlag("activity_group_by_root");
            _blockedOnly = _config.GetViewFlag("activity_blocked_only");
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

    partial void OnBlockedOnlyChanged(bool value)
    {
        Persist("activity_blocked_only", value);
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

            await RunServiceActionAsync(I18n.T("Activity_ActionRefresh", "Refresh hosts activity"), RefreshAsync);
        }
        catch (OperationCanceledException)
        {
            // Superseded by a newer keystroke.
        }
        catch (Exception ex) when (ex is RpcException || ServiceErrors.IsConnectivity(ex))
        {
            StatusText = ServiceErrors.DescribeActionFailure(I18n.T("Activity_ActionRefresh", "Refresh hosts activity"), ex);
        }
    }

    [RelayCommand]
    public async Task RefreshAsync()
    {
        await RunServiceActionAsync(I18n.T("Activity_ActionRefresh", "Refresh hosts activity"), async () =>
        {
            var list = await _client.Hosts.GetActivityAsync(new ActivityRequest
            {
                Search = Filter,
                IncludeHidden = ShowHidden,
            });
            Rows.Clear();
            _rowByDomain.Clear();
            var hidden = 0;
            foreach (var row in list.Rows)
            {
                var isBlocked = row.Status == "blocked";
                // "Blocked only" is a troubleshooting override: show blocked, drop the
                // rest, and ignore "Hide blocked" while it's on.
                if (BlockedOnly)
                {
                    if (!isBlocked)
                    {
                        continue;
                    }
                }
                else if (HideBlocked && isBlocked)
                {
                    hidden++;
                    continue;
                }

                if (HideReverseDns && IsReverseDns(row.Domain))
                {
                    hidden++;
                    continue;
                }

                AddRow(ActivityRowViewModel.From(row));
            }

            StatusText = hidden > 0
                ? I18n.T("Activity_FeedHidden", "{0} domain(s) in feed · {1} hidden", Rows.Count, hidden)
                : I18n.T("Activity_FeedCount", "{0} domain(s) in feed", Rows.Count);
            await LoadSparklinesAsync();
        });
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
                    row.SparklineTip = I18n.T("Activity_Hits24h", "{0} hit(s) in the last 24h", total);
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

        var cts = new CancellationTokenSource();
        _watchCts = cts;
        _ = WatchLoopAsync(cts);
    }

    private async Task WatchLoopAsync(CancellationTokenSource owner)
    {
        var ct = owner.Token;
        var failures = 0;
        try
        {
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    using var call = _client.Monitoring.WatchDns(new Empty(), cancellationToken: ct);
                    failures = 0;
                    await foreach (var ev in call.ResponseStream.ReadAllAsync(ct))
                    {
                        OnUi(() => Upsert(ev));
                    }
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested)
                {
                    break;
                }
                catch (Exception ex) when (WatchRetry.IsStreamFailure(ex))
                {
                    if (ct.IsCancellationRequested)
                    {
                        break;
                    }

                    if (WatchRetry.IsAuthenticationFailure(ex))
                    {
                        OnUi(() => StatusText = I18n.T("Activity_StreamAuthExpired", "Live feed authentication expired - reconnect to the service"));
                        break;
                    }

                    OnUi(() => StatusText = I18n.T("Activity_StreamRetry", "Live feed disconnected - retrying"));
                }

                if (!ct.IsCancellationRequested)
                {
                    try
                    {
                        await Task.Delay(WatchRetry.Delay(failures++), ct);
                    }
                    catch (OperationCanceledException)
                    {
                        break;
                    }
                }
            }
        }
        finally
        {
            if (ReferenceEquals(_watchCts, owner))
            {
                _watchCts = null;
                owner.Dispose();
            }
        }
    }

    private void Upsert(DnsEvent ev)
    {
        _rowByDomain.TryGetValue(ev.Domain, out var existing);
        var dropForBlockFilter = BlockedOnly ? !ev.Blocked : (HideBlocked && ev.Blocked);
        if (dropForBlockFilter
            || (HideReverseDns && IsReverseDns(ev.Domain))
            || (ev.Hidden && !ShowHidden))
        {
            // The feed is filtered — drop live events the active toggles or a
            // persisted hide exclude (and any row that just became excluded).
            // ev.Hidden is authoritative (exact-domain or hidden-root, from the
            // service), so hidden entries never bounce back into the feed.
            if (existing is not null)
            {
                RemoveRow(existing);
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

        var row = new ActivityRowViewModel
        {
            Domain = ev.Domain,
            Root = Core.Domains.GetRoot(ev.Domain),
            Status = ev.Blocked ? "blocked" : string.Empty,
            Process = ev.Process,
            Hits = 1,
            LastSeen = DateTime.Now.ToString("o", System.Globalization.CultureInfo.InvariantCulture),
            Blocklists = ev.Blocklists.ToList(),
        };
        Rows.Insert(0, row);
        _rowByDomain[row.Domain] = row;
        while (Rows.Count > MaxRows)
        {
            var evicted = Rows[^1];
            Rows.RemoveAt(Rows.Count - 1);
            _rowByDomain.Remove(evicted.Domain);
        }
    }

    private void AddRow(ActivityRowViewModel row)
    {
        Rows.Add(row);
        _rowByDomain[row.Domain] = row;
    }

    private void RemoveRow(ActivityRowViewModel row)
    {
        Rows.Remove(row);
        _rowByDomain.Remove(row.Domain);
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
            StatusText = I18n.T("Common_SelectRow", "Select a row first");
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

        if (!ConfirmHostsChange(
            I18n.T("Hosts_ActionBlock", "Block domain"),
            I18n.T("Activity_BlockConfirm", "Add {0} to the hosts-file block list? Existing hosts-file blocks stay unchanged.", domain)))
        {
            return;
        }

        await RunServiceActionAsync(I18n.T("Hosts_ActionBlock", "Block domain"), async () =>
        {
            var ack = await _client.Hosts.BlockAsync(new DomainRequest { Domain = domain, Source = "feed" });
            StatusText = ack.Message;
            await RefreshAsync();
        });
    }

    [RelayCommand]
    public async Task AllowAsync(string domain)
    {
        if (NoSelection(domain))
        {
            return;
        }

        if (!ConfirmHostsChange(
            I18n.T("Hosts_ActionAllow", "Allow domain"),
            I18n.T("Activity_AllowConfirm", "Allow {0} and remove any current hosts-file block for it? Future blocklist imports will keep respecting this allowlist entry.", domain)))
        {
            return;
        }

        await RunServiceActionAsync(I18n.T("Hosts_ActionAllow", "Allow domain"), async () =>
        {
            var ack = await _client.Hosts.AllowAsync(new DomainRequest { Domain = domain, Source = "feed" });
            StatusText = ack.Message;
            await RefreshAsync();
        });
    }

    /// <summary>
    /// Block every selected feed row. The context menu passes the grid's
    /// SelectedItems so a multi-selection blocks all of them; the singular
    /// SelectedItem bind used to block only the primary row. Reports partial
    /// failures (e.g. a transient hosts-file lock) rather than claiming success.
    /// </summary>
    [RelayCommand]
    public async Task BlockSelectedAsync(System.Collections.IList? selected)
    {
        var domains = SelectedDomains(selected);
        if (domains.Count == 0)
        {
            return;
        }

        if (!ConfirmHostsChange(
            I18n.T("Hosts_ActionBlockSelected", "Block selected domains"),
            I18n.T("Activity_BlockManyConfirm", "Add {0} to the hosts-file block list? Existing hosts-file blocks stay unchanged.", FormatDomains(domains))))
        {
            return;
        }

        await RunServiceActionAsync(I18n.T("Hosts_ActionBlockSelected", "Block selected domains"), async () =>
        {
            // NET-105: one RPC + one hosts-file write for the whole selection.
            var request = new BulkDomainsRequest { Source = "feed" };
            request.Domains.AddRange(domains);
            var result = await _client.Hosts.BlockManyAsync(request);
            StatusText = result.Ok
                ? I18n.T("Hosts_BlockedMany", "Blocked {0} domain(s) (+{1} new)", result.Total, result.Applied)
                : result.Message;
            await RefreshAsync();
        });
    }

    /// <summary>
    /// Unblock every selected feed row — remove its <c>0.0.0.0</c> line from the
    /// hosts file so the domain resolves normally again. Unlike Allow (which also
    /// whitelists it against future blocklist imports), this just lifts the block
    /// so you can refresh a page and confirm the fix.
    /// </summary>
    [RelayCommand]
    public async Task UnblockSelectedAsync(System.Collections.IList? selected)
    {
        var domains = SelectedDomains(selected);
        if (domains.Count == 0)
        {
            return;
        }

        if (!ConfirmHostsChange(
            I18n.T("Activity_ActionUnblockSelected", "Unblock selected domains"),
            I18n.T("Activity_UnblockManyConfirm", "Remove {0} from the hosts file so they resolve normally again?", FormatDomains(domains))))
        {
            return;
        }

        await RunServiceActionAsync(I18n.T("Activity_ActionUnblockSelected", "Unblock selected domains"), async () =>
        {
            var removed = 0;
            foreach (var domain in domains)
            {
                var ack = await _client.Hosts.UnblockAsync(new DomainRequest { Domain = domain });
                if (ack.Ok)
                {
                    removed++;
                }
            }

            StatusText = removed == domains.Count
                ? I18n.T("Activity_UnblockedMany", "Unblocked {0} domain(s) - removed from hosts", removed)
                : I18n.T("Activity_UnblockedPartial", "Unblocked {0} of {1}", removed, domains.Count);
            await RefreshAsync();
        });
    }

    /// <summary>Allow every selected feed row (bulk counterpart to <see cref="AllowAsync"/>).</summary>
    [RelayCommand]
    public async Task AllowSelectedAsync(System.Collections.IList? selected)
    {
        var domains = SelectedDomains(selected);
        if (domains.Count == 0)
        {
            return;
        }

        if (!ConfirmHostsChange(
            I18n.T("Hosts_ActionAllowSelected", "Allow selected domains"),
            I18n.T("Activity_AllowManyConfirm", "Allow {0} and remove any current hosts-file blocks for them? Future blocklist imports will respect these allowlist entries.", FormatDomains(domains))))
        {
            return;
        }

        await RunServiceActionAsync(I18n.T("Hosts_ActionAllowSelected", "Allow selected domains"), async () =>
        {
            // NET-105: one RPC + one hosts-file write for the whole selection.
            var request = new BulkDomainsRequest { Source = "feed" };
            request.Domains.AddRange(domains);
            var result = await _client.Hosts.AllowManyAsync(request);
            StatusText = result.Ok ? I18n.T("Hosts_AllowedMany", "Allowed {0} domain(s)", result.Total) : result.Message;
            await RefreshAsync();
        });
    }

    /// <summary>
    /// Right-click "fix purpose": re-label a domain's purpose. The correction is
    /// persisted as a user override that beats the AI and survives restart (NET-107).
    /// </summary>
    [RelayCommand]
    public Task FixPurposeAsync(ActivityRowViewModel? row) => FixLabelAsync(row, "purpose");

    /// <summary>Right-click "fix category": re-label a domain's category (NET-107).</summary>
    [RelayCommand]
    public Task FixCategoryAsync(ActivityRowViewModel? row) => FixLabelAsync(row, "category");

    private async Task FixLabelAsync(ActivityRowViewModel? row, string kind)
    {
        if (row is null || _prompt is null || string.IsNullOrWhiteSpace(row.Domain))
        {
            return;
        }

        var current = kind == "purpose" ? row.Purpose : string.Empty;
        var kindLabel = kind == "purpose"
            ? I18n.T("Activity_Purpose", "purpose")
            : I18n.T("Activity_Category", "category");
        var value = _prompt.Ask(
            I18n.T("Activity_FixLabelTitle", "Fix {0}", kindLabel),
            I18n.T("Activity_FixLabelMessage", "Set the {0} for {1}. Leave blank to clear the override.", kindLabel, row.Domain),
            current);
        if (value is null)
        {
            return;
        }

        await RunServiceActionAsync(I18n.T("Activity_ActionFixLabel", "Fix domain {0}", kindLabel), async () =>
        {
            var ack = await _client.Hosts.OverrideKnowledgeAsync(new KnowledgeOverrideRequest
            {
                Kind = kind,
                Key = row.Domain,
                Value = value,
            });
            StatusText = ack.Message;
            if (kind == "purpose")
            {
                await RefreshAsync();
            }
        });
    }

    [RelayCommand]
    public async Task BlockRootAsync(string domain)
    {
        if (NoSelection(domain))
        {
            return;
        }

        if (!ConfirmHostsChange(
            I18n.T("Hosts_ActionBlockRoot", "Block root domain"),
            I18n.T("Activity_BlockRootConfirm", "Add the root domain for {0} to the hosts-file block list? This can block sibling subdomains too.", domain)))
        {
            return;
        }

        await RunServiceActionAsync(I18n.T("Hosts_ActionBlockRoot", "Block root domain"), async () =>
        {
            var ack = await _client.Hosts.BlockRootAsync(new DomainRequest { Domain = domain, Source = "feed" });
            StatusText = ack.Message;
            await RefreshAsync();
        });
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

        if (!ConfirmHostsChange(
            I18n.T("Activity_ActionTempAllow", "Temporarily allow domain"),
            I18n.T("Activity_TempAllowConfirm", "Temporarily remove {0} from hosts-file blocking for {1} minutes, then restore the block automatically?", domain, minutes)))
        {
            return;
        }

        await RunServiceActionAsync(I18n.T("Activity_ActionTempAllow", "Temporarily allow domain"), async () =>
        {
            var ack = await _client.Hosts.TempAllowAsync(new TempAllowRequest { Domain = domain, Minutes = minutes });
            StatusText = ack.Message;
            await RefreshAsync();
        });
    }

    [RelayCommand]
    public Task TempBlock15Async(string domain) => TempBlockAsync(domain, 15);

    [RelayCommand]
    public Task TempBlock60Async(string domain) => TempBlockAsync(domain, 60);

    [RelayCommand]
    public Task TempBlock480Async(string domain) => TempBlockAsync(domain, 480);

    private async Task TempBlockAsync(string domain, int minutes)
    {
        if (NoSelection(domain))
        {
            return;
        }

        if (!ConfirmHostsChange(
            I18n.T("Activity_ActionTempBlock", "Temporarily block domain"),
            I18n.T("Activity_TempBlockConfirm", "Temporarily block {0} via the hosts file for {1} minutes, then restore its previous state automatically?", domain, minutes)))
        {
            return;
        }

        await RunServiceActionAsync(I18n.T("Activity_ActionTempBlock", "Temporarily block domain"), async () =>
        {
            var ack = await _client.Hosts.TempBlockAsync(new TempBlockRequest { Domain = domain, Minutes = minutes });
            StatusText = ack.Message;
            await RefreshAsync();
        });
    }

    [RelayCommand]
    public async Task HideRootAsync(string domain)
    {
        if (NoSelection(domain))
        {
            return;
        }

        await RunServiceActionAsync(I18n.T("Activity_ActionHideRoot", "Hide root domain"), async () =>
        {
            var ack = await _client.Hosts.HideRootAsync(new DomainRequest { Domain = domain });
            StatusText = ack.Message;
            await RefreshAsync();
        });
    }

    /// <summary>Hide one exact domain from the feed (leaves the rest of the root).</summary>
    [RelayCommand]
    public async Task HideDomainAsync(string domain)
    {
        if (NoSelection(domain))
        {
            return;
        }

        await RunServiceActionAsync(I18n.T("Activity_ActionHideDomain", "Hide domain"), async () =>
        {
            var request = new HideDomainsRequest();
            request.Domains.Add(domain);
            var ack = await _client.Hosts.HideDomainsAsync(request);
            StatusText = ack.Message;
            await RefreshAsync();
        });
    }

    /// <summary>
    /// Hide every selected feed row in one call. The context menu passes the
    /// grid's SelectedItems so a multi-selection hides all of them, not just the
    /// primary SelectedItem (which the singular bind used to send).
    /// </summary>
    [RelayCommand]
    public async Task HideSelectedAsync(System.Collections.IList? selected)
    {
        var domains = SelectedDomains(selected);
        if (domains.Count == 0)
        {
            return;
        }

        await RunServiceActionAsync(I18n.T("Activity_ActionHideSelected", "Hide selected domains"), async () =>
        {
            var request = new HideDomainsRequest();
            request.Domains.AddRange(domains);
            var ack = await _client.Hosts.HideDomainsAsync(request);
            StatusText = ack.Message;
            await RefreshAsync();
        });
    }

    /// <summary>Distinct, non-empty domains from a grid multi-selection.</summary>
    public static IReadOnlyList<string> SelectedDomains(System.Collections.IList? selected)
        => (selected ?? Array.Empty<object>())
            .OfType<ActivityRowViewModel>()
            .Select(r => r.Domain)
            .Where(d => !string.IsNullOrWhiteSpace(d))
            .Distinct(StringComparer.Ordinal)
            .ToList();

    private bool ConfirmHostsChange(string title, string message)
    {
        if (_confirm is null || _confirm.Confirm(title, message))
        {
            return true;
        }

        StatusText = I18n.T("Activity_ChangeCancelled", "Hosts-file change cancelled");
        return false;
    }

    private static string FormatDomains(IReadOnlyList<string> domains)
    {
        var preview = string.Join(", ", domains.Take(5));
        if (domains.Count > 5)
        {
            preview += I18n.T("Activity_AndMore", ", and {0} more", domains.Count - 5);
        }

        return I18n.T("Activity_SelectedDomains", "{0} selected domain(s): {1}", domains.Count, preview);
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

        await RunServiceActionAsync(I18n.T("Activity_ActionHideGroup", "Hide group domains"), async () =>
        {
            var request = new HideDomainsRequest();
            request.Domains.AddRange(domains);
            var ack = await _client.Hosts.HideDomainsAsync(request);
            StatusText = ack.Message;
            await RefreshAsync();
        });
    }

    [RelayCommand]
    public async Task UnhideRootAsync(string domain)
    {
        if (NoSelection(domain))
        {
            return;
        }

        await RunServiceActionAsync(I18n.T("Activity_ActionUnhideRoot", "Unhide root domain"), async () =>
        {
            var ack = await _client.Hosts.UnhideRootAsync(new DomainRequest { Domain = domain });
            StatusText = ack.Message;
            await RefreshAsync();
        });
    }

    /// <summary>AI-research purpose descriptions for feed domains that have none.</summary>
    [RelayCommand]
    public async Task ResearchPurposesAsync()
    {
        await RunServiceActionAsync(I18n.T("Activity_ActionResearch", "Research domain purposes"), async () =>
        {
            StatusText = I18n.T("Activity_Researching", "Asking DeepSeek to research domain purposes...");
            var result = await _client.Hosts.ResearchPurposesAsync(new Empty());
            StatusText = result.Message;
            if (result.Ok && result.Categorized > 0)
            {
                await RefreshAsync();
            }
        });
    }

    [RelayCommand]
    public void ResearchGoogle(string domain) => Research.Open(Research.Sites[0].UrlTemplate, domain);

    [RelayCommand]
    public void ResearchVirusTotal(string domain) => Research.Open(Research.Sites[1].UrlTemplate, domain);

    [RelayCommand]
    public void ResearchWhois(string domain) => Research.Open(Research.Sites[2].UrlTemplate, domain);

    private Task RunServiceActionAsync(string action, Func<Task> work) =>
        ServiceActionGuard.RunAsync(action, s => StatusText = s, work);

    public void Dispose()
    {
        var watch = _watchCts;
        _watchCts = null;
        watch?.Cancel();
        watch?.Dispose();
        _filterCts?.Cancel();
        _filterCts?.Dispose();
        _filterCts = null;
    }
}
