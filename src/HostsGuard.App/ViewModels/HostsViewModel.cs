using System.Collections;
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
/// ViewModel for the Managed Domains view. Talks to the elevated service through
/// <see cref="HostsServiceClient"/> only — no direct hosts/DB access (repository
/// pattern via the service). Fully testable against an in-process service.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed partial class HostsViewModel : ObservableObject
{
    public static string AllStatusLabel => I18n.T("Common_All", "All");
    public static readonly IReadOnlyList<string> StatusFilters = new[]
    {
        AllStatusLabel,
        I18n.T("Common_Blocked", "Blocked"),
        I18n.T("Hosts_Whitelisted", "Whitelisted"),
    };

    private readonly HostsServiceClient _client;
    private readonly IConfirm _confirm;
    private CancellationTokenSource? _filterCts;

    /// <summary>Pause after the last filter keystroke before the service round-trip.</summary>
    public static TimeSpan FilterDebounce { get; set; } = TimeSpan.FromMilliseconds(350);

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(BlockCommand))]
    private string _newDomain = string.Empty;

    [ObservableProperty]
    private string _statusText = I18n.T("Status.Ready", "Ready");

    [ObservableProperty]
    private string _filter = string.Empty;

    [ObservableProperty]
    private string _statusFilter = AllStatusLabel;

    public HostsViewModel(HostsServiceClient client, IConfirm confirm)
    {
        _client = client ?? throw new ArgumentNullException(nameof(client));
        _confirm = confirm ?? throw new ArgumentNullException(nameof(confirm));
    }

    public ObservableCollection<ManagedDomainViewModel> Domains { get; } = new();

    partial void OnStatusFilterChanged(string value) => _ = GuardedRefreshAsync(CancellationToken.None);

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

            await RunServiceActionAsync(I18n.T("Hosts_ActionRefresh", "Refresh domains"), RefreshCoreAsync);
        }
        catch (OperationCanceledException)
        {
            // Superseded by a newer keystroke.
        }
        catch (Exception ex) when (IsServiceFailure(ex))
        {
            StatusText = ServiceFailureStatus(I18n.T("Hosts_ActionRefresh", "Refresh domains"), ex);
        }
    }

    [RelayCommand]
    public Task RefreshAsync()
        => RunServiceActionAsync(I18n.T("Hosts_ActionRefresh", "Refresh domains"), RefreshCoreAsync);

    private async Task RefreshCoreAsync()
    {
        var list = await _client.Hosts.ListDomainsAsync(new ListDomainsRequest
        {
            Search = Filter,
            Status = StatusFilter == AllStatusLabel || StatusFilter.Equals("All", StringComparison.OrdinalIgnoreCase) ? string.Empty
                : StatusFilter.Equals("blocked", StringComparison.OrdinalIgnoreCase) ||
                  StatusFilter == I18n.T("Common_Blocked", "Blocked") ? "blocked"
                : "whitelisted",
        });
        Domains.Clear();
        foreach (var d in list.Domains)
        {
            Domains.Add(ManagedDomainViewModel.From(d));
        }

        await RefreshRedirectsCoreAsync();

        StatusText = I18n.T("Hosts_DomainCount", "{0} domain(s)", Domains.Count);
    }

    [RelayCommand(CanExecute = nameof(CanBlock))]
    public async Task BlockAsync()
    {
        await RunServiceActionAsync(I18n.T("Hosts_ActionBlock", "Block domain"), async () =>
        {
            var domain = NewDomain.Trim();
            var ack = await _client.Hosts.BlockAsync(new DomainRequest { Domain = domain, Source = "manual" });
            StatusText = ack.Ok ? I18n.T("Hosts_BlockedDomain", "Blocked {0}", domain) : ack.Message;
            if (ack.Ok)
            {
                NewDomain = string.Empty;
                await RefreshCoreAsync();
            }
        });
    }

    private bool CanBlock() => !string.IsNullOrWhiteSpace(NewDomain);

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
    public async Task AllowAsync(string domain)
    {
        if (NoSelection(domain))
        {
            return;
        }

        await RunServiceActionAsync(I18n.T("Hosts_ActionAllow", "Allow domain"), async () =>
        {
            var ack = await _client.Hosts.AllowAsync(new DomainRequest { Domain = domain, Source = "manual" });
            StatusText = ack.Ok ? I18n.T("Hosts_AllowedDomain", "Allowed {0}", domain) : ack.Message;
            await RefreshCoreAsync();
        });
    }

    [RelayCommand]
    public async Task UnblockAsync(string domain)
    {
        if (NoSelection(domain))
        {
            return;
        }

        if (!_confirm.Confirm(I18n.T("Hosts_RemoveTitle", "Remove managed domain"),
            I18n.T("Hosts_RemoveMessage", "Remove {0} from managed domains? This stops HostsGuard from writing it to the hosts file.", domain)))
        {
            return;
        }

        await RunServiceActionAsync(I18n.T("Hosts_ActionRemove", "Remove domain"), async () =>
        {
            await _client.Hosts.UnblockAsync(new DomainRequest { Domain = domain });
            StatusText = I18n.T("Hosts_RemovedDomain", "Removed {0}", domain);
            await RefreshCoreAsync();
        });
    }

    [RelayCommand]
    public async Task BlockRootAsync(string domain)
    {
        if (NoSelection(domain))
        {
            return;
        }

        await RunServiceActionAsync(I18n.T("Hosts_ActionBlockRoot", "Block root domain"), async () =>
        {
            var ack = await _client.Hosts.BlockRootAsync(new DomainRequest { Domain = domain, Source = "manual" });
            StatusText = ack.Message;
            await RefreshCoreAsync();
        });
    }

    // ─── Bulk actions (parameter: DataGrid.SelectedItems) ────────────────────

    [RelayCommand]
    public async Task BlockSelectedAsync(IList? selected)
    {
        var domains = SelectedDomains(selected);
        if (domains.Count == 0)
        {
            return;
        }

        // NET-105: one RPC + one hosts-file write for the whole selection.
        await RunServiceActionAsync(I18n.T("Hosts_ActionBlockSelected", "Block selected domains"), async () =>
        {
            var request = new BulkDomainsRequest { Source = "manual" };
            request.Domains.AddRange(domains);
            var result = await _client.Hosts.BlockManyAsync(request);
            StatusText = result.Ok ? I18n.T("Hosts_BlockedMany", "Blocked {0} domain(s) (+{1} new)", result.Total, result.Applied) : result.Message;
            await RefreshCoreAsync();
        });
    }

    [RelayCommand]
    public async Task AllowSelectedAsync(IList? selected)
    {
        var domains = SelectedDomains(selected);
        if (domains.Count == 0)
        {
            return;
        }

        await RunServiceActionAsync(I18n.T("Hosts_ActionAllowSelected", "Allow selected domains"), async () =>
        {
            var request = new BulkDomainsRequest { Source = "manual" };
            request.Domains.AddRange(domains);
            var result = await _client.Hosts.AllowManyAsync(request);
            StatusText = result.Ok ? I18n.T("Hosts_AllowedMany", "Allowed {0} domain(s)", result.Total) : result.Message;
            await RefreshCoreAsync();
        });
    }

    [RelayCommand]
    public async Task RemoveSelectedAsync(IList? selected)
    {
        var domains = SelectedDomains(selected);
        if (domains.Count == 0 || !_confirm.Confirm(I18n.T("Hosts_RemoveManyTitle", "Remove managed domains"),
            I18n.T("Hosts_RemoveManyMessage", "Remove {0} selected domains? HostsGuard will stop writing them to the hosts file.", domains.Count)))
        {
            return;
        }

        await RunServiceActionAsync(I18n.T("Hosts_ActionRemoveSelected", "Remove selected domains"), async () =>
        {
            foreach (var domain in domains)
            {
                await _client.Hosts.UnblockAsync(new DomainRequest { Domain = domain });
            }

            await RefreshCoreAsync();
        });
    }

    private static List<string> SelectedDomains(IList? selected)
        => selected?.OfType<ManagedDomainViewModel>().Select(d => d.Domain).ToList() ?? new List<string>();

    /// <summary>AI-categorize every hosts-file entry lacking a category (DeepSeek).</summary>
    [RelayCommand]
    public async Task AiCategorizeAsync()
    {
        await RunServiceActionAsync(I18n.T("Hosts_ActionCategorize", "Categorize hosts entries"), async () =>
        {
            StatusText = I18n.T("Hosts_Categorizing", "Asking DeepSeek to categorize hosts-file entries...");
            var result = await _client.Hosts.CategorizeDomainsAsync(new CategorizeRequest { HostsFile = true });
            StatusText = result.Message;
            if (result.Ok && result.Categorized > 0)
            {
                await RefreshCoreAsync();
            }
        });
    }

    private async Task RunServiceActionAsync(string action, Func<Task> work)
    {
        try
        {
            await work();
        }
        catch (Exception ex) when (IsServiceFailure(ex))
        {
            StatusText = ServiceFailureStatus(action, ex);
        }
    }

    private static bool IsServiceFailure(Exception ex) => ex is RpcException || ServiceErrors.IsConnectivity(ex);

    private static string ServiceFailureStatus(string action, Exception ex)
        => ServiceErrors.DescribeActionFailure(action, ex);

    [RelayCommand]
    public void ResearchGoogle(string domain) => Research.Open(Research.Sites[0].UrlTemplate, domain);

    [RelayCommand]
    public void ResearchVirusTotal(string domain) => Research.Open(Research.Sites[1].UrlTemplate, domain);

    [RelayCommand]
    public void ResearchWhois(string domain) => Research.Open(Research.Sites[2].UrlTemplate, domain);
}
