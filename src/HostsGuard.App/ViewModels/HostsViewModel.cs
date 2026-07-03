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
    public static readonly IReadOnlyList<string> StatusFilters = new[] { "All", "blocked", "whitelisted" };

    private readonly HostsServiceClient _client;
    private readonly IConfirm _confirm;
    private CancellationTokenSource? _filterCts;

    /// <summary>Pause after the last filter keystroke before the service round-trip.</summary>
    public static TimeSpan FilterDebounce { get; set; } = TimeSpan.FromMilliseconds(350);

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(BlockCommand))]
    private string _newDomain = string.Empty;

    [ObservableProperty]
    private string _statusText = "Ready";

    [ObservableProperty]
    private string _filter = string.Empty;

    [ObservableProperty]
    private string _statusFilter = "All";

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
        var list = await _client.Hosts.ListDomainsAsync(new ListDomainsRequest
        {
            Search = Filter,
            Status = StatusFilter == "All" ? string.Empty : StatusFilter,
        });
        Domains.Clear();
        foreach (var d in list.Domains)
        {
            Domains.Add(ManagedDomainViewModel.From(d));
        }

        StatusText = Plural.Of(Domains.Count, "domain");
    }

    [RelayCommand(CanExecute = nameof(CanBlock))]
    public async Task BlockAsync()
    {
        var domain = NewDomain.Trim();
        var ack = await _client.Hosts.BlockAsync(new DomainRequest { Domain = domain, Source = "manual" });
        StatusText = ack.Ok ? $"Blocked {domain}" : ack.Message;
        if (ack.Ok)
        {
            NewDomain = string.Empty;
            await RefreshAsync();
        }
    }

    private bool CanBlock() => !string.IsNullOrWhiteSpace(NewDomain);

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
    public async Task AllowAsync(string domain)
    {
        if (NoSelection(domain))
        {
            return;
        }

        var ack = await _client.Hosts.AllowAsync(new DomainRequest { Domain = domain, Source = "manual" });
        StatusText = ack.Ok ? $"Allowed {domain}" : ack.Message;
        await RefreshAsync();
    }

    [RelayCommand]
    public async Task UnblockAsync(string domain)
    {
        if (NoSelection(domain))
        {
            return;
        }

        if (!_confirm.Confirm("Remove managed domain",
            $"Remove {domain} from managed domains? This stops HostsGuard from writing it to the hosts file."))
        {
            return;
        }

        await _client.Hosts.UnblockAsync(new DomainRequest { Domain = domain });
        StatusText = $"Removed {domain}";
        await RefreshAsync();
    }

    [RelayCommand]
    public async Task BlockRootAsync(string domain)
    {
        if (NoSelection(domain))
        {
            return;
        }

        var ack = await _client.Hosts.BlockRootAsync(new DomainRequest { Domain = domain, Source = "manual" });
        StatusText = ack.Message;
        await RefreshAsync();
    }

    // ─── Bulk actions (parameter: DataGrid.SelectedItems) ────────────────────

    [RelayCommand]
    public async Task BlockSelectedAsync(IList? selected)
    {
        foreach (var domain in SelectedDomains(selected))
        {
            await _client.Hosts.BlockAsync(new DomainRequest { Domain = domain, Source = "manual" });
        }

        await RefreshAsync();
    }

    [RelayCommand]
    public async Task AllowSelectedAsync(IList? selected)
    {
        foreach (var domain in SelectedDomains(selected))
        {
            await _client.Hosts.AllowAsync(new DomainRequest { Domain = domain, Source = "manual" });
        }

        await RefreshAsync();
    }

    [RelayCommand]
    public async Task RemoveSelectedAsync(IList? selected)
    {
        var domains = SelectedDomains(selected);
        if (domains.Count == 0 || !_confirm.Confirm("Remove managed domains",
            $"Remove {domains.Count} selected domains? HostsGuard will stop writing them to the hosts file."))
        {
            return;
        }

        foreach (var domain in domains)
        {
            await _client.Hosts.UnblockAsync(new DomainRequest { Domain = domain });
        }

        await RefreshAsync();
    }

    private static List<string> SelectedDomains(IList? selected)
        => selected?.OfType<ManagedDomainViewModel>().Select(d => d.Domain).ToList() ?? new List<string>();

    /// <summary>AI-categorize every hosts-file entry lacking a category (DeepSeek).</summary>
    [RelayCommand]
    public async Task AiCategorizeAsync()
    {
        StatusText = "Asking DeepSeek to categorize hosts-file entries…";
        var result = await _client.Hosts.CategorizeDomainsAsync(new CategorizeRequest { HostsFile = true });
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
}
