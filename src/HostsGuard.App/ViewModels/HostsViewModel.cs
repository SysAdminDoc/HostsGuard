using System.Collections;
using System.Collections.ObjectModel;
using System.Runtime.Versioning;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
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

    [ObservableProperty]
    private string _newDomain = string.Empty;

    [ObservableProperty]
    private string _statusText = "Ready";

    [ObservableProperty]
    private string _filter = string.Empty;

    [ObservableProperty]
    private string _statusFilter = "All";

    public HostsViewModel(HostsServiceClient client) => _client = client ?? throw new ArgumentNullException(nameof(client));

    public ObservableCollection<ManagedDomainViewModel> Domains { get; } = new();

    partial void OnStatusFilterChanged(string value) => _ = RefreshAsync();

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

        StatusText = $"{Domains.Count} domains";
    }

    [RelayCommand]
    public async Task BlockAsync()
    {
        var ack = await _client.Hosts.BlockAsync(new DomainRequest { Domain = NewDomain, Source = "manual" });
        StatusText = ack.Ok ? $"Blocked {NewDomain}" : ack.Message;
        if (ack.Ok)
        {
            NewDomain = string.Empty;
            await RefreshAsync();
        }
    }

    [RelayCommand]
    public async Task AllowAsync(string domain)
    {
        var ack = await _client.Hosts.AllowAsync(new DomainRequest { Domain = domain, Source = "manual" });
        StatusText = ack.Ok ? $"Allowed {domain}" : ack.Message;
        await RefreshAsync();
    }

    [RelayCommand]
    public async Task UnblockAsync(string domain)
    {
        await _client.Hosts.UnblockAsync(new DomainRequest { Domain = domain });
        StatusText = $"Removed {domain}";
        await RefreshAsync();
    }

    [RelayCommand]
    public async Task BlockRootAsync(string domain)
    {
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
        foreach (var domain in SelectedDomains(selected))
        {
            await _client.Hosts.UnblockAsync(new DomainRequest { Domain = domain });
        }

        await RefreshAsync();
    }

    private static List<string> SelectedDomains(IList? selected)
        => selected?.OfType<ManagedDomainViewModel>().Select(d => d.Domain).ToList() ?? new List<string>();

    [RelayCommand]
    public void ResearchGoogle(string domain) => Research.Open(Research.Sites[0].UrlTemplate, domain);

    [RelayCommand]
    public void ResearchVirusTotal(string domain) => Research.Open(Research.Sites[1].UrlTemplate, domain);

    [RelayCommand]
    public void ResearchWhois(string domain) => Research.Open(Research.Sites[2].UrlTemplate, domain);
}
