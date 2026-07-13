using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using HostsGuard.App.Services;
using HostsGuard.Contracts;

namespace HostsGuard.App.ViewModels;

public sealed partial class ToolsViewModel
{
    // ─── Blocklist intelligence ───────────────────────────────────────────────

    [ObservableProperty]
    private string _intelStatusText = I18n.T("Intel_Checking", "Checking blocklist intelligence…");

    public async Task LoadIntelStatusAsync()
    {
        await RunServiceActionAsync(I18n.T("Intel_ActionLoad", "Load blocklist intelligence"), s => IntelStatusText = s, async () =>
        {
            var status = await _client.Lists.GetBlocklistIntelligenceAsync(new Empty());
            IntelStatusText = status.Refreshing
                ? I18n.T("Intel_DownloadingBackground", "Downloading reference blocklists in the background…")
                : status.Lists == 0
                    ? I18n.T("Intel_None", "No reference lists downloaded yet — refresh to build the block-candidate index.")
                    : I18n.T("Intel_Status", "{0} reference list(s) · {1:N0} domains indexed{2}", status.Lists, status.Domains,
                        status.Refreshed.Length != 0 ? I18n.T("Intel_RefreshedSuffix", " · refreshed {0}", TimeText.Compact(status.Refreshed)) : string.Empty);
        });
    }

    [RelayCommand]
    public async Task RefreshIntelAsync()
    {
        await RunServiceActionAsync(I18n.T("Intel_ActionRefresh", "Refresh blocklist intelligence"), s => IntelStatusText = s, async () =>
        {
            IntelStatusText = I18n.T("Intel_Downloading", "Downloading reference blocklists — this can take a few minutes…");
            var ack = await _client.Lists.RefreshBlocklistIntelligenceAsync(new Empty());
            StatusText = ack.Message;
            await LoadIntelStatusAsync();
        });
    }

    // ─── IP blocklists → HG_IPBlock_* firewall rules (NET-171) ──────────────

    public ObservableCollection<IpBlocklistRowViewModel> IpBlocklists { get; } = new();

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(ImportIpBlocklistCommand))]
    private string _ipBlocklistName = string.Empty;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(ImportIpBlocklistCommand))]
    private string _ipBlocklistUrl = string.Empty;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(ToggleIpBlocklistCommand))]
    [NotifyCanExecuteChangedFor(nameof(RemoveIpBlocklistCommand))]
    [NotifyCanExecuteChangedFor(nameof(RollbackIpBlocklistCommand))]
    private IpBlocklistRowViewModel? _selectedIpBlocklist;

    [ObservableProperty]
    private string _ipBlocklistStatusText = I18n.T(
        "IpBlock_StatusHint",
        "Subscribe an IP-format list (one IP or CIDR per line) to firewall-block hardcoded-IP endpoints the hosts file cannot stop.");

    [RelayCommand]
    public async Task LoadIpBlocklistsAsync()
    {
        await RunServiceActionAsync(I18n.T("IpBlock_ActionLoad", "Load IP blocklists"), s => IpBlocklistStatusText = s, async () =>
        {
            var selectedName = SelectedIpBlocklist?.Name;
            var list = await _client.Lists.ListIpBlocklistsAsync(new Empty());
            IpBlocklists.Clear();
            foreach (var source in list.Sources)
            {
                IpBlocklists.Add(IpBlocklistRowViewModel.From(source));
            }

            SelectedIpBlocklist = IpBlocklists.FirstOrDefault(s => s.Name == selectedName)
                ?? IpBlocklists.FirstOrDefault();
            if (IpBlocklists.Count != 0)
            {
                IpBlocklistStatusText = I18n.T("IpBlock_StatusLoaded", "{0} IP blocklists · {1} addresses across {2} firewall rules.",
                    IpBlocklists.Count, IpBlocklists.Sum(s => s.AddressCount).ToString("N0"), IpBlocklists.Sum(s => s.RuleCount));
            }
        });
    }

    [RelayCommand(CanExecute = nameof(CanImportIpBlocklist))]
    public async Task ImportIpBlocklistAsync()
    {
        await RunServiceActionAsync(I18n.T("IpBlock_ActionImport", "Import IP blocklist"), s => IpBlocklistStatusText = s, async () =>
        {
            var result = await _client.Lists.ImportIpBlocklistAsync(new BlocklistRequest
            {
                Name = IpBlocklistName.Trim(),
                Url = IpBlocklistUrl.Trim(),
            });
            IpBlocklistStatusText = DescribeIpBlocklistResult(result);
            StatusText = result.Message;
            if (result.Ok)
            {
                IpBlocklistName = string.Empty;
                IpBlocklistUrl = string.Empty;
                await LoadIpBlocklistsAsync();
                IpBlocklistStatusText = DescribeIpBlocklistResult(result);
            }
        });
    }

    private bool CanImportIpBlocklist() =>
        !string.IsNullOrWhiteSpace(IpBlocklistName) && !string.IsNullOrWhiteSpace(IpBlocklistUrl);

    [RelayCommand]
    public async Task RefreshIpBlocklistsAsync()
    {
        await RunServiceActionAsync(I18n.T("IpBlock_ActionRefresh", "Refresh IP blocklists"), s => IpBlocklistStatusText = s, async () =>
        {
            var result = await _client.Lists.RefreshIpBlocklistsAsync(new Empty());
            StatusText = result.Message;
            await LoadIpBlocklistsAsync();
            IpBlocklistStatusText = DescribeIpBlocklistResult(result);
        });
    }

    [RelayCommand(CanExecute = nameof(CanUseSelectedIpBlocklist))]
    public async Task ToggleIpBlocklistAsync()
    {
        if (SelectedIpBlocklist is not { } row)
        {
            return;
        }

        await RunServiceActionAsync(I18n.T("IpBlock_ActionToggle", "Toggle IP blocklist"), s => IpBlocklistStatusText = s, async () =>
        {
            var ack = await _client.Lists.SetIpBlocklistEnabledAsync(new BlocklistToggleRequest
            {
                Name = row.Name,
                Enabled = !row.Enabled,
            });
            StatusText = ack.Message;
            await LoadIpBlocklistsAsync();
            IpBlocklistStatusText = ack.Message;
        });
    }

    [RelayCommand(CanExecute = nameof(CanUseSelectedIpBlocklist))]
    public async Task RemoveIpBlocklistAsync()
    {
        if (SelectedIpBlocklist is not { } row)
        {
            return;
        }

        await RunServiceActionAsync(I18n.T("IpBlock_ActionRemove", "Remove IP blocklist"), s => IpBlocklistStatusText = s, async () =>
        {
            var ack = await _client.Lists.RemoveIpBlocklistAsync(new BlocklistRequest { Name = row.Name });
            StatusText = ack.Message;
            await LoadIpBlocklistsAsync();
            IpBlocklistStatusText = ack.Message;
        });
    }

    [RelayCommand(CanExecute = nameof(CanUseSelectedIpBlocklist))]
    public async Task RollbackIpBlocklistAsync()
    {
        if (SelectedIpBlocklist is not { } row)
        {
            return;
        }

        await RunServiceActionAsync(I18n.T("IpBlock_ActionRollback", "Roll back IP blocklist"), s => IpBlocklistStatusText = s, async () =>
        {
            var result = await _client.Lists.RollbackIpBlocklistAsync(new BlocklistRequest { Name = row.Name });
            StatusText = result.Message;
            await LoadIpBlocklistsAsync();
            IpBlocklistStatusText = DescribeIpBlocklistResult(result);
        });
    }

    private bool CanUseSelectedIpBlocklist() => SelectedIpBlocklist is not null;

    private static string DescribeIpBlocklistResult(IpBlocklistResult result) =>
        result.Warning.Length != 0 ? I18n.T("IpBlock_ResultWarning", "{0} — {1}", result.Message, result.Warning) : result.Message;
}
