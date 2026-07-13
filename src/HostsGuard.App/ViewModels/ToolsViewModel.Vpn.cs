using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using HostsGuard.App.Services;
using HostsGuard.Contracts;

namespace HostsGuard.App.ViewModels;

public sealed partial class ToolsViewModel
{
    // ─── VPN-presence kill-switch (NET-119) ──────────────────────────────────

    public ObservableCollection<AdapterRowViewModel> Adapters { get; } = new();

    [ObservableProperty]
    private AdapterRowViewModel? _selectedAdapter;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(SaveAppVpnBindingCommand))]
    private AdapterRowViewModel? _selectedAppVpnAdapter;

    [ObservableProperty]
    private bool _killSwitchEnabled;

    [ObservableProperty]
    private string _killSwitchStatusText = I18n.T("Vpn_KillSwitchOff", "VPN kill-switch off.");

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(SaveAppVpnBindingCommand))]
    private string _appVpnProgramPath = string.Empty;

    [ObservableProperty]
    private string _appVpnStatusText = I18n.T("Vpn_NoBindings", "No app VPN bindings.");

    [RelayCommand]
    public async Task LoadKillSwitchAsync()
    {
        await RunServiceActionAsync(I18n.T("Vpn_ActionLoadKillSwitch", "Load VPN kill-switch"), s => KillSwitchStatusText = s, async () =>
        {
            var status = await _client.Firewall.GetKillSwitchAsync(new Empty());
            ReplaceAdapters(status.Adapters);

            KillSwitchEnabled = status.Enabled;
            SelectedAdapter = Adapters.FirstOrDefault(a => a.Match == status.Adapter)
                ?? Adapters.FirstOrDefault(a => a.Label.Contains(", VPN", StringComparison.Ordinal))
                ?? Adapters.FirstOrDefault();
            KillSwitchStatusText = status.Enabled
                ? status.Engaged
                    ? I18n.T("Vpn_KillSwitchEngaged", "ENGAGED — all outbound blocked while '{0}' is down", status.Adapter)
                    : I18n.T("Vpn_KillSwitchWatching", "On — watching '{0}'", status.Adapter)
                : I18n.T("Vpn_KillSwitchOff", "VPN kill-switch off.");
        });
    }

    [RelayCommand]
    public async Task ToggleKillSwitchAsync()
    {
        var adapter = SelectedAdapter?.Match ?? string.Empty;
        if (!KillSwitchEnabled)
        {
            if (adapter.Length == 0)
            {
                StatusText = I18n.T("Vpn_ChooseAdapter", "Choose a VPN adapter before enabling the kill-switch.");
                return;
            }

            if (!_confirm.Confirm(I18n.T("Vpn_ConfirmEnableTitle", "Enable VPN kill-switch"),
                I18n.T("Vpn_ConfirmEnableMessage", "Block ALL outbound traffic whenever '{0}' is down? Existing allow rules still apply — keep one for your VPN client so the tunnel can reconnect. You can turn this off here at any time.", adapter)))
            {
                return;
            }
        }

        await RunServiceActionAsync(I18n.T("Vpn_ActionToggleKillSwitch", "Toggle VPN kill-switch"), s => KillSwitchStatusText = s, async () =>
        {
            var ack = await _client.Firewall.SetKillSwitchAsync(new KillSwitchRequest
            {
                Enabled = !KillSwitchEnabled,
                Adapter = adapter,
            });
            StatusText = ack.Message;
            await LoadKillSwitchAsync();
        });
    }

    [RelayCommand]
    public async Task LoadAppVpnBindingsAsync()
    {
        await RunServiceActionAsync(I18n.T("Vpn_ActionLoadBindings", "Load app VPN bindings"), s => AppVpnStatusText = s, async () =>
        {
            var status = await _client.Firewall.GetAppVpnBindingsAsync(new Empty());
            ReplaceAdapters(status.Adapters);
            AppVpnBindings.Clear();
            foreach (var binding in status.Bindings.OrderBy(b => b.ProgramPath, StringComparer.OrdinalIgnoreCase))
            {
                AppVpnBindings.Add(AppVpnBindingRowViewModel.From(binding));
            }

            SelectedAppVpnAdapter ??= Adapters.FirstOrDefault(a => a.Label.Contains(", VPN", StringComparison.Ordinal))
                ?? Adapters.FirstOrDefault();
            AppVpnStatusText = AppVpnBindings.Count == 0
                ? I18n.T("Vpn_NoBindings", "No app VPN bindings.")
                : I18n.T("Vpn_BindingCount", "{0} app VPN binding(s)", AppVpnBindings.Count);
        });
    }

    [RelayCommand(CanExecute = nameof(CanSaveAppVpnBinding))]
    public async Task SaveAppVpnBindingAsync()
    {
        var program = AppVpnProgramPath.Trim();
        var adapter = SelectedAppVpnAdapter?.Match ?? string.Empty;
        await RunServiceActionAsync(I18n.T("Vpn_ActionSaveBinding", "Save app VPN binding"), s => AppVpnStatusText = s, async () =>
        {
            var ack = await _client.Firewall.SetAppVpnBindingAsync(new AppVpnBindingRequest
            {
                ProgramPath = program,
                Adapter = adapter,
                Enabled = true,
            });
            StatusText = ack.Message;
            AppVpnStatusText = ack.Message;
            if (ack.Ok)
            {
                AppVpnProgramPath = string.Empty;
                await LoadAppVpnBindingsAsync();
            }
        });
    }

    private bool CanSaveAppVpnBinding()
        => !string.IsNullOrWhiteSpace(AppVpnProgramPath) && SelectedAppVpnAdapter is not null;

    [RelayCommand]
    public async Task RemoveAppVpnBindingAsync(AppVpnBindingRowViewModel? binding)
    {
        if (binding is null || string.IsNullOrWhiteSpace(binding.ProgramPath))
        {
            return;
        }

        await RunServiceActionAsync(I18n.T("Vpn_ActionRemoveBinding", "Remove app VPN binding"), s => AppVpnStatusText = s, async () =>
        {
            var ack = await _client.Firewall.SetAppVpnBindingAsync(new AppVpnBindingRequest
            {
                ProgramPath = binding.ProgramPath,
                Adapter = binding.Adapter,
                Enabled = false,
            });
            StatusText = ack.Message;
            AppVpnStatusText = ack.Message;
            await LoadAppVpnBindingsAsync();
        });
    }

    private void ReplaceAdapters(IEnumerable<NetworkAdapterInfo> adapters)
    {
        var killMatch = SelectedAdapter?.Match ?? string.Empty;
        var appMatch = SelectedAppVpnAdapter?.Match ?? string.Empty;
        Adapters.Clear();
        foreach (var a in adapters)
        {
            Adapters.Add(new AdapterRowViewModel
            {
                Match = a.Name,
                Label = I18n.T("Vpn_AdapterLabel", "{0} — {1} ({2}{3})", a.Name, a.Description,
                    a.IsUp ? I18n.T("Common_UpLower", "up") : I18n.T("Common_DownLower", "down"),
                    a.IsVpnLikely ? I18n.T("Vpn_LabelSuffix", ", VPN") : string.Empty),
            });
        }

        if (killMatch.Length != 0)
        {
            SelectedAdapter = Adapters.FirstOrDefault(a => a.Match == killMatch);
        }

        if (appMatch.Length != 0)
        {
            SelectedAppVpnAdapter = Adapters.FirstOrDefault(a => a.Match == appMatch);
        }
    }
}
