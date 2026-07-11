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
    private string _killSwitchStatusText = "VPN kill-switch off.";

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(SaveAppVpnBindingCommand))]
    private string _appVpnProgramPath = string.Empty;

    [ObservableProperty]
    private string _appVpnStatusText = "No app VPN bindings.";

    [RelayCommand]
    public async Task LoadKillSwitchAsync()
    {
        await RunServiceActionAsync("Load VPN kill-switch", s => KillSwitchStatusText = s, async () =>
        {
            var status = await _client.Firewall.GetKillSwitchAsync(new Empty());
            ReplaceAdapters(status.Adapters);

            KillSwitchEnabled = status.Enabled;
            SelectedAdapter = Adapters.FirstOrDefault(a => a.Match == status.Adapter)
                ?? Adapters.FirstOrDefault(a => a.Label.Contains(", VPN", StringComparison.Ordinal))
                ?? Adapters.FirstOrDefault();
            KillSwitchStatusText = status.Enabled
                ? status.Engaged
                    ? $"ENGAGED — all outbound blocked while '{status.Adapter}' is down"
                    : $"On — watching '{status.Adapter}'"
                : "VPN kill-switch off.";
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
                StatusText = "Choose a VPN adapter before enabling the kill-switch.";
                return;
            }

            if (!_confirm.Confirm("Enable VPN kill-switch",
                $"Block ALL outbound traffic whenever '{adapter}' is down? Existing allow rules still apply — "
                + "keep one for your VPN client so the tunnel can reconnect. You can turn this off here at any time."))
            {
                return;
            }
        }

        await RunServiceActionAsync("Toggle VPN kill-switch", s => KillSwitchStatusText = s, async () =>
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
        await RunServiceActionAsync("Load app VPN bindings", s => AppVpnStatusText = s, async () =>
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
                ? "No app VPN bindings."
                : $"{Plural.Of(AppVpnBindings.Count, "app VPN binding")}";
        });
    }

    [RelayCommand(CanExecute = nameof(CanSaveAppVpnBinding))]
    public async Task SaveAppVpnBindingAsync()
    {
        var program = AppVpnProgramPath.Trim();
        var adapter = SelectedAppVpnAdapter?.Match ?? string.Empty;
        await RunServiceActionAsync("Save app VPN binding", s => AppVpnStatusText = s, async () =>
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

        await RunServiceActionAsync("Remove app VPN binding", s => AppVpnStatusText = s, async () =>
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
                Label = $"{a.Name} — {a.Description} ({(a.IsUp ? "up" : "down")}{(a.IsVpnLikely ? ", VPN" : string.Empty)})",
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
