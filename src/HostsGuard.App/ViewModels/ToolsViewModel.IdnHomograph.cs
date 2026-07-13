using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using HostsGuard.App.Services;
using HostsGuard.Contracts;

namespace HostsGuard.App.ViewModels;

public sealed partial class ToolsViewModel
{
    [ObservableProperty]
    private bool _idnHomographEnabled;

    [ObservableProperty]
    private string _idnHomographStatus = I18n.T(
        "IdnHomograph_NotLoaded", "IDN homograph detection status not loaded.");

    [RelayCommand]
    public async Task LoadIdnHomographStatusAsync()
    {
        await RunServiceActionAsync(I18n.T("Idn_ActionLoad", "Load IDN homograph status"), s => IdnHomographStatus = s, async () =>
        {
            var status = await _client.Dns.GetIdnHomographStatusAsync(new Empty());
            IdnHomographEnabled = status.Enabled;
            IdnHomographStatus = status.Enabled
                ? I18n.T("IdnHomograph_OnStatus",
                    "Alert-only detection is on · {0} comparison targets · {1}. No automatic block is applied.",
                    status.CorpusSize, status.Standard)
                : I18n.T("IdnHomograph_OffStatus",
                    "Off by default. When enabled, structured evidence appears in Alerts; no automatic block is applied.");
        });
    }

    [RelayCommand]
    public async Task ToggleIdnHomographAsync()
    {
        await RunServiceActionAsync(I18n.T("Idn_ActionSet", "Set IDN homograph alerts"), s => IdnHomographStatus = s, async () =>
        {
            var ack = await _client.Dns.SetIdnHomographAsync(new IdnHomographRequest
            {
                Enabled = !IdnHomographEnabled,
            });
            IdnHomographStatus = ack.Message;
            await LoadIdnHomographStatusAsync();
        });
    }
}
