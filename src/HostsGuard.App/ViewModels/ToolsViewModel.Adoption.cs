using CommunityToolkit.Mvvm.Input;
using HostsGuard.App.Services;
using HostsGuard.Contracts;

namespace HostsGuard.App.ViewModels;

public sealed partial class ToolsViewModel
{
    // ─── Manual-edit adoption (NET-188) ───────────────────────────────────────

    [CommunityToolkit.Mvvm.ComponentModel.ObservableProperty]
    private bool _adoptManualEdits = true;

    [CommunityToolkit.Mvvm.ComponentModel.ObservableProperty]
    private string _adoptionStatusText = I18n.T("Adoption_Checking", "Checking manual-edit adoption…");

    public async Task LoadAdoptionStatusAsync()
    {
        await RunServiceActionAsync(I18n.T("Adoption_ActionLoad", "Load manual-edit adoption"), s => AdoptionStatusText = s, async () =>
        {
            var status = await _client.Hosts.GetHostsAdoptionStatusAsync(new Empty());
            AdoptManualEdits = status.Enabled;
            var backlog = status.Unadopted == 0
                ? I18n.T("Adoption_AllAdopted", "all hosts entries adopted")
                : I18n.T("Adoption_Backlog", "{0} hand-added entries not yet imported", status.Unadopted);
            AdoptionStatusText = I18n.T("Adoption_Status", "Auto-adopt {0} · {1}",
                status.Enabled ? I18n.T("Common_OnLower", "on") : I18n.T("Common_OffLower", "off"), backlog)
                + (status.LastRun.Length != 0 ? I18n.T("Adoption_LastRunSuffix", " · last run {0} ({1})", TimeText.Compact(status.LastRun), status.LastResult) : string.Empty);
        });
    }

    /// <summary>Toggle whether hand edits to the hosts file are auto-imported on change.</summary>
    [RelayCommand]
    public async Task SaveAdoptionConfigAsync()
    {
        await RunServiceActionAsync(I18n.T("Adoption_ActionSave", "Save manual-edit adoption"), s => AdoptionStatusText = s, async () =>
        {
            var ack = await _client.Hosts.SetHostsAdoptionAsync(new HostsAdoptionRequest { Enabled = AdoptManualEdits });
            StatusText = ack.Message;
            await LoadAdoptionStatusAsync();
        });
    }

    /// <summary>Dedupe, organize, categorize, and import any hand-added hosts entries now.</summary>
    [RelayCommand]
    public async Task AdoptHostsNowAsync()
    {
        await RunServiceActionAsync(I18n.T("Adoption_ActionRun", "Adopt manual hosts entries"), s => AdoptionStatusText = s, async () =>
        {
            AdoptionStatusText = I18n.T("Adoption_Importing", "Deduping, organizing, and importing hand-added hosts entries…");
            var result = await _client.Hosts.AdoptHostsEntriesAsync(new Empty());
            StatusText = result.Message;
            await LoadAdoptionStatusAsync();
        });
    }
}
