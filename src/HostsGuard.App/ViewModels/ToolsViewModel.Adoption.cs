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
    private string _adoptionStatusText = "Checking manual-edit adoption…";

    public async Task LoadAdoptionStatusAsync()
    {
        await RunServiceActionAsync("Load manual-edit adoption", s => AdoptionStatusText = s, async () =>
        {
            var status = await _client.Hosts.GetHostsAdoptionStatusAsync(new Empty());
            AdoptManualEdits = status.Enabled;
            var backlog = status.Unadopted == 0
                ? "all hosts entries adopted"
                : $"{Plural.Of(status.Unadopted, "hand-added entry", "hand-added entries")} not yet imported";
            AdoptionStatusText = $"Auto-adopt {(status.Enabled ? "on" : "off")} · {backlog}"
                + (status.LastRun.Length != 0 ? $" · last run {TimeText.Compact(status.LastRun)} ({status.LastResult})" : string.Empty);
        });
    }

    /// <summary>Toggle whether hand edits to the hosts file are auto-imported on change.</summary>
    [RelayCommand]
    public async Task SaveAdoptionConfigAsync()
    {
        await RunServiceActionAsync("Save manual-edit adoption", s => AdoptionStatusText = s, async () =>
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
        await RunServiceActionAsync("Adopt manual hosts entries", s => AdoptionStatusText = s, async () =>
        {
            AdoptionStatusText = "Deduping, organizing, and importing hand-added hosts entries…";
            var result = await _client.Hosts.AdoptHostsEntriesAsync(new Empty());
            StatusText = result.Message;
            await LoadAdoptionStatusAsync();
        });
    }
}
