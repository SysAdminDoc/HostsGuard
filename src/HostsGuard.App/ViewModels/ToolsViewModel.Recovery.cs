using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using HostsGuard.App.Services;
using HostsGuard.Contracts;

namespace HostsGuard.App.ViewModels;

public sealed partial class ToolsViewModel
{
    public ObservableCollection<FullStateSnapshotRowViewModel> FullStateSnapshots { get; } = new();

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(PreviewFullStateRestoreCommand))]
    [NotifyCanExecuteChangedFor(nameof(RestoreFullStateSnapshotCommand))]
    private FullStateSnapshotRowViewModel? _selectedFullStateSnapshot;

    [ObservableProperty]
    private string _fullStateSnapshotStatus = I18n.T("Recovery_StatusHint", "Create a hashed recovery point for the database, hosts state, and non-secret service settings.");

    [ObservableProperty]
    private string _fullStateRestorePreview = I18n.T("Recovery_SelectHint", "Select a snapshot, then preview its verified changes before restoring.");

    private string _previewedSnapshotId = string.Empty;
    private string _previewedSnapshotHash = string.Empty;

    partial void OnSelectedFullStateSnapshotChanged(FullStateSnapshotRowViewModel? value)
    {
        _previewedSnapshotId = string.Empty;
        _previewedSnapshotHash = string.Empty;
        FullStateRestorePreview = value is null
            ? I18n.T("Recovery_SelectHint", "Select a snapshot, then preview its verified changes before restoring.")
            : I18n.T("Recovery_PreviewRequired", "Preview required before restore.");
        RestoreFullStateSnapshotCommand.NotifyCanExecuteChanged();
    }

    [RelayCommand]
    public async Task CreateFullStateSnapshotAsync()
    {
        await RunServiceActionAsync(I18n.T("Recovery_ActionCreate", "Create full-state snapshot"), s => FullStateSnapshotStatus = s, async () =>
        {
            var snapshot = await _client.Recovery.CreateFullStateSnapshotAsync(new Empty());
            FullStateSnapshotStatus = snapshot.Verified
                ? I18n.T("Recovery_Created", "Verified snapshot created: {0} · {1}", snapshot.SnapshotId, snapshot.Sha256)
                : I18n.T("Recovery_VerificationFailed", "Snapshot verification failed: {0}", snapshot.SnapshotId);
            await LoadFullStateSnapshotsCoreAsync(snapshot.SnapshotId);
        });
    }

    [RelayCommand]
    public async Task LoadFullStateSnapshotsAsync()
    {
        await RunServiceActionAsync(I18n.T("Recovery_ActionLoad", "Load full-state snapshots"), s => FullStateSnapshotStatus = s,
            () => LoadFullStateSnapshotsCoreAsync(SelectedFullStateSnapshot?.SnapshotId));
    }

    private async Task LoadFullStateSnapshotsCoreAsync(string? selectId)
    {
        var list = await _client.Recovery.ListFullStateSnapshotsAsync(new Empty());
        FullStateSnapshots.Clear();
        foreach (var snapshot in list.Snapshots.OrderByDescending(item => item.Created, StringComparer.Ordinal))
        {
            FullStateSnapshots.Add(FullStateSnapshotRowViewModel.From(snapshot));
        }

        SelectedFullStateSnapshot = FullStateSnapshots.FirstOrDefault(item =>
            item.SnapshotId.Equals(selectId, StringComparison.Ordinal)) ?? FullStateSnapshots.FirstOrDefault();
        FullStateSnapshotStatus = FullStateSnapshots.Count == 0
            ? I18n.T("Recovery_None", "No full-state snapshots yet.")
            : I18n.T("Recovery_Count", "{0} recovery point(s) available.", FullStateSnapshots.Count);
    }

    [RelayCommand(CanExecute = nameof(CanPreviewFullStateRestore))]
    public async Task PreviewFullStateRestoreAsync()
    {
        if (SelectedFullStateSnapshot is not { } selected)
        {
            return;
        }

        await RunServiceActionAsync(I18n.T("Recovery_ActionPreview", "Preview full-state restore"), s => FullStateRestorePreview = s, async () =>
        {
            var preview = await _client.Recovery.PreviewFullStateRestoreAsync(new FullStateSnapshotRef
            {
                SnapshotId = selected.SnapshotId,
            });
            if (!preview.Ok)
            {
                _previewedSnapshotId = string.Empty;
                _previewedSnapshotHash = string.Empty;
                FullStateRestorePreview = preview.Message;
            }
            else
            {
                _previewedSnapshotId = preview.SnapshotId;
                _previewedSnapshotHash = preview.Sha256;
                var changes = preview.Changes.Count == 0
                    ? I18n.T("Recovery_NoDifferences", "No state differences.")
                    : string.Join(Environment.NewLine, preview.Changes.Select(change => $"• {change}"));
                FullStateRestorePreview = I18n.T("Recovery_PreviewDetails", "Verified SHA-256: {0}{3}Target: HostsGuard {1}, schema {2}{3}{4}",
                    preview.Sha256, preview.AppVersion, preview.SchemaVersion, Environment.NewLine, changes);
            }

            RestoreFullStateSnapshotCommand.NotifyCanExecuteChanged();
        });
    }

    private bool CanPreviewFullStateRestore() => SelectedFullStateSnapshot is not null;

    [RelayCommand(CanExecute = nameof(CanRestoreFullStateSnapshot))]
    public async Task RestoreFullStateSnapshotAsync()
    {
        if (SelectedFullStateSnapshot is not { } selected || !CanRestoreFullStateSnapshot())
        {
            FullStateRestorePreview = I18n.T("Recovery_PreviewAgain", "Preview this snapshot again before restoring.");
            return;
        }

        if (!new MutationConfirmation(
                I18n.T("Recovery_RestoreConfirmTitle", "Stage full-state restore"),
                I18n.T("Recovery_RestoreTarget", "Snapshot {0} ({1}, SHA-256 {2})", selected.SnapshotId, selected.Created, selected.Sha256),
                I18n.T("Recovery_RestoreConsequence",
                    "Stage this verified database, hosts, and non-secret settings snapshot for the next service restart. A pre-restore recovery point and automatic validation rollback remain enabled."))
            .Request(_confirm))
        {
            return;
        }

        await RunServiceActionAsync(I18n.T("Recovery_ActionRestore", "Restore full-state snapshot"), s => FullStateRestorePreview = s, async () =>
        {
            var ack = await _client.Recovery.RestoreFullStateSnapshotAsync(new FullStateRestoreRequest
            {
                SnapshotId = selected.SnapshotId,
                ExpectedSha256 = _previewedSnapshotHash,
                CreatePreRestore = true,
            });
            FullStateRestorePreview = ack.Message;
            _previewedSnapshotId = string.Empty;
            _previewedSnapshotHash = string.Empty;
            RestoreFullStateSnapshotCommand.NotifyCanExecuteChanged();
            if (ack.Ok)
            {
                await LoadFullStateSnapshotsCoreAsync(null);
            }
        });
    }

    private bool CanRestoreFullStateSnapshot() =>
        SelectedFullStateSnapshot is { Verified: true } selected
        && selected.SnapshotId.Equals(_previewedSnapshotId, StringComparison.Ordinal)
        && selected.Sha256.Equals(_previewedSnapshotHash, StringComparison.OrdinalIgnoreCase)
        && _previewedSnapshotHash.Length == 64;
}
