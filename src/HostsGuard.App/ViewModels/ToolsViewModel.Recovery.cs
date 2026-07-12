using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
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
    private string _fullStateSnapshotStatus = "Create a hashed recovery point for the database, hosts state, and non-secret service settings.";

    [ObservableProperty]
    private string _fullStateRestorePreview = "Select a snapshot, then preview its verified changes before restoring.";

    private string _previewedSnapshotId = string.Empty;
    private string _previewedSnapshotHash = string.Empty;

    partial void OnSelectedFullStateSnapshotChanged(FullStateSnapshotRowViewModel? value)
    {
        _previewedSnapshotId = string.Empty;
        _previewedSnapshotHash = string.Empty;
        FullStateRestorePreview = value is null
            ? "Select a snapshot, then preview its verified changes before restoring."
            : "Preview required before restore.";
        RestoreFullStateSnapshotCommand.NotifyCanExecuteChanged();
    }

    [RelayCommand]
    public async Task CreateFullStateSnapshotAsync()
    {
        await RunServiceActionAsync("Create full-state snapshot", s => FullStateSnapshotStatus = s, async () =>
        {
            var snapshot = await _client.Recovery.CreateFullStateSnapshotAsync(new Empty());
            FullStateSnapshotStatus = snapshot.Verified
                ? $"Verified snapshot created: {snapshot.SnapshotId} · {snapshot.Sha256}"
                : $"Snapshot verification failed: {snapshot.SnapshotId}";
            await LoadFullStateSnapshotsCoreAsync(snapshot.SnapshotId);
        });
    }

    [RelayCommand]
    public async Task LoadFullStateSnapshotsAsync()
    {
        await RunServiceActionAsync("Load full-state snapshots", s => FullStateSnapshotStatus = s,
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
            ? "No full-state snapshots yet."
            : $"{FullStateSnapshots.Count} recovery point{(FullStateSnapshots.Count == 1 ? string.Empty : "s")} available.";
    }

    [RelayCommand(CanExecute = nameof(CanPreviewFullStateRestore))]
    public async Task PreviewFullStateRestoreAsync()
    {
        if (SelectedFullStateSnapshot is not { } selected)
        {
            return;
        }

        await RunServiceActionAsync("Preview full-state restore", s => FullStateRestorePreview = s, async () =>
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
                var changes = preview.Changes.Count == 0 ? "No state differences." : string.Join(Environment.NewLine, preview.Changes.Select(change => $"• {change}"));
                FullStateRestorePreview = $"Verified SHA-256: {preview.Sha256}{Environment.NewLine}Target: HostsGuard {preview.AppVersion}, schema {preview.SchemaVersion}{Environment.NewLine}{changes}";
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
            FullStateRestorePreview = "Preview this snapshot again before restoring.";
            return;
        }

        await RunServiceActionAsync("Restore full-state snapshot", s => FullStateRestorePreview = s, async () =>
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
