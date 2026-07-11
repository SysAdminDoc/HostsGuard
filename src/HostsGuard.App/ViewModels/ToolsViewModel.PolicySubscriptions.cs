using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using HostsGuard.App.Services;
using HostsGuard.Contracts;

namespace HostsGuard.App.ViewModels;

public sealed partial class ToolsViewModel
{
    // ─── Remote policy subscriptions (NET-171) ──────────────────────────────

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(DeletePolicySubscriptionCommand))]
    [NotifyCanExecuteChangedFor(nameof(RollbackPolicySubscriptionCommand))]
    private PolicySubscriptionViewModel? _selectedPolicySubscription;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(SavePolicySubscriptionCommand))]
    [NotifyCanExecuteChangedFor(nameof(PreviewPolicySubscriptionCommand))]
    [NotifyCanExecuteChangedFor(nameof(ApplyPolicySubscriptionCommand))]
    private string _policySubscriptionName = string.Empty;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(SavePolicySubscriptionCommand))]
    [NotifyCanExecuteChangedFor(nameof(PreviewPolicySubscriptionCommand))]
    [NotifyCanExecuteChangedFor(nameof(ApplyPolicySubscriptionCommand))]
    private string _policySubscriptionUrl = string.Empty;

    [ObservableProperty]
    private bool _policySubscriptionEnabled = true;

    [ObservableProperty]
    private bool _policySubscriptionAutoApply;

    [ObservableProperty]
    private bool _policySubscriptionPinCurrentHash = true;

    [ObservableProperty]
    private string _policySubscriptionPinHash = string.Empty;

    [ObservableProperty]
    private string _policySubscriptionStatusText = I18n.T(
        "PolicySub_StatusIntro",
        "Add an HTTPS policy JSON subscription, preview it, then apply with a pinned source hash.");

    [RelayCommand]
    public async Task LoadPolicySubscriptionsAsync()
    {
        await RunServiceActionAsync(I18n.T("PolicySub_ActionLoad", "Load policy subscriptions"), s => PolicySubscriptionStatusText = s, async () =>
        {
            var selectedId = SelectedPolicySubscription?.Id ?? 0;
            var list = await _client.Policy.ListPolicySubscriptionsAsync(new Empty());
            PolicySubscriptions.Clear();
            foreach (var sub in list.Subscriptions)
            {
                PolicySubscriptions.Add(PolicySubscriptionViewModel.From(sub));
            }

            SelectedPolicySubscription = PolicySubscriptions.FirstOrDefault(s => s.Id == selectedId)
                ?? PolicySubscriptions.FirstOrDefault();
            PolicySubscriptionStatusText = PolicySubscriptions.Count == 0
                ? I18n.T("PolicySub_StatusNoneSaved", "No policy subscriptions saved.")
                : I18n.T("PolicySub_StatusLoaded", "{0} policy subscriptions loaded.", PolicySubscriptions.Count);
        });
    }

    [RelayCommand(CanExecute = nameof(CanSavePolicySubscription))]
    public async Task SavePolicySubscriptionAsync()
    {
        await RunServiceActionAsync(I18n.T("PolicySub_ActionSave", "Save policy subscription"), s => PolicySubscriptionStatusText = s, async () =>
        {
            var ack = await _client.Policy.SavePolicySubscriptionAsync(CreatePolicySubscriptionRequest());
            PolicySubscriptionStatusText = ack.Message;
            StatusText = ack.Message;
            await LoadPolicySubscriptionsAsync();
        });
    }

    [RelayCommand(CanExecute = nameof(CanUsePolicySubscriptionTarget))]
    public async Task PreviewPolicySubscriptionAsync()
    {
        await RunServiceActionAsync(I18n.T("PolicySub_ActionPreview", "Preview policy subscription"), s => PolicySubscriptionStatusText = s, async () =>
        {
            var result = await _client.Policy.PreviewPolicySubscriptionAsync(CreatePolicySubscriptionRequest());
            PolicySubscriptionStatusText = DescribePolicyImportResult(result);
        });
    }

    [RelayCommand(CanExecute = nameof(CanUsePolicySubscriptionTarget))]
    public async Task ApplyPolicySubscriptionAsync()
    {
        await RunServiceActionAsync(I18n.T("PolicySub_ActionApply", "Apply policy subscription"), s => PolicySubscriptionStatusText = s, async () =>
        {
            var preview = await _client.Policy.PreviewPolicySubscriptionAsync(CreatePolicySubscriptionRequest());
            if (!preview.Ok)
            {
                PolicySubscriptionStatusText = preview.Message;
                return;
            }

            var previewText = $"{preview.Message}\n\n" + string.Join("\n", preview.Summary.Take(8));
            if (!_confirm.Confirm(
                I18n.T("PolicySub_ConfirmApplyTitle", "Apply policy subscription"),
                previewText + "\n\n" + I18n.T("PolicySub_ConfirmApplyMessage", "Create a restore checkpoint and apply this subscription?")))
            {
                PolicySubscriptionStatusText = I18n.T("PolicySub_StatusApplyCancelled", "Policy subscription apply cancelled after preview.");
                return;
            }

            var result = await _client.Policy.ApplyPolicySubscriptionAsync(CreatePolicySubscriptionRequest());
            PolicySubscriptionStatusText = DescribePolicyImportResult(result);
            StatusText = result.Message;
            await LoadPolicySubscriptionsAsync();
        });
    }

    [RelayCommand]
    public async Task RefreshPolicySubscriptionsAsync()
    {
        if (!_confirm.Confirm(
            I18n.T("PolicySub_ConfirmAutoApplyTitle", "Apply trusted policy subscriptions"),
            I18n.T(
                "PolicySub_ConfirmAutoApplyMessage",
                "Apply every enabled policy subscription with auto-apply enabled now? Pinned hashes are enforced and each apply creates a restore checkpoint.")))
        {
            return;
        }

        await RunServiceActionAsync(I18n.T("PolicySub_ActionRefresh", "Refresh policy subscriptions"), s => PolicySubscriptionStatusText = s, async () =>
        {
            var result = await _client.Policy.RefreshPolicySubscriptionsAsync(new Empty());
            PolicySubscriptionStatusText = DescribePolicyImportResult(result);
            StatusText = result.Message;
            await LoadPolicySubscriptionsAsync();
        });
    }

    [RelayCommand(CanExecute = nameof(CanUseSelectedPolicySubscription))]
    public async Task RollbackPolicySubscriptionAsync()
    {
        if (SelectedPolicySubscription is not { } row)
        {
            return;
        }

        if (!_confirm.Confirm(
            I18n.T("PolicySub_ConfirmRollbackTitle", "Rollback policy subscription"),
            I18n.T("PolicySub_ConfirmRollbackMessage", "Restore the checkpoint captured before the latest apply of '{0}'?", row.Name)))
        {
            return;
        }

        await RunServiceActionAsync(I18n.T("PolicySub_ActionRollback", "Rollback policy subscription"), s => PolicySubscriptionStatusText = s, async () =>
        {
            var result = await _client.Policy.RollbackPolicySubscriptionAsync(new PolicySubscriptionRequest { Id = row.Id });
            PolicySubscriptionStatusText = DescribePolicyImportResult(result);
            StatusText = result.Message;
            await LoadPolicySubscriptionsAsync();
        });
    }

    [RelayCommand(CanExecute = nameof(CanUseSelectedPolicySubscription))]
    public async Task DeletePolicySubscriptionAsync()
    {
        if (SelectedPolicySubscription is not { } row)
        {
            return;
        }

        if (!_confirm.Confirm(
            I18n.T("PolicySub_ConfirmRemoveTitle", "Remove policy subscription"),
            I18n.T("PolicySub_ConfirmRemoveMessage", "Remove '{0}' from saved policy subscriptions? Applied policy is not rolled back.", row.Name)))
        {
            return;
        }

        await RunServiceActionAsync(I18n.T("PolicySub_ActionRemove", "Remove policy subscription"), s => PolicySubscriptionStatusText = s, async () =>
        {
            var ack = await _client.Policy.DeletePolicySubscriptionAsync(new PolicySubscriptionRequest { Id = row.Id });
            PolicySubscriptionStatusText = ack.Message;
            StatusText = ack.Message;
            if (ack.Ok)
            {
                ClearPolicySubscriptionEditor();
                await LoadPolicySubscriptionsAsync();
            }
        });
    }

    private bool CanSavePolicySubscription() => !string.IsNullOrWhiteSpace(PolicySubscriptionUrl);

    private bool CanUsePolicySubscriptionTarget() =>
        SelectedPolicySubscription is not null || !string.IsNullOrWhiteSpace(PolicySubscriptionUrl);

    private bool CanUseSelectedPolicySubscription() => SelectedPolicySubscription is not null;

    private PolicySubscriptionRequest CreatePolicySubscriptionRequest() => new()
    {
        Id = SelectedPolicySubscription?.Id ?? 0,
        Name = PolicySubscriptionName.Trim(),
        Url = PolicySubscriptionUrl.Trim(),
        Enabled = PolicySubscriptionEnabled,
        AutoApply = PolicySubscriptionAutoApply,
        PinHash = PolicySubscriptionPinHash.Trim(),
        PinCurrentHash = PolicySubscriptionPinCurrentHash,
    };

    private void ClearPolicySubscriptionEditor()
    {
        SelectedPolicySubscription = null;
        PolicySubscriptionName = string.Empty;
        PolicySubscriptionUrl = string.Empty;
        PolicySubscriptionEnabled = true;
        PolicySubscriptionAutoApply = false;
        PolicySubscriptionPinCurrentHash = true;
        PolicySubscriptionPinHash = string.Empty;
    }

    partial void OnSelectedPolicySubscriptionChanged(PolicySubscriptionViewModel? value)
    {
        if (value is null)
        {
            return;
        }

        PolicySubscriptionName = value.Name;
        PolicySubscriptionUrl = value.Url;
        PolicySubscriptionEnabled = value.Enabled;
        PolicySubscriptionAutoApply = value.AutoApply;
        PolicySubscriptionPinHash = value.PinHash;
        PolicySubscriptionPinCurrentHash = string.IsNullOrWhiteSpace(value.PinHash);
        DeletePolicySubscriptionCommand.NotifyCanExecuteChanged();
        RollbackPolicySubscriptionCommand.NotifyCanExecuteChanged();
    }

    private static string DescribePolicyImportResult(ImportPolicyResult result)
    {
        var detail = result.Summary.Count == 0
            ? string.Empty
            : " " + string.Join("; ", result.Summary.Take(5));
        return result.Ok ? result.Message + detail : result.Message;
    }
}
