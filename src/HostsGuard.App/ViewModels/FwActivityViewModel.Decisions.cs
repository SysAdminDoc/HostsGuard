using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using HostsGuard.App.Services;
using HostsGuard.Contracts;

namespace HostsGuard.App.ViewModels;

public sealed partial class FwActivityViewModel
{
    // ─── Consent history (WFCP-021): recent prompts with re-decide ───────────

    public ObservableCollection<DecisionRowViewModel> ConsentHistory { get; } = new();

    /// <summary>Most-triggered apps: (application, count), highest first (NET-085).</summary>
    public ObservableCollection<string> TopTriggered { get; } = new();

    [ObservableProperty]
    private bool _soundOnBlock;

    [RelayCommand]
    public async Task LoadConsentHistoryAsync()
    {
        await RunServiceActionAsync(I18n.T("FwDecision_ActionLoadHistory", "Load consent history"), async () =>
        {
            var history = await _client.Consent.GetDecisionHistoryAsync(new HistoryRequest { Limit = 200 });
            ConsentHistory.Clear();
            foreach (var entry in history.Entries.Take(50))
            {
                ConsentHistory.Add(new DecisionRowViewModel
                {
                    DecidedAt = entry.DecidedAt,
                    Application = entry.Application,
                    Direction = entry.Direction,
                    RemoteAddress = entry.RemoteAddress,
                    Protocol = entry.Protocol,
                    Verdict = entry.Verdict,
                    Permanent = entry.Permanent,
                    FilterRuntimeId = entry.FilterRuntimeId,
                    FilterOrigin = entry.FilterOrigin,
                    LayerName = entry.LayerName,
                    LayerRuntimeId = entry.LayerRuntimeId,
                    InterfaceIndex = entry.InterfaceIndex,
                    InterfaceName = entry.InterfaceName,
                    FilterOwner = entry.FilterOwner,
                    ExternalFilter = entry.ExternalFilter,
                });
            }

            // Rank the apps that trigger the most decisions (NET-085).
            TopTriggered.Clear();
            foreach (var group in history.Entries
                         .Where(e => e.Application.Length != 0)
                         .GroupBy(e => System.IO.Path.GetFileName(e.Application), StringComparer.OrdinalIgnoreCase)
                         .Select(g => (App: g.Key, Count: g.Count()))
                         .OrderByDescending(g => g.Count)
                         .ThenBy(g => g.App, StringComparer.OrdinalIgnoreCase)
                         .Take(5))
            {
                TopTriggered.Add($"{group.App} — {group.Count}");
            }
        });
    }

    partial void OnSoundOnBlockChanged(bool value)
    {
        if (!_suppressModeWrite)
        {
            _config?.SaveSoundOnBlock(value);
        }
    }

    [RelayCommand]
    public Task ReAllowAsync(DecisionRowViewModel row) => ReDecideAsync(row, "allow");

    [RelayCommand]
    public Task ReBlockAsync(DecisionRowViewModel row) => ReDecideAsync(row, "block");

    private async Task ReDecideAsync(DecisionRowViewModel? row, string verdict)
    {
        if (row is null)
        {
            return;
        }

        await RunServiceActionAsync(I18n.T("FwDecision_ActionRedecide", "{0} connection decision", verdict), async () =>
        {
            var ack = await _client.Consent.DecideAsync(new ConnectionDecision
            {
                Application = row.Application,
                Direction = row.Direction,
                RemoteAddress = row.RemoteAddress,
                Protocol = row.Protocol,
                Verdict = verdict,
                Permanent = true,
            });
            SetOperatorStatus(ack.Message);
            await LoadConsentHistoryAsync();
        });
    }

    // ─── "Decide later" review of Learning-mode auto-decisions (NET-074) ─────

    public ObservableCollection<LearnedRowViewModel> Learned { get; } = new();

    [ObservableProperty]
    private string _learnedStatus = I18n.T("FwDecision_NoneLearned", "No learning-mode decisions awaiting review.");

    [RelayCommand]
    public async Task LoadLearnedAsync()
    {
        await RunServiceActionAsync(I18n.T("FwDecision_ActionLoadLearned", "Load learned decisions"), s => LearnedStatus = s, async () =>
        {
            var list = await _client.Consent.GetLearnedAsync(new Empty());
            Learned.Clear();
            foreach (var e in list.Entries)
            {
                Learned.Add(new LearnedRowViewModel
                {
                    RuleName = e.RuleName,
                    Application = e.Application,
                    Direction = e.Direction,
                    ServiceName = e.ServiceName,
                });
            }

            LearnedStatus = Learned.Count == 0
                ? I18n.T("FwDecision_NoneLearned", "No learning-mode decisions awaiting review.")
                : I18n.T("FwDecision_LearnedCount", "{0} auto-allowed app(s) awaiting review", Learned.Count);
        });
    }

    [RelayCommand]
    public Task PromoteLearnedAsync(LearnedRowViewModel row) => ReviewLearnedAsync("promote", row);

    [RelayCommand]
    public Task BlockLearnedAsync(LearnedRowViewModel row) => ReviewLearnedAsync("block", row);

    [RelayCommand]
    public Task DiscardLearnedAsync(LearnedRowViewModel row) => ReviewLearnedAsync("discard", row);

    [RelayCommand]
    public Task PromoteAllLearnedAsync() => ReviewLearnedAsync("promote", Learned.ToArray());

    [RelayCommand]
    public Task DiscardAllLearnedAsync() => ReviewLearnedAsync("discard", Learned.ToArray());

    private async Task ReviewLearnedAsync(string action, params LearnedRowViewModel[] rows)
    {
        if (rows.Length == 0)
        {
            return;
        }

        await RunServiceActionAsync(I18n.T("FwDecision_ActionReview", "{0} learned decision", action), s => LearnedStatus = s, async () =>
        {
            var request = new LearnedReviewRequest();
            foreach (var row in rows.Where(r => r is not null))
            {
                request.Actions.Add(new LearnedReviewAction { RuleName = row.RuleName, Action = action });
            }

            var ack = await _client.Consent.ReviewLearnedAsync(request);
            LearnedStatus = ack.Message;
            await LoadLearnedAsync();
            await LoadConsentHistoryAsync();
        });
    }
}
