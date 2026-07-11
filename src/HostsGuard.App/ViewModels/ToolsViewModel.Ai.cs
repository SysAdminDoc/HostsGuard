using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using HostsGuard.App.Services;
using HostsGuard.Contracts;

namespace HostsGuard.App.ViewModels;

public sealed partial class ToolsViewModel
{
    // ─── AI categorization (DeepSeek) ─────────────────────────────────────────

    /// <summary>Pushed from the API-key PasswordBox before commands run (no binding).</summary>
    public string AiApiKey { get; set; } = string.Empty;

    [ObservableProperty]
    private string _aiModel = "deepseek-chat";

    [ObservableProperty]
    private bool _aiEnabled;

    [ObservableProperty]
    private string _aiStatusText = "Checking AI configuration…";

    public async Task LoadAiStatusAsync()
    {
        await RunServiceActionAsync("Load AI status", s => AiStatusText = s, async () =>
        {
            var status = await _client.Hosts.GetAiStatusAsync(new Empty());
            AiEnabled = status.Enabled;
            if (status.Model.Length != 0)
            {
                AiModel = status.Model;
            }

            AiStatusText = !status.Configured
                ? "No DeepSeek API key stored — add one to categorize domains with AI."
                : $"DeepSeek key stored · {status.Model} · auto-categorize {(status.Enabled ? "on" : "off")}"
                  + (status.LastRun.Length != 0 ? $" · last run {TimeText.Compact(status.LastRun)} ({status.LastResult})" : string.Empty);
        });
    }

    [RelayCommand]
    public async Task SaveAiConfigAsync()
    {
        await RunServiceActionAsync("Save AI configuration", s => AiStatusText = s, async () =>
        {
            var ack = await _client.Hosts.SetAiConfigAsync(new AiConfig
            {
                ApiKey = AiApiKey,
                Model = AiModel.Trim(),
                Endpoint = string.Empty, // keep the default endpoint
                Enabled = AiEnabled,
            });
            AiApiKey = string.Empty;
            StatusText = ack.Message;
            await LoadAiStatusAsync();
        });
    }

    [RelayCommand]
    public async Task CategorizeAllAsync()
    {
        await RunServiceActionAsync("Categorize domains with AI", s => AiStatusText = s, async () =>
        {
            AiStatusText = "Asking DeepSeek to categorize uncategorized blocked domains...";
            var result = await _client.Hosts.CategorizeDomainsAsync(
                new CategorizeRequest { AllUncategorized = true });
            StatusText = result.Message;
            await LoadAiStatusAsync();
        });
    }

    /// <summary>
    /// Save everything the AI has learned (purposes, categories, connection
    /// info) to a user-readable JSON file — the review path for promoting
    /// entries into the app's curated built-ins.
    /// </summary>
    [RelayCommand]
    public async Task ExportAiKnowledgeAsync()
    {
        await RunServiceActionAsync("Export AI knowledge", s => AiStatusText = s, async () =>
        {
            var payload = await _client.Hosts.ExportAiKnowledgeAsync(new Empty());
            var dir = System.IO.Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "HostsGuard");
            var path = System.IO.Path.Combine(dir, "ai_knowledge.json");
            try
            {
                System.IO.Directory.CreateDirectory(dir);
                await System.IO.File.WriteAllTextAsync(path, payload.Text);
            }
            catch (Exception ex) when (ex is System.IO.IOException or UnauthorizedAccessException)
            {
                // A file error must not reach the global handler, which would
                // misreport it as a lost service connection.
                StatusText = $"Couldn't write the knowledge log: {ex.Message}";
                return;
            }

            StatusText = $"AI knowledge exported to {path}";
            AiStatusText = $"Knowledge log saved: {path}";
        });
    }

    // ─── AI-knowledge review & promote (NET-107) ─────────────────────────────

    public ObservableCollection<KnowledgeEntryViewModel> Knowledge { get; } = new();

    [ObservableProperty]
    private bool _knowledgeOnlyNew = true;

    [ObservableProperty]
    private string _knowledgeStatusText = "Load what the AI has learned to review it.";

    // Inline "correct a domain" mini-form (the remembered correction path).
    [ObservableProperty]
    private string _correctDomain = string.Empty;

    [ObservableProperty]
    private string _correctKind = "category"; // "category" | "purpose"

    [ObservableProperty]
    private string _correctValue = string.Empty;

    public static IReadOnlyList<string> CorrectionKinds { get; } = new[] { "category", "purpose" };

    [RelayCommand]
    public async Task LoadKnowledgeAsync()
    {
        await RunServiceActionAsync("Load AI knowledge", s => KnowledgeStatusText = s, async () =>
        {
            var list = await _client.Hosts.ListAiKnowledgeAsync(new AiKnowledgeRequest { SinceLastReview = KnowledgeOnlyNew });
            Knowledge.Clear();
            foreach (var e in list.Entries.OrderByDescending(e => e.Created))
            {
                Knowledge.Add(new KnowledgeEntryViewModel
                {
                    Kind = e.Kind,
                    Key = e.Key,
                    Value = e.Value,
                    EditValue = e.UserOverride.Length != 0 ? e.UserOverride : e.Value,
                    UserOverride = e.UserOverride,
                    Created = e.Created,
                    IsNew = e.IsNew,
                });
            }

            KnowledgeStatusText = Knowledge.Count == 0
                ? (KnowledgeOnlyNew ? "Nothing new learned since your last review." : "The AI hasn't learned anything yet.")
                : $"{Plural.Of(Knowledge.Count, "learned entry", "learned entries")}"
                  + (list.LastReviewed.Length != 0 ? $" · last review {TimeText.Compact(list.LastReviewed)}" : " · never reviewed");
        });
    }

    [RelayCommand]
    public async Task PromoteKnowledgeAsync(KnowledgeEntryViewModel row)
    {
        if (row is null)
        {
            return;
        }

        await RunServiceActionAsync("Promote AI knowledge", s => KnowledgeStatusText = s, async () =>
        {
            var request = new KnowledgeReviewRequest();
            request.Actions.Add(new KnowledgeReviewAction { Kind = row.Kind, Key = row.Key, Action = "promote", Value = row.EditValue });
            var ack = await _client.Hosts.PromoteKnowledgeAsync(request);
            StatusText = ack.Message;
            await LoadKnowledgeAsync();
        });
    }

    [RelayCommand]
    public async Task DiscardKnowledgeAsync(KnowledgeEntryViewModel row)
    {
        if (row is null)
        {
            return;
        }

        await RunServiceActionAsync("Discard AI knowledge", s => KnowledgeStatusText = s, async () =>
        {
            var request = new KnowledgeReviewRequest();
            request.Actions.Add(new KnowledgeReviewAction { Kind = row.Kind, Key = row.Key, Action = "discard" });
            var ack = await _client.Hosts.PromoteKnowledgeAsync(request);
            StatusText = ack.Message;
            await LoadKnowledgeAsync();
        });
    }

    [RelayCommand]
    public async Task MarkKnowledgeReviewedAsync()
    {
        await RunServiceActionAsync("Mark AI knowledge reviewed", s => KnowledgeStatusText = s, async () =>
        {
            var ack = await _client.Hosts.PromoteKnowledgeAsync(new KnowledgeReviewRequest { MarkReviewed = true });
            StatusText = ack.Message;
            await LoadKnowledgeAsync();
        });
    }

    [RelayCommand]
    public async Task CorrectDomainAsync()
    {
        var domain = CorrectDomain.Trim();
        if (domain.Length == 0)
        {
            StatusText = "Enter a domain to correct.";
            return;
        }

        await RunServiceActionAsync("Correct domain knowledge", s => KnowledgeStatusText = s, async () =>
        {
            var ack = await _client.Hosts.OverrideKnowledgeAsync(new KnowledgeOverrideRequest
            {
                Kind = CorrectKind,
                Key = domain,
                Value = CorrectValue.Trim(),
            });
            StatusText = ack.Message;
            CorrectValue = string.Empty;
            await LoadKnowledgeAsync();
        });
    }
}
