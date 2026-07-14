using System.Collections.ObjectModel;
using System.Runtime.Versioning;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using HostsGuard.App.Services;
using HostsGuard.Contracts;

namespace HostsGuard.App.ViewModels;

/// <summary>Row VM for a blocklist source.</summary>
public sealed partial class BlocklistSourceViewModel : ObservableObject
{
    [ObservableProperty]
    private string _category = string.Empty;

    [ObservableProperty]
    private string _name = string.Empty;

    [ObservableProperty]
    private string _url = string.Empty;

    [ObservableProperty]
    private bool _subscribed;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ToggleLabel))]
    private bool _enabled;

    [ObservableProperty]
    private string _lastRefresh = string.Empty;

    [ObservableProperty]
    private long _domainCount;

    [ObservableProperty]
    private long _ownedDomainCount;

    [ObservableProperty]
    private long _hits30d;

    [ObservableProperty]
    private bool _largeListWarning;

    [ObservableProperty]
    private string _mirror = string.Empty;

    [ObservableProperty]
    private string _healthStatus = "new";

    [ObservableProperty]
    private string _lastError = string.Empty;

    [ObservableProperty]
    private string _lastErrorAt = string.Empty;

    [ObservableProperty]
    private long _previousDomainCount;

    [ObservableProperty]
    private long _rollbackCheckpointId;

    [ObservableProperty]
    private long _lastAttemptDomainCount;

    [ObservableProperty]
    private string _homepage = string.Empty;

    [ObservableProperty]
    private string _license = string.Empty;

    [ObservableProperty]
    private string _tags = string.Empty;

    [ObservableProperty]
    private string _description = string.Empty;

    /// <summary>Gallery tooltip: description + provenance in one hover (NET-174).</summary>
    public string GalleryTip
    {
        get
        {
            var parts = new List<string>();
            if (Description.Length != 0)
            {
                parts.Add(Description);
            }

            if (License.Length != 0)
            {
                parts.Add(I18n.T("Blocklists_License", "License: {0}", License));
            }

            if (Homepage.Length != 0)
            {
                parts.Add(Homepage);
            }

            return parts.Count == 0 ? Url : string.Join('\n', parts);
        }
    }

    public string Flags =>
        (!Enabled && Subscribed ? I18n.T("Common_Disabled", "Disabled") + " " : string.Empty)
        + (HealthStatus is "guarded" or "error" ? HealthStatusText(HealthStatus) + " " : string.Empty)
        + (RollbackCheckpointId > 0 ? I18n.T("Blocklists_Checkpoint", "Checkpoint") + " " : string.Empty)
        + (LargeListWarning ? I18n.T("Blocklists_Large", "Large") + " " : string.Empty)
        + (Mirror.Length != 0 ? I18n.T("Blocklists_Mirror", "Mirror") : string.Empty);

    public string ToggleLabel => Enabled
        ? I18n.T("Common_Disable", "Disable")
        : I18n.T("Common_Enable", "Enable");

    public bool CanRollback => Subscribed && RollbackCheckpointId > 0;

    public string HealthSummary
    {
        get
        {
            var status = HealthStatusText(string.IsNullOrWhiteSpace(HealthStatus) ? "new" : HealthStatus);
            var parts = new List<string> { status };
            if (PreviousDomainCount > 0)
            {
                parts.Add(I18n.T("Blocklists_PreviousCount", "previous {0:N0}", PreviousDomainCount));
            }

            if (LastAttemptDomainCount > 0 && LastAttemptDomainCount != DomainCount)
            {
                parts.Add(I18n.T("Blocklists_AttemptCount", "attempt {0:N0}", LastAttemptDomainCount));
            }

            if (LastError.Length != 0)
            {
                parts.Add(LastErrorAt.Length != 0
                    ? I18n.T("Blocklists_ErrorAt", "{0} at {1}", LastError, TimeText.Compact(LastErrorAt))
                    : LastError);
            }

            return string.Join(" - ", parts);
        }
    }

    private static string HealthStatusText(string status) => status.ToLowerInvariant() switch
    {
        "new" => I18n.T("Blocklists_HealthNew", "New"),
        "healthy" or "ok" => I18n.T("Blocklists_HealthHealthy", "Healthy"),
        "guarded" => I18n.T("Blocklists_HealthGuarded", "Guarded"),
        "error" => I18n.T("Blocklists_HealthError", "Error"),
        "disabled" => I18n.T("Common_Disabled", "Disabled"),
        _ => status,
    };

    public static BlocklistSourceViewModel From(BlocklistSource s) => new()
    {
        Category = s.Category,
        Name = s.Name,
        Url = s.Url,
        Subscribed = s.Subscribed,
        Enabled = s.Enabled,
        LastRefresh = s.LastRefresh,
        DomainCount = s.DomainCount,
        OwnedDomainCount = s.OwnedDomainCount,
        Hits30d = s.Hits30D,
        LargeListWarning = s.LargeListWarning,
        Mirror = s.Mirror,
        HealthStatus = s.HealthStatus,
        LastError = s.LastError,
        LastErrorAt = s.LastErrorAt,
        PreviousDomainCount = s.PreviousDomainCount,
        RollbackCheckpointId = s.RollbackCheckpointId,
        LastAttemptDomainCount = s.LastAttemptDomainCount,
        Homepage = s.Homepage,
        License = s.License,
        Tags = s.Tags,
        Description = s.Description,
    };
}

/// <summary>
/// Blocklists view: the curated catalog with per-source import/unsubscribe,
/// refresh-all, and the allowlist-subscription editor. Importing a known large
/// list confirms first (DNS Client CPU guidance, parity with Python).
/// </summary>
[SupportedOSPlatform("windows")]
public sealed partial class BlocklistsViewModel : ObservableObject
{
    private readonly HostsServiceClient _client;
    private readonly IConfirm _confirm;

    [ObservableProperty]
    private string _statusText = I18n.T("Status.Ready", "Ready");

    [ObservableProperty]
    private string _allowlistUrlsText = string.Empty;

    public BlocklistsViewModel(HostsServiceClient client, IConfirm confirm)
    {
        _client = client ?? throw new ArgumentNullException(nameof(client));
        _confirm = confirm ?? throw new ArgumentNullException(nameof(confirm));
    }

    public ObservableCollection<BlocklistSourceViewModel> Sources { get; } = new();

    [RelayCommand]
    public Task RefreshAsync()
        => RunServiceActionAsync(I18n.T("Blocklists_ActionRefresh", "Refresh blocklists"), RefreshCoreAsync);

    [RelayCommand]
    public void OpenHomepage(BlocklistSourceViewModel? source)
    {
        var url = source?.Homepage ?? string.Empty;
        if (!url.StartsWith("https://", StringComparison.Ordinal))
        {
            return;
        }

        System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(url) { UseShellExecute = true });
    }

    [RelayCommand]
    public async Task ImportAsync(BlocklistSourceViewModel? source)
    {
        if (source is null)
        {
            StatusText = I18n.T("Blocklists_SelectSource", "Select a blocklist source first");
            return;
        }

        if (source.LargeListWarning && !_confirm.Confirm(I18n.T("Blocklists_LargeTitle", "Import large blocklist"),
            I18n.T("Blocklists_LargeMessage", "{0} can make the hosts file very large and increase Windows DNS Client CPU. Import it now?", source.Name)))
        {
            return;
        }

        await RunServiceActionAsync(I18n.T("Blocklists_ActionImport", "Import {0}", source.Name), async () =>
        {
            StatusText = I18n.T("Blocklists_Importing", "Importing {0}...", source.Name);
            var result = await _client.Lists.ImportBlocklistAsync(new BlocklistRequest { Name = source.Name, Url = source.Url });
            CaptureConnectivityWarnings(result);
            StatusText = FormatResult(result);
            await RefreshCoreAsync();
        });
    }

    [RelayCommand]
    public async Task PreviewAsync(BlocklistSourceViewModel? source)
    {
        if (source is null)
        {
            StatusText = I18n.T("Blocklists_SelectSource", "Select a blocklist source first");
            return;
        }

        await RunServiceActionAsync(I18n.T("Blocklists_ActionPreview", "Preview {0}", source.Name), async () =>
        {
            StatusText = I18n.T("Blocklists_Previewing", "Previewing {0}...", source.Name);
            var result = await _client.Lists.PreviewBlocklistAsync(new BlocklistRequest { Name = source.Name, Url = source.Url });
            CaptureConnectivityWarnings(result);
            StatusText = FormatResult(result);
        });
    }

    /// <summary>Compose the NET-077 health report into a one-line status.</summary>
    public static string FormatResult(BlocklistResult r)
    {
        if (!r.Ok)
        {
            return r.Message;
        }

        var report = new List<string>();
        if (r.Duplicates > 0) report.Add(I18n.T("Blocklists_ResultDup", "{0} dup", r.Duplicates));
        if (r.Invalid > 0) report.Add(I18n.T("Blocklists_ResultInvalid", "{0} invalid", r.Invalid));
        if (r.ModifiersStripped > 0) report.Add(I18n.T("Blocklists_ResultModifiers", "{0} modifier-stripped", r.ModifiersStripped));
        if (r.HijackFlagged > 0) report.Add(I18n.T("Blocklists_ResultHijack", "{0} hijack-flagged", r.HijackFlagged));
        if (r.AllowlistOverrides > 0) report.Add(I18n.T("Blocklists_ResultAllowed", "{0} allowlist-kept", r.AllowlistOverrides));
        if (r.Removed > 0) report.Add(I18n.T("Blocklists_ResultRemoved", "{0} removed", r.Removed));
        if (r.Preserved > 0) report.Add(I18n.T("Blocklists_ResultPreserved", "{0} preserved", r.Preserved));
        if (r.Guarded > 0) report.Add(I18n.T("Blocklists_ResultGuarded", "{0} guarded", r.Guarded));
        if (r.Failed > 0) report.Add(I18n.T("Blocklists_ResultFailed", "{0} failed", r.Failed));
        if (r.CheckpointId > 0) report.Add(I18n.T("Blocklists_ResultCheckpoint", "checkpoint {0}", r.CheckpointId));
        var health = report.Count != 0 ? $" [{string.Join(", ", report)}]" : string.Empty;
        var prefix = r.Preview ? I18n.T("Blocklists_PreviewPrefix", "Preview: ") : string.Empty;
        var warn = r.Warning.Length != 0 ? $" - {r.Warning}" : string.Empty;
        return $"{prefix}{r.Message}{health}{warn}";
    }

    [RelayCommand]
    public async Task UnsubscribeAsync(BlocklistSourceViewModel? source)
    {
        if (source is null)
        {
            StatusText = I18n.T("Blocklists_SelectSource", "Select a blocklist source first");
            return;
        }

        if (!new MutationConfirmation(
                I18n.T("Blocklists_RemoveConfirmTitle", "Remove blocklist subscription"),
                I18n.T("Blocklists_SourceTarget", "{0} ({1})", source.Name, source.Url),
                I18n.T("Blocklists_RemoveConsequence",
                    "Unsubscribe this source and remove its {0:N0} source-owned domains. Shared, manual, and allowlisted domains are preserved.",
                    source.OwnedDomainCount)).Request(_confirm))
        {
            return;
        }

        await RunServiceActionAsync(I18n.T("Blocklists_ActionRemove", "Remove {0}", source.Name), async () =>
        {
            var ack = await _client.Lists.RemoveBlocklistSubscriptionAsync(new BlocklistRequest { Name = source.Name });
            StatusText = ack.Message;
            await RefreshCoreAsync();
        });
    }

    [RelayCommand]
    public async Task RollbackAsync(BlocklistSourceViewModel? source)
    {
        if (source is null)
        {
            StatusText = I18n.T("Blocklists_SelectSource", "Select a blocklist source first");
            return;
        }

        if (!source.CanRollback)
        {
            StatusText = I18n.T("Blocklists_NoCheckpoint", "{0} has no refresh checkpoint to restore", source.Name);
            return;
        }

        if (!new MutationConfirmation(
                I18n.T("Blocklists_RollbackConfirmTitle", "Restore blocklist checkpoint"),
                I18n.T("Blocklists_CheckpointTarget", "{0}, checkpoint {1}", source.Name, source.RollbackCheckpointId),
                I18n.T("Blocklists_RollbackConsequence",
                    "Replace the current source-owned domain set with the previous verified refresh. Manual and allowlisted decisions remain unchanged."))
            .Request(_confirm))
        {
            return;
        }

        await RunServiceActionAsync(I18n.T("Blocklists_ActionRestore", "Restore {0} checkpoint", source.Name), async () =>
        {
            var ack = await _client.Lists.RestoreBlocklistCheckpointAsync(new BlocklistRequest { Name = source.Name });
            StatusText = ack.Message;
            await RefreshCoreAsync();
        });
    }


    [RelayCommand]
    public async Task ToggleEnabledAsync(BlocklistSourceViewModel? source)
    {
        if (source is null)
        {
            StatusText = I18n.T("Blocklists_SelectSource", "Select a blocklist source first");
            return;
        }

        await RunServiceActionAsync(I18n.T("Blocklists_ActionToggle", "{0} {1}", source.ToggleLabel, source.Name), async () =>
        {
            var enable = !source.Enabled;
            var ack = await _client.Lists.SetBlocklistEnabledAsync(new BlocklistToggleRequest
            {
                Name = source.Name,
                Enabled = enable,
            });
            StatusText = ack.Message;
            await RefreshCoreAsync();
        });
    }

    [RelayCommand]
    public async Task RefreshAllListsAsync()
    {
        await RunServiceActionAsync(I18n.T("Blocklists_ActionRefreshSubscriptions", "Refresh subscriptions"), async () =>
        {
            StatusText = I18n.T("Blocklists_RefreshingSubscriptions", "Refreshing all subscriptions...");
            var result = await _client.Lists.RefreshBlocklistsAsync(new Empty());
            StatusText = FormatResult(result);
            await RefreshCoreAsync();
        });
    }

    [RelayCommand]
    public async Task SaveAllowlistsAsync()
    {
        await RunServiceActionAsync(I18n.T("Blocklists_ActionSaveAllowlists", "Save allowlists"), async () =>
        {
            var urls = new AllowlistUrls();
            urls.Urls.AddRange(AllowlistUrlsText
                .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Where(u => u.Length != 0));
            var ack = await _client.Lists.SetAllowlistsAsync(urls);
            StatusText = ack.Message;
            if (ack.Ok)
            {
                var refresh = await _client.Lists.RefreshAllowlistsAsync(new Empty());
                StatusText = refresh.Message;
            }
        });
    }

    private async Task RefreshCoreAsync()
    {
        var list = await _client.Lists.ListBlocklistSourcesAsync(new Empty());
        Sources.Clear();
        foreach (var s in list.Sources)
        {
            Sources.Add(BlocklistSourceViewModel.From(s));
        }

        var allow = await _client.Lists.GetAllowlistsAsync(new Empty());
        AllowlistUrlsText = string.Join(Environment.NewLine, allow.Urls);
        StatusText = I18n.T("Blocklists_SourceSummary", "{0} source(s), {1} subscribed, {2:N0} hits/30d",
            Sources.Count, Sources.Count(s => s.Subscribed), Sources.Sum(s => s.Hits30d));
    }

    private Task RunServiceActionAsync(string action, Func<Task> work) =>
        ServiceActionGuard.RunAsync(action, s => StatusText = s, work);
}
