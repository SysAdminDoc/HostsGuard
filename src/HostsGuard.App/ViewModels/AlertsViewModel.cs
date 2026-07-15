using System.Collections.ObjectModel;
using System.Runtime.Versioning;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Grpc.Core;
using HostsGuard.App.Services;
using HostsGuard.Contracts;

namespace HostsGuard.App.ViewModels;

/// <summary>Stateful low-volume alert inbox (NET-153), separate from the event ledger.</summary>
[SupportedOSPlatform("windows")]
public sealed partial class AlertsViewModel : ObservableObject
{
    private readonly HostsServiceClient _client;

    [ObservableProperty]
    private bool _includeRead;

    [ObservableProperty]
    private bool _surfaceOnly = true;

    [ObservableProperty]
    private string _typeFilter = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(UnreadTitle))]
    [NotifyPropertyChangedFor(nameof(UnreadText))]
    private int _unreadCount;

    [ObservableProperty]
    private string _statusText = I18n.T("Alerts_NotLoaded", "Alerts not loaded");

    [ObservableProperty]
    private AlertRowViewModel? _selectedAlert;

    public AlertsViewModel(HostsServiceClient client)
    {
        _client = client ?? throw new ArgumentNullException(nameof(client));
    }

    public ObservableCollection<AlertRowViewModel> Alerts { get; } = new();

    public ObservableCollection<AlertTypeRowViewModel> AlertTypes { get; } = new();

    public ObservableCollection<AllowlistRecommendationViewModel> AllowlistRecommendations { get; } = new();

    public string UnreadTitle => UnreadCount == 0
        ? I18n.T("Alerts_Clear", "Clear")
        : I18n.T("Alerts_UnreadTitle", "{0} unread", UnreadCount);

    public string UnreadText => UnreadCount == 0
        ? I18n.T("Alerts_NoneSurfaced", "No surfaced alerts")
        : I18n.T("Alerts_SurfacedCount", "{0} surfaced alert(s)", UnreadCount);

    public async Task LoadAsync()
    {
        await RunServiceActionAsync(I18n.T("Alerts_ActionLoad", "Load alerts"), async () =>
        {
            var listCall = _client.Monitoring.ListAlertsAsync(new AlertRequest
            {
                Limit = 500,
                IncludeRead = IncludeRead,
                IncludeLogOnly = !SurfaceOnly,
                Type = TypeFilter,
            });
            var recommendationsCall = _client.Monitoring.ListAllowlistRecommendationsAsync(new Empty());
            var typesCall = _client.Monitoring.ListAlertTypesAsync(new Empty());
            await Task.WhenAll(
                listCall.ResponseAsync,
                recommendationsCall.ResponseAsync,
                typesCall.ResponseAsync);

            var list = await listCall.ResponseAsync;

            var selectedId = SelectedAlert?.Id;
            Alerts.Clear();
            foreach (var row in list.Entries)
            {
                Alerts.Add(AlertRowViewModel.From(row));
            }

            SelectedAlert = selectedId is { } id
                ? Alerts.FirstOrDefault(alert => alert.Id == id)
                : Alerts.FirstOrDefault();

            UnreadCount = list.Unread;
            StatusText = I18n.T("Alerts_Loaded", "Loaded {0} of {1} alerts", list.Entries.Count, list.Total);
            ApplyAllowlistRecommendations(await recommendationsCall.ResponseAsync);
            ApplyTypes(await typesCall.ResponseAsync);
        });
    }

    [RelayCommand]
    public Task RefreshAsync() => LoadAsync();

    [RelayCommand]
    public async Task AckAsync(AlertRowViewModel? row)
    {
        if (row is null)
        {
            StatusText = I18n.T("Alerts_SelectFirst", "Select an alert first");
            return;
        }

        await RunServiceActionAsync(I18n.T("Alerts_ActionAck", "Acknowledge alert"), async () =>
        {
            var request = new AlertAckRequest();
            request.Ids.Add(row.Id);
            var ack = await _client.Monitoring.AckAlertAsync(request);
            StatusText = ack.Message;
            await LoadAsync();
        });
    }

    [RelayCommand]
    public async Task AckAllAsync()
    {
        await RunServiceActionAsync(I18n.T("Alerts_ActionAckAll", "Acknowledge alerts"), async () =>
        {
            var ack = await _client.Monitoring.AckAlertAsync(new AlertAckRequest
            {
                All = true,
                Type = TypeFilter,
            });
            StatusText = ack.Message;
            await LoadAsync();
        });
    }

    [RelayCommand]
    public async Task AllowRecommendationAsync(AllowlistRecommendationViewModel? row)
    {
        if (row is null)
        {
            StatusText = I18n.T("AllowlistReview_Select", "Select a recommendation first");
            return;
        }

        await RunServiceActionAsync(I18n.T("AllowlistReview_ActionAllow", "Allow recommended domain"), async () =>
        {
            var ack = await _client.Hosts.AllowAsync(new DomainRequest
            {
                Domain = row.Domain,
                Source = "allowlist-review",
                Reason = "false-positive-review",
            });
            StatusText = ack.Ok
                ? I18n.T("AllowlistReview_Allowed", "Allowed {0}; the recommendation was removed", row.Domain)
                : ack.Message;
            if (ack.Ok)
            {
                await LoadAllowlistRecommendationsAsync();
            }
        });
    }

    private async Task LoadAllowlistRecommendationsAsync()
    {
        var response = await _client.Monitoring.ListAllowlistRecommendationsAsync(new Empty());
        ApplyAllowlistRecommendations(response);
    }

    private void ApplyAllowlistRecommendations(AllowlistRecommendationList response)
    {
        AllowlistRecommendations.Clear();
        foreach (var entry in response.Entries)
        {
            AllowlistRecommendations.Add(AllowlistRecommendationViewModel.From(entry));
        }
    }

    private void ApplyTypes(AlertTypeList types)
    {
        AlertTypes.Clear();
        foreach (var row in types.Types_)
        {
            AlertTypes.Add(new AlertTypeRowViewModel(row.Type, row.Label, row.Surface, row.Unread, SetTypeSurfaceAsync));
        }
    }

    private async Task SetTypeSurfaceAsync(AlertTypeRowViewModel row, bool surface)
    {
        await RunServiceActionAsync(I18n.T("Alerts_ActionSurface", "Set alert surface"), async () =>
        {
            var ack = await _client.Monitoring.SetAlertTypeAsync(new AlertTypeRequest
            {
                Type = row.Type,
                Surface = surface,
            });
            StatusText = ack.Message;
            await LoadAsync();
        });
    }

    partial void OnIncludeReadChanged(bool value) => _ = LoadAsync();

    partial void OnSurfaceOnlyChanged(bool value) => _ = LoadAsync();

    partial void OnTypeFilterChanged(string value) => _ = LoadAsync();

    private Task RunServiceActionAsync(string action, Func<Task> work) =>
        ServiceActionGuard.RunAsync(action, s => StatusText = s, work);
}

public sealed record AllowlistRecommendationViewModel(
    string Domain,
    long Hits,
    int Score,
    string Process,
    string ParentApp,
    string CdnEvidence,
    string TrustEvidence)
{
    public static AllowlistRecommendationViewModel From(AllowlistRecommendationEntry entry) => new(
        entry.Domain,
        entry.Hits,
        entry.Score,
        entry.Process,
        entry.ParentApp,
        entry.CdnEvidence,
        entry.TrustEvidence);
}

public sealed partial class AlertRowViewModel : ObservableObject
{
    [ObservableProperty]
    private long _id;

    [ObservableProperty]
    private string _created = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(UpdatedText))]
    private string _updated = string.Empty;

    public string UpdatedText => TimeText.Compact(Updated);

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsIdnHomograph))]
    private string _type = string.Empty;

    public bool IsIdnHomograph => Type.Equals("idn_homograph", StringComparison.OrdinalIgnoreCase);

    public bool IsDgaAlert => Type.Equals("suspicious_domain", StringComparison.OrdinalIgnoreCase);

    public DgaEvidence? DgaEvidence { get; private init; }

    public bool HasDgaEvidence => IsDgaAlert && DgaEvidence is not null;

    public string DgaRegistrableLabel => DgaEvidence is { } evidence
        ? I18n.T("Dga_LabelValue", "{0} ({1} characters; {2})",
            evidence.RegistrableLabel, evidence.LabelLength, evidence.Version)
        : string.Empty;

    public string DgaScoreText => DgaEvidence is { } evidence
        ? I18n.T("Dga_ScoreValue", "{0:F2} (decision threshold {1:F2})", evidence.Score, evidence.DecisionThreshold)
        : string.Empty;

    public string DgaEntropyText => DgaEvidence is { } evidence
        ? I18n.T("Dga_MetricValue", "{0:F2} (threshold {1:F2})", evidence.Entropy, evidence.EntropyThreshold)
        : string.Empty;

    public string DgaVowelRatioText => DgaEvidence is { } evidence
        ? I18n.T("Dga_PercentValue", "{0:P0} (threshold {1:P0})", evidence.VowelRatio, evidence.VowelRatioThreshold)
        : string.Empty;

    public string DgaDigitRatioText => DgaEvidence is { } evidence
        ? I18n.T("Dga_PercentValue", "{0:P0} (threshold {1:P0})", evidence.DigitRatio, evidence.DigitRatioThreshold)
        : string.Empty;

    public string DgaConsonantRunText => DgaEvidence is { } evidence
        ? I18n.T("Dga_RunValue", "{0} (threshold {1})", evidence.MaxConsonantRun, evidence.ConsonantRunThreshold)
        : string.Empty;

    public string DgaReason => DgaEvidence is { } evidence
        ? I18n.T("Dga_ReasonValue", "{0}; algorithmic={1}", evidence.Reason, evidence.IsAlgorithmic)
        : string.Empty;

    [ObservableProperty]
    private string _severity = string.Empty;

    [ObservableProperty]
    private string _title = string.Empty;

    [ObservableProperty]
    private string _subject = string.Empty;

    [ObservableProperty]
    private string _details = string.Empty;

    [ObservableProperty]
    private string _action = string.Empty;

    [ObservableProperty]
    private string _process = string.Empty;

    [ObservableProperty]
    private bool _isRead;

    [ObservableProperty]
    private bool _surfaced;

    public static AlertRowViewModel From(AlertEntry row)
    {
        ArgumentNullException.ThrowIfNull(row);
        return new()
        {
            Id = row.Id,
            Created = row.Created,
            Updated = row.Updated,
            Type = row.Type,
            Severity = row.Severity,
            Title = row.Title,
            Subject = row.Subject,
            Details = row.Details,
            Action = row.Action,
            Process = row.Process,
            IsRead = row.IsRead,
            Surfaced = row.Surfaced,
            DgaEvidence = row.DgaEvidence,
        };
    }
}

public sealed partial class AlertTypeRowViewModel : ObservableObject
{
    private readonly Func<AlertTypeRowViewModel, bool, Task> _setSurface;
    private bool _suppress;

    public AlertTypeRowViewModel(string type, string label, bool surface, int unread, Func<AlertTypeRowViewModel, bool, Task> setSurface)
    {
        Type = type;
        Label = label;
        _surface = surface;
        Unread = unread;
        _setSurface = setSurface ?? throw new ArgumentNullException(nameof(setSurface));
    }

    [ObservableProperty]
    private string _type = string.Empty;

    [ObservableProperty]
    private string _label = string.Empty;

    [ObservableProperty]
    private bool _surface;

    [ObservableProperty]
    private int _unread;

    partial void OnSurfaceChanged(bool value)
    {
        if (_suppress)
        {
            return;
        }

        _ = ApplySurfaceAsync(value);
    }

    private async Task ApplySurfaceAsync(bool value)
    {
        try
        {
            await _setSurface(this, value);
        }
        catch (Exception ex) when (ex is RpcException || ServiceErrors.IsConnectivity(ex))
        {
            _suppress = true;
            Surface = !value;
            _suppress = false;
        }
    }
}
