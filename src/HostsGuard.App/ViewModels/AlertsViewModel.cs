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
    private string _statusText = "Alerts not loaded";

    [ObservableProperty]
    private AlertRowViewModel? _selectedAlert;

    public AlertsViewModel(HostsServiceClient client)
    {
        _client = client ?? throw new ArgumentNullException(nameof(client));
    }

    public ObservableCollection<AlertRowViewModel> Alerts { get; } = new();

    public ObservableCollection<AlertTypeRowViewModel> AlertTypes { get; } = new();

    public string UnreadTitle => UnreadCount == 0 ? "Clear" : $"{UnreadCount} unread";

    public string UnreadText => UnreadCount == 0 ? "No surfaced alerts" : $"{UnreadCount} surfaced alert{(UnreadCount == 1 ? string.Empty : "s")}";

    public async Task LoadAsync()
    {
        await RunServiceActionAsync("Load alerts", async () =>
        {
            var list = await _client.Monitoring.ListAlertsAsync(new AlertRequest
            {
                Limit = 500,
                IncludeRead = IncludeRead,
                IncludeLogOnly = !SurfaceOnly,
                Type = TypeFilter,
            });

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
            StatusText = $"Loaded {list.Entries.Count} of {list.Total} alerts";
            await LoadTypesAsync();
        });
    }

    [RelayCommand]
    public Task RefreshAsync() => LoadAsync();

    [RelayCommand]
    public async Task AckAsync(AlertRowViewModel? row)
    {
        if (row is null)
        {
            StatusText = "Select an alert first";
            return;
        }

        await RunServiceActionAsync("Acknowledge alert", async () =>
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
        await RunServiceActionAsync("Acknowledge alerts", async () =>
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

    private async Task LoadTypesAsync()
    {
        var types = await _client.Monitoring.ListAlertTypesAsync(new Empty());
        AlertTypes.Clear();
        foreach (var row in types.Types_)
        {
            AlertTypes.Add(new AlertTypeRowViewModel(row.Type, row.Label, row.Surface, row.Unread, SetTypeSurfaceAsync));
        }
    }

    private async Task SetTypeSurfaceAsync(AlertTypeRowViewModel row, bool surface)
    {
        await RunServiceActionAsync("Set alert surface", async () =>
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
