using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Windows.Data;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Grpc.Core;
using HostsGuard.App.Services;
using HostsGuard.Contracts;

namespace HostsGuard.App.ViewModels;

public sealed partial class FwActivityViewModel
{
    private static readonly Dictionary<string, string> ListenerFilterAliases = new(StringComparer.Ordinal)
    {
        ["proto"] = "protocol",
        ["addr"] = "address",
        ["app"] = "process",
        ["profile"] = "profiles",
        ["scope"] = "bind",
        ["status"] = "coverage",
    };

    private ICollectionView? _listenerView;

    public ObservableCollection<ListenerExposureRowViewModel> Listeners { get; } = new();

    [ObservableProperty]
    private string _listenerFilter = string.Empty;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(LoadListenersCommand))]
    private bool _listenersLoading;

    [ObservableProperty]
    private bool _listenerLoadFailed;

    [ObservableProperty]
    private string _listenerStatus = "Not scanned yet";

    public ICollectionView ListenerView
    {
        get
        {
            if (_listenerView is null)
            {
                _listenerView = CollectionViewSource.GetDefaultView(Listeners);
                _listenerView.Filter = value =>
                    value is ListenerExposureRowViewModel row && MatchesListenerFilter(row);
                _listenerView.SortDescriptions.Add(new(
                    nameof(ListenerExposureRowViewModel.RiskRank),
                    System.ComponentModel.ListSortDirection.Descending));
                _listenerView.SortDescriptions.Add(new(
                    nameof(ListenerExposureRowViewModel.LocalPort),
                    System.ComponentModel.ListSortDirection.Ascending));
            }

            return _listenerView;
        }
    }

    public bool MatchesListenerFilter(ListenerExposureRowViewModel row)
    {
        ArgumentNullException.ThrowIfNull(row);
        if (string.IsNullOrWhiteSpace(ListenerFilter))
        {
            return true;
        }

        return Core.SearchQuery.Matches(new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["protocol"] = row.Protocol,
            ["address"] = row.LocalAddress,
            ["port"] = row.LocalPort.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["process"] = row.Process,
            ["pid"] = row.Pid.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["service"] = row.Service,
            ["package"] = row.Package,
            ["bind"] = row.BindScope,
            ["profiles"] = row.ActiveProfiles,
            ["coverage"] = row.Coverage,
            ["risk"] = row.Risk,
            ["reason"] = row.Reason,
        }, ListenerFilter, ListenerFilterAliases);
    }

    partial void OnListenerFilterChanged(string value) => _listenerView?.Refresh();

    private bool CanLoadListeners() => !ListenersLoading;

    [RelayCommand(CanExecute = nameof(CanLoadListeners))]
    public async Task LoadListenersAsync()
    {
        ListenersLoading = true;
        ListenerLoadFailed = false;
        ListenerStatus = "Scanning local listeners and effective firewall coverageâ€¦";
        try
        {
            var response = await _client.Monitoring.ListListenersAsync(new Empty());
            var rows = response.Listeners.Select(item => new ListenerExposureRowViewModel
            {
                Protocol = item.Protocol,
                LocalAddress = item.LocalAddress,
                LocalPort = item.LocalPort,
                Process = item.Process,
                Pid = item.Pid,
                Service = item.Service,
                Package = item.Package,
                BindScope = item.BindScope,
                ActiveProfiles = item.ActiveProfiles,
                Coverage = item.Coverage,
                Risk = item.Risk,
                Reason = item.Reason,
            }).ToList();

            Listeners.Clear();
            foreach (var row in rows)
            {
                Listeners.Add(row);
            }

            ListenerStatus = rows.Count == 0
                ? "No active TCP or UDP listeners found"
                : $"{rows.Count} local listener{(rows.Count == 1 ? string.Empty : "s")} analyzed";
        }
        catch (Exception ex) when (ex is RpcException or IOException)
        {
            ListenerLoadFailed = true;
            ListenerStatus = ServiceErrors.DescribeActionFailure("Scan listener exposure", ex);
        }
        finally
        {
            ListenersLoading = false;
        }
    }
}
