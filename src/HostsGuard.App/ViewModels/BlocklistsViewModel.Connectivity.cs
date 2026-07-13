using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using HostsGuard.App.Services;
using HostsGuard.Contracts;

namespace HostsGuard.App.ViewModels;

public sealed partial class WindowsConnectivityWarningViewModel : ObservableObject
{
    [ObservableProperty]
    private string _domain = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(DisplayReason))]
    [NotifyPropertyChangedFor(nameof(DisplayMetadata))]
    private string _probeKind = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(DisplayMetadata))]
    private string _era = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(DisplayReason))]
    private string _reason = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(StateText))]
    private bool _recovered;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(StateText))]
    private bool _preview;

    public string StateText => Recovered
        ? I18n.T("Ncsi_Recovered", "allowed / list block reverted")
        : Preview
            ? I18n.T("Ncsi_WouldBlock", "would be blocked by this list")
            : I18n.T("Ncsi_Blocked", "blocked by this list");

    public string DisplayReason => ProbeKind.ToLowerInvariant() switch
    {
        "web" => I18n.T("Ncsi_WebReason", "Windows active web connectivity probe"),
        "dns" => I18n.T("Ncsi_DnsReason", "Windows DNS connectivity probe"),
        _ => Reason,
    };

    public string DisplayMetadata
    {
        get
        {
            var kind = ProbeKind.ToLowerInvariant() switch
            {
                "web" => I18n.T("Ncsi_WebKind", "web probe"),
                "dns" => I18n.T("Ncsi_DnsKind", "DNS probe"),
                _ => ProbeKind,
            };
            var era = Era.ToLowerInvariant() switch
            {
                "current" => I18n.T("Ncsi_CurrentEra", "current Windows"),
                "legacy" => I18n.T("Ncsi_LegacyEra", "legacy Windows"),
                _ => Era,
            };
            return I18n.T("Ncsi_Metadata", "{0} | {1}", kind, era);
        }
    }

    public static WindowsConnectivityWarningViewModel From(WindowsConnectivityWarning warning)
    {
        ArgumentNullException.ThrowIfNull(warning);
        return new()
        {
            Domain = warning.Domain,
            ProbeKind = warning.ProbeKind,
            Era = warning.Era,
            Reason = warning.Reason,
        };
    }
}

public sealed partial class BlocklistsViewModel
{
    public ObservableCollection<WindowsConnectivityWarningViewModel> ConnectivityWarnings { get; } = new();

    [ObservableProperty]
    private bool _hasConnectivityWarnings;

    [ObservableProperty]
    private string _connectivityWarningStatus = string.Empty;

    private bool _connectivityWarningsFromPreview;

    public void CaptureConnectivityWarnings(BlocklistResult result)
    {
        ArgumentNullException.ThrowIfNull(result);
        ConnectivityWarnings.Clear();
        foreach (var warning in result.ConnectivityWarnings
            .GroupBy(item => item.Domain, StringComparer.OrdinalIgnoreCase)
            .Select(group => group.First())
            .OrderBy(item => item.Domain, StringComparer.OrdinalIgnoreCase))
        {
            var row = WindowsConnectivityWarningViewModel.From(warning);
            row.Preview = result.Preview;
            ConnectivityWarnings.Add(row);
        }

        _connectivityWarningsFromPreview = result.Preview;
        HasConnectivityWarnings = ConnectivityWarnings.Count != 0;
        ConnectivityWarningStatus = HasConnectivityWarnings
            ? result.Preview
                ? I18n.T("Ncsi_PreviewStatus",
                    "Preview found {0} exact Windows connectivity-check domain(s). Import remains available; recovery becomes available after import.",
                    ConnectivityWarnings.Count)
                : I18n.T("Ncsi_WarningStatus",
                    "This list contains {0} exact Windows connectivity-check domain(s). Import remains available.",
                    ConnectivityWarnings.Count)
            : string.Empty;
        RecoverWindowsConnectivityCommand.NotifyCanExecuteChanged();
    }

    private bool CanRecoverWindowsConnectivity() =>
        HasConnectivityWarnings && !_connectivityWarningsFromPreview &&
        ConnectivityWarnings.Any(row => !row.Recovered);

    [RelayCommand(CanExecute = nameof(CanRecoverWindowsConnectivity))]
    public async Task RecoverWindowsConnectivityAsync()
    {
        var domains = ConnectivityWarnings.Where(row => !row.Recovered)
            .Select(row => row.Domain)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        if (domains.Length == 0)
        {
            return;
        }

        await ServiceActionGuard.RunAsync("Recover Windows connectivity checks",
            status => ConnectivityWarningStatus = status,
            async () =>
            {
                var request = new WindowsConnectivityRecoveryRequest();
                request.Domains.AddRange(domains);
                var result = await _client.Lists.RecoverWindowsConnectivityAsync(request);
                var recovered = result.RecoveredDomains.ToHashSet(StringComparer.OrdinalIgnoreCase);
                foreach (var row in ConnectivityWarnings)
                {
                    row.Recovered = recovered.Contains(row.Domain);
                }

                ConnectivityWarningStatus = result.Message;
                RecoverWindowsConnectivityCommand.NotifyCanExecuteChanged();
                await RefreshCoreAsync();
            });
    }
}
