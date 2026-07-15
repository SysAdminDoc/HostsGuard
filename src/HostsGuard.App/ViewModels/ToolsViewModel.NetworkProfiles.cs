using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using HostsGuard.App.Services;
using HostsGuard.Contracts;

namespace HostsGuard.App.ViewModels;

public sealed partial class ToolsViewModel
{
    private CurrentNetwork? _currentNetwork;
    private string _networkRuleFingerprint = string.Empty;

    public ObservableCollection<NetworkProfileRuleViewModel> NetworkProfileRules { get; } = new();

    public IReadOnlyList<string> NetworkVpnOptions { get; } = new[]
    {
        I18n.T("ProfileMatch_VpnAny", "Any VPN state"),
        I18n.T("ProfileMatch_VpnPresent", "VPN present"),
        I18n.T("ProfileMatch_VpnAbsent", "VPN absent"),
    };

    [ObservableProperty]
    private string _currentNetworkText = I18n.T(
        "ProfileMatch_CurrentOffline", "Current network is offline or unavailable");

    [ObservableProperty]
    private bool _hasCurrentNetworkGatewayDrift;

    [ObservableProperty]
    private string _currentNetworkGatewayDriftText = string.Empty;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(DeleteNetworkProfileRuleCommand))]
    private NetworkProfileRuleViewModel? _selectedNetworkProfileRule;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(SaveNetworkProfileRuleCommand))]
    private string _networkRuleLabel = string.Empty;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(SaveNetworkProfileRuleCommand))]
    private string _networkRuleGatewayMac = string.Empty;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(SaveNetworkProfileRuleCommand))]
    private string _networkRuleSsid = string.Empty;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(SaveNetworkProfileRuleCommand))]
    private string _networkRuleInterface = string.Empty;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(SaveNetworkProfileRuleCommand))]
    private string _networkRuleDnsSuffix = string.Empty;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(SaveNetworkProfileRuleCommand))]
    private string _selectedNetworkVpnOption = I18n.T("ProfileMatch_VpnAny", "Any VPN state");

    partial void OnSelectedNetworkProfileRuleChanged(NetworkProfileRuleViewModel? value)
    {
        if (value is null)
        {
            return;
        }

        _networkRuleFingerprint = value.Fingerprint;
        NetworkRuleLabel = value.Label;
        SelectedProfile = value.Profile;
        NetworkRuleGatewayMac = value.GatewayMac;
        NetworkRuleSsid = value.Ssid;
        NetworkRuleInterface = value.InterfaceName;
        NetworkRuleDnsSuffix = value.DnsSuffix;
        SelectedNetworkVpnOption = value.VpnPresent switch
        {
            true => NetworkVpnOptions[1],
            false => NetworkVpnOptions[2],
            null => NetworkVpnOptions[0],
        };
    }

    [RelayCommand]
    public async Task LoadNetworkProfileRulesAsync()
    {
        await RunServiceActionAsync(
            I18n.T("ProfileMatch_ActionLoad", "Load automatic profile rules"),
            async () =>
            {
                _currentNetwork = await _client.Policy.GetCurrentNetworkAsync(new Empty());
                CurrentNetworkText = DescribeCurrentNetwork(_currentNetwork);
                HasCurrentNetworkGatewayDrift = _currentNetwork.GatewayDriftStatus == "changed";
                CurrentNetworkGatewayDriftText = HasCurrentNetworkGatewayDrift
                    ? DescribeGatewayDrift(_currentNetwork)
                    : string.Empty;

                var map = await _client.Policy.GetNetworkProfilesAsync(new Empty());
                NetworkProfileRules.Clear();
                foreach (var entry in map.Entries
                             .OrderBy(e => e.Profile, StringComparer.OrdinalIgnoreCase)
                             .ThenBy(e => e.Label, StringComparer.OrdinalIgnoreCase))
                {
                    NetworkProfileRules.Add(NetworkProfileRuleViewModel.From(entry));
                }

                SelectedNetworkProfileRule = NetworkProfileRules.FirstOrDefault();
            });
    }

    [RelayCommand]
    private void UseCurrentNetwork()
    {
        if (_currentNetwork is not { Online: true } current)
        {
            CurrentNetworkText = I18n.T(
                "ProfileMatch_CurrentOffline", "Current network is offline or unavailable");
            return;
        }

        NetworkRuleLabel = current.Label;
        NetworkRuleGatewayMac = current.GatewayMac;
        NetworkRuleSsid = current.Ssid;
        NetworkRuleInterface = current.InterfaceName;
        NetworkRuleDnsSuffix = current.DnsSuffix;
        SelectedNetworkVpnOption = current.VpnPresent ? NetworkVpnOptions[1] : NetworkVpnOptions[0];
        _networkRuleFingerprint = HasVisibleCriterion() ? string.Empty : current.Fingerprint;
        SaveNetworkProfileRuleCommand.NotifyCanExecuteChanged();
    }

    [RelayCommand(CanExecute = nameof(CanSaveNetworkProfileRule))]
    private async Task SaveNetworkProfileRuleAsync()
    {
        if (!CanSaveNetworkProfileRule())
        {
            StatusText = I18n.T(
                "ProfileMatch_SelectProfile",
                "Select a saved profile and enter at least one match criterion.");
            return;
        }

        await RunServiceActionAsync(
            I18n.T("ProfileMatch_ActionSave", "Save automatic profile rule"),
            async () =>
            {
                var request = BuildNetworkProfileEntry(SelectedProfile!);
                var ack = await _client.Policy.SetNetworkProfileAsync(request);
                StatusText = ack.Message;
                if (ack.Ok)
                {
                    ClearNetworkRuleEditor();
                    await LoadNetworkProfileRulesAsync();
                }
            });
    }

    [RelayCommand(CanExecute = nameof(CanDeleteNetworkProfileRule))]
    private async Task DeleteNetworkProfileRuleAsync()
    {
        if (SelectedNetworkProfileRule is not { } selected)
        {
            return;
        }

        await RunServiceActionAsync(
            I18n.T("ProfileMatch_ActionDelete", "Delete automatic profile rule"),
            async () =>
            {
                var ack = await _client.Policy.SetNetworkProfileAsync(selected.ToEntry(string.Empty));
                StatusText = ack.Message;
                if (ack.Ok)
                {
                    ClearNetworkRuleEditor();
                    await LoadNetworkProfileRulesAsync();
                }
            });
    }

    private bool CanSaveNetworkProfileRule() =>
        !string.IsNullOrWhiteSpace(SelectedProfile) &&
        (HasVisibleCriterion() || !string.IsNullOrWhiteSpace(_networkRuleFingerprint));

    private bool CanDeleteNetworkProfileRule() => SelectedNetworkProfileRule is not null;

    private bool HasVisibleCriterion() =>
        !string.IsNullOrWhiteSpace(NetworkRuleGatewayMac) ||
        !string.IsNullOrWhiteSpace(NetworkRuleSsid) ||
        !string.IsNullOrWhiteSpace(NetworkRuleInterface) ||
        !string.IsNullOrWhiteSpace(NetworkRuleDnsSuffix) ||
        VpnCondition().HasValue;

    private NetworkProfileEntry BuildNetworkProfileEntry(string profile)
    {
        var entry = new NetworkProfileEntry
        {
            Fingerprint = _networkRuleFingerprint.Trim(),
            Profile = profile.Trim(),
            Label = NetworkRuleLabel.Trim(),
            GatewayMac = NetworkRuleGatewayMac.Trim(),
            Ssid = NetworkRuleSsid.Trim(),
            InterfaceName = NetworkRuleInterface.Trim(),
            DnsSuffix = NetworkRuleDnsSuffix.Trim(),
        };
        if (VpnCondition() is { } vpn)
        {
            entry.VpnPresent = vpn;
        }

        return entry;
    }

    private bool? VpnCondition() =>
        SelectedNetworkVpnOption == NetworkVpnOptions[1] ? true :
        SelectedNetworkVpnOption == NetworkVpnOptions[2] ? false : null;

    private void ClearNetworkRuleEditor()
    {
        _networkRuleFingerprint = string.Empty;
        SelectedNetworkProfileRule = null;
        NetworkRuleLabel = string.Empty;
        NetworkRuleGatewayMac = string.Empty;
        NetworkRuleSsid = string.Empty;
        NetworkRuleInterface = string.Empty;
        NetworkRuleDnsSuffix = string.Empty;
        SelectedNetworkVpnOption = NetworkVpnOptions[0];
        SaveNetworkProfileRuleCommand.NotifyCanExecuteChanged();
    }

    private static string DescribeCurrentNetwork(CurrentNetwork current)
    {
        if (!current.Online)
        {
            return I18n.T("ProfileMatch_CurrentOffline", "Current network is offline or unavailable");
        }

        var details = new List<string>();
        Add(details, I18n.T("ProfileMatch_Ssid", "Wi-Fi SSID"), current.Ssid);
        Add(details, I18n.T("ProfileMatch_Interface", "Interface"), current.InterfaceName);
        Add(details, I18n.T("ProfileMatch_DnsSuffix", "DNS suffix"), current.DnsSuffix);
        Add(details, I18n.T("ProfileMatch_Gateway", "Gateway MAC"), current.GatewayMac);
        details.Add(current.VpnPresent
            ? I18n.T("ProfileMatch_VpnPresent", "VPN present")
            : I18n.T("ProfileMatch_VpnAbsent", "VPN absent"));
        if (details.Count == 1 && !string.IsNullOrWhiteSpace(current.Fingerprint))
        {
            details.Insert(0, current.Fingerprint);
        }

        return I18n.T("ProfileMatch_Current", "Current network: {0}",
            string.Join(" | ", details));
    }

    internal static string DescribeGatewayDrift(CurrentNetwork current) => I18n.T(
        "ProfileMatch_GatewayDriftDetails",
        "Saved gateway {0}; current gateway {1}. Possible network impersonation or router replacement. Verify the router or access point, then update the saved mapping if the replacement is expected.",
        current.SavedGatewayId,
        current.CurrentGatewayId);

    private static void Add(List<string> values, string label, string value)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            values.Add($"{label}: {value}");
        }
    }
}

public sealed partial class NetworkProfileRuleViewModel : ObservableObject
{
    public string Fingerprint { get; init; } = string.Empty;
    public string Profile { get; init; } = string.Empty;
    public string Label { get; init; } = string.Empty;
    public string GatewayMac { get; init; } = string.Empty;
    public string Ssid { get; init; } = string.Empty;
    public string InterfaceName { get; init; } = string.Empty;
    public string DnsSuffix { get; init; } = string.Empty;
    public bool? VpnPresent { get; init; }

    public string CriteriaText
    {
        get
        {
            var criteria = new List<string>();
            Add(criteria, I18n.T("ProfileMatch_Gateway", "Gateway MAC"), GatewayMac);
            Add(criteria, I18n.T("ProfileMatch_Ssid", "Wi-Fi SSID"), Ssid);
            Add(criteria, I18n.T("ProfileMatch_DnsSuffix", "DNS suffix"), DnsSuffix);
            Add(criteria, I18n.T("ProfileMatch_Interface", "Interface"), InterfaceName);
            Add(criteria, "ID", Fingerprint);
            if (VpnPresent.HasValue)
            {
                criteria.Add(VpnPresent.Value
                    ? I18n.T("ProfileMatch_VpnPresent", "VPN present")
                    : I18n.T("ProfileMatch_VpnAbsent", "VPN absent"));
            }

            return string.Join(" | ", criteria);
        }
    }

    public static NetworkProfileRuleViewModel From(NetworkProfileEntry entry) => new()
    {
        Fingerprint = entry.Fingerprint,
        Profile = entry.Profile,
        Label = entry.Label,
        GatewayMac = entry.GatewayMac,
        Ssid = entry.Ssid,
        InterfaceName = entry.InterfaceName,
        DnsSuffix = entry.DnsSuffix,
        VpnPresent = entry.HasVpnPresent ? entry.VpnPresent : null,
    };

    public NetworkProfileEntry ToEntry(string profile)
    {
        var entry = new NetworkProfileEntry
        {
            Fingerprint = Fingerprint,
            Profile = profile,
            Label = Label,
            GatewayMac = GatewayMac,
            Ssid = Ssid,
            InterfaceName = InterfaceName,
            DnsSuffix = DnsSuffix,
        };
        if (VpnPresent.HasValue)
        {
            entry.VpnPresent = VpnPresent.Value;
        }

        return entry;
    }

    private static void Add(List<string> values, string label, string value)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            values.Add($"{label}: {value}");
        }
    }
}
