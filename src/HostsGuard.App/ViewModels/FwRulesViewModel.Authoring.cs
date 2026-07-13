using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using HostsGuard.App.Services;
using HostsGuard.Contracts;
using HostsGuard.Core;

namespace HostsGuard.App.ViewModels;

public sealed partial class FirewallInterfaceAliasViewModel : ObservableObject
{
    [ObservableProperty]
    private string _name = string.Empty;

    [ObservableProperty]
    private string _description = string.Empty;

    [ObservableProperty]
    private bool _isSelected;

    internal Action? SelectionChanged { get; set; }

    partial void OnIsSelectedChanged(bool value) => SelectionChanged?.Invoke();
}

public sealed partial class FwRulesViewModel
{
    private string _editingOriginalName = string.Empty;

    public ObservableCollection<FirewallInterfaceAliasViewModel> InterfaceAliases { get; } = new();

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(CreateRuleCommand))]
    [NotifyPropertyChangedFor(nameof(CreateRulePreview))]
    [NotifyPropertyChangedFor(nameof(CreateRuleHelpText))]
    private string _newRuleLocalPorts = "Any";

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(CreateRuleCommand))]
    [NotifyPropertyChangedFor(nameof(CreateRulePreview))]
    [NotifyPropertyChangedFor(nameof(CreateRuleHelpText))]
    private string _newRuleRemotePorts = "Any";

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(CreateRuleCommand))]
    [NotifyPropertyChangedFor(nameof(CreateRulePreview))]
    [NotifyPropertyChangedFor(nameof(CreateRuleHelpText))]
    private string _newRuleInterfaces = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(AuthoringTitle))]
    [NotifyPropertyChangedFor(nameof(AuthoringActionText))]
    private bool _isEditingRule;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CreateRulePreview))]
    private bool _newRuleEnabled = true;

    [ObservableProperty]
    private string _interfaceAliasStatus = I18n.T(
        "FwRules_InterfacesNotLoaded", "Interface aliases not loaded. Refresh to validate exact current aliases.");

    public string AuthoringTitle => IsEditingRule
        ? I18n.T("FwRules_EditTitle", "Edit HostsGuard rule")
        : I18n.T("Xaml_Create_HostsGuard_rule_0516d184", "Create HostsGuard rule");

    public string AuthoringActionText => IsEditingRule
        ? I18n.T("FwRules_UpdateAction", "Update rule")
        : I18n.T("Xaml_Create_rule_69c3acdb", "Create rule");

    public string CreateRulePreview
    {
        get
        {
            _ = TryNormalizePorts(NewRuleLocalPorts, NewRuleProtocol, out var local, out _);
            _ = TryNormalizePorts(NewRuleRemotePorts, NewRuleProtocol, out var remote, out _);
            var interfaces = SelectedInterfaceValue();
            var target = NewRulePackageFamily.Length != 0
                ? I18n.T("FwRules_PreviewPackage", "package {0}", NewRulePackageFamily)
                : NewRuleProgram.Length != 0
                    ? I18n.T("FwRules_PreviewProgram", "program {0}", NewRuleProgram)
                    : I18n.T("FwRules_PreviewAllPrograms", "all programs");
            return I18n.T("FwRules_ScopePreview",
                "Preview: {0} {1} | {2} | {3} | local ports {4} | remote ports {5} | interfaces {6} | {7}",
                NewRuleDirection, NewRuleAction, NewRuleProtocol,
                NewRuleEnabled ? I18n.T("FwRules_Enabled", "enabled") : I18n.T("FwRules_Disabled", "disabled"),
                local.Length == 0 ? "?" : local,
                remote.Length == 0 ? "?" : remote,
                interfaces.Length == 0 ? I18n.T("FwRules_AnyInterface", "Any") : interfaces,
                target);
        }
    }

    public string? AuthoringValidationError()
    {
        if (!TryNormalizePorts(NewRuleLocalPorts, NewRuleProtocol, out _, out var localError))
        {
            return I18n.T("FwRules_LocalPortsError", "Local ports: {0}", localError);
        }

        if (!TryNormalizePorts(NewRuleRemotePorts, NewRuleProtocol, out _, out var remoteError))
        {
            return I18n.T("FwRules_RemotePortsError", "Remote ports: {0}", remoteError);
        }

        if (!FirewallRuleAuthoring.TryNormalizeInterfaces(SelectedInterfaceValue(), out _, out _))
        {
            return I18n.T("FwRules_InterfaceFormatError",
                "Interface aliases must be comma-separated visible names (maximum 64, 256 characters each).");
        }

        return null;
    }

    public static bool TryNormalizePorts(string? input, string protocol, out string normalized, out string error)
    {
        if (!FirewallRuleAuthoring.TryNormalizePorts(input, out normalized, out _))
        {
            normalized = string.Empty;
            error = I18n.T("FwRules_PortFormatError",
                "use comma-separated ports or ascending ranges from 1 to 65535");
            return false;
        }

        if (normalized != "Any" && !protocol.Equals("TCP", StringComparison.OrdinalIgnoreCase) &&
            !protocol.Equals("UDP", StringComparison.OrdinalIgnoreCase))
        {
            normalized = string.Empty;
            error = I18n.T("FwRules_PortsNeedProtocol", "select TCP or UDP when restricting ports");
            return false;
        }

        error = string.Empty;
        return true;
    }

    [RelayCommand]
    public void EditRule(FwRuleViewModel? row)
    {
        if (row is null || row.Source != "hostsguard" ||
            !row.Name.StartsWith("HG_", StringComparison.Ordinal))
        {
            StatusText = I18n.T("FwRules_EditManagedOnly", "Only HostsGuard-managed HG_ rules can be edited here.");
            return;
        }

        IsEditingRule = true;
        _editingOriginalName = row.Name;
        NewRuleName = row.Name[3..];
        NewRuleDirection = row.Direction;
        NewRuleAction = row.Action;
        NewRuleProtocol = row.Protocol;
        NewRuleRemoteAddr = row.RemoteAddr is "Any" ? string.Empty : row.RemoteAddr;
        NewRuleProgram = row.Program;
        NewRulePackageFamily = row.PackageFamilyName;
        NewRuleLocalPorts = row.LocalPorts;
        NewRuleRemotePorts = row.RemotePortsForDisplay;
        NewRuleEnabled = row.Enabled;
        ApplyInterfaceSelection(row.Interfaces);
        NotifyAuthoringChanged();
    }

    [RelayCommand]
    public void CancelRuleEdit() => ResetRuleAuthoring();

    [RelayCommand]
    public async Task LoadInterfaceAliasesAsync()
    {
        await ServiceActionGuard.RunAsync(I18n.T("FwRules_ActionLoadInterfaces", "Load firewall interfaces"), s => InterfaceAliasStatus = s, async () =>
        {
            var selected = SelectedInterfaceValue().Split(',',
                StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
            var result = await _client.Firewall.ListInterfaceAliasesAsync(new Empty());
            InterfaceAliases.Clear();
            foreach (var item in result.Interfaces.OrderBy(item => item.Alias, StringComparer.OrdinalIgnoreCase))
            {
                var row = new FirewallInterfaceAliasViewModel
                {
                    Name = item.Alias,
                    Description = $"{item.Description} | {item.InterfaceType}" +
                                  (item.IsUp
                                      ? " | " + I18n.T("FwRules_InterfaceUp", "up")
                                      : " | " + I18n.T("FwRules_InterfaceDown", "down")),
                    IsSelected = selected.Remove(item.Alias),
                    SelectionChanged = OnInterfaceSelectionChanged,
                };
                InterfaceAliases.Add(row);
            }

            NewRuleInterfaces = string.Join(", ", selected);
            InterfaceAliasStatus = result.Interfaces.Count == 0
                ? I18n.T("FwRules_NoInterfaces",
                    "No current interface aliases returned; named interface scoping is unavailable.")
                : I18n.T("FwRules_InterfaceCount", "{0} current interface aliases", result.Interfaces.Count);
            NotifyAuthoringChanged();
        });
    }

    internal void ResetRuleAuthoring()
    {
        IsEditingRule = false;
        _editingOriginalName = string.Empty;
        NewRuleName = string.Empty;
        NewRuleRemoteAddr = string.Empty;
        NewRuleProgram = string.Empty;
        NewRulePackageFamily = string.Empty;
        NewRuleLocalPorts = "Any";
        NewRuleRemotePorts = "Any";
        NewRuleEnabled = true;
        NewRuleInterfaces = string.Empty;
        foreach (var alias in InterfaceAliases)
        {
            alias.IsSelected = false;
        }

        NotifyAuthoringChanged();
    }

    private void ApplyInterfaceSelection(string value)
    {
        var selected = value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var alias in InterfaceAliases)
        {
            alias.IsSelected = selected.Remove(alias.Name);
        }

        NewRuleInterfaces = string.Join(", ", selected);
    }

    private string SelectedInterfaceValue()
    {
        var selected = InterfaceAliases.Where(alias => alias.IsSelected).Select(alias => alias.Name);
        var manual = NewRuleInterfaces.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        return string.Join(',', selected.Concat(manual).Distinct(StringComparer.OrdinalIgnoreCase));
    }

    private void OnInterfaceSelectionChanged() => NotifyAuthoringChanged();

    private void NotifyAuthoringChanged()
    {
        OnPropertyChanged(nameof(CreateRulePreview));
        OnPropertyChanged(nameof(CreateRuleHelpText));
        CreateRuleCommand.NotifyCanExecuteChanged();
    }

    partial void OnNewRuleDirectionChanged(string value) => NotifyAuthoringChanged();
    partial void OnNewRuleActionChanged(string value) => NotifyAuthoringChanged();
    partial void OnNewRuleProtocolChanged(string value) => NotifyAuthoringChanged();
    partial void OnNewRuleRemoteAddrChanged(string value) => NotifyAuthoringChanged();
}
