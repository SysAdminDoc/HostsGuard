using System.Collections;
using System.Collections.ObjectModel;
using System.IO;
using System.Runtime.Versioning;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Grpc.Core;
using HostsGuard.App.Services;
using HostsGuard.Contracts;

namespace HostsGuard.App.ViewModels;

/// <summary>Row VM for a firewall rule (orphan ⚠ / drift flags included).</summary>
public sealed partial class FwRuleViewModel : ObservableObject
{
    [ObservableProperty]
    private string _name = string.Empty;

    [ObservableProperty]
    private string _direction = string.Empty;

    [ObservableProperty]
    private string _action = string.Empty;

    [ObservableProperty]
    private bool _enabled;

    [ObservableProperty]
    private string _remoteAddr = string.Empty;

    [ObservableProperty]
    private string _protocol = string.Empty;

    [ObservableProperty]
    private string _program = string.Empty;

    [ObservableProperty]
    private string _packageFamilyName = string.Empty;

    [ObservableProperty]
    private string _packageSid = string.Empty;

    [ObservableProperty]
    private string _packageDisplayName = string.Empty;

    [ObservableProperty]
    private string _packageFullName = string.Empty;

    [ObservableProperty]
    private string _packageBinaries = string.Empty;

    [ObservableProperty]
    private string _source = string.Empty;

    [ObservableProperty]
    private bool _orphaned;

    [ObservableProperty]
    private bool _drifted;

    [ObservableProperty]
    private string _driftStatus = string.Empty;

    [ObservableProperty]
    private string _driftDetail = string.Empty;

    [ObservableProperty]
    private string _firstSeen = string.Empty;

    [ObservableProperty]
    private string _lastSeen = string.Empty;

    [ObservableProperty]
    private string _changedAt = string.Empty;

    /// <summary>An existing WF rule HostsGuard adopted into its view (NET-095).</summary>
    [ObservableProperty]
    private bool _adopted;

    /// <summary>SCM short name the rule is scoped to (NET-073); "" = whole program.</summary>
    [ObservableProperty]
    private string _serviceName = string.Empty;

    [ObservableProperty]
    private string _localPorts = string.Empty;

    [ObservableProperty]
    private string _interfaces = string.Empty;

    public string Ports
    {
        get
        {
            var parts = new List<string>(2);
            if (LocalPorts is not ("" or "Any")) parts.Add($"local {LocalPorts}");
            if (RemotePortsForDisplay is not ("" or "Any")) parts.Add($"remote {RemotePortsForDisplay}");
            return parts.Count == 0 ? "Any" : string.Join(" | ", parts);
        }
    }

    public string TargetKind => PackageFamilyName.Length != 0 || PackageSid.Length != 0
        ? "package"
        : Program.Length != 0 ? "program" : "global";

    public string PackageLabel => PackageDisplayName.Length != 0 && PackageFamilyName.Length != 0
        ? $"{PackageDisplayName} ({PackageFamilyName})"
        : PackageDisplayName.Length != 0 ? PackageDisplayName :
        PackageFamilyName.Length != 0 ? PackageFamilyName :
        PackageSid.Length != 0 ? PackageSid : string.Empty;

    public string Target => TargetKind switch
    {
        "package" => PackageLabel,
        "program" => Program,
        _ => "All programs",
    };

    [ObservableProperty]
    private string _remotePortsForDisplay = string.Empty;

    public string Flags => (Orphaned ? "⚠ orphaned " : string.Empty)
        + (Drifted ? "⚠ drifted " : string.Empty)
        + (!string.IsNullOrWhiteSpace(DriftStatus) ? $"{DriftStatus} " : string.Empty)
        + (Adopted ? "★ adopted" : string.Empty);

    /// <summary>
    /// Provenance (NET-118): why this rule exists, derived from its HG_ name
    /// prefix (or adopted/system source). Turns an opaque rule list into an
    /// auditable one.
    /// </summary>
    public string Origin => OriginFor(Name, Source, Adopted);

    public static string OriginFor(string name, string source, bool adopted)
    {
        if (source != "hostsguard")
        {
            return adopted ? "adopted" : "system";
        }

        return name switch
        {
            _ when name.StartsWith("HG_Consent_", StringComparison.Ordinal) => "consent",
            _ when name.StartsWith("HG_Learn_", StringComparison.Ordinal) => "learning",
            _ when name.StartsWith("HG_Base_", StringComparison.Ordinal) => "baseline",
            _ when name.StartsWith("HG_Child_", StringComparison.Ordinal) => "child-allow",
            _ when name.StartsWith("HG_Once_", StringComparison.Ordinal) => "temporary",
            _ when name.StartsWith("HG_Domain_", StringComparison.Ordinal) => "domain",
            _ when name.StartsWith("HG_Package_", StringComparison.Ordinal) => "package",
            _ when name.StartsWith("HG_VPNBind_", StringComparison.Ordinal) => "app VPN",
            _ when name.StartsWith("HG_Scope_", StringComparison.Ordinal) => "app-scope",
            _ when name.StartsWith("HG_DoH_", StringComparison.Ordinal)
                || name.StartsWith("HG_DoT_", StringComparison.Ordinal) => "DoH block",
            _ when name.StartsWith("HG_QUIC_", StringComparison.Ordinal) => "QUIC block",
            _ when name.StartsWith("HG_LAN_", StringComparison.Ordinal) => "LAN hardening",
            _ => "manual",
        };
    }

    public static FwRuleViewModel From(FirewallRule r) => new()
    {
        Name = r.Name,
        Direction = r.Direction,
        Action = r.Action,
        Enabled = r.Enabled,
        RemoteAddr = r.RemoteAddr,
        Protocol = r.Protocol,
        Program = r.Program,
        PackageFamilyName = r.PackageFamilyName,
        PackageSid = r.PackageSid,
        PackageDisplayName = r.PackageDisplayName,
        PackageFullName = r.PackageFullName,
        PackageBinaries = r.PackageBinaries,
        Source = r.Source,
        Orphaned = r.Orphaned,
        Drifted = r.Drifted,
        DriftStatus = r.DriftStatus,
        DriftDetail = r.DriftDetail,
        FirstSeen = r.FirstSeen,
        LastSeen = r.LastSeen,
        ChangedAt = r.ChangedAt,
        Adopted = r.Adopted,
        ServiceName = r.ServiceName,
        LocalPorts = r.LocalPorts,
        Interfaces = r.Interfaces,
        RemotePortsForDisplay = r.RemotePorts,
    };
}

public sealed partial class AppPackageViewModel : ObservableObject
{
    [ObservableProperty]
    private string _packageFamilyName = string.Empty;

    [ObservableProperty]
    private string _packageSid = string.Empty;

    [ObservableProperty]
    private string _displayName = string.Empty;

    [ObservableProperty]
    private string _packageFullName = string.Empty;

    [ObservableProperty]
    private string _binaries = string.Empty;

    public string Label => DisplayName.Length != 0 && PackageFamilyName.Length != 0
        ? $"{DisplayName} ({PackageFamilyName})"
        : PackageFamilyName.Length != 0 ? PackageFamilyName : PackageSid;

    public static AppPackageViewModel From(AppPackage package) => new()
    {
        PackageFamilyName = package.PackageFamilyName,
        PackageSid = package.PackageSid,
        DisplayName = package.DisplayName,
        PackageFullName = package.PackageFullName,
        Binaries = package.Binaries,
    };
}

/// <summary>Row VM for a named rule group (NET-103).</summary>
public sealed partial class RuleGroupViewModel : ObservableObject
{
    [ObservableProperty]
    private string _name = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(Label))]
    private int _enabledCount;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(Label))]
    private int _total;

    public string Label => $"{Name} ({EnabledCount}/{Total} on)";
}

/// <summary>
/// FW Rules tab: rule viewer (all rules or HostsGuard-only), enable/disable and
/// delete for HG_ rules, bulk delete, quick-block, and an inline custom-rule
/// form. Drift and orphan states surface as row flags.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed partial class FwRulesViewModel : ObservableObject
{
    private readonly HostsServiceClient _client;
    private readonly IConfirm _confirm;
    private readonly IFilePicker? _filePicker;
    private readonly IPrompt? _prompt;
    private CancellationTokenSource? _filterCts;

    /// <summary>Pause after the last filter keystroke before the service round-trip.</summary>
    public static TimeSpan FilterDebounce { get; set; } = TimeSpan.FromMilliseconds(350);

    [ObservableProperty]
    private string _filter = string.Empty;

    [ObservableProperty]
    private bool _hostsGuardOnly = true;

    [ObservableProperty]
    private bool _driftOnly;

    [ObservableProperty]
    private string _statusText = "Ready";

    // Inline custom-rule form.
    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(CreateRuleCommand))]
    [NotifyPropertyChangedFor(nameof(CreateRuleHelpText))]
    private string _newRuleName = string.Empty;

    [ObservableProperty]
    private string _newRuleDirection = "Out";

    [ObservableProperty]
    private string _newRuleAction = "Block";

    [ObservableProperty]
    private string _newRuleProtocol = "Any";

    [ObservableProperty]
    private string _newRuleRemoteAddr = string.Empty;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(CreateRuleCommand))]
    [NotifyPropertyChangedFor(nameof(CreateRuleHelpText))]
    private string _newRuleProgram = string.Empty;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(CreateRuleCommand))]
    [NotifyPropertyChangedFor(nameof(CreateRuleHelpText))]
    private string _newRulePackageFamily = string.Empty;

    public string CreateRuleHelpText => AuthoringValidationError() is { } validationError
        ? validationError
        : string.IsNullOrWhiteSpace(NewRuleName)
        ? I18n.T("FwRules_CreateNeedsName", "Enter a name to create this rule.")
        : HasConflictingTarget
            ? I18n.T("FwRules_CreateChooseOneTarget", "Choose either a package or a program path, not both.")
            : I18n.T("FwRules_CreateReady", "Ready to create this HostsGuard-managed rule.");

    public FwRulesViewModel(HostsServiceClient client, IConfirm confirm, IFilePicker? filePicker = null, IPrompt? prompt = null)
    {
        _client = client ?? throw new ArgumentNullException(nameof(client));
        _confirm = confirm ?? throw new ArgumentNullException(nameof(confirm));
        _filePicker = filePicker;
        _prompt = prompt;
    }

    public ObservableCollection<FwRuleViewModel> Rules { get; } = new();

    public ObservableCollection<AppPackageViewModel> AppPackages { get; } = new();

    /// <summary>Named rule groups (NET-103) with enable/disable toggles.</summary>
    public ObservableCollection<RuleGroupViewModel> RuleGroups { get; } = new();

    public static IReadOnlyList<string> Directions { get; } = new[] { "Out", "In" };

    public static IReadOnlyList<string> Actions { get; } = new[] { "Block", "Allow" };

    public static IReadOnlyList<string> Protocols { get; } = new[] { "Any", "TCP", "UDP" };

    partial void OnHostsGuardOnlyChanged(bool value) => _ = GuardedRefreshAsync(CancellationToken.None);

    partial void OnDriftOnlyChanged(bool value) => _ = GuardedRefreshAsync(CancellationToken.None);

    /// <summary>Live search: re-query shortly after typing stops instead of waiting for Refresh.</summary>
    partial void OnFilterChanged(string value)
    {
        _filterCts?.Cancel();
        _filterCts?.Dispose();
        _filterCts = new CancellationTokenSource();
        _ = GuardedRefreshAsync(_filterCts.Token);
    }

    private async Task GuardedRefreshAsync(CancellationToken ct)
    {
        try
        {
            if (ct.CanBeCanceled)
            {
                await Task.Delay(FilterDebounce, ct);
            }

            await RunServiceActionAsync("Refresh firewall rules", RefreshCoreAsync);
        }
        catch (OperationCanceledException)
        {
            // Superseded by a newer keystroke.
        }
        catch (Exception ex) when (ex is RpcException || ServiceErrors.IsConnectivity(ex))
        {
            StatusText = ServiceErrors.DescribeActionFailure("Refresh firewall rules", ex);
        }
    }

    [RelayCommand]
    public Task RefreshAsync()
        => RunServiceActionAsync("Refresh firewall rules", RefreshCoreAsync);

    private async Task RefreshCoreAsync()
    {
        var packages = await _client.Firewall.ListAppPackagesAsync(new Empty());
        AppPackages.Clear();
        foreach (var package in packages.Packages
            .OrderBy(p => string.IsNullOrWhiteSpace(p.DisplayName) ? p.PackageFamilyName : p.DisplayName, StringComparer.OrdinalIgnoreCase))
        {
            AppPackages.Add(AppPackageViewModel.From(package));
        }

        var list = await _client.Firewall.ListRulesAsync(new Empty());
        var filter = Filter.Trim();
        var driftCount = list.Rules.Count(r => !string.IsNullOrWhiteSpace(r.DriftStatus));
        Rules.Clear();
        foreach (var r in list.Rules)
        {
            if (DriftOnly)
            {
                if (string.IsNullOrWhiteSpace(r.DriftStatus))
                {
                    continue;
                }
            }
            else if (HostsGuardOnly && r.Source != "hostsguard")
            {
                continue;
            }

            if (filter.Length != 0 &&
                !r.Name.Contains(filter, StringComparison.OrdinalIgnoreCase) &&
                !r.RemoteAddr.Contains(filter, StringComparison.OrdinalIgnoreCase) &&
                !r.Program.Contains(filter, StringComparison.OrdinalIgnoreCase) &&
                !r.PackageFamilyName.Contains(filter, StringComparison.OrdinalIgnoreCase) &&
                !r.PackageSid.Contains(filter, StringComparison.OrdinalIgnoreCase) &&
                !r.PackageDisplayName.Contains(filter, StringComparison.OrdinalIgnoreCase) &&
                !r.PackageFullName.Contains(filter, StringComparison.OrdinalIgnoreCase) &&
                !r.ServiceName.Contains(filter, StringComparison.OrdinalIgnoreCase) &&
                !r.Interfaces.Contains(filter, StringComparison.OrdinalIgnoreCase) &&
                !r.DriftStatus.Contains(filter, StringComparison.OrdinalIgnoreCase) &&
                !r.DriftDetail.Contains(filter, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            Rules.Add(FwRuleViewModel.From(r));
        }

        StatusText = driftCount == 0
            ? Plural.Of(Rules.Count, "rule")
            : $"{Plural.Of(Rules.Count, "rule")} - {Plural.Of(driftCount, "drift event")}";
        await LoadRuleGroupsCoreAsync();
    }

    // ─── Rule groups (NET-103) ───────────────────────────────────────────────

    [RelayCommand]
    public Task LoadRuleGroupsAsync()
        => RunServiceActionAsync("Load rule groups", LoadRuleGroupsCoreAsync);

    private async Task LoadRuleGroupsCoreAsync()
    {
        var list = await _client.Firewall.ListRuleGroupsAsync(new Empty());
        RuleGroups.Clear();
        foreach (var g in list.Groups.OrderBy(g => g.Name, StringComparer.OrdinalIgnoreCase))
        {
            RuleGroups.Add(new RuleGroupViewModel { Name = g.Name, EnabledCount = g.EnabledCount, Total = g.Total });
        }
    }

    /// <summary>Assign the selected HG_ rules to a named group (prompting for the name).</summary>
    [RelayCommand]
    public async Task AssignToGroupAsync(System.Collections.IList? selected)
    {
        var names = selected?.OfType<FwRuleViewModel>()
            .Where(r => r.Source == "hostsguard")
            .Select(r => r.Name).ToList() ?? new List<string>();
        if (names.Count == 0)
        {
            StatusText = "Select one or more HostsGuard (HG_) rules first";
            return;
        }

        var group = _prompt?.Ask("Assign to rule group",
            $"Group name for {Plural.Of(names.Count, "rule")} (blank removes them from all groups):");
        if (group is null)
        {
            return;
        }

        await RunServiceActionAsync("Assign firewall rule group", async () =>
        {
            var assigned = 0;
            foreach (var name in names)
            {
                var ack = await _client.Firewall.AssignRuleGroupAsync(new RuleGroupAssignment { RuleName = name, Group = group });
                if (ack.Ok)
                {
                    assigned++;
                }
            }

            StatusText = group.Trim().Length == 0
                ? $"Removed {assigned} rules from groups"
                : $"Assigned {assigned} rules to '{group.Trim()}'";
            await LoadRuleGroupsCoreAsync();
        });
    }

    [RelayCommand]
    public async Task EnableGroupAsync(RuleGroupViewModel? group) => await ToggleGroupAsync(group, true);

    [RelayCommand]
    public async Task DisableGroupAsync(RuleGroupViewModel? group) => await ToggleGroupAsync(group, false);

    private async Task ToggleGroupAsync(RuleGroupViewModel? group, bool enabled)
    {
        if (group is null)
        {
            return;
        }

        await RunServiceActionAsync($"{(enabled ? "Enable" : "Disable")} rule group", async () =>
        {
            var ack = await _client.Firewall.ToggleRuleGroupAsync(new RuleGroupToggle { Group = group.Name, Enabled = enabled });
            StatusText = ack.Message;
            await RefreshCoreAsync();
        });
    }

    [RelayCommand]
    public async Task ToggleRuleAsync(FwRuleViewModel rule)
    {
        if (rule is null)
        {
            StatusText = "Select a firewall rule first";
            return;
        }

        await RunServiceActionAsync("Toggle firewall rule", async () =>
        {
            var ack = await _client.Firewall.SetRuleEnabledAsync(new RuleEnabledRequest { Name = rule.Name, Enabled = !rule.Enabled });
            StatusText = ack.Message;
            await RefreshCoreAsync();
        });
    }

    [RelayCommand]
    public async Task DeleteRuleAsync(string name)
    {
        if (!_confirm.Confirm("Delete firewall rule",
            $"Delete firewall rule {name}? Connections covered only by this rule may be blocked or allowed differently."))
        {
            return;
        }

        await RunServiceActionAsync("Delete firewall rule", async () =>
        {
            var ack = await _client.Firewall.DeleteRuleAsync(new RuleNameRequest { Name = name });
            StatusText = ack.Message;
            await RefreshCoreAsync();
        });
    }

    [RelayCommand]
    public async Task DeleteSelectedAsync(IList? selected)
    {
        var names = selected?.OfType<FwRuleViewModel>().Select(r => r.Name).ToList() ?? new List<string>();
        if (names.Count == 0 || !_confirm.Confirm("Delete firewall rules",
            $"Delete {names.Count} selected rules? Connections covered only by these rules may behave differently."))
        {
            return;
        }

        await RunServiceActionAsync("Delete selected firewall rules", async () =>
        {
            var deleted = 0;
            foreach (var name in names)
            {
                var ack = await _client.Firewall.DeleteRuleAsync(new RuleNameRequest { Name = name });
                if (ack.Ok)
                {
                    deleted++;
                }
            }

            StatusText = $"Deleted {deleted} of {Plural.Of(names.Count, "rule")}";
            await RefreshCoreAsync();
        });
    }

    /// <summary>
    /// Orphan rebind: rank identity-matched replacement binaries; a confident
    /// single match confirms and applies, an ambiguous or empty result falls
    /// back to a manual file pick. Manual picks are applied as a user override.
    /// </summary>
    [RelayCommand]
    public async Task RebindRuleAsync(FwRuleViewModel? rule)
    {
        if (rule is null || rule.Program.Length == 0)
        {
            StatusText = "Select a program rule to rebind";
            return;
        }

        StatusText = "Scanning for replacement binaries…";
        await RunServiceActionAsync("Rebind firewall rule", async () =>
        {
            var suggestions = await _client.Firewall.SuggestRebindAsync(new RuleNameRequest { Name = rule.Name });

            string? target = null;
            if (suggestions.Candidates.Count != 0 && !suggestions.Ambiguous)
            {
                var best = suggestions.Candidates[0];
                if (_confirm.Confirm("Rebind firewall rule",
                    $"Re-target {rule.Name}\nfrom: {suggestions.OldPath}\nto: {best.Path}\n" +
                    $"Confidence {best.Score}/100 ({best.Reasons}). The old executable path will no longer be covered."))
                {
                    target = best.Path;
                }
            }
            else
            {
                target = _filePicker?.PickFile(
                    suggestions.Candidates.Count == 0
                        ? $"No confident match found — select the replacement for {rule.Name}"
                        : $"Multiple candidates — select the replacement for {rule.Name}",
                    suggestions.Candidates.FirstOrDefault()?.Path ?? suggestions.OldPath);
            }

            if (target is null)
            {
                StatusText = "Rebind cancelled";
                return;
            }

            var ack = await _client.Firewall.RebindRuleAsync(new RebindRequest { Name = rule.Name, NewProgram = target });
            StatusText = ack.Message;
            if (ack.Ok)
            {
                await RefreshCoreAsync();
            }
        });
    }

    /// <summary>
    /// NET-095: adopt the machine's existing (non-HG_) Windows Firewall rules into
    /// HostsGuard's view so onboarding isn't a blank slate. Non-destructive — the
    /// live firewall is never changed. Shows all rules afterward so they're visible.
    /// </summary>
    [RelayCommand]
    public async Task AdoptRulesAsync()
    {
        await RunServiceActionAsync("Import existing firewall rules", async () =>
        {
            var result = await _client.Firewall.AdoptFirewallRulesAsync(new Empty());
            StatusText = result.Message;
            if (result.Ok)
            {
                HostsGuardOnly = false; // reveal the adopted (non-HG_) rules
                await RefreshCoreAsync();
            }
        });
    }

    [RelayCommand(CanExecute = nameof(CanCreateRule))]
    public async Task CreateRuleAsync()
    {
        await RunServiceActionAsync("Create firewall rule", async () =>
        {
            if (!string.IsNullOrWhiteSpace(NewRuleProgram) && !string.IsNullOrWhiteSpace(NewRulePackageFamily))
            {
                StatusText = I18n.T(
                    "FwRules_CreateChooseOneTarget",
                    "Choose either a package or a program path, not both.");
                return;
            }

            if (!TryNormalizePorts(NewRuleLocalPorts, NewRuleProtocol, out var localPorts, out _) ||
                !TryNormalizePorts(NewRuleRemotePorts, NewRuleProtocol, out var remotePorts, out _))
            {
                StatusText = CreateRuleHelpText;
                return;
            }

            var request = new FirewallRule
            {
                Name = IsEditingRule ? _editingOriginalName : NewRuleName.Trim(),
                Direction = NewRuleDirection,
                Action = NewRuleAction,
                Protocol = NewRuleProtocol,
                RemoteAddr = NewRuleRemoteAddr.Trim(),
                Program = NewRuleProgram.Trim(),
                PackageFamilyName = NewRulePackageFamily.Trim(),
                LocalPorts = localPorts,
                RemotePorts = remotePorts,
                Interfaces = SelectedInterfaceValue(),
                Enabled = NewRuleEnabled,
            };
            var ack = IsEditingRule
                ? await _client.Firewall.UpdateRuleAsync(request)
                : await _client.Firewall.CreateRuleAsync(request);
            StatusText = ack.Message;
            if (ack.Ok)
            {
                ResetRuleAuthoring();
                await RefreshCoreAsync();
            }
        });
    }

    private bool HasConflictingTarget =>
        !string.IsNullOrWhiteSpace(NewRuleProgram)
        && !string.IsNullOrWhiteSpace(NewRulePackageFamily);

    private bool CanCreateRule() =>
        !string.IsNullOrWhiteSpace(NewRuleName) && !HasConflictingTarget && AuthoringValidationError() is null;

    private Task RunServiceActionAsync(string action, Func<Task> work) =>
        ServiceActionGuard.RunAsync(action, s => StatusText = s, work);
}
