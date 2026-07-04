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
    private string _source = string.Empty;

    [ObservableProperty]
    private bool _orphaned;

    [ObservableProperty]
    private bool _drifted;

    /// <summary>An existing WF rule HostsGuard adopted into its view (NET-095).</summary>
    [ObservableProperty]
    private bool _adopted;

    /// <summary>SCM short name the rule is scoped to (NET-073); "" = whole program.</summary>
    [ObservableProperty]
    private string _serviceName = string.Empty;

    public string Flags => (Orphaned ? "⚠ orphaned " : string.Empty)
        + (Drifted ? "⚠ drifted " : string.Empty)
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
            _ when name.StartsWith("HG_Scope_", StringComparison.Ordinal) => "app-scope",
            _ when name.StartsWith("HG_DoH_", StringComparison.Ordinal)
                || name.StartsWith("HG_DoT_", StringComparison.Ordinal) => "DoH block",
            _ when name.StartsWith("HG_QUIC_", StringComparison.Ordinal) => "QUIC block",
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
        Source = r.Source,
        Orphaned = r.Orphaned,
        Drifted = r.Drifted,
        Adopted = r.Adopted,
        ServiceName = r.ServiceName,
    };
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
    private CancellationTokenSource? _filterCts;

    /// <summary>Pause after the last filter keystroke before the service round-trip.</summary>
    public static TimeSpan FilterDebounce { get; set; } = TimeSpan.FromMilliseconds(350);

    [ObservableProperty]
    private string _filter = string.Empty;

    [ObservableProperty]
    private bool _hostsGuardOnly = true;

    [ObservableProperty]
    private string _statusText = "Ready";

    // Inline custom-rule form.
    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(CreateRuleCommand))]
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
    private string _newRuleProgram = string.Empty;

    public FwRulesViewModel(HostsServiceClient client, IConfirm confirm, IFilePicker? filePicker = null)
    {
        _client = client ?? throw new ArgumentNullException(nameof(client));
        _confirm = confirm ?? throw new ArgumentNullException(nameof(confirm));
        _filePicker = filePicker;
    }

    public ObservableCollection<FwRuleViewModel> Rules { get; } = new();

    public static IReadOnlyList<string> Directions { get; } = new[] { "Out", "In" };

    public static IReadOnlyList<string> Actions { get; } = new[] { "Block", "Allow" };

    public static IReadOnlyList<string> Protocols { get; } = new[] { "Any", "TCP", "UDP" };

    partial void OnHostsGuardOnlyChanged(bool value) => _ = GuardedRefreshAsync(CancellationToken.None);

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

            await RefreshAsync();
        }
        catch (OperationCanceledException)
        {
            // Superseded by a newer keystroke.
        }
        catch (Exception ex) when (ex is RpcException or IOException)
        {
            StatusText = "Service unavailable — reconnect from the status bar";
        }
    }

    [RelayCommand]
    public async Task RefreshAsync()
    {
        var list = await _client.Firewall.ListRulesAsync(new Empty());
        var filter = Filter.Trim();
        Rules.Clear();
        foreach (var r in list.Rules)
        {
            if (HostsGuardOnly && r.Source != "hostsguard")
            {
                continue;
            }

            if (filter.Length != 0 &&
                !r.Name.Contains(filter, StringComparison.OrdinalIgnoreCase) &&
                !r.RemoteAddr.Contains(filter, StringComparison.OrdinalIgnoreCase) &&
                !r.Program.Contains(filter, StringComparison.OrdinalIgnoreCase) &&
                !r.ServiceName.Contains(filter, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            Rules.Add(FwRuleViewModel.From(r));
        }

        StatusText = Plural.Of(Rules.Count, "rule");
    }

    [RelayCommand]
    public async Task ToggleRuleAsync(FwRuleViewModel rule)
    {
        var ack = await _client.Firewall.SetRuleEnabledAsync(new RuleEnabledRequest { Name = rule.Name, Enabled = !rule.Enabled });
        StatusText = ack.Message;
        await RefreshAsync();
    }

    [RelayCommand]
    public async Task DeleteRuleAsync(string name)
    {
        if (!_confirm.Confirm("Delete firewall rule",
            $"Delete firewall rule {name}? Connections covered only by this rule may be blocked or allowed differently."))
        {
            return;
        }

        var ack = await _client.Firewall.DeleteRuleAsync(new RuleNameRequest { Name = name });
        StatusText = ack.Message;
        await RefreshAsync();
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
        await RefreshAsync();
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
            await RefreshAsync();
        }
    }

    /// <summary>
    /// NET-095: adopt the machine's existing (non-HG_) Windows Firewall rules into
    /// HostsGuard's view so onboarding isn't a blank slate. Non-destructive — the
    /// live firewall is never changed. Shows all rules afterward so they're visible.
    /// </summary>
    [RelayCommand]
    public async Task AdoptRulesAsync()
    {
        if (!_confirm.Confirm("Import existing firewall rules",
            "Read the machine's current Windows Firewall rules into HostsGuard's view? " +
            "This is read-only — nothing on the live firewall is changed. Adopted rules are marked ★."))
        {
            return;
        }

        var result = await _client.Firewall.AdoptFirewallRulesAsync(new Empty());
        StatusText = result.Message;
        if (result.Ok)
        {
            HostsGuardOnly = false; // reveal the adopted (non-HG_) rules
            await RefreshAsync();
        }
    }

    [RelayCommand(CanExecute = nameof(CanCreateRule))]
    public async Task CreateRuleAsync()
    {
        var ack = await _client.Firewall.CreateRuleAsync(new FirewallRule
        {
            Name = NewRuleName.Trim(),
            Direction = NewRuleDirection,
            Action = NewRuleAction,
            Protocol = NewRuleProtocol,
            RemoteAddr = NewRuleRemoteAddr.Trim(),
            Program = NewRuleProgram.Trim(),
            Enabled = true,
        });
        StatusText = ack.Message;
        if (ack.Ok)
        {
            NewRuleName = string.Empty;
            NewRuleRemoteAddr = string.Empty;
            NewRuleProgram = string.Empty;
            await RefreshAsync();
        }
    }

    private bool CanCreateRule() => !string.IsNullOrWhiteSpace(NewRuleName);
}
