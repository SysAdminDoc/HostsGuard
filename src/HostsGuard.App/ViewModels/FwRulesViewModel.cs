using System.Collections;
using System.Collections.ObjectModel;
using System.Runtime.Versioning;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
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

    public string Flags => (Orphaned ? "⚠ orphaned " : string.Empty) + (Drifted ? "⚠ drifted" : string.Empty);

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

    [ObservableProperty]
    private string _filter = string.Empty;

    [ObservableProperty]
    private bool _hostsGuardOnly = true;

    [ObservableProperty]
    private string _statusText = "Ready";

    // Inline custom-rule form.
    [ObservableProperty]
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

    public FwRulesViewModel(HostsServiceClient client)
        => _client = client ?? throw new ArgumentNullException(nameof(client));

    public ObservableCollection<FwRuleViewModel> Rules { get; } = new();

    public static IReadOnlyList<string> Directions { get; } = new[] { "Out", "In" };

    public static IReadOnlyList<string> Actions { get; } = new[] { "Block", "Allow" };

    public static IReadOnlyList<string> Protocols { get; } = new[] { "Any", "TCP", "UDP" };

    partial void OnHostsGuardOnlyChanged(bool value) => _ = RefreshAsync();

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
                !r.Program.Contains(filter, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            Rules.Add(FwRuleViewModel.From(r));
        }

        StatusText = $"{Rules.Count} rules";
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
        var ack = await _client.Firewall.DeleteRuleAsync(new RuleNameRequest { Name = name });
        StatusText = ack.Message;
        await RefreshAsync();
    }

    [RelayCommand]
    public async Task DeleteSelectedAsync(IList? selected)
    {
        var names = selected?.OfType<FwRuleViewModel>().Select(r => r.Name).ToList() ?? new List<string>();
        var deleted = 0;
        foreach (var name in names)
        {
            var ack = await _client.Firewall.DeleteRuleAsync(new RuleNameRequest { Name = name });
            if (ack.Ok)
            {
                deleted++;
            }
        }

        StatusText = $"Deleted {deleted}/{names.Count} rules";
        await RefreshAsync();
    }

    [RelayCommand]
    public async Task CreateRuleAsync()
    {
        var ack = await _client.Firewall.CreateRuleAsync(new FirewallRule
        {
            Name = NewRuleName,
            Direction = NewRuleDirection,
            Action = NewRuleAction,
            Protocol = NewRuleProtocol,
            RemoteAddr = NewRuleRemoteAddr,
            Program = NewRuleProgram,
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
}
