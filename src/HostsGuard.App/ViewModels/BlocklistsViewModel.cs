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

    public string Flags =>
        (!Enabled && Subscribed ? "disabled " : string.Empty)
        + (LargeListWarning ? "large " : string.Empty)
        + (Mirror.Length != 0 ? "mirror" : string.Empty);

    public string ToggleLabel => Enabled ? "Disable" : "Enable";

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
    private string _statusText = "Ready";

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
        => RunServiceActionAsync("Refresh blocklists", RefreshCoreAsync);

    [RelayCommand]
    public async Task ImportAsync(BlocklistSourceViewModel? source)
    {
        if (source is null)
        {
            StatusText = "Select a blocklist source first";
            return;
        }

        if (source.LargeListWarning && !_confirm.Confirm("Import large blocklist",
            $"{source.Name} can make the hosts file very large and increase Windows DNS Client CPU. Import it now?"))
        {
            return;
        }

        await RunServiceActionAsync($"Import {source.Name}", async () =>
        {
            StatusText = $"Importing {source.Name}...";
            var result = await _client.Lists.ImportBlocklistAsync(new BlocklistRequest { Name = source.Name, Url = source.Url });
            StatusText = FormatResult(result);
            await RefreshCoreAsync();
        });
    }

    [RelayCommand]
    public async Task PreviewAsync(BlocklistSourceViewModel? source)
    {
        if (source is null)
        {
            StatusText = "Select a blocklist source first";
            return;
        }

        await RunServiceActionAsync($"Preview {source.Name}", async () =>
        {
            StatusText = $"Previewing {source.Name}...";
            var result = await _client.Lists.PreviewBlocklistAsync(new BlocklistRequest { Name = source.Name, Url = source.Url });
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
        if (r.Duplicates > 0) report.Add($"{r.Duplicates} dup");
        if (r.Invalid > 0) report.Add($"{r.Invalid} invalid");
        if (r.HijackFlagged > 0) report.Add($"{r.HijackFlagged} hijack-flagged");
        if (r.AllowlistOverrides > 0) report.Add($"{r.AllowlistOverrides} allowlist-kept");
        if (r.Removed > 0) report.Add($"{r.Removed} removed");
        if (r.Preserved > 0) report.Add($"{r.Preserved} preserved");
        var health = report.Count != 0 ? $" [{string.Join(", ", report)}]" : string.Empty;
        var prefix = r.Preview ? "Preview: " : string.Empty;
        var warn = r.Warning.Length != 0 ? $" - {r.Warning}" : string.Empty;
        return $"{prefix}{r.Message}{health}{warn}";
    }

    [RelayCommand]
    public async Task UnsubscribeAsync(BlocklistSourceViewModel? source)
    {
        if (source is null)
        {
            StatusText = "Select a blocklist source first";
            return;
        }

        await RunServiceActionAsync($"Remove {source.Name}", async () =>
        {
            var ack = await _client.Lists.RemoveBlocklistSubscriptionAsync(new BlocklistRequest { Name = source.Name });
            StatusText = ack.Message;
            await RefreshCoreAsync();
        });
    }

    [RelayCommand]
    public async Task ToggleEnabledAsync(BlocklistSourceViewModel? source)
    {
        if (source is null)
        {
            StatusText = "Select a blocklist source first";
            return;
        }

        await RunServiceActionAsync($"{(source.Enabled ? "Disable" : "Enable")} {source.Name}", async () =>
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
        await RunServiceActionAsync("Refresh subscriptions", async () =>
        {
            StatusText = "Refreshing all subscriptions...";
            var result = await _client.Lists.RefreshBlocklistsAsync(new Empty());
            StatusText = FormatResult(result);
            await RefreshCoreAsync();
        });
    }

    [RelayCommand]
    public async Task SaveAllowlistsAsync()
    {
        await RunServiceActionAsync("Save allowlists", async () =>
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
        StatusText = $"{Plural.Of(Sources.Count, "source")}, {Sources.Count(s => s.Subscribed)} subscribed, {Sources.Sum(s => s.Hits30d):N0} hits/30d";
    }

    private Task RunServiceActionAsync(string action, Func<Task> work) =>
        ServiceActionGuard.RunAsync(action, s => StatusText = s, work);
}
