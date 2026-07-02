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
    private string _lastRefresh = string.Empty;

    [ObservableProperty]
    private long _domainCount;

    [ObservableProperty]
    private bool _largeListWarning;

    [ObservableProperty]
    private string _mirror = string.Empty;

    public string Flags =>
        (LargeListWarning ? "⚠ large " : string.Empty) + (Mirror.Length != 0 ? "↔ mirror" : string.Empty);

    public static BlocklistSourceViewModel From(BlocklistSource s) => new()
    {
        Category = s.Category,
        Name = s.Name,
        Url = s.Url,
        Subscribed = s.Subscribed,
        LastRefresh = s.LastRefresh,
        DomainCount = s.DomainCount,
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
    public async Task RefreshAsync()
    {
        var list = await _client.Lists.ListBlocklistSourcesAsync(new Empty());
        Sources.Clear();
        foreach (var s in list.Sources)
        {
            Sources.Add(BlocklistSourceViewModel.From(s));
        }

        var allow = await _client.Lists.GetAllowlistsAsync(new Empty());
        AllowlistUrlsText = string.Join(Environment.NewLine, allow.Urls);
        StatusText = $"{Sources.Count} sources, {Sources.Count(s => s.Subscribed)} subscribed";
    }

    [RelayCommand]
    public async Task ImportAsync(BlocklistSourceViewModel source)
    {
        if (source.LargeListWarning && !_confirm.Confirm("Large blocklist",
            $"{source.Name} is large enough to bloat the hosts file and spike Windows DNS Client CPU. Import anyway?"))
        {
            return;
        }

        StatusText = $"Importing {source.Name}…";
        var result = await _client.Lists.ImportBlocklistAsync(new BlocklistRequest { Name = source.Name, Url = source.Url });
        StatusText = FormatResult(result);
        await RefreshAsync();
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
        var health = report.Count != 0 ? $" [{string.Join(", ", report)}]" : string.Empty;
        var warn = r.Warning.Length != 0 ? $" — {r.Warning}" : string.Empty;
        return $"{r.Message}{health}{warn}";
    }

    [RelayCommand]
    public async Task UnsubscribeAsync(BlocklistSourceViewModel source)
    {
        var ack = await _client.Lists.RemoveBlocklistSubscriptionAsync(new BlocklistRequest { Name = source.Name });
        StatusText = ack.Message;
        await RefreshAsync();
    }

    [RelayCommand]
    public async Task RefreshAllListsAsync()
    {
        StatusText = "Refreshing all subscriptions…";
        var result = await _client.Lists.RefreshBlocklistsAsync(new Empty());
        StatusText = FormatResult(result);
        await RefreshAsync();
    }

    [RelayCommand]
    public async Task SaveAllowlistsAsync()
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
    }
}
