using System.Collections.ObjectModel;
using System.IO;
using System.Runtime.Versioning;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Grpc.Core;
using HostsGuard.App.Services;
using HostsGuard.Contracts;

namespace HostsGuard.App.ViewModels;

/// <summary>
/// Hosts Activity tab: a snapshot of recent DNS sightings (GetActivity) kept
/// live by the WatchDns server-stream. Row actions round-trip through the
/// service. Collection mutations marshal to the captured UI context; in
/// headless tests (no context) they run inline.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed partial class HostsActivityViewModel : ObservableObject, IDisposable
{
    private const int MaxRows = 1000;

    private readonly HostsServiceClient _client;
    private readonly SynchronizationContext? _ui;
    private CancellationTokenSource? _watchCts;

    [ObservableProperty]
    private string _filter = string.Empty;

    [ObservableProperty]
    private bool _showHidden;

    [ObservableProperty]
    private string _statusText = "Ready";

    public HostsActivityViewModel(HostsServiceClient client)
    {
        _client = client ?? throw new ArgumentNullException(nameof(client));
        _ui = SynchronizationContext.Current;
    }

    public ObservableCollection<ActivityRowViewModel> Rows { get; } = new();

    partial void OnShowHiddenChanged(bool value) => _ = RefreshAsync();

    [RelayCommand]
    public async Task RefreshAsync()
    {
        var list = await _client.Hosts.GetActivityAsync(new ActivityRequest
        {
            Search = Filter,
            IncludeHidden = ShowHidden,
        });
        Rows.Clear();
        foreach (var row in list.Rows)
        {
            Rows.Add(ActivityRowViewModel.From(row));
        }

        StatusText = $"{Rows.Count} domains in feed";
    }

    /// <summary>Start consuming the live DNS stream until disposed.</summary>
    public void StartWatching()
    {
        if (_watchCts is not null)
        {
            return;
        }

        _watchCts = new CancellationTokenSource();
        _ = WatchLoopAsync(_watchCts.Token);
    }

    private async Task WatchLoopAsync(CancellationToken ct)
    {
        try
        {
            using var call = _client.Monitoring.WatchDns(new Empty(), cancellationToken: ct);
            await foreach (var ev in call.ResponseStream.ReadAllAsync(ct))
            {
                OnUi(() => Upsert(ev));
            }
        }
        catch (Exception ex) when (ex is RpcException or OperationCanceledException or IOException)
        {
            OnUi(() => StatusText = ct.IsCancellationRequested ? StatusText : "Live feed disconnected");
        }
    }

    private void Upsert(DnsEvent ev)
    {
        var existing = Rows.FirstOrDefault(r => r.Domain == ev.Domain);
        if (existing is not null)
        {
            existing.Hits++;
            existing.LastSeen = DateTime.Now.ToString("o", System.Globalization.CultureInfo.InvariantCulture);
            if (!string.IsNullOrEmpty(ev.Process))
            {
                existing.Process = ev.Process;
            }

            var idx = Rows.IndexOf(existing);
            if (idx > 0)
            {
                Rows.Move(idx, 0);
            }

            return;
        }

        Rows.Insert(0, new ActivityRowViewModel
        {
            Domain = ev.Domain,
            Root = Core.Domains.GetRoot(ev.Domain),
            Status = ev.Blocked ? "blocked" : string.Empty,
            Process = ev.Process,
            Hits = 1,
            LastSeen = DateTime.Now.ToString("o", System.Globalization.CultureInfo.InvariantCulture),
        });
        while (Rows.Count > MaxRows)
        {
            Rows.RemoveAt(Rows.Count - 1);
        }
    }

    private void OnUi(Action action)
    {
        if (_ui is null)
        {
            action();
        }
        else
        {
            _ui.Post(_ => action(), null);
        }
    }

    [RelayCommand]
    public async Task BlockAsync(string domain)
    {
        var ack = await _client.Hosts.BlockAsync(new DomainRequest { Domain = domain, Source = "feed" });
        StatusText = ack.Message;
        await RefreshAsync();
    }

    [RelayCommand]
    public async Task AllowAsync(string domain)
    {
        var ack = await _client.Hosts.AllowAsync(new DomainRequest { Domain = domain, Source = "feed" });
        StatusText = ack.Message;
        await RefreshAsync();
    }

    [RelayCommand]
    public async Task BlockRootAsync(string domain)
    {
        var ack = await _client.Hosts.BlockRootAsync(new DomainRequest { Domain = domain, Source = "feed" });
        StatusText = ack.Message;
        await RefreshAsync();
    }

    [RelayCommand]
    public Task TempAllow15Async(string domain) => TempAllowAsync(domain, 15);

    [RelayCommand]
    public Task TempAllow60Async(string domain) => TempAllowAsync(domain, 60);

    [RelayCommand]
    public Task TempAllow480Async(string domain) => TempAllowAsync(domain, 480);

    private async Task TempAllowAsync(string domain, int minutes)
    {
        var ack = await _client.Hosts.TempAllowAsync(new TempAllowRequest { Domain = domain, Minutes = minutes });
        StatusText = ack.Message;
        await RefreshAsync();
    }

    [RelayCommand]
    public async Task HideRootAsync(string domain)
    {
        var ack = await _client.Hosts.HideRootAsync(new DomainRequest { Domain = domain });
        StatusText = ack.Message;
        await RefreshAsync();
    }

    [RelayCommand]
    public async Task UnhideRootAsync(string domain)
    {
        var ack = await _client.Hosts.UnhideRootAsync(new DomainRequest { Domain = domain });
        StatusText = ack.Message;
        await RefreshAsync();
    }

    [RelayCommand]
    public void ResearchGoogle(string domain) => Research.Open(Research.Sites[0].UrlTemplate, domain);

    [RelayCommand]
    public void ResearchVirusTotal(string domain) => Research.Open(Research.Sites[1].UrlTemplate, domain);

    [RelayCommand]
    public void ResearchWhois(string domain) => Research.Open(Research.Sites[2].UrlTemplate, domain);

    public void Dispose()
    {
        _watchCts?.Cancel();
        _watchCts?.Dispose();
        _watchCts = null;
    }
}
