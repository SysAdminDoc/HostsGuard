using System.Collections.ObjectModel;
using System.IO;
using System.Runtime.Versioning;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Grpc.Core;
using HostsGuard.App.Services;
using HostsGuard.Contracts;

namespace HostsGuard.App.ViewModels;

/// <summary>Row VM for a live connection.</summary>
public sealed partial class ConnectionRowViewModel : ObservableObject
{
    [ObservableProperty]
    private string _protocol = string.Empty;

    [ObservableProperty]
    private string _localAddr = string.Empty;

    [ObservableProperty]
    private int _localPort;

    [ObservableProperty]
    private string _remoteAddr = string.Empty;

    [ObservableProperty]
    private int _remotePort;

    [ObservableProperty]
    private string _process = string.Empty;

    [ObservableProperty]
    private int _pid;

    [ObservableProperty]
    private string _state = string.Empty;

    [ObservableProperty]
    private string _country = string.Empty;

    [ObservableProperty]
    private string _fwStatus = string.Empty;

    public string Key => $"{Protocol}|{LocalAddr}:{LocalPort}|{RemoteAddr}:{RemotePort}|{Pid}";
}

/// <summary>
/// FW Activity tab: live connections from the WatchConnections stream with
/// quick-block (IP / program) actions that create visible HG_ COM rules.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed partial class FwActivityViewModel : ObservableObject, IDisposable
{
    private const int MaxRows = 2000;

    private readonly HostsServiceClient _client;
    private readonly SynchronizationContext? _ui;
    private CancellationTokenSource? _watchCts;

    [ObservableProperty]
    private string _filter = string.Empty;

    [ObservableProperty]
    private string _statusText = "Waiting for live connections…";

    public FwActivityViewModel(HostsServiceClient client)
    {
        _client = client ?? throw new ArgumentNullException(nameof(client));
        _ui = SynchronizationContext.Current;
    }

    public ObservableCollection<ConnectionRowViewModel> Rows { get; } = new();

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
            using var call = _client.Monitoring.WatchConnections(new Empty(), cancellationToken: ct);
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

    private void Upsert(ConnectionEvent ev)
    {
        var key = $"{ev.Protocol}|{ev.LocalAddr}:{ev.LocalPort}|{ev.RemoteAddr}:{ev.RemotePort}|{ev.Pid}";
        var existing = Rows.FirstOrDefault(r => r.Key == key);
        if (existing is not null)
        {
            existing.State = ev.State;
            existing.FwStatus = ev.FwStatus;
            return;
        }

        Rows.Insert(0, new ConnectionRowViewModel
        {
            Protocol = ev.Protocol,
            LocalAddr = ev.LocalAddr,
            LocalPort = ev.LocalPort,
            RemoteAddr = ev.RemoteAddr,
            RemotePort = ev.RemotePort,
            Process = ev.Process,
            Pid = ev.Pid,
            State = ev.State,
            Country = ev.Country,
            FwStatus = ev.FwStatus,
        });
        while (Rows.Count > MaxRows)
        {
            Rows.RemoveAt(Rows.Count - 1);
        }

        StatusText = $"{Rows.Count} connections";
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
    public async Task QuickBlockIpAsync(string remoteAddr)
    {
        var ack = await _client.Firewall.BlockIpAsync(new FirewallIpRequest { Address = remoteAddr, Direction = "Outbound" });
        StatusText = ack.Message;
    }

    [RelayCommand]
    public async Task QuickBlockProcessAsync(ConnectionRowViewModel row)
    {
        if (row.Pid <= 0)
        {
            StatusText = "No PID for this connection";
            return;
        }

        string path;
        try
        {
            path = System.Diagnostics.Process.GetProcessById(row.Pid).MainModule?.FileName ?? string.Empty;
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            StatusText = $"Cannot resolve program for PID {row.Pid}";
            return;
        }

        if (path.Length == 0)
        {
            StatusText = $"Cannot resolve program for PID {row.Pid}";
            return;
        }

        var ack = await _client.Firewall.BlockProgramAsync(new FirewallProgramRequest { ProgramPath = path, Direction = "Outbound" });
        StatusText = ack.Message;
    }

    [RelayCommand]
    public void ResearchGoogle(string remoteAddr) => Research.Open(Research.Sites[0].UrlTemplate, remoteAddr);

    [RelayCommand]
    public void ResearchAbuseIpdb(string remoteAddr) => Research.Open(Research.Sites[7].UrlTemplate, remoteAddr);

    public void Dispose()
    {
        _watchCts?.Cancel();
        _watchCts?.Dispose();
        _watchCts = null;
    }
}
