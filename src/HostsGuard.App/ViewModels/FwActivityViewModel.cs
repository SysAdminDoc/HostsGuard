using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Runtime.Versioning;
using System.Windows.Data;
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

    /// <summary>Owning SCM service display name(s) (NET-073); "" for plain apps.</summary>
    [ObservableProperty]
    private string _service = string.Empty;

    public string Key => $"{Protocol}|{LocalAddr}:{LocalPort}|{RemoteAddr}:{RemotePort}|{Pid}";
}

/// <summary>Row VM for a recorded consent decision (WFCP-021 history).</summary>
public sealed partial class DecisionRowViewModel : ObservableObject
{
    [ObservableProperty]
    private string _decidedAt = string.Empty;

    [ObservableProperty]
    private string _application = string.Empty;

    [ObservableProperty]
    private string _direction = string.Empty;

    [ObservableProperty]
    private string _remoteAddress = string.Empty;

    [ObservableProperty]
    private string _protocol = string.Empty;

    [ObservableProperty]
    private string _verdict = string.Empty;

    [ObservableProperty]
    private bool _permanent;

    public string Scope => Permanent ? "permanent" : "once";
}

/// <summary>One timeline series: per-minute new-connection counts for a process.</summary>
public sealed partial class TimelineSeriesViewModel : ObservableObject
{
    [ObservableProperty]
    private string _name = string.Empty;

    /// <summary>Polyline points on a 600×100 canvas ("x,y x,y …").</summary>
    [ObservableProperty]
    private string _pointsText = string.Empty;

    [ObservableProperty]
    private int _colorIndex;

    /// <summary>Legend suffix (e.g. bandwidth totals); empty for count series.</summary>
    [ObservableProperty]
    private string _legendText = string.Empty;
}

/// <summary>Row VM for a recorded (historical) connection (NET-070).</summary>
public sealed partial class HistoryRowViewModel : ObservableObject
{
    [ObservableProperty]
    private string _ts = string.Empty;

    [ObservableProperty]
    private string _process = string.Empty;

    [ObservableProperty]
    private int _pid;

    [ObservableProperty]
    private string _protocol = string.Empty;

    [ObservableProperty]
    private string _remoteAddr = string.Empty;

    [ObservableProperty]
    private int _remotePort;

    [ObservableProperty]
    private string _country = string.Empty;

    [ObservableProperty]
    private string _fwStatus = string.Empty;
}

/// <summary>
/// FW Activity tab: live connections from the WatchConnections stream with
/// quick-block (IP / program) actions that create visible HG_ COM rules, a
/// per-app activity timeline, and the lockdown / learning / observe mode
/// toggles (lockdown = service-side default-outbound posture; learning and
/// observe persist to the config.json keys shared with the Python build).
/// </summary>
[SupportedOSPlatform("windows")]
public sealed partial class FwActivityViewModel : ObservableObject, IDisposable
{
    private const int MaxRows = 2000;

    // Timeline geometry + window (canvas coordinates are normalized by a Viewbox).
    public const int TimelineMinutes = 30;
    public const double TimelineWidth = 600;
    public const double TimelineHeight = 100;
    private const int TimelineMaxSeries = 5;
    private static readonly TimeSpan TimelineRecomputeInterval = TimeSpan.FromSeconds(5);

    private readonly HostsServiceClient _client;
    private readonly IConfirm _confirm;
    private readonly AppConfigStore? _config;
    private readonly SynchronizationContext? _ui;
    private readonly List<(DateTime Ts, string Process)> _events = new();
    private CancellationTokenSource? _watchCts;
    private DateTime _lastTimelineCompute = DateTime.MinValue;
    private bool _suppressPostureWrite;
    private bool _suppressModeWrite;

    [ObservableProperty]
    private string _filter = string.Empty;

    [ObservableProperty]
    private string _statusText = "Waiting for live connections…";

    [ObservableProperty]
    private bool _lockdown;

    [ObservableProperty]
    private string _postureText = string.Empty;

    [ObservableProperty]
    private bool _learningMode;

    [ObservableProperty]
    private bool _observeMode;

    [ObservableProperty]
    private string _timelineStatus = "No activity yet";

    public FwActivityViewModel(HostsServiceClient client, IConfirm confirm, AppConfigStore? config = null)
    {
        _client = client ?? throw new ArgumentNullException(nameof(client));
        _confirm = confirm ?? throw new ArgumentNullException(nameof(confirm));
        _config = config;
        _ui = SynchronizationContext.Current;
        if (_config is not null)
        {
            _suppressModeWrite = true;
            LearningMode = _config.LearningMode;
            ObserveMode = _config.ObserveMode;
            _suppressModeWrite = false;
        }
    }

    public ObservableCollection<ConnectionRowViewModel> Rows { get; } = new();

    public ObservableCollection<TimelineSeriesViewModel> Timeline { get; } = new();

    // ─── Grouped + searchable live view (NET-071) ─────────────────────────────

    /// <summary>Search-DSL field aliases for the live-connection filter.</summary>
    private static readonly Dictionary<string, string> FilterAliases = new(StringComparer.Ordinal)
    {
        ["proto"] = "protocol",
        ["addr"] = "remote",
        ["ip"] = "remote",
        ["app"] = "process",
        ["status"] = "fw",
    };

    private ICollectionView? _view;

    [ObservableProperty]
    private bool _groupByApp = true;

    /// <summary>
    /// The live-connection view: filtered by the shared search DSL
    /// (<c>field:value</c>, <c>!term</c>, <c>field!=value</c>) and optionally
    /// grouped by owning process.
    /// </summary>
    public ICollectionView ConnectionsView
    {
        get
        {
            if (_view is null)
            {
                _view = CollectionViewSource.GetDefaultView(Rows);
                _view.Filter = o => o is ConnectionRowViewModel r && MatchesFilter(r);
                ApplyGrouping(_view);
            }

            return _view;
        }
    }

    /// <summary>Whether a row matches the current search query (shared DSL).</summary>
    public bool MatchesFilter(ConnectionRowViewModel row)
    {
        ArgumentNullException.ThrowIfNull(row);
        if (string.IsNullOrWhiteSpace(Filter))
        {
            return true;
        }

        return Core.SearchQuery.Matches(new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["process"] = row.Process,
            ["pid"] = row.Pid.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["protocol"] = row.Protocol,
            ["remote"] = row.RemoteAddr,
            ["port"] = row.RemotePort.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["state"] = row.State,
            ["country"] = row.Country,
            ["fw"] = row.FwStatus,
            ["service"] = row.Service,
        }, Filter, FilterAliases);
    }

    partial void OnFilterChanged(string value) => _view?.Refresh();

    partial void OnGroupByAppChanged(bool value)
    {
        if (_view is not null)
        {
            ApplyGrouping(_view);
        }
    }

    private void ApplyGrouping(ICollectionView view)
    {
        view.GroupDescriptions.Clear();
        if (GroupByApp)
        {
            view.GroupDescriptions.Add(new PropertyGroupDescription(nameof(ConnectionRowViewModel.Process)));
        }
    }

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
            Service = ev.Service,
        });
        while (Rows.Count > MaxRows)
        {
            Rows.RemoveAt(Rows.Count - 1);
        }

        StatusText = $"{Rows.Count} connections";
        RecordConnectionEvent(DateTime.Now, ev.Process);
    }

    // ─── Per-app activity timeline ────────────────────────────────────────────

    /// <summary>Record a new-connection event; recomputes the timeline (throttled).</summary>
    public void RecordConnectionEvent(DateTime ts, string process)
    {
        var name = string.IsNullOrWhiteSpace(process) ? "(unknown)" : process;
        _events.Add((ts, name));
        var cutoff = ts.AddMinutes(-(TimelineMinutes + 5));
        _events.RemoveAll(e => e.Ts < cutoff);
        if (ts - _lastTimelineCompute >= TimelineRecomputeInterval)
        {
            RecomputeTimeline(ts);
        }
    }

    /// <summary>Rebuild the polyline series from the raw event window.</summary>
    public void RecomputeTimeline(DateTime now)
    {
        _lastTimelineCompute = now;
        var start = now.AddMinutes(-(TimelineMinutes - 1));
        var origin = new DateTime(start.Year, start.Month, start.Day, start.Hour, start.Minute, 0, start.Kind);

        var buckets = new Dictionary<string, int[]>(StringComparer.OrdinalIgnoreCase);
        foreach (var (ts, process) in _events)
        {
            var slot = (int)(ts - origin).TotalMinutes;
            if (slot < 0 || slot >= TimelineMinutes)
            {
                continue;
            }

            if (!buckets.TryGetValue(process, out var counts))
            {
                counts = new int[TimelineMinutes];
                buckets[process] = counts;
            }

            counts[slot]++;
        }

        var top = buckets
            .OrderByDescending(kv => kv.Value.Sum())
            .ThenBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase)
            .Take(TimelineMaxSeries)
            .ToList();

        Timeline.Clear();
        if (top.Count == 0)
        {
            TimelineStatus = "No activity yet";
            return;
        }

        var peak = Math.Max(1, top.Max(kv => kv.Value.Max()));
        var stepX = TimelineWidth / (TimelineMinutes - 1);
        for (var s = 0; s < top.Count; s++)
        {
            var points = new System.Text.StringBuilder();
            for (var i = 0; i < TimelineMinutes; i++)
            {
                var x = i * stepX;
                var y = TimelineHeight - (top[s].Value[i] / (double)peak * (TimelineHeight - 6)) - 2;
                if (i != 0)
                {
                    points.Append(' ');
                }

                points.Append(x.ToString("0.#", System.Globalization.CultureInfo.InvariantCulture))
                      .Append(',')
                      .Append(y.ToString("0.#", System.Globalization.CultureInfo.InvariantCulture));
            }

            Timeline.Add(new TimelineSeriesViewModel
            {
                Name = top[s].Key,
                PointsText = points.ToString(),
                ColorIndex = s,
            });
        }

        TimelineStatus = $"Top {top.Count} apps · last {TimelineMinutes} min · peak {peak}/min";
    }

    // ─── Connection history + per-app bandwidth (NET-070) ────────────────────

    public ObservableCollection<HistoryRowViewModel> HistoryRows { get; } = new();

    public ObservableCollection<TimelineSeriesViewModel> Bandwidth { get; } = new();

    [ObservableProperty]
    private string _historySearch = string.Empty;

    [ObservableProperty]
    private string _historyStatus = string.Empty;

    [ObservableProperty]
    private string _bandwidthStatus = "Not loaded";

    [ObservableProperty]
    private int _retentionDays = 30;

    [RelayCommand]
    public async Task LoadHistoryAsync()
    {
        var settings = await _client.Monitoring.GetHistorySettingsAsync(new Empty());
        RetentionDays = settings.RetentionDays;
        var history = await _client.Monitoring.GetConnectionHistoryAsync(new ConnectionHistoryRequest
        {
            Limit = 500,
            Search = HistorySearch ?? string.Empty,
        });
        HistoryRows.Clear();
        foreach (var row in history.Rows)
        {
            HistoryRows.Add(new HistoryRowViewModel
            {
                Ts = row.Ts,
                Process = row.Process,
                Pid = row.Pid,
                Protocol = row.Protocol,
                RemoteAddr = row.RemoteAddr,
                RemotePort = row.RemotePort,
                Country = row.Country,
                FwStatus = row.FwStatus,
            });
        }

        HistoryStatus = $"{HistoryRows.Count} recorded connections · retained {RetentionDays} days";
        await LoadBandwidthAsync();
    }

    [RelayCommand]
    public async Task SaveRetentionAsync()
    {
        var ack = await _client.Monitoring.SetHistorySettingsAsync(new HistorySettings { RetentionDays = RetentionDays });
        HistoryStatus = ack.Message;
    }

    public async Task LoadBandwidthAsync()
    {
        var list = await _client.Monitoring.GetAppBandwidthAsync(new BandwidthRequest { Minutes = 60, Top = TimelineMaxSeries });
        BuildBandwidthSeries(list);
    }

    /// <summary>Rebuild the bandwidth polylines from a fetched series list (pure; testable).</summary>
    public void BuildBandwidthSeries(AppBandwidthList list)
    {
        ArgumentNullException.ThrowIfNull(list);
        Bandwidth.Clear();
        if (list.Series.Count == 0)
        {
            BandwidthStatus = list.CountersActive
                ? "No traffic recorded yet"
                : "Byte counters inactive (service not elevated)";
            return;
        }

        var peak = Math.Max(1, list.Series.Max(s => s.Bytes.Count == 0 ? 0 : s.Bytes.Max()));
        for (var i = 0; i < list.Series.Count; i++)
        {
            var s = list.Series[i];
            var points = new System.Text.StringBuilder();
            var stepX = s.Bytes.Count > 1 ? TimelineWidth / (s.Bytes.Count - 1) : 0;
            for (var b = 0; b < s.Bytes.Count; b++)
            {
                var x = b * stepX;
                var y = TimelineHeight - (s.Bytes[b] / (double)peak * (TimelineHeight - 6)) - 2;
                if (b != 0)
                {
                    points.Append(' ');
                }

                points.Append(x.ToString("0.#", System.Globalization.CultureInfo.InvariantCulture))
                      .Append(',')
                      .Append(y.ToString("0.#", System.Globalization.CultureInfo.InvariantCulture));
            }

            Bandwidth.Add(new TimelineSeriesViewModel
            {
                Name = s.Process,
                PointsText = points.ToString(),
                ColorIndex = i,
                LegendText = $"↑{FormatBytes(s.TotalSent)} ↓{FormatBytes(s.TotalRecv)}",
            });
        }

        BandwidthStatus = $"Top {list.Series.Count} apps · last 60 min · peak {FormatBytes(peak)}/min";
    }

    /// <summary>Humanized byte count ("1.4 MB").</summary>
    public static string FormatBytes(long bytes)
    {
        string[] units = ["B", "KB", "MB", "GB", "TB"];
        double value = Math.Max(0, bytes);
        var unit = 0;
        while (value >= 1024 && unit < units.Length - 1)
        {
            value /= 1024;
            unit++;
        }

        return string.Create(System.Globalization.CultureInfo.InvariantCulture, $"{value:0.#} {units[unit]}");
    }

    // ─── Consent history (WFCP-021): recent prompts with re-decide ───────────

    public ObservableCollection<DecisionRowViewModel> ConsentHistory { get; } = new();

    [RelayCommand]
    public async Task LoadConsentHistoryAsync()
    {
        var history = await _client.Consent.GetDecisionHistoryAsync(new HistoryRequest { Limit = 50 });
        ConsentHistory.Clear();
        foreach (var entry in history.Entries)
        {
            ConsentHistory.Add(new DecisionRowViewModel
            {
                DecidedAt = entry.DecidedAt,
                Application = entry.Application,
                Direction = entry.Direction,
                RemoteAddress = entry.RemoteAddress,
                Protocol = entry.Protocol,
                Verdict = entry.Verdict,
                Permanent = entry.Permanent,
            });
        }
    }

    [RelayCommand]
    public Task ReAllowAsync(DecisionRowViewModel row) => ReDecideAsync(row, "allow");

    [RelayCommand]
    public Task ReBlockAsync(DecisionRowViewModel row) => ReDecideAsync(row, "block");

    private async Task ReDecideAsync(DecisionRowViewModel? row, string verdict)
    {
        if (row is null)
        {
            return;
        }

        var ack = await _client.Consent.DecideAsync(new ConnectionDecision
        {
            Application = row.Application,
            Direction = row.Direction,
            RemoteAddress = row.RemoteAddress,
            Protocol = row.Protocol,
            Verdict = verdict,
            Permanent = true,
        });
        StatusText = ack.Message;
        await LoadConsentHistoryAsync();
    }

    // ─── Modes: lockdown (service posture) + learning/observe (config) ───────

    /// <summary>Pull the current default-outbound posture from the service.</summary>
    public async Task LoadPostureAsync()
    {
        var posture = await _client.Firewall.GetPostureAsync(new Empty());
        _suppressPostureWrite = true;
        Lockdown = posture.Available && posture.Lockdown;
        _suppressPostureWrite = false;
        PostureText = !posture.Available
            ? "Firewall posture unavailable"
            : string.Join("  ", posture.Profiles.Select(p =>
                $"{p.Name}: {(p.Enabled ? "on" : "OFF")}/{(p.OutboundBlock ? "block" : "allow")}"));
    }

    partial void OnLockdownChanged(bool value)
    {
        if (_suppressPostureWrite)
        {
            return;
        }

        _ = ApplyLockdownAsync(value);
    }

    private async Task ApplyLockdownAsync(bool enable)
    {
        if (enable && !_confirm.Confirm("Enable lockdown",
            "Set the default outbound action to Block on every firewall profile? " +
            "New outbound connections are blocked unless a rule allows them."))
        {
            _suppressPostureWrite = true;
            Lockdown = false;
            _suppressPostureWrite = false;
            return;
        }

        var ack = await _client.Firewall.SetDefaultOutboundAsync(new OutboundRequest { Block = enable });
        StatusText = ack.Message;
        if (!ack.Ok)
        {
            // Don't pretend: revert the toggle when the policy change failed.
            _suppressPostureWrite = true;
            Lockdown = !enable;
            _suppressPostureWrite = false;
        }

        await LoadPostureAsync();
    }

    partial void OnLearningModeChanged(bool value)
    {
        if (!_suppressModeWrite)
        {
            _config?.SaveModes(value, ObserveMode);
        }
    }

    partial void OnObserveModeChanged(bool value)
    {
        if (!_suppressModeWrite)
        {
            _config?.SaveModes(LearningMode, value);
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
