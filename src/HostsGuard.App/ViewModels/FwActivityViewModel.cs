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

    /// <summary>Site the remote IP was resolved as (ETW DNS); "" when unknown.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ResearchTarget))]
    private string _host = string.Empty;

    /// <summary>AI explanation of what this connection is likely for; "" until identified.</summary>
    [ObservableProperty]
    private string _info = string.Empty;

    /// <summary>
    /// The identity to research (NET-121): the resolved domain when known —
    /// the meaningful identity — else the raw remote IP.
    /// </summary>
    public string ResearchTarget => Host.Length != 0 ? Host : RemoteAddr;

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
    [NotifyPropertyChangedFor(nameof(DecidedAtText))]
    private string _decidedAt = string.Empty;

    /// <summary>Compact display form of <see cref="DecidedAt"/>.</summary>
    public string DecidedAtText => TimeText.Compact(DecidedAt);

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

/// <summary>Row VM for a Learning-mode auto-decision awaiting review (NET-074).</summary>
public sealed partial class LearnedRowViewModel : ObservableObject
{
    [ObservableProperty]
    private string _ruleName = string.Empty;

    [ObservableProperty]
    private string _application = string.Empty;

    [ObservableProperty]
    private string _direction = string.Empty;

    [ObservableProperty]
    private string _serviceName = string.Empty;
}

/// <summary>Row VM for a recorded (historical) connection (NET-070).</summary>
public sealed partial class HistoryRowViewModel : ObservableObject
{
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(TsText))]
    private string _ts = string.Empty;

    /// <summary>Compact display form of <see cref="Ts"/>.</summary>
    public string TsText => TimeText.Compact(Ts);

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

/// <summary>Row VM for the persisted structured event ledger.</summary>
public sealed partial class EventLogRowViewModel : ObservableObject
{
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(TsText))]
    private string _ts = string.Empty;

    public string TsText => TimeText.Compact(Ts);

    [ObservableProperty]
    private string _category = string.Empty;

    [ObservableProperty]
    private string _action = string.Empty;

    [ObservableProperty]
    private string _reason = string.Empty;

    [ObservableProperty]
    private string _domain = string.Empty;

    [ObservableProperty]
    private string _process = string.Empty;

    [ObservableProperty]
    private string _details = string.Empty;
}

/// <summary>One ordered factor from the rule decision simulator.</summary>
public sealed partial class DecisionStepViewModel : ObservableObject
{
    [ObservableProperty]
    private int _order;

    [ObservableProperty]
    private string _layer = string.Empty;

    [ObservableProperty]
    private string _outcome = string.Empty;

    [ObservableProperty]
    private string _owner = string.Empty;

    [ObservableProperty]
    private string _detail = string.Empty;

    [ObservableProperty]
    private string _nextAction = string.Empty;

    public string Header => $"{Order}. {Outcome} - {Layer}";
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
    private readonly IFilePicker? _filePicker;
    private readonly SynchronizationContext? _ui;
    private readonly List<(DateTime Ts, string Process)> _events = new();
    private CancellationTokenSource? _watchCts;
    private DateTime _lastTimelineCompute = DateTime.MinValue;
    private bool _suppressPostureWrite;
    private bool _suppressModeWrite;
    private bool _liveStatusOwnsText = true;

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

    [ObservableProperty]
    private string _explainInput = string.Empty;

    [ObservableProperty]
    private string _decisionSummary = "Select a connection or enter a target to explain.";

    [ObservableProperty]
    private string _decisionNextAction = string.Empty;

    public FwActivityViewModel(HostsServiceClient client, IConfirm confirm, AppConfigStore? config = null,
        IFilePicker? filePicker = null)
    {
        _client = client ?? throw new ArgumentNullException(nameof(client));
        _confirm = confirm ?? throw new ArgumentNullException(nameof(confirm));
        _config = config;
        _filePicker = filePicker;
        _ui = SynchronizationContext.Current;
        if (_config is not null)
        {
            _suppressModeWrite = true;
            LearningMode = _config.LearningMode;
            ObserveMode = _config.ObserveMode;
            SoundOnBlock = _config.SoundOnBlock;
            GroupByApp = _config.GetViewFlag("fw_group_by_app", true);
            GroupByCountry = _config.GetViewFlag("fw_group_by_country");
            ResolveIps = _config.GetViewFlag("fw_resolve_ips");
            _suppressModeWrite = false;
        }
    }

    public ObservableCollection<ConnectionRowViewModel> Rows { get; } = new();

    public ObservableCollection<TimelineSeriesViewModel> Timeline { get; } = new();

    public ObservableCollection<DecisionStepViewModel> DecisionChain { get; } = new();

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

    /// <summary>Group the live connections by remote country (NET-124), a triage axis.</summary>
    [ObservableProperty]
    private bool _groupByCountry;

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

    // ─── Reverse-DNS via the service (persisted, remembered forever) ──────────

    /// <summary>IP→host learned this session; applied to rows as they arrive.</summary>
    private readonly Dictionary<string, string> _resolvedHosts = new(StringComparer.Ordinal);

    [ObservableProperty]
    private bool _resolveIps;

    partial void OnResolveIpsChanged(bool value)
    {
        if (!_suppressModeWrite)
        {
            _config?.SaveViewFlag("fw_resolve_ips", value);
        }

        if (value)
        {
            _ = ResolvePendingHostsAsync();
        }
    }

    /// <summary>
    /// Reverse-resolve every visible row without a host through the service,
    /// which persists each result so future connections to the same IP show
    /// the host automatically — even after a restart.
    /// </summary>
    private async Task ResolvePendingHostsAsync()
    {
        var ips = Rows.Where(r => r.Host.Length == 0)
            .Select(r => r.RemoteAddr)
            .Where(a => a.Length != 0 && !_resolvedHosts.ContainsKey(a))
            .Distinct(StringComparer.Ordinal)
            .ToList();
        if (ips.Count == 0)
        {
            ApplyResolvedHosts();
            return;
        }

        SetOperatorStatus($"Resolving {ips.Count} addresses…");
        try
        {
            var request = new ResolveHostsRequest();
            request.Addresses.AddRange(ips);
            var result = await _client.Dns.ResolveHostsAsync(request);
            foreach (var entry in result.Hosts.Where(h => h.Host.Length != 0))
            {
                _resolvedHosts[entry.Address] = entry.Host;
            }

            var applied = ApplyResolvedHosts();
            SetOperatorStatus($"Resolved {applied} of {ips.Count} addresses");
        }
        catch (Exception ex) when (ex is Grpc.Core.RpcException or IOException)
        {
            SetOperatorStatus(ServiceErrors.DescribeActionFailure("Resolve remote IPs", ex));
        }
    }

    /// <summary>Fill any row whose IP we've resolved but whose host is still blank.</summary>
    private int ApplyResolvedHosts()
    {
        var applied = 0;
        foreach (var row in Rows)
        {
            if (row.Host.Length == 0 && _resolvedHosts.TryGetValue(row.RemoteAddr, out var host))
            {
                row.Host = host;
                applied++;
            }
        }

        return applied;
    }

    // ─── AI connection identification (DeepSeek) ──────────────────────────────

    /// <summary>Learned key(host|ip)→info map, applied to current and future rows.</summary>
    private readonly Dictionary<string, string> _connectionInfo = new(StringComparer.Ordinal);

    private static string InfoKey(ConnectionRowViewModel row)
        => (row.Host.Length != 0 ? row.Host : row.RemoteAddr).ToLowerInvariant();

    [RelayCommand]
    public async Task IdentifyConnectionsAsync()
    {
        await RunServiceActionAsync("Identify connections", async () =>
        {
            var pending = Rows.Where(r => r.Info.Length == 0).ToList();
            if (pending.Count == 0)
            {
                SetOperatorStatus("Every connection is already identified");
                return;
            }

            SetOperatorStatus($"Asking DeepSeek about {Plural.Of(pending.Count, "connection")}…");
            var request = new IdentifyRequest();
            foreach (var row in pending)
            {
                request.Items.Add(new IdentifyItem
                {
                    RemoteAddr = row.RemoteAddr,
                    Host = row.Host,
                    Process = row.Process,
                    RemotePort = row.RemotePort,
                });
            }

            var result = await _client.Hosts.IdentifyConnectionsAsync(request);
            SetOperatorStatus(result.Message);
            if (!result.Ok)
            {
                return;
            }

            foreach (var item in result.Items)
            {
                _connectionInfo[item.Key] = item.Info;
            }

            foreach (var row in Rows)
            {
                if (row.Info.Length == 0 && _connectionInfo.TryGetValue(InfoKey(row), out var info))
                {
                    row.Info = info;
                }
            }
        });
    }

    [RelayCommand]
    public async Task ExplainInputAsync()
    {
        var target = (ExplainInput ?? string.Empty).Trim();
        if (target.Length == 0)
        {
            DecisionSummary = "Enter a domain, IP, process, or executable path to explain.";
            DecisionNextAction = string.Empty;
            DecisionChain.Clear();
            return;
        }

        await ExplainDecisionAsync(new DecisionExplainRequest { Target = target });
    }

    [RelayCommand]
    public async Task ExplainSelectedAsync(ConnectionRowViewModel? row)
    {
        if (row is null)
        {
            DecisionSummary = "Select a connection first.";
            DecisionNextAction = string.Empty;
            DecisionChain.Clear();
            return;
        }

        var programPath = ResolveProgramPath(row.Pid);
        ExplainInput = row.ResearchTarget;
        await ExplainDecisionAsync(new DecisionExplainRequest
        {
            Domain = row.Host,
            RemoteAddr = row.RemoteAddr,
            RemotePort = row.RemotePort,
            Protocol = row.Protocol,
            Process = row.Process,
            ProgramPath = programPath,
            Direction = "Out",
            Service = row.Service,
        });
    }

    private async Task ExplainDecisionAsync(DecisionExplainRequest request)
    {
        try
        {
            var result = await _client.Firewall.ExplainDecisionAsync(request);
            DecisionChain.Clear();
            foreach (var step in result.Steps)
            {
                DecisionChain.Add(new DecisionStepViewModel
                {
                    Order = step.Order,
                    Layer = step.Layer,
                    Outcome = step.Outcome,
                    Owner = step.Owner,
                    Detail = step.Detail,
                    NextAction = step.NextAction,
                });
            }

            DecisionSummary = $"{result.Verdict}: {result.Summary}";
            DecisionNextAction = result.NextSafeAction;
            SetOperatorStatus(result.Summary);
        }
        catch (Exception ex) when (ex is Grpc.Core.RpcException or IOException)
        {
            DecisionSummary = "Decision explanation failed - service unavailable";
            DecisionNextAction = "Reconnect from the status bar, then retry.";
            DecisionChain.Clear();
            SetOperatorStatus(DecisionSummary);
        }
    }

    partial void OnGroupByAppChanged(bool value)
    {
        if (_view is not null)
        {
            ApplyGrouping(_view);
        }

        if (!_suppressModeWrite)
        {
            _config?.SaveViewFlag("fw_group_by_app", value);
        }
    }

    partial void OnGroupByCountryChanged(bool value)
    {
        if (_view is not null)
        {
            ApplyGrouping(_view);
        }

        if (!_suppressModeWrite)
        {
            _config?.SaveViewFlag("fw_group_by_country", value);
        }
    }

    private void ApplyGrouping(ICollectionView view)
    {
        view.GroupDescriptions.Clear();
        // Country first (outer), then app (inner) when both axes are on (NET-124).
        if (GroupByCountry)
        {
            view.GroupDescriptions.Add(new PropertyGroupDescription(nameof(ConnectionRowViewModel.Country)));
        }

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

        var cts = new CancellationTokenSource();
        _watchCts = cts;
        _ = WatchLoopAsync(cts);
    }

    private async Task WatchLoopAsync(CancellationTokenSource owner)
    {
        var ct = owner.Token;
        var failures = 0;
        try
        {
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    using var call = _client.Monitoring.WatchConnections(new Empty(), cancellationToken: ct);
                    failures = 0;
                    await foreach (var ev in call.ResponseStream.ReadAllAsync(ct))
                    {
                        OnUi(() => Upsert(ev));
                    }
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested)
                {
                    break;
                }
                catch (Exception ex) when (WatchRetry.IsStreamFailure(ex))
                {
                    if (ct.IsCancellationRequested)
                    {
                        break;
                    }

                    if (WatchRetry.IsAuthenticationFailure(ex))
                    {
                        OnUi(() => SetLiveStatus("Live feed authentication expired - reconnect to the service", force: true));
                        break;
                    }

                    OnUi(() => SetLiveStatus("Live feed disconnected - retrying", force: true));
                }

                if (!ct.IsCancellationRequested)
                {
                    try
                    {
                        await Task.Delay(WatchRetry.Delay(failures++), ct);
                    }
                    catch (OperationCanceledException)
                    {
                        break;
                    }
                }
            }
        }
        finally
        {
            if (ReferenceEquals(_watchCts, owner))
            {
                _watchCts = null;
                owner.Dispose();
            }
        }
    }

    // Keyed index over Rows so live upserts are O(1) instead of a linear scan
    // of up to MaxRows on every connection event.
    private readonly Dictionary<string, ConnectionRowViewModel> _rowByKey = new(StringComparer.Ordinal);

    private void Upsert(ConnectionEvent ev)
    {
        var key = $"{ev.Protocol}|{ev.LocalAddr}:{ev.LocalPort}|{ev.RemoteAddr}:{ev.RemotePort}|{ev.Pid}";
        if (_rowByKey.TryGetValue(key, out var existing))
        {
            existing.State = ev.State;
            existing.FwStatus = ev.FwStatus;
            if (ev.Host.Length != 0)
            {
                existing.Host = ev.Host; // the resolution can arrive after the first sighting
            }

            return;
        }

        var row = new ConnectionRowViewModel
        {
            Protocol = ev.Protocol,
            LocalAddr = ev.LocalAddr,
            LocalPort = ev.LocalPort,
            RemoteAddr = ev.RemoteAddr,
            RemotePort = ev.RemotePort,
            Host = ev.Host,
            Process = ev.Process,
            Pid = ev.Pid,
            State = ev.State,
            Country = ev.Country,
            FwStatus = ev.FwStatus,
            Service = ev.Service,
        };
        if (_connectionInfo.TryGetValue(InfoKey(row), out var knownInfo))
        {
            row.Info = knownInfo;
        }

        if (row.Host.Length == 0 && _resolvedHosts.TryGetValue(row.RemoteAddr, out var knownHost))
        {
            row.Host = knownHost; // already resolved this session
        }

        Rows.Insert(0, row);
        _rowByKey[key] = row;
        if (ResolveIps && row.Host.Length == 0)
        {
            _ = ResolvePendingHostsAsync();
        }
        while (Rows.Count > MaxRows)
        {
            var evicted = Rows[^1];
            Rows.RemoveAt(Rows.Count - 1);
            _rowByKey.Remove(evicted.Key);
        }

        SetLiveStatus(Plural.Of(Rows.Count, "connection"));
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

        TimelineStatus = $"Top {Plural.Of(top.Count, "app")} · last {TimelineMinutes} min · peak {peak}/min";
    }

    // ─── Connection history + per-app bandwidth (NET-070) ────────────────────

    public ObservableCollection<HistoryRowViewModel> HistoryRows { get; } = new();

    public ObservableCollection<EventLogRowViewModel> EventRows { get; } = new();

    public ObservableCollection<TimelineSeriesViewModel> Bandwidth { get; } = new();

    public static IReadOnlyList<string> EventCategories { get; } = new[]
    {
        string.Empty,
        "hosts",
        "firewall",
        "consent",
        "dns",
        "lists",
        "policy",
        "defender",
        "support",
        "other",
    };

    [ObservableProperty]
    private string _historySearch = string.Empty;

    [ObservableProperty]
    private string _historyStatus = "Click Load to show recorded connections.";

    [ObservableProperty]
    private string _eventSearch = string.Empty;

    [ObservableProperty]
    private string _eventSince = string.Empty;

    [ObservableProperty]
    private string _eventUntil = string.Empty;

    [ObservableProperty]
    private string _eventAction = string.Empty;

    [ObservableProperty]
    private string _eventReason = string.Empty;

    [ObservableProperty]
    private string _eventDomain = string.Empty;

    [ObservableProperty]
    private string _eventProcess = string.Empty;

    [ObservableProperty]
    private string _eventCategory = string.Empty;

    [ObservableProperty]
    private string _eventStatus = "Click Load events to browse the persisted event ledger.";

    [ObservableProperty]
    private int _eventLimit = 200;

    [ObservableProperty]
    private int _eventOffset;

    [ObservableProperty]
    private string _bandwidthStatus = "Not loaded";

    [ObservableProperty]
    private int _retentionDays = 30;

    [RelayCommand]
    public async Task LoadHistoryAsync()
    {
        await RunServiceActionAsync("Load connection history", s => HistoryStatus = s, async () =>
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

            HistoryStatus = $"{Plural.Of(HistoryRows.Count, "recorded connection")} · retained {Plural.Of(RetentionDays, "day")}";
            await LoadBandwidthAsync();
        });
    }

    [RelayCommand]
    public async Task LoadEventsAsync()
    {
        await RunServiceActionAsync("Load event log", s => EventStatus = s, async () =>
        {
            var limit = Math.Clamp(EventLimit <= 0 ? 200 : EventLimit, 1, 2000);
            EventLimit = limit;
            EventOffset = Math.Max(0, EventOffset);
            var events = await _client.Monitoring.ListEventsAsync(new EventLogRequest
            {
                Limit = limit,
                Offset = EventOffset,
                Search = EventSearch ?? string.Empty,
                Since = EventSince ?? string.Empty,
                Until = EventUntil ?? string.Empty,
                Action = EventAction ?? string.Empty,
                Reason = EventReason ?? string.Empty,
                Domain = EventDomain ?? string.Empty,
                Process = EventProcess ?? string.Empty,
                Category = EventCategory ?? string.Empty,
            });
            EventRows.Clear();
            foreach (var row in events.Entries)
            {
                EventRows.Add(new EventLogRowViewModel
                {
                    Ts = row.Ts,
                    Category = row.Category,
                    Action = row.Action,
                    Reason = row.Reason,
                    Domain = row.Domain,
                    Process = row.Process,
                    Details = row.Details,
                });
            }

            EventStatus = $"{Plural.Of(EventRows.Count, "event")} shown of {Plural.Of(events.Total, "match")} · offset {events.Offset}";
        });
    }

    [RelayCommand]
    public async Task PreviousEventsPageAsync()
    {
        EventOffset = Math.Max(0, EventOffset - Math.Max(1, EventLimit));
        await LoadEventsAsync();
    }

    [RelayCommand]
    public async Task NextEventsPageAsync()
    {
        EventOffset += Math.Max(1, EventLimit);
        await LoadEventsAsync();
    }

    [RelayCommand]
    public async Task SaveRetentionAsync()
    {
        await RunServiceActionAsync("Save history retention", s => HistoryStatus = s, async () =>
        {
            var ack = await _client.Monitoring.SetHistorySettingsAsync(new HistorySettings { RetentionDays = RetentionDays });
            HistoryStatus = ack.Message;
        });
    }

    /// <summary>Export the loaded connection history to a CSV file (NET-091).</summary>
    [RelayCommand]
    public void ExportHistoryCsv()
    {
        if (_filePicker is null)
        {
            return;
        }

        if (HistoryRows.Count == 0)
        {
            HistoryStatus = "Load history first — nothing to export.";
            return;
        }

        var path = _filePicker.SaveFile("Export connection history (CSV)", "connection_history.csv",
            "CSV files (*.csv)|*.csv");
        if (string.IsNullOrEmpty(path))
        {
            return;
        }

        try
        {
            System.IO.File.WriteAllText(path, BuildHistoryCsv(HistoryRows));
            HistoryStatus = $"Exported {Plural.Of(HistoryRows.Count, "connection")} to {System.IO.Path.GetFileName(path)}";
        }
        catch (Exception ex) when (ex is System.IO.IOException or UnauthorizedAccessException)
        {
            HistoryStatus = $"Export failed: {ex.Message}";
        }
    }

    /// <summary>Serialize connection-history rows to CSV (RFC-4180 quoting). Pure — unit-tested.</summary>
    public static string BuildHistoryCsv(IEnumerable<HistoryRowViewModel> rows)
    {
        var sb = new System.Text.StringBuilder();
        sb.Append("When,Process,PID,Protocol,Remote,Port,Country,Firewall\r\n");
        foreach (var r in rows)
        {
            sb.Append(Csv(r.Ts)).Append(',')
              .Append(Csv(r.Process)).Append(',')
              .Append(r.Pid).Append(',')
              .Append(Csv(r.Protocol)).Append(',')
              .Append(Csv(r.RemoteAddr)).Append(',')
              .Append(r.RemotePort).Append(',')
              .Append(Csv(r.Country)).Append(',')
              .Append(Csv(r.FwStatus)).Append("\r\n");
        }

        return sb.ToString();

        static string Csv(string? v)
        {
            v ??= string.Empty;
            return v.IndexOfAny(new[] { ',', '"', '\n', '\r' }) >= 0
                ? "\"" + v.Replace("\"", "\"\"", StringComparison.Ordinal) + "\""
                : v;
        }
    }

    public async Task LoadBandwidthAsync()
    {
        await RunServiceActionAsync("Load bandwidth timeline", s => BandwidthStatus = s, async () =>
        {
            var list = await _client.Monitoring.GetAppBandwidthAsync(new BandwidthRequest { Minutes = 60, Top = TimelineMaxSeries });
            BuildBandwidthSeries(list);
        });
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

        BandwidthStatus = $"Top {Plural.Of(list.Series.Count, "app")} · last 60 min · peak {FormatBytes(peak)}/min";
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

    /// <summary>Most-triggered apps: (application, count), highest first (NET-085).</summary>
    public ObservableCollection<string> TopTriggered { get; } = new();

    [ObservableProperty]
    private bool _soundOnBlock;

    [RelayCommand]
    public async Task LoadConsentHistoryAsync()
    {
        await RunServiceActionAsync("Load consent history", async () =>
        {
            var history = await _client.Consent.GetDecisionHistoryAsync(new HistoryRequest { Limit = 200 });
            ConsentHistory.Clear();
            foreach (var entry in history.Entries.Take(50))
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

            // Rank the apps that trigger the most decisions (NET-085).
            TopTriggered.Clear();
            foreach (var group in history.Entries
                         .Where(e => e.Application.Length != 0)
                         .GroupBy(e => System.IO.Path.GetFileName(e.Application), StringComparer.OrdinalIgnoreCase)
                         .Select(g => (App: g.Key, Count: g.Count()))
                         .OrderByDescending(g => g.Count)
                         .ThenBy(g => g.App, StringComparer.OrdinalIgnoreCase)
                         .Take(5))
            {
                TopTriggered.Add($"{group.App} — {group.Count}");
            }
        });
    }

    partial void OnSoundOnBlockChanged(bool value)
    {
        if (!_suppressModeWrite)
        {
            _config?.SaveSoundOnBlock(value);
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

        await RunServiceActionAsync($"{verdict} connection decision", async () =>
        {
            var ack = await _client.Consent.DecideAsync(new ConnectionDecision
            {
                Application = row.Application,
                Direction = row.Direction,
                RemoteAddress = row.RemoteAddress,
                Protocol = row.Protocol,
                Verdict = verdict,
                Permanent = true,
            });
            SetOperatorStatus(ack.Message);
            await LoadConsentHistoryAsync();
        });
    }

    // ─── "Decide later" review of Learning-mode auto-decisions (NET-074) ─────

    public ObservableCollection<LearnedRowViewModel> Learned { get; } = new();

    [ObservableProperty]
    private string _learnedStatus = "No learning-mode decisions awaiting review.";

    [RelayCommand]
    public async Task LoadLearnedAsync()
    {
        await RunServiceActionAsync("Load learned decisions", s => LearnedStatus = s, async () =>
        {
            var list = await _client.Consent.GetLearnedAsync(new Empty());
            Learned.Clear();
            foreach (var e in list.Entries)
            {
                Learned.Add(new LearnedRowViewModel
                {
                    RuleName = e.RuleName,
                    Application = e.Application,
                    Direction = e.Direction,
                    ServiceName = e.ServiceName,
                });
            }

            LearnedStatus = Learned.Count == 0
                ? "No learning-mode decisions awaiting review"
                : $"{Plural.Of(Learned.Count, "auto-allowed app")} awaiting review";
        });
    }

    [RelayCommand]
    public Task PromoteLearnedAsync(LearnedRowViewModel row) => ReviewLearnedAsync("promote", row);

    [RelayCommand]
    public Task BlockLearnedAsync(LearnedRowViewModel row) => ReviewLearnedAsync("block", row);

    [RelayCommand]
    public Task DiscardLearnedAsync(LearnedRowViewModel row) => ReviewLearnedAsync("discard", row);

    [RelayCommand]
    public Task PromoteAllLearnedAsync() => ReviewLearnedAsync("promote", Learned.ToArray());

    [RelayCommand]
    public Task DiscardAllLearnedAsync() => ReviewLearnedAsync("discard", Learned.ToArray());

    private async Task ReviewLearnedAsync(string action, params LearnedRowViewModel[] rows)
    {
        if (rows.Length == 0)
        {
            return;
        }

        await RunServiceActionAsync($"{action} learned decision", s => LearnedStatus = s, async () =>
        {
            var request = new LearnedReviewRequest();
            foreach (var row in rows.Where(r => r is not null))
            {
                request.Actions.Add(new LearnedReviewAction { RuleName = row.RuleName, Action = action });
            }

            var ack = await _client.Consent.ReviewLearnedAsync(request);
            LearnedStatus = ack.Message;
            await LoadLearnedAsync();
            await LoadConsentHistoryAsync();
        });
    }

    // ─── Modes: lockdown (service posture) + learning/observe (config) ───────

    /// <summary>Pull the current default-outbound posture from the service.</summary>
    public async Task LoadPostureAsync()
    {
        await RunServiceActionAsync("Load firewall posture", s => PostureText = s, async () =>
        {
            var posture = await _client.Firewall.GetPostureAsync(new Empty());
            _suppressPostureWrite = true;
            try
            {
                Lockdown = posture.Available && posture.Lockdown;
            }
            finally
            {
                _suppressPostureWrite = false;
            }

            PostureText = !posture.Available
                ? "Firewall posture unavailable"
                : string.Join("  ", posture.Profiles.Select(p =>
                    $"{p.Name}: {(p.Enabled ? "on" : "OFF")}/{(p.OutboundBlock ? "block" : "allow")}"));
        });
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
            "Block new outbound traffic on every firewall profile unless an allow rule already covers it?"))
        {
            _suppressPostureWrite = true;
            Lockdown = false;
            _suppressPostureWrite = false;
            return;
        }

        try
        {
            var ack = await _client.Firewall.SetDefaultOutboundAsync(new OutboundRequest { Block = enable });
            SetOperatorStatus(ack.Message);
            if (!ack.Ok)
            {
                // Don't pretend: revert the toggle when the policy change failed.
                _suppressPostureWrite = true;
                Lockdown = !enable;
                _suppressPostureWrite = false;
            }

            await LoadPostureAsync();
        }
        catch (Exception ex) when (ex is RpcException || ServiceErrors.IsConnectivity(ex))
        {
            SetOperatorStatus(ServiceErrors.DescribeActionFailure("Apply lockdown posture", ex));
            _suppressPostureWrite = true;
            Lockdown = !enable;
            _suppressPostureWrite = false;
        }
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

    private void SetLiveStatus(string text, bool force = false)
    {
        if (!force && !_liveStatusOwnsText)
        {
            return;
        }

        StatusText = text;
        _liveStatusOwnsText = true;
    }

    private void SetOperatorStatus(string text)
    {
        StatusText = text;
        _liveStatusOwnsText = false;
    }

    [RelayCommand]
    public async Task QuickBlockIpAsync(string remoteAddr)
    {
        if (string.IsNullOrWhiteSpace(remoteAddr))
        {
            SetOperatorStatus("Select a row first");
            return;
        }

        await RunServiceActionAsync("Block remote IP", async () =>
        {
            var ack = await _client.Firewall.BlockIpAsync(new FirewallIpRequest { Address = remoteAddr, Direction = "Outbound" });
            SetOperatorStatus(ack.Message);
        });
    }

    [RelayCommand]
    public async Task QuickBlockProcessAsync(ConnectionRowViewModel? row)
    {
        if (row is null)
        {
            SetOperatorStatus("Select a row first");
            return;
        }

        if (row.Pid <= 0)
        {
            SetOperatorStatus("No PID for this connection");
            return;
        }

        string path;
        try
        {
            path = System.Diagnostics.Process.GetProcessById(row.Pid).MainModule?.FileName ?? string.Empty;
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            SetOperatorStatus($"Cannot resolve program for PID {row.Pid}");
            return;
        }

        if (path.Length == 0)
        {
            SetOperatorStatus($"Cannot resolve program for PID {row.Pid}");
            return;
        }

        await RunServiceActionAsync("Block process", async () =>
        {
            var ack = await _client.Firewall.BlockProgramAsync(new FirewallProgramRequest { ProgramPath = path, Direction = "Outbound" });
            SetOperatorStatus(ack.Message);
        });
    }

    private static string ResolveProgramPath(int pid)
    {
        if (pid <= 0)
        {
            return string.Empty;
        }

        try
        {
            return System.Diagnostics.Process.GetProcessById(pid).MainModule?.FileName ?? string.Empty;
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            return string.Empty;
        }
    }

    /// <summary>
    /// NET-115: pivot a connection to a domain rule — block the row's resolved site
    /// (hostname) via the hosts file, the durable driver-free rule since IPs rotate.
    /// Falls back to blocking the IP when the row has no resolved host, so the
    /// action is never a no-op.
    /// </summary>
    [RelayCommand]
    public async Task BlockSiteAsync(ConnectionRowViewModel? row)
    {
        if (row is null)
        {
            SetOperatorStatus("Select a row first");
            return;
        }

        var host = row.Host.Trim().ToLowerInvariant();
        if (HostsGuard.Core.Domains.LooksLikeDomain(host))
        {
            await RunServiceActionAsync("Block site", async () =>
            {
                var ack = await _client.Hosts.BlockAsync(new DomainRequest { Domain = host, Source = "connection" });
                SetOperatorStatus(ack.Ok ? $"Blocked {host} in hosts" : ack.Message);
            });
        }
        else if (!string.IsNullOrWhiteSpace(row.RemoteAddr))
        {
            await QuickBlockIpAsync(row.RemoteAddr);
        }
        else
        {
            SetOperatorStatus("No site or address to block for this row");
        }
    }

    /// <summary>NET-115: allow (whitelist) the row's resolved site via the hosts file.</summary>
    [RelayCommand]
    public async Task AllowSiteAsync(ConnectionRowViewModel? row)
    {
        var host = (row?.Host ?? string.Empty).Trim().ToLowerInvariant();
        if (!HostsGuard.Core.Domains.LooksLikeDomain(host))
        {
            SetOperatorStatus("This row has no resolved domain to allow");
            return;
        }

        await RunServiceActionAsync("Allow site", async () =>
        {
            var ack = await _client.Hosts.AllowAsync(new DomainRequest { Domain = host, Source = "connection" });
            SetOperatorStatus(ack.Ok ? $"Allowed {host} in hosts" : ack.Message);
        });
    }

    /// <summary>Per-app scope block (NET-076): "internet" | "lan" | "localhost" | "inbound".</summary>
    [RelayCommand]
    public async Task BlockScopeAsync(string parameter)
    {
        // Parameter is "<scope>|<pid>" from the split menu so one command serves all scopes.
        var parts = (parameter ?? string.Empty).Split('|', 2);
        if (parts.Length != 2 || !int.TryParse(parts[1], out var pid) || pid <= 0)
        {
            SetOperatorStatus("No PID for this connection");
            return;
        }

        string path;
        try
        {
            path = System.Diagnostics.Process.GetProcessById(pid).MainModule?.FileName ?? string.Empty;
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            SetOperatorStatus($"Cannot resolve program for PID {pid}");
            return;
        }

        if (path.Length == 0)
        {
            SetOperatorStatus($"Cannot resolve program for PID {pid}");
            return;
        }

        await RunServiceActionAsync("Block app scope", async () =>
        {
            var ack = await _client.Firewall.BlockAppScopeAsync(new AppScopeRequest { ProgramPath = path, Scope = parts[0] });
            SetOperatorStatus(ack.Message);
        });
    }

    [RelayCommand]
    public void ResearchGoogle(string remoteAddr) => Research.Open(Research.Sites[0].UrlTemplate, remoteAddr);

    // NET-121: VirusTotal + who.is on the connection's resolved domain (or IP).
    [RelayCommand]
    public void ResearchVirusTotal(string target) => Research.Open(Research.Sites[1].UrlTemplate, target);

    [RelayCommand]
    public void ResearchWhois(string target) => Research.Open(Research.Sites[2].UrlTemplate, target);

    [RelayCommand]
    public void ResearchAbuseIpdb(string remoteAddr) => Research.Open(Research.Sites[7].UrlTemplate, remoteAddr);

    private Task RunServiceActionAsync(string action, Func<Task> work) =>
        ServiceActionGuard.RunAsync(action, SetOperatorStatus, work);

    private static Task RunServiceActionAsync(string action, Action<string> setStatus, Func<Task> work) =>
        ServiceActionGuard.RunAsync(action, setStatus, work);

    public void Dispose()
    {
        var watch = _watchCts;
        _watchCts = null;
        watch?.Cancel();
        watch?.Dispose();
    }
}
