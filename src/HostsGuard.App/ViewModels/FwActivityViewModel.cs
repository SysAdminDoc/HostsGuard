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
using HostsGuard.Core;

namespace HostsGuard.App.ViewModels;

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
    private const int MaxQuicProcesses = 100;

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
    private readonly Dictionary<string, HashSet<string>> _quicEndpoints = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, QuicProcessRowViewModel> _quicProcessByKey = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _quicSteeredPrograms = new(StringComparer.OrdinalIgnoreCase);

    [ObservableProperty]
    private string _filter = string.Empty;

    [ObservableProperty]
    private string _statusText = I18n.T("FwActivity_WaitingLive", "Waiting for live connections…");

    [ObservableProperty]
    private string _integrityStatusText = string.Empty;

    [ObservableProperty]
    private bool _lockdown;

    [ObservableProperty]
    private string _postureText = string.Empty;

    [ObservableProperty]
    private bool _learningMode;

    [ObservableProperty]
    private bool _observeMode;

    [ObservableProperty]
    private string _timelineStatus = I18n.T("FwActivity_NoActivity", "No activity yet");

    [ObservableProperty]
    private string _explainInput = string.Empty;

    [ObservableProperty]
    private string _decisionSummary = I18n.T("FwActivity_ExplainPrompt", "Select a connection or enter a target to explain.");

    [ObservableProperty]
    private string _decisionNextAction = string.Empty;

    [ObservableProperty]
    private bool _flowTeardownEnabled;

    [ObservableProperty]
    private string _flowTeardownText = I18n.T("FwPosture_TeardownOff", "TCP teardown: off");

    private bool _suppressFlowTeardownWrite;

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

    public ObservableCollection<QuicProcessRowViewModel> QuicProcesses { get; } = new();

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

        SetOperatorStatus(ips.Count == 1
            ? I18n.T("FwActivity_ResolvingAddress", "Resolving {0} address…", ips.Count)
            : I18n.T("FwActivity_ResolvingAddresses", "Resolving {0} addresses…", ips.Count));
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
            SetOperatorStatus(ips.Count == 1
                ? I18n.T("FwActivity_ResolvedAddress", "Resolved {0} of {1} address", applied, ips.Count)
                : I18n.T("FwActivity_ResolvedAddresses", "Resolved {0} of {1} addresses", applied, ips.Count));
        }
        catch (Exception ex) when (ex is Grpc.Core.RpcException or IOException)
        {
            SetOperatorStatus(ServiceErrors.DescribeActionFailure(I18n.T("FwActivity_ActionResolveIps", "Resolve remote IPs"), ex));
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
        await RunServiceActionAsync(I18n.T("FwActivity_ActionIdentify", "Identify connections"), async () =>
        {
            var pending = Rows.Where(r => r.Info.Length == 0).ToList();
            if (pending.Count == 0)
            {
                SetOperatorStatus(I18n.T("FwActivity_AllIdentified", "Every connection is already identified"));
                return;
            }

            SetOperatorStatus(pending.Count == 1
                ? I18n.T("FwActivity_IdentifyingConnection", "Asking DeepSeek about {0} connection…", pending.Count)
                : I18n.T("FwActivity_IdentifyingConnections", "Asking DeepSeek about {0} connections…", pending.Count));
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
            DecisionSummary = I18n.T("FwActivity_ExplainTargetRequired", "Enter a domain, IP, process, or executable path to explain.");
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
            DecisionSummary = I18n.T("FwActivity_SelectConnectionFirstPeriod", "Select a connection first.");
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

            DecisionSummary = I18n.T("FwActivity_DecisionSummary", "{0}: {1}", result.Verdict, result.Summary);
            DecisionNextAction = result.NextSafeAction;
            SetOperatorStatus(result.Summary);
        }
        catch (Exception ex) when (ex is Grpc.Core.RpcException or IOException)
        {
            DecisionSummary = I18n.T("FwActivity_ExplainUnavailable", "Decision explanation failed — service unavailable");
            DecisionNextAction = I18n.T("FwActivity_ExplainReconnect", "Reconnect from the status bar, then retry.");
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
        _ = RefreshQuicSteerStateAsync(cts.Token);
        _ = IntegrityLoopAsync(cts.Token);
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
                        OnUi(() => SetLiveStatus(I18n.T("FwActivity_LiveAuthExpired", "Live feed authentication expired — reconnect to the service"), force: true));
                        break;
                    }

                    OnUi(() => SetLiveStatus(I18n.T("FwActivity_LiveDisconnected", "Live feed disconnected — retrying"), force: true));
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
                await owner.CancelAsync();
                _watchCts = null;
                owner.Dispose();
            }
        }
    }

    private async Task IntegrityLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            await RefreshIntegrityStatusAsync(ct);
            try
            {
                await Task.Delay(TimeSpan.FromSeconds(15), ct);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
    }

    private async Task RefreshIntegrityStatusAsync(CancellationToken ct)
    {
        try
        {
            var status = await _client.Diagnostics.GetStatusAsync(new Empty(), cancellationToken: ct);
            OnUi(() => IntegrityStatusText = ObservationIntegrityText.ForFeed(
                status, "network_etw", "security_log"));
        }
        catch (Exception ex) when (WatchRetry.IsStreamFailure(ex))
        {
            // The stream path owns connectivity messaging; retain last-known
            // completeness until the service can be queried again.
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
            Asn = ev.Asn,
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
        RecordQuicObservation(row, ResolveProgramPath(row.Pid));
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

        SetLiveStatus(Rows.Count == 1
            ? I18n.T("FwActivity_ConnectionCount", "{0} connection", Rows.Count)
            : I18n.T("FwActivity_ConnectionCountPlural", "{0} connections", Rows.Count));
        RecordConnectionEvent(DateTime.Now, ev.Process);
    }

    /// <summary>
    /// Record one newly observed UDP/443 connection tuple. The optional path is
    /// resolved by the live stream and injectable for deterministic tests.
    /// </summary>
    public void RecordQuicObservation(ConnectionRowViewModel row, string programPath = "")
    {
        ArgumentNullException.ThrowIfNull(row);
        if (!row.Protocol.Equals("UDP", StringComparison.OrdinalIgnoreCase) || row.RemotePort != 443)
        {
            return;
        }

        var path = programPath.Trim();
        var process = string.IsNullOrWhiteSpace(row.Process)
            ? I18n.T("Common_UnknownParenthesized", "(unknown)")
            : row.Process.Trim();
        var key = path.Length != 0 ? path : $"{process}|{row.Pid}";
        if (!_quicProcessByKey.TryGetValue(key, out var rollup))
        {
            rollup = new QuicProcessRowViewModel
            {
                Process = process,
                ProgramPath = path,
                Pid = row.Pid,
                IsSteered = path.Length != 0 && _quicSteeredPrograms.Contains(path),
            };
            _quicProcessByKey[key] = rollup;
            _quicEndpoints[key] = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            QuicProcesses.Add(rollup);
        }

        rollup.ConnectionCount++;
        rollup.Pid = row.Pid;
        rollup.LastEndpoint = FormatEndpoint(row.RemoteAddr, row.RemotePort);
        _quicEndpoints[key].Add(rollup.LastEndpoint);
        rollup.EndpointCount = _quicEndpoints[key].Count;
        ReorderQuicProcess(rollup);

        while (QuicProcesses.Count > MaxQuicProcesses)
        {
            var removed = QuicProcesses[^1];
            QuicProcesses.RemoveAt(QuicProcesses.Count - 1);
            var removedKey = _quicProcessByKey.First(pair => ReferenceEquals(pair.Value, removed)).Key;
            _quicProcessByKey.Remove(removedKey);
            _quicEndpoints.Remove(removedKey);
        }
    }

    private static string FormatEndpoint(string address, int port)
        => address.Contains(':', StringComparison.Ordinal) ? $"[{address}]:{port}" : $"{address}:{port}";

    private void ReorderQuicProcess(QuicProcessRowViewModel row)
    {
        QuicProcesses.Remove(row);
        var index = 0;
        while (index < QuicProcesses.Count &&
               (QuicProcesses[index].ConnectionCount > row.ConnectionCount ||
                (QuicProcesses[index].ConnectionCount == row.ConnectionCount &&
                 string.Compare(QuicProcesses[index].Process, row.Process, StringComparison.OrdinalIgnoreCase) <= 0)))
        {
            index++;
        }

        QuicProcesses.Insert(index, row);
    }

    private async Task RefreshQuicSteerStateAsync(CancellationToken ct)
    {
        try
        {
            var rules = await _client.Firewall.ListRulesAsync(new Empty(), cancellationToken: ct);
            var paths = rules.Rules
                .Where(static rule => rule.Enabled &&
                    rule.Name.StartsWith("HG_QuicSteer_", StringComparison.Ordinal) &&
                    rule.Protocol.Equals("UDP", StringComparison.OrdinalIgnoreCase) &&
                    rule.RemotePorts.Equals("443", StringComparison.Ordinal))
                .Select(static rule => rule.Program)
                .Where(static path => path.Length != 0)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
            OnUi(() =>
            {
                _quicSteeredPrograms.Clear();
                _quicSteeredPrograms.UnionWith(paths);
                foreach (var row in QuicProcesses)
                {
                    row.IsSteered = row.ProgramPath.Length != 0 && _quicSteeredPrograms.Contains(row.ProgramPath);
                }
            });
        }
        catch (Exception ex) when (WatchRetry.IsStreamFailure(ex))
        {
            // The live stream owns connectivity messaging; keep observed rows.
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // Normal shutdown while the initial posture read is in flight.
        }
    }

    // ─── Per-app activity timeline ────────────────────────────────────────────

    /// <summary>Record a new-connection event; recomputes the timeline (throttled).</summary>
    public void RecordConnectionEvent(DateTime ts, string process)
    {
        var name = string.IsNullOrWhiteSpace(process) ? I18n.T("Common_UnknownParenthesized", "(unknown)") : process;
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
            TimelineStatus = I18n.T("FwActivity_NoActivity", "No activity yet");
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

        TimelineStatus = top.Count == 1
            ? I18n.T("FwActivity_TimelineStatus", "Top {0} app · last {1} min · peak {2}/min", top.Count, TimelineMinutes, peak)
            : I18n.T("FwActivity_TimelineStatusPlural", "Top {0} apps · last {1} min · peak {2}/min", top.Count, TimelineMinutes, peak);
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
            SetOperatorStatus(I18n.T("Common_SelectRowFirst", "Select a row first"));
            return;
        }

        await RunServiceActionAsync(I18n.T("FwActivity_ActionBlockRemoteIp", "Block remote IP"), async () =>
        {
            var ack = await _client.Firewall.BlockIpAsync(new FirewallIpRequest { Address = remoteAddr, Direction = "Outbound" });
            SetOperatorStatus(ack.Message);
        });
    }

    [RelayCommand]
    public async Task CloseConnectionAsync(ConnectionRowViewModel? row)
    {
        if (row is null)
        {
            SetOperatorStatus(I18n.T("Common_SelectRowFirst", "Select a row first"));
            return;
        }

        await RunServiceActionAsync(I18n.T("FwActivity_ActionCloseConnection", "Close connection"), async () =>
        {
            var ack = await _client.Firewall.CloseConnectionAsync(new FlowCloseRequest
            {
                Protocol = row.Protocol,
                LocalAddr = row.LocalAddr,
                LocalPort = row.LocalPort,
                RemoteAddr = row.RemoteAddr,
                RemotePort = row.RemotePort,
                Process = row.Process,
            });
            SetOperatorStatus(ack.Message);
        });
    }

    [RelayCommand]
    public async Task QuickBlockProcessAsync(ConnectionRowViewModel? row)
    {
        if (row is null)
        {
            SetOperatorStatus(I18n.T("Common_SelectRowFirst", "Select a row first"));
            return;
        }

        if (row.Pid <= 0)
        {
            SetOperatorStatus(I18n.T("FwActivity_NoPid", "No PID for this connection"));
            return;
        }

        string path;
        try
        {
            path = System.Diagnostics.Process.GetProcessById(row.Pid).MainModule?.FileName ?? string.Empty;
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            SetOperatorStatus(I18n.T("FwActivity_CannotResolveProgram", "Cannot resolve program for PID {0}", row.Pid));
            return;
        }

        if (path.Length == 0)
        {
            SetOperatorStatus(I18n.T("FwActivity_CannotResolveProgram", "Cannot resolve program for PID {0}", row.Pid));
            return;
        }

        await RunServiceActionAsync(I18n.T("FwActivity_ActionBlockProcess", "Block process"), async () =>
        {
            var ack = await _client.Firewall.BlockProgramAsync(new FirewallProgramRequest { ProgramPath = path, Direction = "Outbound" });
            SetOperatorStatus(ack.Message);
        });
    }

    [RelayCommand]
    public async Task BlockQuicForProcessAsync(QuicProcessRowViewModel? row)
    {
        if (row is null)
        {
            SetOperatorStatus(I18n.T("QuicPosture_SelectProcess", "Select a QUIC process first"));
            return;
        }

        if (row.ProgramPath.Length == 0)
        {
            SetOperatorStatus(I18n.T("QuicPosture_CannotResolveProgram", "Cannot resolve the executable path for {0}", row.Process));
            return;
        }

        await RunServiceActionAsync(I18n.T("QuicPosture_Action", "Steer QUIC app to TCP"), async () =>
        {
            var ack = await _client.Firewall.BlockQuicForProgramAsync(new FirewallProgramRequest
            {
                ProgramPath = row.ProgramPath,
                Direction = "Outbound",
            });
            if (ack.Ok)
            {
                _quicSteeredPrograms.Add(row.ProgramPath);
                row.IsSteered = true;
            }

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
            SetOperatorStatus(I18n.T("Common_SelectRowFirst", "Select a row first"));
            return;
        }

        var host = row.Host.Trim().ToLowerInvariant();
        if (HostsGuard.Core.Domains.LooksLikeDomain(host))
        {
            await RunServiceActionAsync(I18n.T("FwActivity_ActionBlockSite", "Block site"), async () =>
            {
                var ack = await _client.Hosts.BlockAsync(new DomainRequest { Domain = host, Source = "connection" });
                SetOperatorStatus(ack.Ok ? I18n.T("FwActivity_BlockedInHosts", "Blocked {0} in hosts", host) : ack.Message);
            });
        }
        else if (!string.IsNullOrWhiteSpace(row.RemoteAddr))
        {
            await QuickBlockIpAsync(row.RemoteAddr);
        }
        else
        {
            SetOperatorStatus(I18n.T("FwActivity_NoBlockTarget", "No site or address to block for this row"));
        }
    }

    /// <summary>
    /// NET-154: block the row's resolved domain for this app only, using a
    /// DNS-following HG_Domain_* firewall rule instead of a global IP block.
    /// </summary>
    [RelayCommand]
    public async Task BlockDomainFirewallAsync(ConnectionRowViewModel? row)
    {
        if (row is null)
        {
            SetOperatorStatus(I18n.T("Common_SelectRowFirst", "Select a row first"));
            return;
        }

        var host = row.Host.Trim().ToLowerInvariant();
        if (!HostsGuard.Core.Domains.LooksLikeDomain(host))
        {
            SetOperatorStatus(I18n.T("FwActivity_NoDomainForFirewallRule", "This row has no resolved domain for a domain firewall rule"));
            return;
        }

        var path = ResolveProgramPath(row.Pid);
        if (path.Length == 0)
        {
            SetOperatorStatus(I18n.T("FwActivity_CannotResolveProgram", "Cannot resolve program for PID {0}", row.Pid));
            return;
        }

        await RunServiceActionAsync(I18n.T("FwActivity_ActionBlockSiteForApp", "Block site for this app"), async () =>
        {
            var ack = await _client.Firewall.CreateDomainFirewallRuleAsync(new DomainFirewallRuleRequest
            {
                Domain = host,
                ProgramPath = path,
            });
            SetOperatorStatus(ack.Message);
        });
    }

    /// <summary>NET-115: allow (whitelist) the row's resolved site via the hosts file.</summary>
    [RelayCommand]
    public async Task AllowSiteAsync(ConnectionRowViewModel? row)
    {
        var host = (row?.Host ?? string.Empty).Trim().ToLowerInvariant();
        if (!HostsGuard.Core.Domains.LooksLikeDomain(host))
        {
            SetOperatorStatus(I18n.T("FwActivity_NoDomainToAllow", "This row has no resolved domain to allow"));
            return;
        }

        await RunServiceActionAsync(I18n.T("FwActivity_ActionAllowSite", "Allow site"), async () =>
        {
            var ack = await _client.Hosts.AllowAsync(new DomainRequest { Domain = host, Source = "connection" });
            SetOperatorStatus(ack.Ok ? I18n.T("FwActivity_AllowedInHosts", "Allowed {0} in hosts", host) : ack.Message);
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
            SetOperatorStatus(I18n.T("FwActivity_NoPid", "No PID for this connection"));
            return;
        }

        string path;
        try
        {
            path = System.Diagnostics.Process.GetProcessById(pid).MainModule?.FileName ?? string.Empty;
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            SetOperatorStatus(I18n.T("FwActivity_CannotResolveProgram", "Cannot resolve program for PID {0}", pid));
            return;
        }

        if (path.Length == 0)
        {
            SetOperatorStatus(I18n.T("FwActivity_CannotResolveProgram", "Cannot resolve program for PID {0}", pid));
            return;
        }

        await RunServiceActionAsync(I18n.T("FwActivity_ActionBlockAppScope", "Block app scope"), async () =>
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
