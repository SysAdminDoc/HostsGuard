using System.IO;
using System.Runtime.Versioning;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Grpc.Core;
using HostsGuard.App.Services;
using HostsGuard.Contracts;

namespace HostsGuard.App.ViewModels;

/// <summary>
/// Shell ViewModel: owns the service connection, the per-tab ViewModels, the
/// status-bar state, and the theme/scale settings. The service-client factory
/// is injected so tests can point the whole shell at an in-process service.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed partial class MainViewModel : ObservableObject, IDisposable
{
    private readonly Func<HostsServiceClient> _connectFactory;
    private readonly AppConfigStore _config;
    private readonly ThemeManager _themes;
    private readonly IConfirm _confirm;
    private readonly IFilePicker? _filePicker;
    private readonly IPrompt? _prompt;
    private readonly IReleaseUpdateChecker _releaseUpdateChecker;
    private readonly SynchronizationContext? _ui = SynchronizationContext.Current;
    private HostsServiceClient? _client;
    private CancellationTokenSource? _decisionCts;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ConnectionStateTitle))]
    [NotifyPropertyChangedFor(nameof(PostureText))]
    [NotifyPropertyChangedFor(nameof(PostureIsSafe))]
    [NotifyPropertyChangedFor(nameof(FilteringModeTitle))]
    [NotifyPropertyChangedFor(nameof(FilteringModeDisplayText))]
    [NotifyPropertyChangedFor(nameof(EnforcementPauseTitle))]
    [NotifyPropertyChangedFor(nameof(EnforcementPauseDisplayText))]
    [NotifyPropertyChangedFor(nameof(ServiceVersionText))]
    [NotifyPropertyChangedFor(nameof(HostsBlockedText))]
    [NotifyPropertyChangedFor(nameof(DbBlockedText))]
    [NotifyPropertyChangedFor(nameof(DbAllowedText))]
    [NotifyPropertyChangedFor(nameof(ServiceCommandAvailabilityText))]
    [NotifyCanExecuteChangedFor(nameof(SetFilteringModeCommand))]
    [NotifyCanExecuteChangedFor(nameof(SetGlobalModeCommand))]
    [NotifyCanExecuteChangedFor(nameof(PauseEnforcementCommand))]
    [NotifyCanExecuteChangedFor(nameof(RestoreSafeNetworkPostureCommand))]
    [NotifyCanExecuteChangedFor(nameof(RunDiagnosticsCommand))]
    private bool _isConnected;

    [ObservableProperty]
    private string _connectionText = I18n.T("Status.Connecting", "Connecting to service…");

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ServiceVersionText))]
    private string _serviceVersion = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HostsBlockedText))]
    private int _hostsBlocked;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(DbBlockedText))]
    private int _dbBlocked;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(DbAllowedText))]
    private int _dbAllowed;

    [ObservableProperty]
    private HostsViewModel? _hosts;

    [ObservableProperty]
    private HostsActivityViewModel? _activity;

    [ObservableProperty]
    private RawHostsViewModel? _rawHosts;

    [ObservableProperty]
    private FwActivityViewModel? _fwActivity;

    [ObservableProperty]
    private AlertsViewModel? _alerts;

    [ObservableProperty]
    private FwRulesViewModel? _fwRules;

    [ObservableProperty]
    private ToolsViewModel? _tools;

    [ObservableProperty]
    private BlocklistsViewModel? _blocklists;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ThemeToggleText))]
    private string _theme;

    [ObservableProperty]
    private int _uiScalePct;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(FilteringModeTitle))]
    private string _filteringMode = "normal";

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(FilteringModeTitle))]
    [NotifyPropertyChangedFor(nameof(FilteringModeDisplayText))]
    private string _filteringModeText = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(EnforcementPauseTitle))]
    [NotifyPropertyChangedFor(nameof(PostureText))]
    [NotifyPropertyChangedFor(nameof(PostureIsSafe))]
    private bool _enforcementPauseActive;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(EnforcementPauseTitle))]
    [NotifyPropertyChangedFor(nameof(PostureText))]
    private bool _enforcementPauseSuspended;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(EnforcementPauseTitle))]
    [NotifyPropertyChangedFor(nameof(EnforcementPauseDisplayText))]
    private string _enforcementPauseText = I18n.T("Shell_EnforcementActive", "Enforcement active.");

    /// <summary>Child-process auto-allow (NET-093): direct children inherit a trusted parent's allow.</summary>
    [ObservableProperty]
    private bool _childInherit;

    /// <summary>Inbound-connection consent (NET-104): prompt on unruled inbound too (opt-in, default off).</summary>
    [ObservableProperty]
    private bool _inboundConsent;

    /// <summary>Raised on the UI thread when the service pushes a consent prompt.</summary>
    public event Action<ConnectionDecisionRequest>? DecisionRequested;

    public MainViewModel(
        Func<HostsServiceClient> connectFactory, AppConfigStore config, ThemeManager themes,
        IConfirm confirm, IFilePicker? filePicker = null, IPrompt? prompt = null,
        IReleaseUpdateChecker? releaseUpdateChecker = null)
    {
        _connectFactory = connectFactory ?? throw new ArgumentNullException(nameof(connectFactory));
        _config = config ?? throw new ArgumentNullException(nameof(config));
        _themes = themes ?? throw new ArgumentNullException(nameof(themes));
        _confirm = confirm ?? throw new ArgumentNullException(nameof(confirm));
        _filePicker = filePicker;
        _prompt = prompt;
        _releaseUpdateChecker = releaseUpdateChecker ?? ReleaseUpdateChecker.CreateDefault();
        _theme = config.Theme;
        _uiScalePct = config.UiScalePct;
    }

    /// <summary>LayoutTransform scale factor derived from the persisted percent.</summary>
    public double UiScale => UiScalePct / 100.0;

    public string AppVersion { get; } = typeof(MainViewModel).Assembly.GetName().Version?.ToString(3) ?? string.Empty;

    public string ConnectionStateTitle => IsConnected
        ? I18n.T("Shell_Connected", "Connected")
        : I18n.T("Shell_Disconnected", "Disconnected");

    /// <summary>
    /// Whether the top-band posture claim ("Safe posture") is actually true —
    /// only when connected AND enforcement is not paused/suspended. Drives the
    /// header's shield colour so it never reassures green while offline or paused.
    /// </summary>
    public bool PostureIsSafe => IsConnected && !EnforcementPauseActive;

    public string PostureText => !IsConnected
        ? I18n.T("Shell_PostureOffline", "Service offline")
        : EnforcementPauseActive
            ? (EnforcementPauseSuspended ? I18n.T("Shell_Suspended", "Suspended") : I18n.T("Shell_Paused", "Paused"))
            : I18n.T("TopBand_SafePosture", "Safe posture");

    // Localized status-bar counters (the label + value must translate together).
    public string HostsBlockedText => IsConnected
        ? I18n.T("Shell_StatusHostsFile", "Hosts file: {0}", HostsBlocked)
        : I18n.T("Shell_StatusHostsFileUnavailable", "Hosts file: unavailable");

    public string DbBlockedText => IsConnected
        ? I18n.T("Shell_StatusBlocked", "Blocked: {0}", DbBlocked)
        : I18n.T("Shell_StatusBlockedUnavailable", "Blocked: unavailable");

    public string DbAllowedText => IsConnected
        ? I18n.T("Shell_StatusAllowed", "Allowed: {0}", DbAllowed)
        : I18n.T("Shell_StatusAllowedUnavailable", "Allowed: unavailable");

    public string ServiceVersionText => IsConnected
        ? I18n.T("Shell_StatusService", "service {0}", ServiceVersion)
        : I18n.T("Shell_StatusServiceUnavailable", "service unavailable");

    public string ThemeToggleText => Theme == "dark"
        ? I18n.T("Shell_LightTheme", "Light theme")
        : I18n.T("Shell_DarkTheme", "Dark theme");

    public static IReadOnlyList<int> UiScaleChoices => AppConfigStore.UiScaleChoices;

    public string FilteringModeTitle => !IsConnected
        ? I18n.T("Shell_Unavailable", "Unavailable")
        : string.IsNullOrWhiteSpace(FilteringModeText)
            ? I18n.T("Shell_LoadingState", "Loading…")
        : FilteringMode switch
        {
            "notify" => I18n.T("Shell_ModeNotify", "Notify"),
            "learning" => I18n.T("Shell_ModeLearning", "Learning"),
            _ => I18n.T("Shell_ModeNormal", "Normal"),
        };

    public string FilteringModeDisplayText => IsConnected
        ? string.IsNullOrWhiteSpace(FilteringModeText)
            ? I18n.T("Shell_LoadingServiceState", "Loading service state…")
            : FilteringModeText
        : I18n.T("Shell_FilteringUnavailable", "Connect to view or change filtering mode.");

    public string EnforcementPauseTitle => !IsConnected
        ? I18n.T("Shell_Unavailable", "Unavailable")
        : string.IsNullOrWhiteSpace(EnforcementPauseText)
            ? I18n.T("Shell_LoadingState", "Loading…")
        : EnforcementPauseActive
            ? EnforcementPauseSuspended ? I18n.T("Shell_Suspended", "Suspended") : I18n.T("Shell_Paused", "Paused")
            : I18n.T("Shell_Active", "Active");

    public string EnforcementPauseDisplayText => IsConnected
        ? string.IsNullOrWhiteSpace(EnforcementPauseText)
            ? I18n.T("Shell_LoadingServiceState", "Loading service state…")
            : EnforcementPauseText
        : I18n.T("Shell_PostureUnavailable", "Connect to view or change global posture.");

    public string ServiceCommandAvailabilityText => IsConnected
        ? I18n.T("Shell_ServiceActionAvailable", "Available while connected to HostsGuardSvc.")
        : I18n.T("Shell_ServiceActionUnavailable", "Requires a connected HostsGuardSvc. Reconnect first.");

    [RelayCommand]
    public async Task ConnectAsync()
    {
        ResetConnection();

        try
        {
            _client = _connectFactory();
            var client = _client;
            var status = await client.Diagnostics.GetStatusAsync(new Empty());
            ServiceVersion = status.Version;
            HostsBlocked = status.HostsBlocked;
            DbBlocked = status.DbBlocked;
            DbAllowed = status.DbAllowed;
            InitializeViews(client);
            var hosts = Hosts!;
            var activity = Activity!;
            var rawHosts = RawHosts!;
            var fwActivity = FwActivity!;
            var alerts = Alerts!;
            var fwRules = FwRules!;
            var tools = Tools!;
            var blocklists = Blocklists!;
            IsConnected = true;
            ConnectionText = I18n.T("Status.ConnectedLoading", "Connected - loading views...");

            await hosts.RefreshAsync();
            await activity.RefreshAsync();
            activity.StartWatching();
            await rawHosts.LoadAsync();
            fwActivity.StartWatching();
            await fwActivity.LoadPostureAsync();
            await fwActivity.LoadFlowTeardownAsync();
            await fwActivity.LoadConsentHistoryAsync();
            await fwActivity.LoadLearnedAsync();
            await alerts.LoadAsync();
            await fwRules.RefreshAsync();
            await fwRules.LoadInterfaceAliasesAsync();
            await tools.LoadSchedulesAsync();
            await tools.LoadServicesAsync();
            await tools.LoadDohStatusAsync();
            await tools.LoadIdnHomographStatusAsync();
            await tools.LoadDnsAdaptersAsync();
            await tools.LoadResolverHealthAsync();
            await tools.LoadLanAttackSurfaceAsync();
            await tools.LoadProfilesAsync();
            await tools.LoadNetworkProfileRulesAsync();
            await tools.LoadPolicySubscriptionsAsync();
            await tools.LoadIpBlocklistsAsync();
            await tools.LoadHealthAsync();
            await tools.InspectProxyBaselineAsync();
            await tools.LoadDefenderStatusAsync();
            await tools.LoadBackupsAsync();
            await tools.LoadFullStateSnapshotsAsync();
            await tools.LoadSecureRulesAsync();
            await tools.LoadAiStatusAsync();
            await tools.LoadAdoptionStatusAsync();
            await tools.LoadIntelStatusAsync();
            await tools.LoadTrustedPublishersAsync();
            await tools.LoadTrustedFoldersAsync();
            await tools.LoadKillSwitchAsync();
            await tools.LoadAppVpnBindingsAsync();
            await blocklists.RefreshAsync();
            await LoadFilteringModeAsync();
            await LoadEnforcementPauseAsync();
            StartDecisionWatch();
            ConnectionText = I18n.T("Status.Connected", "Connected — service v{0}", status.Version)
                + (status.Elevated ? I18n.T("Shell_ElevatedSuffix", " (elevated)") : string.Empty);
        }
        catch (Exception ex)
        {
            ResetConnection();
            IsConnected = false;
            ConnectionText = I18n.T(
                "Status.Unavailable",
                "Service unavailable - start or restart HostsGuardSvc, then reconnect. Details: {0}",
                ex.Message);
        }
    }

    /// <summary>
    /// Builds a deterministic connected/populated shell for the release visual gate.
    /// No RPC is sent and no machine policy is read or mutated.
    /// </summary>
    internal void PrepareVisualSmokeFixture()
    {
        PrepareVisualSmokeConnectionFixture();

        ServiceVersion = AppVersion;
        HostsBlocked = 42;
        DbBlocked = 40;
        DbAllowed = 2;
        FilteringMode = "normal";
        FilteringModeText = "Normal — deterministic fixture";
        EnforcementPauseText = "Hosts and firewall enforcement active.";
        ConnectionText = "Connected — deterministic visual fixture";

        Activity!.Rows.Add(new ActivityRowViewModel
        {
            Domain = "telemetry.example.test",
            Root = "example.test",
            Status = "blocked",
            Process = "browser.exe",
            Hits = 27,
            LastSeen = "2026-07-14T12:00:00Z",
            Purpose = "Visual smoke telemetry",
            Reason = "Curated fixture",
            Bytes = 184_320,
            IsNew = true,
            SparklinePoints = "0,18 12,12 24,16 36,7 48,13 60,4",
        });
        Activity.Rows.Add(new ActivityRowViewModel
        {
            Domain = "cdn.example.test",
            Root = "example.test",
            Status = "allowed",
            Process = "updater.exe",
            Hits = 8,
            LastSeen = "2026-07-14T11:58:00Z",
            Purpose = "Content delivery",
            Reason = "Manual allow",
            Bytes = 2_621_440,
        });
        Activity.IntegrityStatusText = "Evidence is incomplete — DNS ETW degraded since 14:00 (lost 3, gaps 0, restarts 1): observing after buffer loss";

        Alerts!.Alerts.Add(new AlertRowViewModel
        {
            Id = 1,
            Created = "2026-07-14T11:55:00Z",
            Updated = "2026-07-14T11:55:00Z",
            Type = "hosts_tamper",
            Severity = "high",
            Title = "Hosts file change restored",
            Subject = "hosts",
            Details = "A deterministic external edit was detected and restored.",
            Action = "restored",
            Process = "fixture-editor.exe",
            Surfaced = true,
        });
        Alerts.UnreadCount = 1;
        Alerts.SelectedAlert = Alerts.Alerts[0];
        Alerts.StatusText = "1 deterministic alert";

        Hosts!.Domains.Add(new ManagedDomainViewModel
        {
            Domain = "telemetry.example.test",
            Status = "blocked",
            Source = "manual",
            Reason = "Visual smoke policy",
            Hits = 27,
            Category = "Telemetry",
        });
        Hosts.Domains.Add(new ManagedDomainViewModel
        {
            Domain = "cdn.example.test",
            Status = "whitelisted",
            Source = "manual",
            Reason = "Required content",
            Hits = 8,
            Category = "Infrastructure",
        });
        Hosts.StatusText = "2 deterministic managed domains";
        RawHosts!.Text = "# HostsGuard deterministic visual fixture\n0.0.0.0 telemetry.example.test\n";
        RawHosts.StatusText = "2 fixture lines";

        FwActivity!.Rows.Add(new ConnectionRowViewModel
        {
            Protocol = "TCP",
            LocalAddr = "192.0.2.10",
            LocalPort = 53142,
            RemoteAddr = "203.0.113.20",
            RemotePort = 443,
            Host = "api.example.test",
            Process = "browser.exe",
            Pid = 4711,
            State = "Established",
            Country = "US",
            Asn = "AS64500 Example Network",
            FwStatus = "Allowed",
        });
        FwActivity.Rows.Add(new ConnectionRowViewModel
        {
            Protocol = "UDP",
            LocalAddr = "192.0.2.10",
            LocalPort = 53000,
            RemoteAddr = "198.51.100.53",
            RemotePort = 53,
            Host = "resolver.example.test",
            Process = "system-service.exe",
            Pid = 902,
            State = "Observed",
            Country = "US",
            FwStatus = "Monitored",
        });
        FwActivity.StatusText = "2 deterministic live connections";
        FwActivity.IntegrityStatusText = "Evidence is incomplete — Security log degraded since 14:00 (lost 1, gaps 25, restarts 1): rollover detected";

        FwRules!.Rules.Add(new FwRuleViewModel
        {
            Name = "HG_Domain_browser_example_test",
            Direction = "Out",
            Action = "Block",
            Enabled = true,
            RemoteAddr = "203.0.113.20",
            Protocol = "TCP",
            Program = @"C:\Program Files\Browser\browser.exe",
            Source = "hostsguard",
            RemotePortsForDisplay = "443",
        });
        FwRules.Rules.Add(new FwRuleViewModel
        {
            Name = "HG_LAN_SMB_Inbound",
            Direction = "In",
            Action = "Block",
            Enabled = true,
            RemoteAddr = "Any",
            Protocol = "TCP",
            Source = "hostsguard",
            LocalPorts = "445",
        });
        FwRules.StatusText = "2 deterministic HostsGuard rules";

        Tools!.Schedules.Add(new ScheduleRowViewModel
        {
            Target = "telemetry.example.test",
            DaysText = "Mon,Tue,Wed,Thu,Fri",
            Start = "09:00",
            End = "17:00",
        });
        Tools.HealthRows.Add(new HealthRowViewModel
        {
            Aspect = "DNS observation (ETW)",
            State = "Up",
            Detail = "lost 3 · gaps 0 · restarts 1 · transition 14:01 · observing after event loss",
            Healthy = true,
        });
        Tools.HealthRows.Add(new HealthRowViewModel
        {
            Aspect = "Network observation (ETW)",
            State = "Up",
            Detail = "lost 0 · gaps 0 · restarts 0 · transition 13:55 · observing",
            Healthy = true,
        });
        Tools.HealthRows.Add(new HealthRowViewModel
        {
            Aspect = "Blocked evidence (Security log)",
            State = "Degraded",
            Detail = "lost 1 · gaps 25 · restarts 1 · transition 14:00 · rollover detected",
            Healthy = false,
        });
        Tools.HealthStatusText = "1 health check needs attention — evidence is incomplete.";
        Tools.StatusText = "Deterministic diagnostics ready";

    }

    /// <summary>
    /// Establishes the deterministic, non-RPC shell connection used by the
    /// rendered state matrix. Callers can then seed empty, loading, populated,
    /// or disconnected presentation state without contacting the service.
    /// </summary>
    internal void PrepareVisualSmokeConnectionFixture()
    {
        ResetConnection();
        _client = _connectFactory();
        InitializeViews(_client);
        IsConnected = true;
    }

    private void InitializeViews(HostsServiceClient client)
    {
        Hosts = new HostsViewModel(client, _confirm);
        Activity = new HostsActivityViewModel(client, _config, _prompt, _confirm);
        RawHosts = new RawHostsViewModel(client);
        FwActivity = new FwActivityViewModel(client, _confirm, _config, _filePicker);
        Alerts = new AlertsViewModel(client);
        FwRules = new FwRulesViewModel(client, _confirm, _filePicker, _prompt);
        Tools = new ToolsViewModel(client, _confirm);
        Blocklists = new BlocklistsViewModel(client, _confirm);
    }

    // ─── Filtering mode + consent prompts (WFC parity) ────────────────────────

    public async Task LoadFilteringModeAsync()
    {
        if (_client is null)
        {
            return;
        }

        await RunServiceActionAsync(I18n.T("Shell_ActionLoadFiltering", "Load filtering mode"), async () =>
        {
            var mode = await _client.Consent.GetModeAsync(new Empty());
            FilteringMode = mode.Mode;
            FilteringModeText = DescribeFilteringMode(mode.Mode, mode.DetectionArmed, mode.LearnMinutes);
            _suppressChildInherit = true;
            ChildInherit = mode.ChildInherit;
            _suppressChildInherit = false;
            _suppressInboundConsent = true;
            InboundConsent = mode.InboundConsent;
            _suppressInboundConsent = false;
        });
    }

    private bool _suppressChildInherit;
    private bool _suppressInboundConsent;

    /// <summary>Two-way bound from the consent UI toggle; pushes to the service.</summary>
    partial void OnChildInheritChanged(bool value)
    {
        if (_client is null || _suppressChildInherit)
        {
            return;
        }

        _ = SetChildInheritAsync(value);
    }

    private async Task SetChildInheritAsync(bool enabled)
    {
        await RunServiceActionAsync(I18n.T("Shell_ActionChildInheritance", "Set child-process inheritance"), async () =>
        {
            var ack = await _client!.Consent.SetChildInheritAsync(new ChildInheritRequest { Enabled = enabled });
            ConnectionText = ack.Message;
        });
    }

    /// <summary>Two-way bound from the inbound-consent UI toggle; pushes to the service.</summary>
    partial void OnInboundConsentChanged(bool value)
    {
        if (_client is null || _suppressInboundConsent)
        {
            return;
        }

        _ = SetInboundConsentAsync(value);
    }

    private async Task SetInboundConsentAsync(bool enabled)
    {
        await RunServiceActionAsync(I18n.T("Shell_ActionInboundConsent", "Set inbound consent"), async () =>
        {
            var ack = await _client!.Consent.SetInboundConsentAsync(new InboundConsentRequest { Enabled = enabled });
            ConnectionText = ack.Message;
        });
    }

    [RelayCommand(CanExecute = nameof(CanUseConnectedService))]
    public Task SetFilteringModeAsync(string mode) => SetFilteringModeAsync(mode, 0);

    /// <summary>
    /// Switch filtering mode; when <paramref name="learnMinutes"/> &gt; 0 and mode
    /// is "learning", arm a time-boxed window that auto-reverts to Normal (NET-101).
    /// </summary>
    public async Task SetFilteringModeAsync(string mode, int learnMinutes)
    {
        if (_client is null)
        {
            return;
        }

        if (mode is "notify" or "learning" && FilteringMode == "normal")
        {
            var warning = await RemoteSessionWarning.DescribeAsync(_client);
            var message = RemoteSessionWarning.AppendTo(
                I18n.T("Shell_EnableFilteringMessage", "Switch to {0} mode? HostsGuard will set every firewall profile to default-deny until you return to Normal mode, then restore the prior posture.", mode),
                warning);
            if (!_confirm.Confirm(I18n.T("Shell_EnableFilteringTitle", "Enable connection filtering"), message))
            {
                return;
            }
        }

        await RunServiceActionAsync(I18n.T("Shell_ActionSetFiltering", "Set filtering mode"), async () =>
        {
            var ack = await _client.Consent.SetModeAsync(new FilteringMode { Mode = mode, LearnMinutes = learnMinutes });
            ConnectionText = ack.Message;
            await LoadFilteringModeAsync();
            if (FwActivity is not null)
            {
                await FwActivity.LoadPostureAsync();
            }
        });
    }

    /// <summary>Apply a global outbound posture (NET-076): "block-all" | "allow-all".</summary>
    [RelayCommand(CanExecute = nameof(CanUseConnectedService))]
    public async Task SetGlobalModeAsync(string mode)
    {
        if (_client is null)
        {
            return;
        }

        if (mode == "block-all")
        {
            var warning = await RemoteSessionWarning.DescribeAsync(_client);
            var message = RemoteSessionWarning.AppendTo(
                I18n.T("Shell_BlockAllMessage", "Block new outbound traffic on every firewall profile unless an allow rule already covers it?"),
                warning);
            if (!_confirm.Confirm(I18n.T("Shell_BlockAllTitle", "Block all outbound"), message))
            {
                return;
            }
        }

        await RunServiceActionAsync(I18n.T("Shell_ActionGlobalMode", "Set global outbound mode"), async () =>
        {
            var ack = await _client.Firewall.SetGlobalModeAsync(new GlobalModeRequest { Mode = mode });
            ConnectionText = ack.Message;
            if (FwActivity is not null)
            {
                await FwActivity.LoadPostureAsync();
            }
        });
    }

    public async Task LoadEnforcementPauseAsync()
    {
        if (_client is null)
        {
            return;
        }

        await RunServiceActionAsync(I18n.T("Shell_ActionLoadPause", "Load enforcement pause"), async () =>
        {
            var status = await _client.Firewall.GetEnforcementPauseAsync(new Empty());
            EnforcementPauseActive = status.Active;
            EnforcementPauseSuspended = status.SuspendedByKillSwitch;
            EnforcementPauseText = DescribeEnforcementPause(status);
        });
    }

    [RelayCommand(CanExecute = nameof(CanUseConnectedService))]
    public async Task PauseEnforcementAsync(object? minutesValue)
    {
        if (_client is null)
        {
            return;
        }

        var minutesText = minutesValue?.ToString() ?? string.Empty;
        if (!int.TryParse(minutesText, out var minutes))
        {
            ConnectionText = I18n.T("Shell_PauseInvalid", "Pause unavailable - invalid duration");
            return;
        }

        await RunServiceActionAsync(I18n.T("Shell_ActionPause", "Pause enforcement"), async () =>
        {
            var ack = await _client.Firewall.PauseEnforcementAsync(new EnforcementPauseRequest { Minutes = minutes });
            ConnectionText = ack.Message;
            await LoadEnforcementPauseAsync();
            if (FwActivity is not null)
            {
                await FwActivity.LoadPostureAsync();
            }
        });
    }

    [RelayCommand(CanExecute = nameof(CanUseConnectedService))]
    public async Task RestoreSafeNetworkPostureAsync()
    {
        if (_client is null)
        {
            ConnectionText = I18n.T("Shell_SafePostureUnavailable", "Safe posture unavailable - service is not connected");
            return;
        }

        await RunServiceActionAsync(I18n.T("Shell_ActionSafePosture", "Restore safe network posture"), async () =>
        {
            var messages = new List<string>();
            var failures = 0;
            async Task Apply(string label, Func<Task<Ack>> action)
            {
                try
                {
                    var ack = await action();
                    messages.Add($"{label}: {ack.Message}");
                    if (!ack.Ok)
                    {
                        failures++;
                    }
                }
                catch (RpcException ex)
                {
                    messages.Add(I18n.T("Shell_ApplyFailed", "{0}: failed ({1})", label, ex.Status.Detail));
                    failures++;
                }
            }

            await Apply(I18n.T("Shell_LabelFiltering", "filtering mode"), () => _client.Consent.SetModeAsync(
                new FilteringMode { Mode = "normal" }).ResponseAsync);
            try
            {
                var killSwitch = await _client.Firewall.GetKillSwitchAsync(new Empty());
                await Apply(I18n.T("Shell_LabelKillSwitch", "VPN kill-switch"), () => _client.Firewall.SetKillSwitchAsync(
                    new KillSwitchRequest { Enabled = false, Adapter = killSwitch.Adapter }).ResponseAsync);
            }
            catch (RpcException ex)
            {
                messages.Add(I18n.T("Shell_ApplyFailed", "{0}: failed ({1})", I18n.T("Shell_LabelKillSwitch", "VPN kill-switch"), ex.Status.Detail));
                failures++;
            }

            await Apply(I18n.T("Shell_LabelGlobalOutbound", "global outbound"), () => _client.Firewall.SetGlobalModeAsync(
                new GlobalModeRequest { Mode = "allow-all" }).ResponseAsync);
            await Apply(I18n.T("Shell_LabelDefaultOutbound", "default outbound"), () => _client.Firewall.SetDefaultOutboundAsync(
                new OutboundRequest { Block = false }).ResponseAsync);
            await Apply(I18n.T("Shell_LabelEncryptedDns", "encrypted DNS blocks"), () => _client.Firewall.UnblockEncryptedDnsAsync(
                new Empty()).ResponseAsync);
            await Apply(I18n.T("Shell_LabelQuic", "QUIC block"), () => _client.Firewall.UnblockQuicAsync(
                new Empty()).ResponseAsync);
            await Apply(I18n.T("Shell_LabelCname", "CNAME-cloak blocking"), () => _client.Dns.SetCnameCloakAsync(
                new CnameCloakRequest { Enabled = false }).ResponseAsync);
            await Apply(I18n.T("Shell_LabelFlowTeardown", "TCP flow teardown"), () => _client.Firewall.SetFlowTeardownAsync(
                new FlowTeardownRequest { Enabled = false }).ResponseAsync);

            await LoadFilteringModeAsync();
            await LoadEnforcementPauseAsync();
            if (FwActivity is not null)
            {
                await FwActivity.LoadPostureAsync();
                await FwActivity.LoadFlowTeardownAsync();
            }

            if (Tools is not null)
            {
                await Tools.LoadDohStatusAsync();
                await Tools.LoadKillSwitchAsync();
            }

            var outcome = failures == 0
                ? I18n.T("Shell_SafePostureRestored", "Safe network posture restored")
                : I18n.T("Shell_SafePostureWarnings", "Safe network posture restored with warnings");
            ConnectionText = I18n.T("Shell_SafePostureResult", "{0} - hosts-file blocks left unchanged. {1}", outcome, string.Join("; ", messages));
        });
    }

    private void StartDecisionWatch()
    {
        if (_decisionCts is not null || _client is null)
        {
            return;
        }

        var cts = new CancellationTokenSource();
        _decisionCts = cts;
        _ = WatchDecisionsAsync(_client, cts);
    }

    private async Task WatchDecisionsAsync(HostsServiceClient client, CancellationTokenSource owner)
    {
        var ct = owner.Token;
        var failures = 0;
        try
        {
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    using var call = client.Consent.WatchDecisions(new Empty(), cancellationToken: ct);
                    failures = 0;
                    await foreach (var request in call.ResponseStream.ReadAllAsync(ct))
                    {
                        // Optional audible alert on a new block/prompt (NET-085).
                        if (_config.SoundOnBlock)
                        {
                            try
                            {
                                System.Media.SystemSounds.Exclamation.Play();
                            }
                            catch (InvalidOperationException)
                            {
                                // No audio device - never let it break the prompt flow.
                            }
                        }

                        if (_ui is null)
                        {
                            DecisionRequested?.Invoke(request);
                        }
                        else
                        {
                            _ui.Post(_ => DecisionRequested?.Invoke(request), null);
                        }
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
                        SetConnectionTextOnUi(I18n.T("Shell_ConsentAuthExpired", "Consent prompt stream authentication expired - reconnect to the service."));
                        break;
                    }

                    SetConnectionTextOnUi(I18n.T("Shell_ConsentRetry", "Consent prompt stream disconnected - retrying..."));
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
            if (ReferenceEquals(_decisionCts, owner))
            {
                _decisionCts = null;
                owner.Dispose();
            }
        }
    }

    private void SetConnectionTextOnUi(string text)
    {
        if (_ui is null)
        {
            ConnectionText = text;
        }
        else
        {
            _ui.Post(_ => ConnectionText = text, null);
        }
    }

    /// <summary>
    /// Send a consent decision back to the service. Returns whether the service
    /// accepted it — false means the decision was NOT applied (pipe down or the
    /// service refused), so the caller must warn: the consent window has already
    /// closed and default-deny is silently keeping the connection blocked.
    /// </summary>
    public async Task<bool> SendDecisionAsync(ConnectionDecision decision)
    {
        if (_client is null)
        {
            return false;
        }

        try
        {
            var ack = await _client.Consent.DecideAsync(decision);
            ConnectionText = ack.Message;
            if (FwActivity is not null)
            {
                await FwActivity.LoadConsentHistoryAsync();
            }

            return ack.Ok;
        }
        catch (Exception ex) when (ex is Grpc.Core.RpcException || ServiceErrors.IsConnectivity(ex))
        {
            ConnectionText = ServiceErrors.DescribeActionFailure(I18n.T("Shell_ActionSendDecision", "Send connection decision"), ex);
            return false;
        }
    }

    [RelayCommand]
    public void ToggleTheme()
    {
        Theme = Theme == "dark" ? "light" : "dark";
        _themes.Apply(Theme);
        _config.Save(Theme, UiScalePct);
    }

    // ─── File menu ────────────────────────────────────────────────────────────

    private static string HostsFileFilter => I18n.T("Shell_HostsFileFilter", "Hosts files (*.txt;hosts)|*.txt;hosts|All files (*.*)|*.*");
    private static string JsonFilter => I18n.T("Shell_JsonFileFilter", "JSON (*.json)|*.json|All files (*.*)|*.*");
    private const int MaxImportBytes = 10 * 1024 * 1024;

    /// <summary>Replace the live hosts file with a picked file (backs up first).</summary>
    [RelayCommand]
    public async Task ImportHostsFileAsync()
    {
        if (_client is null || _filePicker is null)
        {
            return;
        }

        var path = _filePicker.PickFile(I18n.T("Shell_ImportHostsTitle", "Import hosts file"), filter: HostsFileFilter);
        if (path is null)
        {
            return;
        }

        var info = new FileInfo(path);
        if (!info.Exists || info.Length > MaxImportBytes)
        {
            ConnectionText = I18n.T("Shell_ImportTooLarge", "Import failed - the file is missing or over 10 MB");
            return;
        }

        if (!_confirm.Confirm(I18n.T("Shell_ImportHostsTitle", "Import hosts file"),
            I18n.T("Shell_ImportHostsMessage", "Replace the live hosts file with {0}? The current file is backed up first.", Path.GetFileName(path))))
        {
            return;
        }

        string text;
        try
        {
            text = await File.ReadAllTextAsync(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            ConnectionText = I18n.T("Shell_ReadFailed", "Couldn't read {0}: {1}", Path.GetFileName(path), ex.Message);
            return;
        }

        await RunServiceActionAsync(I18n.T("Shell_ActionImportHosts", "Import hosts file"), async () =>
        {
            await _client.Hosts.BackupHostsAsync(new Empty());
            var ack = await _client.Hosts.SetHostsTextAsync(new HostsText { Text = text });
            ConnectionText = ack.Ok ? I18n.T("Shell_HostsImported", "Imported {0} into the hosts file", Path.GetFileName(path)) : ack.Message;
            if (ack.Ok)
            {
                if (RawHosts is not null)
                {
                    await RawHosts.LoadAsync();
                }

                if (Hosts is not null)
                {
                    await Hosts.RefreshAsync();
                }
            }
        });
    }

    /// <summary>Write the live hosts file to a picked destination.</summary>
    [RelayCommand]
    public async Task ExportHostsFileAsync()
    {
        if (_client is null || _filePicker is null)
        {
            return;
        }

        var path = _filePicker.SaveFile(I18n.T("Shell_ExportHostsTitle", "Export hosts file"), "hosts.txt", HostsFileFilter);
        if (path is null)
        {
            return;
        }

        await RunServiceActionAsync(I18n.T("Shell_ActionExportHosts", "Export hosts file"), async () =>
        {
            var text = await _client.Hosts.GetHostsTextAsync(new Empty());
            if (await TryWriteFileAsync(path, text.Text))
            {
                ConnectionText = I18n.T("Shell_HostsExported", "Hosts file exported to {0}", path);
            }
        });
    }

    /// <summary>
    /// Write a file, reporting any I/O failure in the status bar. File errors
    /// must NOT reach the global handler, which would misclassify an IOException
    /// as a lost service connection.
    /// </summary>
    private async Task<bool> TryWriteFileAsync(string path, string content)
    {
        try
        {
            await File.WriteAllTextAsync(path, content);
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            ConnectionText = I18n.T("Shell_WriteFailed", "Couldn't write {0}: {1}", Path.GetFileName(path), ex.Message);
            return false;
        }
    }

    /// <summary>Export the managed-domain policy (with categories) as JSON.</summary>
    [RelayCommand]
    public async Task ExportDomainsAsync()
    {
        if (_client is null || _filePicker is null)
        {
            return;
        }

        var path = _filePicker.SaveFile(I18n.T("Shell_ExportDomainsTitle", "Export managed domains"), "hostsguard_domains.json", JsonFilter);
        if (path is null)
        {
            return;
        }

        await RunServiceActionAsync(I18n.T("Shell_ActionExportDomains", "Export managed domains"), async () =>
        {
            var list = await _client.Hosts.ListDomainsAsync(new ListDomainsRequest());
            var rows = list.Domains.Select(d => new
            {
                domain = d.Domain,
                status = d.Status,
                category = d.Category,
                source = d.Source,
                reason = d.Reason,
                hits = d.Hits,
            });
            var json = System.Text.Json.JsonSerializer.Serialize(
                rows, new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
            if (await TryWriteFileAsync(path, json))
            {
                ConnectionText = I18n.T("Shell_DomainsExported", "Exported {0} domain(s) to {1}", list.Domains.Count, path);
            }
        });
    }

    /// <summary>Export the whole machine policy as one versioned JSON document (NET-089).</summary>
    [RelayCommand]
    public async Task ExportPolicyAsync()
    {
        if (_client is null || _filePicker is null)
        {
            return;
        }

        var path = _filePicker.SaveFile(I18n.T("Shell_ExportPolicyTitle", "Export policy"), "hostsguard_policy.json", JsonFilter);
        if (path is null)
        {
            return;
        }

        await RunServiceActionAsync(I18n.T("Shell_ActionExportPolicy", "Export policy"), async () =>
        {
            var doc = await _client.Policy.ExportPolicyAsync(new Empty());
            if (await TryWriteFileAsync(path, doc.Json))
            {
                ConnectionText = I18n.T("Shell_PolicyExported", "Policy exported to {0}", path);
            }
        });
    }

    /// <summary>Reconstruct the machine policy from an exported JSON document (NET-089).</summary>
    [RelayCommand]
    public async Task ImportPolicyAsync()
    {
        if (_client is null || _filePicker is null)
        {
            return;
        }

        var path = _filePicker.PickFile(I18n.T("Shell_ImportPolicyTitle", "Import policy"), filter: JsonFilter);
        if (path is null)
        {
            return;
        }

        var info = new FileInfo(path);
        if (!info.Exists || info.Length > MaxImportBytes)
        {
            ConnectionText = I18n.T("Shell_ImportTooLarge", "Import failed - the file is missing or over 10 MB");
            return;
        }

        string json;
        try
        {
            json = await File.ReadAllTextAsync(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            ConnectionText = I18n.T("Shell_ReadFailed", "Couldn't read {0}: {1}", Path.GetFileName(path), ex.Message);
            return;
        }

        await RunServiceActionAsync(I18n.T("Shell_ActionImportPolicy", "Import policy"), async () =>
        {
            var preview = await _client.Policy.PreviewPolicyImportAsync(new ImportPolicyRequest { Json = json, Preview = true });
            if (!preview.Ok)
            {
                ConnectionText = preview.Message;
                return;
            }

            var previewText = $"{preview.Message}\n\n" + string.Join("\n", preview.Summary.Take(8));
            if (!_confirm.Confirm(I18n.T("Shell_ImportPolicyTitle", "Import policy"),
                previewText + "\n\n" + I18n.T("Shell_ImportPolicyConfirm", "Create a restore checkpoint and apply this policy?")))
            {
                ConnectionText = I18n.T("Shell_PolicyImportCancelled", "Policy import cancelled after preview");
                return;
            }

            var result = await _client.Policy.ImportPolicyAsync(new ImportPolicyRequest { Json = json });
            ConnectionText = result.Ok
                ? I18n.T("Shell_PolicyImported", "Policy imported - checkpoint {0}; {1}", result.CheckpointId, string.Join("; ", result.Summary))
                : result.Message;
            if (result.Ok)
            {
                await RefreshAllAsync();
                if (RawHosts is not null)
                {
                    await RawHosts.LoadAsync();
                }
            }
        });
    }

    [RelayCommand]
    public async Task RestorePolicyCheckpointAsync()
    {
        if (_client is null)
        {
            return;
        }

        await RunServiceActionAsync(I18n.T("Shell_ActionRestorePolicy", "Restore policy checkpoint"), async () =>
        {
            if (!_confirm.Confirm(I18n.T("Shell_RestorePolicyTitle", "Restore policy checkpoint"),
                I18n.T("Shell_RestorePolicyMessage", "Restore the latest policy-import checkpoint and reconcile domains, firewall rules, schedules, profiles, and subscriptions?")))
            {
                return;
            }

            var result = await _client.Policy.RestorePolicyCheckpointAsync(new Empty());
            ConnectionText = result.Ok ? I18n.T("Shell_PolicyRestored", "Policy checkpoint restored - {0}", string.Join("; ", result.Summary)) : result.Message;
            if (result.Ok)
            {
                await RefreshAllAsync();
                if (RawHosts is not null)
                {
                    await RawHosts.LoadAsync();
                }
            }
        });
    }

    // ─── View menu ────────────────────────────────────────────────────────────

    /// <summary>Persist the UI language (NET-098); it applies on the next launch.</summary>
    [RelayCommand]
    public void SetLanguage(string? tag)
    {
        _config.SaveLanguage(tag ?? string.Empty);
        var name = AppConfigStore.Languages.FirstOrDefault(l => l.Tag == (tag ?? string.Empty)).Name
            ?? I18n.T("Shell_SystemDefault", "System default");
        ConnectionText = I18n.T("Shell_LanguageSet", "Language set to {0} - restart HostsGuard to apply.", name);
    }

    /// <summary>Back to defaults: filters cleared, toggles reset, 100% scale.</summary>
    [RelayCommand]
    public void ResetView()
    {
        if (Activity is not null)
        {
            Activity.Filter = string.Empty;
            Activity.ShowHidden = false;
            Activity.HideBlocked = false;
            Activity.HideReverseDns = false;
            Activity.BlockedOnly = false;
            Activity.GroupByRoot = false;
        }

        if (Hosts is not null)
        {
            Hosts.Filter = string.Empty;
            Hosts.StatusFilter = HostsViewModel.AllStatusLabel;
        }

        if (FwActivity is not null)
        {
            FwActivity.Filter = string.Empty;
            FwActivity.GroupByApp = true;
            FwActivity.GroupByCountry = false;
            FwActivity.ResolveIps = false;
        }

        if (FwRules is not null)
        {
            FwRules.Filter = string.Empty;
            FwRules.HostsGuardOnly = true;
            FwRules.DriftOnly = false;
        }

        UiScalePct = 100;
        ConnectionText = I18n.T("Shell_ViewReset", "View reset to defaults");
    }

    /// <summary>Re-query every tab from the service.</summary>
    [RelayCommand]
    public async Task RefreshAllAsync()
    {
        if (Activity is not null)
        {
            await Activity.RefreshAsync();
        }

        if (Hosts is not null)
        {
            await Hosts.RefreshAsync();
        }

        if (FwRules is not null)
        {
            await FwRules.RefreshAsync();
            await FwRules.LoadInterfaceAliasesAsync();
        }

        if (Blocklists is not null)
        {
            await Blocklists.RefreshAsync();
        }

        if (RawHosts is not null && !RawHosts.IsDirty)
        {
            await RawHosts.LoadAsync();
        }

        if (FwActivity is not null)
        {
            await FwActivity.LoadPostureAsync();
            await FwActivity.LoadFlowTeardownAsync();
            await FwActivity.LoadConsentHistoryAsync();
            await FwActivity.LoadLearnedAsync();
        }

        if (Alerts is not null)
        {
            await Alerts.LoadAsync();
        }

        if (Tools is not null)
        {
            await Tools.LoadSchedulesAsync();
            await Tools.LoadServicesAsync();
            await Tools.LoadDohStatusAsync();
            await Tools.LoadIdnHomographStatusAsync();
            await Tools.LoadResolverHealthAsync();
            await Tools.LoadLanAttackSurfaceAsync();
            await Tools.LoadProfilesAsync();
            await Tools.LoadPolicySubscriptionsAsync();
            await Tools.LoadIpBlocklistsAsync();
            await Tools.LoadHealthAsync();
            await Tools.InspectProxyBaselineAsync();
            await Tools.LoadDefenderStatusAsync();
            await Tools.LoadBackupsAsync();
            await Tools.LoadFullStateSnapshotsAsync();
            await Tools.LoadSecureRulesAsync();
            await Tools.LoadAiStatusAsync();
            await Tools.LoadAdoptionStatusAsync();
            await Tools.LoadIntelStatusAsync();
            await Tools.LoadTrustedPublishersAsync();
            await Tools.LoadTrustedFoldersAsync();
            await Tools.LoadKillSwitchAsync();
            await Tools.LoadAppVpnBindingsAsync();
        }

        await LoadEnforcementPauseAsync();
        ConnectionText = I18n.T("Shell_AllRefreshed", "All visible surfaces refreshed");
    }

    [RelayCommand(CanExecute = nameof(CanUseConnectedService))]
    public async Task RunDiagnosticsAsync()
    {
        if (_client is null)
        {
            ConnectionText = I18n.T("Shell_DiagnosticsUnavailable", "Diagnostics unavailable - service is not connected");
            return;
        }

        await RunServiceActionAsync(I18n.T("Shell_ActionDiagnostics", "Run diagnostics"), async () =>
        {
            var status = await _client.Diagnostics.GetStatusAsync(new Empty());
            ServiceVersion = status.Version;
            HostsBlocked = status.HostsBlocked;
            DbBlocked = status.DbBlocked;
            DbAllowed = status.DbAllowed;
            ConnectionText = I18n.T("Shell_DiagnosticsOk",
                "Diagnostics OK - service v{0}, uptime {1} min, DNS {2}, connections {3}",
                status.Version, status.UptimeSeconds / 60,
                status.DnsMonitorActive ? I18n.T("Common_On", "on") : I18n.T("Common_Off", "off"),
                status.ConnectionMonitorActive ? I18n.T("Common_On", "on") : I18n.T("Common_Off", "off"));
        });
    }

    [RelayCommand]
    public async Task CheckForUpdatesAsync()
    {
        ConnectionText = I18n.T("Shell_CheckingUpdates", "Checking GitHub releases...");
        try
        {
            var result = await _releaseUpdateChecker.CheckAsync(AppVersion);
            ConnectionText = result.Message;
        }
        catch (Exception ex)
        {
            ConnectionText = I18n.T("Shell_UpdateFailed", "Update check failed: {0}", ex.Message);
        }
    }

    [RelayCommand]
    public void SetScale(object? pct)
    {
        if (pct is int value)
        {
            UiScalePct = value;
        }
        else if (int.TryParse(pct?.ToString(), out var parsed))
        {
            UiScalePct = parsed;
        }
    }

    private static string DescribeFilteringMode(string mode, bool armed, int learnMinutes = 0)
    {
        var label = mode switch
        {
            "notify" => I18n.T("Shell_NotifyDescription", "Notify - prompt on new outbound connections"),
            "learning" => learnMinutes > 0
                ? I18n.T("Shell_LearningTimed", "Learning - auto-allow and record ({0} min left, then locks)", learnMinutes)
                : I18n.T("Shell_LearningDescription", "Learning - auto-allow and record for review"),
            _ => I18n.T("Shell_NormalDescription", "Normal - enforce existing policy silently"),
        };
        return armed ? I18n.T("Shell_DefaultDenyArmed", "{0} (default-deny armed)", label) : label;
    }

    private static string DescribeEnforcementPause(EnforcementPauseStatus status)
    {
        if (!status.Active)
        {
            return I18n.T("Shell_HostsFirewallActive", "Hosts and firewall enforcement active.");
        }

        var remaining = Math.Max(1, status.MinutesRemaining);
        var prefix = status.SuspendedByKillSwitch
            ? I18n.T("Shell_PauseSuspended", "Pause suspended by VPN kill-switch")
            : I18n.T("Shell_EnforcementPaused", "Hosts and outbound enforcement paused");
        return I18n.T("Shell_PauseResumes", "{0} - resumes in {1} min.", prefix, remaining);
    }

    partial void OnUiScalePctChanged(int value)
    {
        OnPropertyChanged(nameof(UiScale));
        _config.Save(Theme, value);
    }

    private Task RunServiceActionAsync(string action, Func<Task> work) =>
        ServiceActionGuard.RunAsync(action, s => ConnectionText = s, work);

    private bool CanUseConnectedService() => IsConnected && _client is not null;

    private void ResetConnection()
    {
        IsConnected = false;
        _decisionCts?.Cancel();
        _decisionCts?.Dispose();
        _decisionCts = null;
        Activity?.Dispose();
        FwActivity?.Dispose();
        Hosts = null;
        Activity = null;
        RawHosts = null;
        FwActivity = null;
        Alerts = null;
        FwRules = null;
        Tools = null;
        Blocklists = null;
        _client?.Dispose();
        _client = null;
        FilteringMode = string.Empty;
        FilteringModeText = string.Empty;
        EnforcementPauseActive = false;
        EnforcementPauseSuspended = false;
        EnforcementPauseText = string.Empty;
    }

    public void Dispose() => ResetConnection();
}
