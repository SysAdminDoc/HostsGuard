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
    private readonly SynchronizationContext? _ui = SynchronizationContext.Current;
    private HostsServiceClient? _client;
    private CancellationTokenSource? _decisionCts;

    [ObservableProperty]
    private bool _isConnected;

    [ObservableProperty]
    private string _connectionText = I18n.T("Status.Connecting", "Connecting to service…");

    [ObservableProperty]
    private string _serviceVersion = string.Empty;

    [ObservableProperty]
    private int _hostsBlocked;

    [ObservableProperty]
    private int _dbBlocked;

    [ObservableProperty]
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
    private string _filteringMode = "normal";

    [ObservableProperty]
    private string _filteringModeText = string.Empty;

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
        IConfirm confirm, IFilePicker? filePicker = null, IPrompt? prompt = null)
    {
        _connectFactory = connectFactory ?? throw new ArgumentNullException(nameof(connectFactory));
        _config = config ?? throw new ArgumentNullException(nameof(config));
        _themes = themes ?? throw new ArgumentNullException(nameof(themes));
        _confirm = confirm ?? throw new ArgumentNullException(nameof(confirm));
        _filePicker = filePicker;
        _prompt = prompt;
        _theme = config.Theme;
        _uiScalePct = config.UiScalePct;
    }

    /// <summary>LayoutTransform scale factor derived from the persisted percent.</summary>
    public double UiScale => UiScalePct / 100.0;

    public string ThemeToggleText => Theme == "dark" ? "Light theme" : "Dark theme";

    public static IReadOnlyList<int> UiScaleChoices => AppConfigStore.UiScaleChoices;

    [RelayCommand]
    public async Task ConnectAsync()
    {
        try
        {
            _client ??= _connectFactory();
            var status = await _client.Diagnostics.GetStatusAsync(new Empty());
            ServiceVersion = status.Version;
            HostsBlocked = status.HostsBlocked;
            DbBlocked = status.DbBlocked;
            DbAllowed = status.DbAllowed;
            Hosts ??= new HostsViewModel(_client, _confirm);
            await Hosts.RefreshAsync();
            Activity ??= new HostsActivityViewModel(_client, _config, _prompt);
            await Activity.RefreshAsync();
            Activity.StartWatching();
            RawHosts ??= new RawHostsViewModel(_client);
            await RawHosts.LoadAsync();
            FwActivity ??= new FwActivityViewModel(_client, _confirm, _config, _filePicker);
            FwActivity.StartWatching();
            await FwActivity.LoadPostureAsync();
            await FwActivity.LoadConsentHistoryAsync();
            await FwActivity.LoadLearnedAsync();
            FwRules ??= new FwRulesViewModel(_client, _confirm, _filePicker, _prompt);
            await FwRules.RefreshAsync();
            Tools ??= new ToolsViewModel(_client, _confirm);
            await Tools.LoadSchedulesAsync();
            await Tools.LoadServicesAsync();
            await Tools.LoadDohStatusAsync();
            await Tools.LoadProfilesAsync();
            await Tools.LoadDefenderStatusAsync();
            await Tools.LoadBackupsAsync();
            await Tools.LoadSecureRulesAsync();
            await Tools.LoadAiStatusAsync();
            await Tools.LoadIntelStatusAsync();
            await Tools.LoadTrustedPublishersAsync();
            await Tools.LoadTrustedFoldersAsync();
            await Tools.LoadKillSwitchAsync();
            Blocklists ??= new BlocklistsViewModel(_client, _confirm);
            await Blocklists.RefreshAsync();
            await LoadFilteringModeAsync();
            StartDecisionWatch();
            IsConnected = true;
            ConnectionText = I18n.T("Status.Connected", "Connected — service v{0}", status.Version)
                + (status.Elevated ? " (elevated)" : string.Empty);
        }
        catch (Exception ex)
        {
            IsConnected = false;
            ConnectionText = I18n.T(
                "Status.Unavailable",
                "Service unavailable - start or restart HostsGuardSvc, then reconnect. Details: {0}",
                ex.Message);
        }
    }

    // ─── Filtering mode + consent prompts (WFC parity) ────────────────────────

    public async Task LoadFilteringModeAsync()
    {
        if (_client is null)
        {
            return;
        }

        var mode = await _client.Consent.GetModeAsync(new Empty());
        FilteringMode = mode.Mode;
        FilteringModeText = DescribeFilteringMode(mode.Mode, mode.DetectionArmed, mode.LearnMinutes);
        _suppressChildInherit = true;
        ChildInherit = mode.ChildInherit;
        _suppressChildInherit = false;
        _suppressInboundConsent = true;
        InboundConsent = mode.InboundConsent;
        _suppressInboundConsent = false;
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
        var ack = await _client!.Consent.SetChildInheritAsync(new ChildInheritRequest { Enabled = enabled });
        ConnectionText = ack.Message;
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
        var ack = await _client!.Consent.SetInboundConsentAsync(new InboundConsentRequest { Enabled = enabled });
        ConnectionText = ack.Message;
    }

    [RelayCommand]
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

        if (mode is "notify" or "learning" && FilteringMode == "normal" &&
            !_confirm.Confirm("Enable connection filtering",
                $"Switch to {mode} mode? HostsGuard will set every firewall profile to default-deny " +
                "until you return to Normal mode, then restore the prior posture."))
        {
            return;
        }

        var ack = await _client.Consent.SetModeAsync(new FilteringMode { Mode = mode, LearnMinutes = learnMinutes });
        ConnectionText = ack.Message;
        await LoadFilteringModeAsync();
        if (FwActivity is not null)
        {
            await FwActivity.LoadPostureAsync();
        }
    }

    /// <summary>Apply a global outbound posture (NET-076): "block-all" | "allow-all".</summary>
    [RelayCommand]
    public async Task SetGlobalModeAsync(string mode)
    {
        if (_client is null)
        {
            return;
        }

        if (mode == "block-all" &&
            !_confirm.Confirm("Block all outbound",
                "Block new outbound traffic on every firewall profile unless an allow rule already covers it?"))
        {
            return;
        }

        var ack = await _client.Firewall.SetGlobalModeAsync(new GlobalModeRequest { Mode = mode });
        ConnectionText = ack.Message;
        if (FwActivity is not null)
        {
            await FwActivity.LoadPostureAsync();
        }
    }

    private void StartDecisionWatch()
    {
        if (_decisionCts is not null || _client is null)
        {
            return;
        }

        _decisionCts = new CancellationTokenSource();
        _ = WatchDecisionsAsync(_client, _decisionCts.Token);
    }

    private async Task WatchDecisionsAsync(HostsServiceClient client, CancellationToken ct)
    {
        try
        {
            using var call = client.Consent.WatchDecisions(new Empty(), cancellationToken: ct);
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
                        // No audio device — never let it break the prompt flow.
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
        catch (Exception ex) when (ex is Grpc.Core.RpcException or OperationCanceledException or System.IO.IOException)
        {
            // Stream ends with the connection; reconnect restarts it.
            _decisionCts?.Dispose();
            _decisionCts = null;
        }
    }

    /// <summary>Send a consent decision back to the service.</summary>
    public async Task SendDecisionAsync(ConnectionDecision decision)
    {
        if (_client is null)
        {
            return;
        }

        var ack = await _client.Consent.DecideAsync(decision);
        ConnectionText = ack.Message;
        if (FwActivity is not null)
        {
            await FwActivity.LoadConsentHistoryAsync();
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

    private const string HostsFileFilter = "Hosts files (*.txt;hosts)|*.txt;hosts|All files (*.*)|*.*";
    private const string JsonFilter = "JSON (*.json)|*.json|All files (*.*)|*.*";
    private const int MaxImportBytes = 10 * 1024 * 1024;

    /// <summary>Replace the live hosts file with a picked file (backs up first).</summary>
    [RelayCommand]
    public async Task ImportHostsFileAsync()
    {
        if (_client is null || _filePicker is null)
        {
            return;
        }

        var path = _filePicker.PickFile("Import hosts file", filter: HostsFileFilter);
        if (path is null)
        {
            return;
        }

        var info = new FileInfo(path);
        if (!info.Exists || info.Length > MaxImportBytes)
        {
            ConnectionText = "Import failed — the file is missing or over 10 MB";
            return;
        }

        if (!_confirm.Confirm("Import hosts file",
            $"Replace the live hosts file with {Path.GetFileName(path)}? The current file is backed up first."))
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
            ConnectionText = $"Couldn't read {Path.GetFileName(path)}: {ex.Message}";
            return;
        }

        await _client.Hosts.BackupHostsAsync(new Empty());
        var ack = await _client.Hosts.SetHostsTextAsync(new HostsText { Text = text });
        ConnectionText = ack.Ok ? $"Imported {Path.GetFileName(path)} into the hosts file" : ack.Message;
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
    }

    /// <summary>Write the live hosts file to a picked destination.</summary>
    [RelayCommand]
    public async Task ExportHostsFileAsync()
    {
        if (_client is null || _filePicker is null)
        {
            return;
        }

        var path = _filePicker.SaveFile("Export hosts file", "hosts.txt", HostsFileFilter);
        if (path is null)
        {
            return;
        }

        var text = await _client.Hosts.GetHostsTextAsync(new Empty());
        if (await TryWriteFileAsync(path, text.Text))
        {
            ConnectionText = $"Hosts file exported to {path}";
        }
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
            ConnectionText = $"Couldn't write {Path.GetFileName(path)}: {ex.Message}";
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

        var path = _filePicker.SaveFile("Export managed domains", "hostsguard_domains.json", JsonFilter);
        if (path is null)
        {
            return;
        }

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
            ConnectionText = $"Exported {Plural.Of(list.Domains.Count, "domain")} to {path}";
        }
    }

    /// <summary>Export the whole machine policy as one versioned JSON document (NET-089).</summary>
    [RelayCommand]
    public async Task ExportPolicyAsync()
    {
        if (_client is null || _filePicker is null)
        {
            return;
        }

        var path = _filePicker.SaveFile("Export policy", "hostsguard_policy.json", JsonFilter);
        if (path is null)
        {
            return;
        }

        var doc = await _client.Policy.ExportPolicyAsync(new Empty());
        if (await TryWriteFileAsync(path, doc.Json))
        {
            ConnectionText = $"Policy exported to {path}";
        }
    }

    /// <summary>Reconstruct the machine policy from an exported JSON document (NET-089).</summary>
    [RelayCommand]
    public async Task ImportPolicyAsync()
    {
        if (_client is null || _filePicker is null)
        {
            return;
        }

        var path = _filePicker.PickFile("Import policy", filter: JsonFilter);
        if (path is null)
        {
            return;
        }

        var info = new FileInfo(path);
        if (!info.Exists || info.Length > MaxImportBytes)
        {
            ConnectionText = "Import failed — the file is missing or over 10 MB";
            return;
        }

        if (!_confirm.Confirm("Import policy",
            $"Reconstruct domains, firewall rules, schedules, profiles, locks and subscriptions from {Path.GetFileName(path)}? Existing policy is merged, not wiped."))
        {
            return;
        }

        string json;
        try
        {
            json = await File.ReadAllTextAsync(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            ConnectionText = $"Couldn't read {Path.GetFileName(path)}: {ex.Message}";
            return;
        }

        var result = await _client.Policy.ImportPolicyAsync(new ImportPolicyRequest { Json = json });
        ConnectionText = result.Ok ? $"Policy imported — {string.Join("; ", result.Summary)}" : result.Message;
        if (result.Ok)
        {
            await RefreshAllAsync();
            if (RawHosts is not null)
            {
                await RawHosts.LoadAsync();
            }
        }
    }

    // ─── View menu ────────────────────────────────────────────────────────────

    /// <summary>Persist the UI language (NET-098); it applies on the next launch.</summary>
    [RelayCommand]
    public void SetLanguage(string? tag)
    {
        _config.SaveLanguage(tag ?? string.Empty);
        var name = AppConfigStore.Languages.FirstOrDefault(l => l.Tag == (tag ?? string.Empty)).Name ?? "System default";
        ConnectionText = $"Language set to {name} — restart HostsGuard to apply.";
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
            Activity.GroupByRoot = false;
        }

        if (Hosts is not null)
        {
            Hosts.Filter = string.Empty;
            Hosts.StatusFilter = "All";
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
        }

        UiScalePct = 100;
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
            await FwActivity.LoadConsentHistoryAsync();
            await FwActivity.LoadLearnedAsync();
        }

        if (Tools is not null)
        {
            await Tools.LoadAiStatusAsync();
            await Tools.LoadIntelStatusAsync();
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
            "notify" => "Notify - prompt on new outbound connections",
            "learning" => learnMinutes > 0
                ? $"Learning - auto-allow and record ({learnMinutes} min left, then locks)"
                : "Learning - auto-allow and record for review",
            _ => "Normal - enforce existing policy silently",
        };
        return armed ? $"{label} (default-deny armed)" : label;
    }

    partial void OnUiScalePctChanged(int value)
    {
        OnPropertyChanged(nameof(UiScale));
        _config.Save(Theme, value);
    }

    public void Dispose()
    {
        _decisionCts?.Cancel();
        _decisionCts?.Dispose();
        _decisionCts = null;
        Activity?.Dispose();
        FwActivity?.Dispose();
        _client?.Dispose();
    }
}
