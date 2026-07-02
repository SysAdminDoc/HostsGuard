using System.Runtime.Versioning;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
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
    private HostsServiceClient? _client;

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
    private string _theme;

    [ObservableProperty]
    private int _uiScalePct;

    public MainViewModel(Func<HostsServiceClient> connectFactory, AppConfigStore config, ThemeManager themes, IConfirm confirm)
    {
        _connectFactory = connectFactory ?? throw new ArgumentNullException(nameof(connectFactory));
        _config = config ?? throw new ArgumentNullException(nameof(config));
        _themes = themes ?? throw new ArgumentNullException(nameof(themes));
        _confirm = confirm ?? throw new ArgumentNullException(nameof(confirm));
        _theme = config.Theme;
        _uiScalePct = config.UiScalePct;
    }

    /// <summary>LayoutTransform scale factor derived from the persisted percent.</summary>
    public double UiScale => UiScalePct / 100.0;

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
            Activity ??= new HostsActivityViewModel(_client);
            await Activity.RefreshAsync();
            Activity.StartWatching();
            RawHosts ??= new RawHostsViewModel(_client);
            await RawHosts.LoadAsync();
            FwActivity ??= new FwActivityViewModel(_client);
            FwActivity.StartWatching();
            FwRules ??= new FwRulesViewModel(_client, _confirm);
            await FwRules.RefreshAsync();
            Tools ??= new ToolsViewModel(_client, _confirm);
            await Tools.LoadSchedulesAsync();
            await Tools.LoadServicesAsync();
            await Tools.LoadDohStatusAsync();
            await Tools.LoadProfilesAsync();
            Blocklists ??= new BlocklistsViewModel(_client, _confirm);
            await Blocklists.RefreshAsync();
            IsConnected = true;
            ConnectionText = I18n.T("Status.Connected", "Connected — service v{0}", status.Version)
                + (status.Elevated ? " (elevated)" : string.Empty);
        }
        catch (Exception ex)
        {
            IsConnected = false;
            ConnectionText = I18n.T("Status.Unavailable", "Service unavailable — {0}", ex.Message);
        }
    }

    [RelayCommand]
    public void ToggleTheme()
    {
        Theme = Theme == "dark" ? "light" : "dark";
        _themes.Apply(Theme);
        _config.Save(Theme, UiScalePct);
    }

    partial void OnUiScalePctChanged(int value)
    {
        OnPropertyChanged(nameof(UiScale));
        _config.Save(Theme, value);
    }

    public void Dispose()
    {
        Activity?.Dispose();
        FwActivity?.Dispose();
        _client?.Dispose();
    }
}
