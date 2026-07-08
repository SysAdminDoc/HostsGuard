using CommunityToolkit.Mvvm.ComponentModel;
using HostsGuard.App.Services;

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
