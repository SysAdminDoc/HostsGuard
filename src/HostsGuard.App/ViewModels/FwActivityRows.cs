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
    [NotifyPropertyChangedFor(nameof(RemoteAddressSortKey))]
    private string _remoteAddr = string.Empty;

    public NetworkAddressSortKey RemoteAddressSortKey => NetworkAddressSortKey.Create(RemoteAddr);

    /// <summary>Site the remote IP was resolved as (ETW DNS); "" when unknown.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ResearchTarget))]
    private string _host = string.Empty;

    [ObservableProperty]
    private int _remotePort;

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

    /// <summary>"AS#### Org" from the offline ASN MMDB (NET-202); "" when unknown.</summary>
    [ObservableProperty]
    private string _asn = string.Empty;

    [ObservableProperty]
    private string _fwStatus = string.Empty;

    /// <summary>Owning SCM service display name(s) (NET-073); "" for plain apps.</summary>
    [ObservableProperty]
    private string _service = string.Empty;

    public string Key => $"{Protocol}|{LocalAddr}:{LocalPort}|{RemoteAddr}:{RemotePort}|{Pid}";
}

/// <summary>A local listening endpoint and the effective firewall coverage observed for it.</summary>
public sealed partial class ListenerExposureRowViewModel : ObservableObject
{
    [ObservableProperty]
    private string _protocol = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(Endpoint))]
    [NotifyPropertyChangedFor(nameof(AddressSortKey))]
    private string _localAddress = string.Empty;

    public NetworkAddressSortKey AddressSortKey => NetworkAddressSortKey.Create(LocalAddress);

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(Endpoint))]
    private int _localPort;

    [ObservableProperty]
    private string _process = string.Empty;

    [ObservableProperty]
    private int _pid;

    [ObservableProperty]
    private string _service = string.Empty;

    [ObservableProperty]
    private string _package = string.Empty;

    [ObservableProperty]
    private string _bindScope = string.Empty;

    [ObservableProperty]
    private string _activeProfiles = string.Empty;

    [ObservableProperty]
    private string _coverage = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(RiskRank))]
    private string _risk = string.Empty;

    [ObservableProperty]
    private string _reason = string.Empty;

    public string Endpoint => LocalAddress.Contains(':', StringComparison.Ordinal)
        ? $"[{LocalAddress}]:{LocalPort}"
        : $"{LocalAddress}:{LocalPort}";

    public int RiskRank => Risk.ToUpperInvariant() switch
    {
        "CRITICAL" => 4,
        "HIGH" => 3,
        "MEDIUM" => 2,
        "LOW" => 1,
        _ => 0,
    };
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
    [NotifyPropertyChangedFor(nameof(RemoteAddressSortKey))]
    private string _remoteAddress = string.Empty;

    public NetworkAddressSortKey RemoteAddressSortKey => NetworkAddressSortKey.Create(RemoteAddress);

    [ObservableProperty]
    private string _protocol = string.Empty;

    [ObservableProperty]
    private string _verdict = string.Empty;

    [ObservableProperty]
    private bool _permanent;

    public string Scope => Permanent ? "permanent" : "once";

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(FilterOriginText))]
    private string _filterOrigin = string.Empty;

    [ObservableProperty]
    private string _filterRuntimeId = string.Empty;

    [ObservableProperty]
    private string _layerName = string.Empty;

    [ObservableProperty]
    private string _layerRuntimeId = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(InterfaceText))]
    private int _interfaceIndex;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(InterfaceText))]
    private string _interfaceName = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(OriginBadge))]
    private string _filterOwner = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(OriginBadge))]
    private bool _externalFilter;

    public string FilterOriginText => FilterOrigin.Length == 0 ? "Origin unavailable" : FilterOrigin;

    public string InterfaceText => InterfaceName.Length != 0
        ? InterfaceIndex > 0 ? $"{InterfaceName} ({InterfaceIndex})" : InterfaceName
        : InterfaceIndex > 0 ? $"ifIndex {InterfaceIndex}" : string.Empty;

    public string OriginBadge => ExternalFilter
        ? "Not HostsGuard"
        : FilterOwner.Length != 0 ? FilterOwner : "Unknown origin";
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
    [NotifyPropertyChangedFor(nameof(RemoteAddressSortKey))]
    private string _remoteAddr = string.Empty;

    public NetworkAddressSortKey RemoteAddressSortKey => NetworkAddressSortKey.Create(RemoteAddr);

    [ObservableProperty]
    private string _host = string.Empty;

    [ObservableProperty]
    private int _remotePort;

    [ObservableProperty]
    private string _country = string.Empty;

    /// <summary>"AS#### Org" from the offline ASN MMDB (NET-202); "" when unknown.</summary>
    [ObservableProperty]
    private string _asn = string.Empty;

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

/// <summary>Row VM for a daily app/domain usage rollup.</summary>
public sealed partial class UsageRollupRowViewModel : ObservableObject
{
    [ObservableProperty]
    private string _day = string.Empty;

    [ObservableProperty]
    private string _process = string.Empty;

    [ObservableProperty]
    private string _domain = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(SentText))]
    [NotifyPropertyChangedFor(nameof(Total))]
    [NotifyPropertyChangedFor(nameof(TotalText))]
    private long _sent;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(RecvText))]
    [NotifyPropertyChangedFor(nameof(Total))]
    [NotifyPropertyChangedFor(nameof(TotalText))]
    private long _recv;

    public long Total => Sent + Recv;

    public string SentText => FwActivityViewModel.FormatBytes(Sent);

    public string RecvText => FwActivityViewModel.FormatBytes(Recv);

    public string TotalText => FwActivityViewModel.FormatBytes(Total);
}

/// <summary>Row VM for an alert-only app/domain usage quota.</summary>
public sealed partial class UsageQuotaRuleViewModel : ObservableObject
{
    [ObservableProperty]
    private long _id;

    [ObservableProperty]
    private string _scope = string.Empty;

    [ObservableProperty]
    private string _match = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(LimitText))]
    private long _limitBytes;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(UsedText))]
    [NotifyPropertyChangedFor(nameof(PercentText))]
    private long _usedBytes;

    [ObservableProperty]
    private int _windowDays;

    [ObservableProperty]
    private bool _enabled;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(LastAlertedText))]
    private long _lastAlertedBytes;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(LastAlertedText))]
    private string _lastAlertedAt = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(BlockText))]
    private bool _blockOnExceed;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(BlockText))]
    private bool _blockActive;

    public string BlockText => !BlockOnExceed
        ? string.Empty
        : BlockActive
            ? I18n.T("Quota_BlockActive", "Blocked")
            : I18n.T("Quota_BlockArmed", "Armed");

    public string LimitText => FwActivityViewModel.FormatBytes(LimitBytes);

    public string UsedText => FwActivityViewModel.FormatBytes(UsedBytes);

    public string PercentText => LimitBytes <= 0 ? string.Empty : $"{Math.Min(999, UsedBytes * 100.0 / LimitBytes):0.#}%";

    public string LastAlertedText => string.IsNullOrWhiteSpace(LastAlertedAt)
        ? string.Empty
        : $"{TimeText.Compact(LastAlertedAt)} at {FwActivityViewModel.FormatBytes(LastAlertedBytes)}";
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
