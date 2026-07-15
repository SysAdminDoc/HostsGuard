using CommunityToolkit.Mvvm.ComponentModel;
using HostsGuard.Contracts;

namespace HostsGuard.App.ViewModels;

/// <summary>Row VM for the Hosts Activity feed.</summary>
public sealed partial class ActivityRowViewModel : ObservableObject
{
    [ObservableProperty]
    private string _domain = string.Empty;

    [ObservableProperty]
    private string _root = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsBlockCandidate))]
    [NotifyPropertyChangedFor(nameof(StatusText))]
    private string _status = string.Empty;

    [ObservableProperty]
    private string _process = string.Empty;

    [ObservableProperty]
    private long _hits;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(LastSeenText))]
    private string _lastSeen = string.Empty;

    /// <summary>Compact display form of <see cref="LastSeen"/>.</summary>
    public string LastSeenText => Services.TimeText.Compact(LastSeen);

    [ObservableProperty]
    private bool _hidden;

    [ObservableProperty]
    private string _reason = string.Empty;

    /// <summary>24h hourly hit sparkline as Polyline points ("" until loaded).</summary>
    [ObservableProperty]
    private string _sparklinePoints = string.Empty;

    [ObservableProperty]
    private string _sparklineTip = string.Empty;

    /// <summary>Curated purpose label ("Google Analytics", "Akamai CDN"), or "".</summary>
    [ObservableProperty]
    private string _purpose = string.Empty;

    /// <summary>Per-domain data volume in bytes (sent+recv), attributed via resolved IP (NET-108).</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(DataText))]
    private long _bytes;

    /// <summary>Humanized data volume ("" when nothing has been attributed yet).</summary>
    public string DataText => Bytes <= 0 ? string.Empty : FormatBytes(Bytes);

    /// <summary>First observed on this machine within the newly-observed window (server-computed).</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(NewText))]
    private bool _isNew;

    /// <summary>Compact "NEW" cue for the activity grid; "" for established domains.</summary>
    public string NewText => IsNew ? Services.I18n.T("Activity_New", "NEW") : string.Empty;

    private static string FormatBytes(long bytes)
    {
        string[] units = { "B", "KB", "MB", "GB", "TB" };
        double value = bytes;
        var unit = 0;
        while (value >= 1024 && unit < units.Length - 1)
        {
            value /= 1024;
            unit++;
        }

        return unit == 0
            ? $"{value:0} {units[unit]}"
            : $"{value:0.#} {units[unit]}";
    }

    /// <summary>Reference blocklists that block this domain (intelligence index).</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(BlocklistsText))]
    [NotifyPropertyChangedFor(nameof(BlocklistsTip))]
    [NotifyPropertyChangedFor(nameof(IsBlockCandidate))]
    private IReadOnlyList<string> _blocklists = Array.Empty<string>();

    /// <summary>Short list-membership label ("3 lists"); "" when clean.</summary>
    public string BlocklistsText => Blocklists.Count switch
    {
        0 => string.Empty,
        1 => Services.I18n.T("Activity_OneList", "1 list"),
        var n => Services.I18n.T("Activity_ManyLists", "{0} lists", n),
    };

    public string BlocklistsTip => Blocklists.Count == 0
        ? string.Empty
        : Services.I18n.T("Activity_BlockedBy", "Blocked by: {0}", string.Join(", ", Blocklists));

    /// <summary>Undecided domain the reference lists would block — a candidate.</summary>
    public bool IsBlockCandidate => Blocklists.Count > 0 && Status.Length == 0;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasResolutionChain))]
    private IReadOnlyList<ResolutionHopViewModel> _resolutionChain = Array.Empty<ResolutionHopViewModel>();

    public bool HasResolutionChain => ResolutionChain.Count != 0;

    /// <summary>Human status label for the dense activity grid.</summary>
    public string StatusText => Status.ToLowerInvariant() switch
    {
        "allowed" => Services.I18n.T("Common_Allowed", "Allowed"),
        "blocked" => Services.I18n.T("Common_Blocked", "Blocked"),
        "" => Services.I18n.T("Activity_Observed", "Observed"),
        var s => char.ToUpperInvariant(s[0]) + s[1..],
    };

    public static ActivityRowViewModel From(ActivityRow r) => new()
    {
        Domain = r.Domain,
        Root = r.Root,
        Status = r.Status,
        Process = r.Process,
        Hits = r.Hits,
        LastSeen = r.LastSeen,
        Hidden = r.Hidden,
        Reason = r.Reason,
        Purpose = r.Purpose.Length != 0 ? r.Purpose : Core.DomainPurpose.Lookup(r.Domain),
        Blocklists = r.Blocklists.ToList(),
        Bytes = r.Bytes,
        IsNew = r.IsNew,
        ResolutionChain = r.ResolutionChain.Select(ResolutionHopViewModel.From).ToList(),
    };
}

public sealed class ResolutionHopViewModel
{
    public string Value { get; init; } = string.Empty;

    public string Kind { get; init; } = string.Empty;

    public string Verdict { get; init; } = string.Empty;

    public IReadOnlyList<string> Blocklists { get; init; } = Array.Empty<string>();

    public string KindText => Kind switch
    {
        "query" => Services.I18n.T("CnameChain_Query", "Query"),
        "cname" => "CNAME",
        _ => Kind,
    };

    public string VerdictText => Verdict switch
    {
        "blocked" => Services.I18n.T("Common_Blocked", "Blocked"),
        "whitelisted" => Services.I18n.T("Hosts_Whitelisted", "Whitelisted"),
        "listed" => Services.I18n.T("CnameChain_Listed", "Listed"),
        "resolved" => Services.I18n.T("CnameChain_Resolved", "Resolved"),
        _ => Services.I18n.T("Activity_Observed", "Observed"),
    };

    public string BlocklistsText => Blocklists.Count == 0 ? string.Empty : string.Join(", ", Blocklists);

    public static ResolutionHopViewModel From(ResolutionHop hop) => new()
    {
        Value = hop.Value,
        Kind = hop.Kind,
        Verdict = hop.Verdict,
        Blocklists = hop.Blocklists.ToList(),
    };
}
