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
        1 => "1 list",
        var n => $"{n} lists",
    };

    public string BlocklistsTip => Blocklists.Count == 0
        ? string.Empty
        : "Blocked by: " + string.Join(", ", Blocklists);

    /// <summary>Undecided domain the reference lists would block — a candidate.</summary>
    public bool IsBlockCandidate => Blocklists.Count > 0 && Status.Length == 0;

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
        Purpose = Core.DomainPurpose.Lookup(r.Domain),
        Blocklists = r.Blocklists.ToList(),
    };
}
