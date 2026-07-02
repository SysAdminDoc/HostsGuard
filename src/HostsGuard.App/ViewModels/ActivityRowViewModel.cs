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
    private string _status = string.Empty;

    [ObservableProperty]
    private string _process = string.Empty;

    [ObservableProperty]
    private long _hits;

    [ObservableProperty]
    private string _lastSeen = string.Empty;

    [ObservableProperty]
    private bool _hidden;

    [ObservableProperty]
    private string _reason = string.Empty;

    /// <summary>24h hourly hit sparkline as Polyline points ("" until loaded).</summary>
    [ObservableProperty]
    private string _sparklinePoints = string.Empty;

    [ObservableProperty]
    private string _sparklineTip = string.Empty;

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
    };
}
