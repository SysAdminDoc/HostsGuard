using CommunityToolkit.Mvvm.ComponentModel;
using HostsGuard.Contracts;

namespace HostsGuard.App.ViewModels;

/// <summary>Row VM for a managed domain in the Hosts tables.</summary>
public sealed partial class ManagedDomainViewModel : ObservableObject
{
    [ObservableProperty]
    private string _domain = string.Empty;

    [ObservableProperty]
    private string _status = string.Empty;

    [ObservableProperty]
    private string _source = string.Empty;

    [ObservableProperty]
    private string _reason = string.Empty;

    [ObservableProperty]
    private long _hits;

    public static ManagedDomainViewModel From(ManagedDomain d) => new()
    {
        Domain = d.Domain,
        Status = d.Status,
        Source = d.Source,
        Reason = d.Reason,
        Hits = d.Hits,
    };
}
