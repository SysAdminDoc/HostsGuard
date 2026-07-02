using HostsGuard.Data;
using HostsGuard.Windows;

namespace HostsGuard.Service;

/// <summary>
/// Shared engine state for the service's gRPC implementations. Owns the hosts
/// engine and database; a single instance is registered as a DI singleton.
/// </summary>
public sealed class ServiceState : IDisposable
{
    public ServiceState(HostsEngine hosts, HostsDatabase db)
    {
        Hosts = hosts ?? throw new ArgumentNullException(nameof(hosts));
        Db = db ?? throw new ArgumentNullException(nameof(db));
        StartedAtUtc = DateTime.UtcNow;
    }

    public HostsEngine Hosts { get; }

    public HostsDatabase Db { get; }

    public DateTime StartedAtUtc { get; }

    public void Dispose() => Db.Dispose();
}
