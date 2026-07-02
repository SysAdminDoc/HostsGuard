using System.Runtime.Versioning;
using Google.Protobuf.WellKnownTypes;
using HostsGuard.Contracts;
using HostsGuard.Data;
using HostsGuard.Windows;

namespace HostsGuard.Service;

/// <summary>
/// Shared engine state for the service's gRPC implementations. Owns the hosts
/// engine, database, event bus, and temp-allow scheduler; a single instance is
/// registered as a DI singleton. Constructing it resumes persisted temp-allow
/// windows (expired ones revert immediately).
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class ServiceState : IDisposable
{
    public ServiceState(
        HostsEngine hosts,
        HostsDatabase db,
        IFirewallEngine? firewall = null,
        FirewallIdentity? identity = null,
        IDnsConfig? dns = null,
        string? dataDir = null,
        IListFetcher? listFetcher = null,
        IDefender? defender = null)
    {
        Hosts = hosts ?? throw new ArgumentNullException(nameof(hosts));
        Db = db ?? throw new ArgumentNullException(nameof(db));
        Firewall = firewall;
        Identity = identity;
        Dns = dns;
        DataDir = dataDir ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "HostsGuard");
        StartedAtUtc = DateTime.UtcNow;
        Bus = new EventBus();
        TempAllows = new TempAllowScheduler(hosts, db, Bus);
        TempAllows.Resume();
        Schedules = new ScheduleEnforcer(hosts, db);
        Doh = new DohIntelligence(DataDir);
        ListFetcher = listFetcher;
        Defender = defender;
        if (listFetcher is not null)
        {
            Lists = new ListImporter(hosts, db, listFetcher);
        }
    }

    public HostsEngine Hosts { get; }

    public HostsDatabase Db { get; }

    public IFirewallEngine? Firewall { get; }

    public FirewallIdentity? Identity { get; }

    public IDnsConfig? Dns { get; }

    /// <summary>Service data directory (backups, support bundles). ProgramData in production.</summary>
    public string DataDir { get; }

    public ScheduleEnforcer Schedules { get; }

    public ListImporter? Lists { get; }

    public DohIntelligence Doh { get; }

    public IListFetcher? ListFetcher { get; }

    public IDefender? Defender { get; }

    public EventBus Bus { get; }

    public TempAllowScheduler TempAllows { get; }

    public DateTime StartedAtUtc { get; }

    /// <summary>
    /// Record a DNS sighting: persist to the activity feed and publish to live
    /// watchers. Called by the ETW pipeline (production) and tests.
    /// </summary>
    public void RecordDns(string domain, string process = "", int pid = 0, bool blocked = false)
    {
        var d = domain.ToLowerInvariant().Trim();
        if (d.Length == 0)
        {
            return;
        }

        Db.RecordFeed(d, process);
        Bus.Publish(new DnsEvent
        {
            Domain = d,
            Process = process,
            Pid = pid,
            Blocked = blocked,
            Ts = Timestamp.FromDateTime(DateTime.UtcNow),
        });
    }

    /// <summary>Publish a live connection sighting to WatchConnections streams.</summary>
    public void PublishConnection(ConnectionInfo info)
    {
        ArgumentNullException.ThrowIfNull(info);
        var category = string.Empty;
        if (info.RemotePort is 443 or 853 && Doh.CurrentIps().Contains(info.RemoteAddress))
        {
            category = "DoH/DoT"; // browser/app DNS tunneling detection
        }

        Bus.Publish(new ConnectionEvent
        {
            Protocol = info.Protocol,
            LocalAddr = info.LocalAddress,
            LocalPort = info.LocalPort,
            RemoteAddr = info.RemoteAddress,
            RemotePort = info.RemotePort,
            Process = info.Process,
            Pid = info.Pid,
            State = info.State,
            Category = category,
            Ts = Timestamp.FromDateTime(DateTime.UtcNow),
        });
    }

    public void Dispose()
    {
        Lists?.Dispose();
        Schedules.Dispose();
        TempAllows.Dispose();
        Db.Dispose();
    }
}
