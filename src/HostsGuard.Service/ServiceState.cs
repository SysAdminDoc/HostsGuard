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
        IDefender? defender = null,
        IAiCompleter? aiCompleter = null)
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
        Schedules = new ScheduleEnforcer(hosts, db, firewall);
        Doh = new DohIntelligence(DataDir);
        Threats = new ThreatIntel(DataDir);
        GeoIp = new GeoIpService(DataDir);
        DirectIp = new Core.DirectIpHeuristic();
        Consent = new ConsentBroker(db, Bus, firewall, identity, DataDir)
        {
            LookupCountry = GeoIp.Lookup,
            LookupThreat = Threats.Contains,
        };
        SecureRules = new SecureRulesGuard(firewall, db);
        CnameCloak = new CnameCloakGuard(hosts, db);
        Lock = new SettingsLock(DataDir);
        ListFetcher = listFetcher;
        Defender = defender;
        ResolvedIps = new Core.ResolvedIpCache();
        Ai = new AiCategorizer(db, hosts, aiCompleter ?? new DeepSeekCompleter(), DataDir);
        if (listFetcher is not null)
        {
            Lists = new ListImporter(hosts, db, listFetcher);
            Intel = new BlocklistIntelligence(db, listFetcher);
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

    public ThreatIntel Threats { get; }

    public GeoIpService GeoIp { get; }

    /// <summary>Direct-to-IP (no-DNS) heuristic for the block-P2P signal (NET-076).</summary>
    public Core.DirectIpHeuristic DirectIp { get; }

    /// <summary>ETW-fed IP→domain map so live connections show the site name.</summary>
    public Core.ResolvedIpCache ResolvedIps { get; }

    /// <summary>Reference blocklist index for block-candidate flagging; null without a fetcher.</summary>
    public BlocklistIntelligence? Intel { get; }

    /// <summary>DeepSeek domain categorization.</summary>
    public AiCategorizer Ai { get; }

    /// <summary>Live ETW DNS monitor state (wired by the host; false when unavailable).</summary>
    public bool DnsMonitorActive { get; set; }

    /// <summary>Live connection-feed state (wired by the host).</summary>
    public bool ConnectionMonitorActive { get; set; }

    public EventBus Bus { get; }

    public ConsentBroker Consent { get; }

    public SecureRulesGuard SecureRules { get; }

    public CnameCloakGuard CnameCloak { get; }

    /// <summary>Settings/rule lock (NET-079).</summary>
    public SettingsLock Lock { get; }

    /// <summary>
    /// Refuse a mutating action when the settings lock is armed and not inside a
    /// timed-unlock window (NET-079). Returns a locked-error Ack, else null.
    /// </summary>
    public Contracts.Ack? GateWhenLocked()
    {
        if (Lock.IsLocked(DateTime.UtcNow))
        {
            return new Contracts.Ack
            {
                Ok = false,
                Message = "settings are locked — unlock with the settings-lock password to make changes",
                ErrorCode = "hostsguard.error.v1/locked",
            };
        }

        return null;
    }

    public TempAllowScheduler TempAllows { get; }

    /// <summary>Per-app byte-counter aggregator (NET-070); wired by the host when ETW is available.</summary>
    public BandwidthAggregator? Bandwidth { get; set; }

    /// <summary>PID→service display attribution (NET-073); wired by the host.</summary>
    public Func<int, string>? LookupService { get; set; }

    /// <summary>Current-network identity source (NET-083); wired by the host.</summary>
    public Windows.INetworkIdentity? NetworkIdentity { get; set; }

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

        var root = Core.Domains.GetRoot(d);
        Db.RecordFeed(d, process);
        Db.RecordHourly(root, DateTime.Now);
        // The live ETW event can't know a domain's managed status, so the feed's
        // "blocked" signal must come from the DB — the same source the snapshot
        // uses. Without this the live stream re-adds blocked domains as normal
        // rows and "Hide blocked" never sticks. Caller may still force via arg.
        var isBlocked = blocked || string.Equals(Db.GetDomainStatus(d), "blocked", StringComparison.Ordinal);
        var ev = new DnsEvent
        {
            Domain = d,
            Process = process,
            Pid = pid,
            Blocked = isBlocked,
            Hidden = Db.IsHidden(d, root),
            Ts = Timestamp.FromDateTime(DateTime.UtcNow),
        };
        ev.Blocklists.AddRange(Db.GetBlocklistsFor(d));
        Bus.Publish(ev);
    }

    /// <summary>
    /// Publish a live connection sighting to WatchConnections streams; first
    /// sightings also land in the retention-bounded connection history (NET-070).
    /// </summary>
    public void PublishConnection(ConnectionInfo info, bool recordHistory = false)
    {
        ArgumentNullException.ThrowIfNull(info);
        var category = string.Empty;
        if (info.RemotePort is 443 or 853 && Doh.CurrentIps().Contains(info.RemoteAddress))
        {
            category = "DoH/DoT"; // browser/app DNS tunneling detection
        }

        var country = GeoIp.Lookup(info.RemoteAddress);
        var host = ResolveKnownHost(info.RemoteAddress);
        var fwStatus = Threats.Contains(info.RemoteAddress) ? "THREAT"
            : DirectIp.IsDirect(info.RemoteAddress, DateTime.Now) ? "DIRECT-IP"
            : string.Empty;
        if (recordHistory)
        {
            Db.RecordConnection(new ConnHistoryRow(
                DateTime.Now.ToString("o", System.Globalization.CultureInfo.InvariantCulture),
                info.Process, info.Pid, info.Protocol, info.RemoteAddress, info.RemotePort,
                country, fwStatus));
        }

        Bus.Publish(new ConnectionEvent
        {
            Protocol = info.Protocol,
            LocalAddr = info.LocalAddress,
            LocalPort = info.LocalPort,
            RemoteAddr = info.RemoteAddress,
            RemotePort = info.RemotePort,
            Host = host,
            Process = info.Process,
            Pid = info.Pid,
            State = info.State,
            Category = category,
            Country = country,
            FwStatus = fwStatus,
            Service = LookupService?.Invoke(info.Pid) ?? string.Empty,
            Ts = Timestamp.FromDateTime(DateTime.UtcNow),
        });
    }

    /// <summary>
    /// The best known host for an IP: the fast in-memory ETW cache first, then
    /// the persistent resolved-host store (survives restarts). Empty when the
    /// IP has never been resolved.
    /// </summary>
    public string ResolveKnownHost(string ip)
    {
        var live = ResolvedIps.Lookup(ip, DateTime.Now);
        return live.Length != 0 ? live : Db.GetResolvedHost(ip);
    }

    /// <summary>
    /// Remember a forward DNS resolution (domain → its addresses): seed the
    /// in-memory cache AND persist each mapping so it survives restarts and
    /// auto-populates future connections to the same IP.
    /// </summary>
    public void RememberResolution(string domain, IReadOnlyList<string> addresses)
    {
        ArgumentNullException.ThrowIfNull(addresses);
        var d = (domain ?? string.Empty).ToLowerInvariant().Trim();
        if (d.Length == 0 || addresses.Count == 0)
        {
            return;
        }

        var now = DateTime.Now;
        ResolvedIps.Record(d, addresses, now);
        Db.UpsertResolvedHosts(addresses.Select(a => (a, d)), "dns");
    }

    public void Dispose()
    {
        Intel?.Dispose();
        SecureRules.Dispose();
        Consent.Dispose();
        GeoIp.Dispose();
        Lists?.Dispose();
        Schedules.Dispose();
        TempAllows.Dispose();
        Db.Dispose();
    }
}
