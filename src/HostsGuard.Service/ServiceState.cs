using System.Runtime.CompilerServices;
using System.Runtime.Versioning;
using Google.Protobuf.WellKnownTypes;
using HostsGuard.Contracts;
using HostsGuard.Core;
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
        IAiCompleter? aiCompleter = null,
        IFlowTerminator? flowTerminator = null,
        Func<IReadOnlyList<ConnectionInfo>>? connectionSnapshot = null,
        Func<string, CancellationToken, Task<IReadOnlyList<string>>>? domainResolver = null,
        ILanAttackSurfaceStore? lanSurfaceStore = null,
        IProxyConfigurationSnapshotSource? proxySnapshotSource = null,
        IDnsServiceBindingQuery? serviceBindingQuery = null,
        ICaptivePortalProbe? captivePortalProbe = null,
        IClock? clock = null)
    {
        Hosts = hosts ?? throw new ArgumentNullException(nameof(hosts));
        Db = db ?? throw new ArgumentNullException(nameof(db));
        Clock = clock ?? SystemClock.Instance;
        ShutdownToken = _shutdown.Token;
        IdnHomographs = new IdnHomographMonitor(db, clock: Clock);
        DnsTunnels = new DnsTunnelDetector();
        Firewall = firewall;
        Identity = identity;
        Dns = dns;
        ResolverHealth = new ResolverHealthCoordinator(dns, db, Clock);
        ServiceBindingQuery = serviceBindingQuery;
        DataDir = dataDir ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "HostsGuard");
        Snapshots = new StateSnapshotCoordinator(
            db,
            hosts.HostsPath,
            DataDir,
            typeof(ServiceState).Assembly.GetName().Version?.ToString() ?? "0.0.0");
        StartedAtUtc = Clock.UtcNow;
        Bus = new EventBus();
        // Surface new alerts on the bus so the outbound webhook deliverer can
        // forward tamper/detector notifications, not just DNS/connection activity.
        // Log-only (unsurfaced) alert types are not forwarded.
        Db.AlertRaised += OnAlertRaised;
        ActivityPersistence = new ActivityPersistenceQueue(db);
        TempAllows = new TempAllowScheduler(hosts, db, Bus, Clock);
        TempAllows.Resume();
        TempBlocks = new TempBlockScheduler(hosts, db, Bus, Clock);
        TempBlocks.Resume();
        EnforcementPause = new EnforcementPauseCoordinator(hosts, db, firewall, DataDir, Clock);
        EnforcementPause.Resume();
        CaptivePortalProbe = captivePortalProbe ?? new WindowsNcsiCaptivePortalProbe();
        ConnectionSnapshot = connectionSnapshot ?? (() => new ConnectionMonitor().Snapshot());
        FlowTeardown = new FlowTeardownCoordinator(
            db,
            flowTerminator,
            ConnectionSnapshot);
        DomainFirewall = new DomainFirewallRuleCoordinator(db, firewall, domainResolver);
        LanAttackSurface = new LanAttackSurfaceCoordinator(
            db,
            firewall,
            lanSurfaceStore ?? NullLanAttackSurfaceStore.Instance);
        Schedules = new ScheduleEnforcer(hosts, db, firewall, clock: Clock);
        QuotaEnforcer = new UsageQuotaEnforcer(db, hosts, firewall);
        Doh = new DohIntelligence(DataDir, clock: Clock);
        Threats = new ThreatIntel(DataDir);
        ThreatHistoryRescan = new ThreatHistoryRescanCoordinator(db, Threats.Contains);
        GeoIp = new GeoIpService(DataDir);
        Asn = new AsnService(DataDir);
        DirectIp = new Core.DirectIpHeuristic();
        Consent = new ConsentBroker(db, Bus, firewall, identity, DataDir, Clock)
        {
            LookupCountry = GeoIp.Lookup,
            LookupThreat = Threats.Contains,
            FlowTeardown = FlowTeardown,
        };
        SecureRules = new SecureRulesGuard(firewall, db);
        FirewallDrift = new FirewallDriftMonitor(firewall, db);
        if (proxySnapshotSource is not null)
        {
            ProxyBaseline = new ProxyBaselineMonitor(proxySnapshotSource, db);
            ProxyBaseline.Start();
        }
        CnameCloak = new CnameCloakGuard(hosts, db);
        Lock = new SettingsLock(DataDir);
        if (Lock.Degraded)
        {
            Db.AddAlert(
                "settings_lock_security",
                "critical",
                "Settings lock state requires recovery",
                "settings lock",
                Lock.DegradedMessage,
                action: "state_corrupt");
            Db.LogEvent(
                "settings",
                "lock_state_corrupt",
                details: "persisted settings-lock verifier could not be read; protected mutations fail closed",
                reason: "lock");
        }
        Webhooks = WebhookConfig.Load(DataDir);
        ListFetcher = listFetcher;
        Defender = defender;
        ResolvedIps = new Core.ResolvedIpCache();
        Ai = new AiCategorizer(db, hosts, aiCompleter ?? new DeepSeekCompleter(), DataDir);
        Adoption = new HostsAdoptionCoordinator(hosts, db);
        if (listFetcher is not null)
        {
            Lists = new ListImporter(hosts, db, listFetcher);
            Intel = new BlocklistIntelligence(db, listFetcher, Clock);
            IpBlocklists = new IpBlocklistCoordinator(db, firewall, listFetcher);
            Updater = new SelfUpdater(db, DataDir, listFetcher,
                typeof(ServiceState).Assembly.GetName().Version?.ToString() ?? "0.0.0",
                clock: Clock);
        }
    }

    public HostsEngine Hosts { get; }

    public HostsDatabase Db { get; }

    public IClock Clock { get; }

    public IdnHomographMonitor IdnHomographs { get; }

    /// <summary>Bounded, report-only rolling detector for encoded DNS subdomain bursts.</summary>
    public DnsTunnelDetector DnsTunnels { get; }

    public IFirewallEngine? Firewall { get; }

    public FirewallIdentity? Identity { get; }

    public IDnsConfig? Dns { get; }

    /// <summary>Cached manual/opt-in scheduled, report-only resolver health matrix.</summary>
    internal ResolverHealthCoordinator ResolverHealth { get; }

    /// <summary>Cancellable direct HTTPS/SVCB query seam; null when the Windows API is unavailable.</summary>
    public IDnsServiceBindingQuery? ServiceBindingQuery { get; }

    /// <summary>Service data directory (backups, support bundles). ProgramData in production.</summary>
    public string DataDir { get; }

    /// <summary>Integrity-protected, non-secret full-state recovery points.</summary>
    public StateSnapshotCoordinator Snapshots { get; }

    public ScheduleEnforcer Schedules { get; }

    /// <summary>Opt-in usage-budget block-on-exceed enforcement (NET-172).</summary>
    public UsageQuotaEnforcer QuotaEnforcer { get; }

    public ListImporter? Lists { get; }

    /// <summary>IP-format blocklists enforced as HG_IPBlock_* firewall rules (NET-171); null without a fetcher.</summary>
    public IpBlocklistCoordinator? IpBlocklists { get; }

    /// <summary>SHA-256-verified self-update (NET-187); null without a fetcher.</summary>
    public SelfUpdater? Updater { get; }

    public DohIntelligence Doh { get; }

    public IListFetcher? ListFetcher { get; }

    public IDefender? Defender { get; }

    public ThreatIntel Threats { get; }

    public ThreatHistoryRescanCoordinator ThreatHistoryRescan { get; }

    public GeoIpService GeoIp { get; }

    public AsnService Asn { get; }

    /// <summary>Direct-to-IP (no-DNS) heuristic for the block-P2P signal (NET-076).</summary>
    public Core.DirectIpHeuristic DirectIp { get; }

    /// <summary>ETW-fed IP→domain map so live connections show the site name.</summary>
    public Core.ResolvedIpCache ResolvedIps { get; }

    /// <summary>Reference blocklist index for block-candidate flagging; null without a fetcher.</summary>
    public BlocklistIntelligence? Intel { get; }

    /// <summary>DeepSeek domain categorization.</summary>
    public AiCategorizer Ai { get; }

    /// <summary>Adopts hand-added hosts entries into the managed DB (NET-188).</summary>
    public HostsAdoptionCoordinator Adoption { get; }

    /// <summary>Live ETW DNS monitor state (wired by the host; false when unavailable).</summary>
    public bool DnsMonitorActive { get; set; }

    /// <summary>Live connection-feed state (wired by the host).</summary>
    public bool ConnectionMonitorActive { get; set; }

    /// <summary>ETW and Security-log completeness snapshots (wired by the host).</summary>
    public Func<IReadOnlyList<ObservationIntegritySnapshot>> ObservationHealth { get; set; } =
        static () => Array.Empty<ObservationIntegritySnapshot>();

    public EventBus Bus { get; }

    /// <summary>Single-reader durable writer for DNS/SNI persistence.</summary>
    public ActivityPersistenceQueue ActivityPersistence { get; }

    public ConsentBroker Consent { get; }

    public SecureRulesGuard SecureRules { get; }

    public FirewallDriftMonitor FirewallDrift { get; }

    /// <summary>Report-only WinINET/WinHTTP proxy and PAC drift monitor.</summary>
    public ProxyBaselineMonitor? ProxyBaseline { get; }

    public CnameCloakGuard CnameCloak { get; }

    /// <summary>Settings/rule lock (NET-079).</summary>
    public SettingsLock Lock { get; }

    /// <summary>Outbound event-webhook config (NET-044b); shared with the deliverer + loopback API.</summary>
    public WebhookConfig Webhooks { get; }

    /// <summary>
    /// Refuse a mutating action when the settings lock is armed and not inside a
    /// timed-unlock window (NET-079). Returns a locked-error Ack, else null.
    /// </summary>
    public Contracts.Ack? GateWhenLocked()
    {
        if (Lock.IsLocked(Clock.UtcNow))
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

    /// <summary>
    /// Apply the centralized RPC classification before using the settings-lock
    /// gate. Calling this from a read-only/protective RPC is a coding error.
    /// </summary>
    public Contracts.Ack? GateWhenLocked(
        string service,
        [CallerMemberName] string method = "")
    {
        var kind = RpcMutationPolicy.GetRequired(service, method);
        if (kind != RpcMutationKind.LockProtectedMutation)
        {
            throw new InvalidOperationException($"{service}/{method} is classified {kind} and must not use the settings-lock gate");
        }

        return GateWhenLocked();
    }

    public TempAllowScheduler TempAllows { get; }

    public TempBlockScheduler TempBlocks { get; }

    public EnforcementPauseCoordinator EnforcementPause { get; }

    public ICaptivePortalProbe CaptivePortalProbe { get; }

    public FlowTeardownCoordinator FlowTeardown { get; }

    /// <summary>Current TCP/UDP endpoint snapshot used by exposure analysis and flow teardown.</summary>
    public Func<IReadOnlyList<ConnectionInfo>> ConnectionSnapshot { get; }

    /// <summary>Reactive domain-scoped firewall rules (NET-154).</summary>
    public DomainFirewallRuleCoordinator DomainFirewall { get; }

    public LanAttackSurfaceCoordinator LanAttackSurface { get; }

    /// <summary>Per-app byte-counter aggregator (NET-070); wired by the host when ETW is available.</summary>
    public BandwidthAggregator? Bandwidth { get; set; }

    /// <summary>PID→service display attribution (NET-073); wired by the host.</summary>
    public Func<int, string>? LookupService { get; set; }

    /// <summary>Exact SCM key/display pair when a PID has one unambiguous service owner.</summary>
    public Func<int, (string Key, string Display)?>? LookupSoleService { get; set; }

    /// <summary>Current-network identity source (NET-083); wired by the host.</summary>
    public Windows.INetworkIdentity? NetworkIdentity { get; set; }

    /// <summary>Read-only active/recent Remote Desktop session inventory.</summary>
    public Windows.IRemoteSessionSource RemoteSessions { get; set; } =
        new Windows.UnavailableRemoteSessionSource("not_configured");

    /// <summary>Driver-free TLS SNI capture (NET-109); wired by the host, opt-in.</summary>
    public Windows.SniSniffer? Sni { get; set; }

    /// <summary>VPN-presence kill-switch (NET-119); wired by the host, opt-in.</summary>
    public KillSwitchMonitor? KillSwitch { get; set; }

    /// <summary>Per-app VPN adapter bindings (NET-157); wired by the host, opt-in.</summary>
    public AppVpnBindingCoordinator? AppVpnBindings { get; set; }

    private int _echUnavailableSniObservations;

    public int EchUnavailableSniObservations => Volatile.Read(ref _echUnavailableSniObservations);

    /// <summary>
    /// Record a TLS SNI observation (NET-109): persist the IP→host mapping (source
    /// "sni") and seed the live cache so the connection feed names an HTTPS dial
    /// even when DNS was resolved over DoH. ECH-encrypted SNI carries no cleartext
    /// name, so nothing is recorded — the connection stays IP-only (as intended).
    /// </summary>
    public void RecordSni(Windows.SniObservation obs)
    {
        ArgumentNullException.ThrowIfNull(obs);
        if (obs.EchUnavailable)
        {
            Interlocked.Increment(ref _echUnavailableSniObservations);
            return;
        }

        if (string.IsNullOrEmpty(obs.Host) || string.IsNullOrEmpty(obs.RemoteAddress))
        {
            return;
        }

        var host = obs.Host.ToLowerInvariant();
        ResolvedIps.Record(host, new[] { obs.RemoteAddress }, Clock.Now);
        ActivityPersistence.EnqueueResolvedHosts(new[] { (obs.RemoteAddress, host) }, "sni");
    }

    public DateTime StartedAtUtc { get; }

    private readonly CancellationTokenSource _shutdown = new();

    /// <summary>
    /// Cancelled when the service state is disposed (shutdown). Fire-and-forget
    /// background work (e.g. AI categorization) links to this so it stops with
    /// the service instead of running past teardown on <c>CancellationToken.None</c>.
    /// Captured from the source at construction so a task reading it after Dispose
    /// gets the (already-cancelled) token instead of an <see cref="ObjectDisposedException"/>.
    /// </summary>
    public CancellationToken ShutdownToken { get; }

    /// <summary>
    /// Record a DNS sighting: persist to the activity feed and publish to live
    /// watchers. Called by the ETW pipeline (production) and tests.
    /// </summary>
    public void RecordDns(
        string domain,
        string process = "",
        int pid = 0,
        bool blocked = false,
        string queryType = "A",
        DateTime? observedAtUtc = null)
    {
        var d = Core.Domains.ToAscii(domain);
        if (d.Length == 0)
        {
            return;
        }

        var root = Core.Domains.GetRoot(d);
        // Capture first-contact BEFORE the (async) feed write so a brand-new
        // domain is detectable for the newly-observed alert.
        var firstContact = !Db.FeedContains(d);
        IdnHomographs.Observe(d, process);
        if (!Db.IsHistoryPersistenceExcluded(process, d))
            ActivityPersistence.EnqueueDnsSighting(d, process, reason: null, Clock.Now);
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
            Ts = Timestamp.FromDateTime(Clock.UtcNow),
        };
        ev.Blocklists.AddRange(Db.GetBlocklistsFor(d));
        Bus.Publish(ev);

        MaybeAlertSuspiciousDomain(d, root, process);
        MaybeAlertDnsTunnel(d, process, pid, queryType, observedAtUtc ?? Clock.UtcNow);
        MaybeAlertNewlyObserved(d, process, firstContact);
    }

    // Alert dedup sets are bounded/TTL'd so the always-on service never grows
    // one retained entry per distinct domain/root/process for its whole lifetime.
    private readonly BoundedDedupSet _dgaAlerted = new(comparer: StringComparer.Ordinal);
    private readonly BoundedDedupSet _newlyObservedAlerted = new(comparer: StringComparer.Ordinal);
    private const int BinaryIdentityCacheCap = 4096;
    private readonly Dictionary<string, FileIdentity> _binaryIdentityCache = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _binaryIdentityGate = new();

    /// <summary>
    /// Opt-in first-contact signal: when a domain is observed that this machine
    /// has never seen before, raise a "newly observed" alert. Gated on the type
    /// being enabled (off by default — a fresh install would otherwise flag
    /// everything), and deduped in-memory so the pre-flush window can't double-fire.
    /// </summary>
    private void MaybeAlertNewlyObserved(string domain, string process, bool firstContact)
    {
        if (!firstContact || !Db.IsAlertTypeSurfaced("newly_observed_domain"))
        {
            return;
        }

        if (_newlyObservedAlerted.Add(domain, Clock.UtcNow))
        {
            Db.AddAlert(
                "newly_observed_domain",
                "info",
                "Newly observed domain",
                domain,
                $"{domain} was contacted for the first time on this machine.",
                action: "newly_observed_domain",
                process: process);
        }
    }

    /// <summary>
    /// NET-201: raise a one-time alert when a domain's registrable name looks
    /// algorithmically generated (DGA). Cheap fast-reject first
    /// (short/normal labels never match), then skip curated-known domains, then
    /// alert once per flagged root so the set stays small over long uptime.
    /// </summary>
    private void MaybeAlertSuspiciousDomain(string domain, string root, string process)
    {
        if (root.Length == 0 || !Db.IsAlertTypeSurfaced("suspicious_domain")
            || Core.DomainPurpose.Lookup(domain).Length != 0)
        {
            return;
        }

        var evidence = DgaHeuristic.Analyze(root);
        if (!evidence.IsAlgorithmic)
        {
            return;
        }

        if (_dgaAlerted.Add(root, Clock.UtcNow))
        {
            Db.AddAlert(
                "suspicious_domain",
                "warning",
                "Algorithmic-looking domain observed",
                root,
                BuildDgaEvidenceDetails(domain, evidence),
                action: "suspicious_domain",
                process: process);
        }
    }

    internal static string BuildDgaEvidenceDetails(string domain, DgaScoreBreakdown evidence) =>
        FormattableString.Invariant(
            $"{domain} has an algorithmic-looking registered label '{evidence.RegistrableLabel}'. Score {evidence.Score:F2}/{evidence.DecisionThreshold:F2}; entropy {evidence.Entropy:F3} (threshold {evidence.EntropyThreshold:F3}); vowel ratio {evidence.VowelRatio:P1} (low below {evidence.VowelRatioThreshold:P1}); digit ratio {evidence.DigitRatio:P1} (high at {evidence.DigitRatioThreshold:P1}); max consonant run {evidence.MaxConsonantRun} (high at {evidence.ConsonantRunThreshold}); reason {evidence.Reason}; model {evidence.Version}. Alert only — no domain was blocked.");

    private void MaybeAlertDnsTunnel(string domain, string process, int pid, string queryType, DateTime observedAtUtc)
    {
        if (!Db.IsAlertTypeSurfaced("dns_tunnel"))
        {
            return;
        }

        var evidence = DnsTunnels.Observe(domain, process, pid, queryType, observedAtUtc);
        if (evidence is null)
        {
            return;
        }

        var identity = evidence.ProcessName.Length != 0
            ? evidence.ProcessName
            : evidence.ProcessId > 0 ? $"PID {evidence.ProcessId}" : "unknown process";
        Db.AddAlert(
            "dns_tunnel",
            "warning",
            "Possible DNS-tunneling burst observed",
            $"{evidence.RootDomain} [{identity}]",
            BuildDnsTunnelEvidenceDetails(evidence),
            action: "dns_tunnel",
            process: identity);
    }

    internal static string BuildDnsTunnelEvidenceDetails(DnsTunnelDetection evidence)
    {
        var recordTypes = string.Join(", ", evidence.RecordTypes.Select(item =>
            FormattableString.Invariant($"{item.RecordType}={item.Count} ({item.Ratio:P1})")));
        return FormattableString.Invariant(
            $"{evidence.RootDomain} produced {evidence.QueryCount} queries ({evidence.UniqueQueryCount} unique; ratio {evidence.UniqueQueryRatio:P1}, threshold {evidence.UniqueQueryRatioThreshold:P1}) in {evidence.WindowSeconds:F1}s ({evidence.QueriesPerSecond:F2}/s, threshold {evidence.QueriesPerSecondThreshold:F2}/s). Subdomain payload length averaged {evidence.AverageSubdomainLength:F1}, max {evidence.MaximumSubdomainLength}; {evidence.LongSubdomainCount}/{evidence.QueryCount} were at least {evidence.SubdomainLengthThreshold} characters (ratio {evidence.LongSubdomainRatio:P1}, threshold {evidence.LongSubdomainRatioThreshold:P1}). Entropy averaged {evidence.AverageSubdomainEntropy:F3}, max {evidence.MaximumSubdomainEntropy:F3}; {evidence.HighEntropyCount}/{evidence.QueryCount} met {evidence.SubdomainEntropyThreshold:F3} (ratio {evidence.HighEntropyRatio:P1}, threshold {evidence.HighEntropyRatioThreshold:P1}). Record types: {recordTypes}; suspicious type ratio {evidence.SuspiciousRecordTypeRatio:P1} (threshold {evidence.SuspiciousRecordTypeRatioThreshold:P1}). Signals {evidence.SignalCount}/{evidence.DecisionThreshold}; model {evidence.Version}. Alert only — no domain was blocked.");
    }

    private readonly BoundedDedupSet _dnsBypassAlerted = new(comparer: StringComparer.OrdinalIgnoreCase);

    // The Windows DNS Client (dnscache) legitimately owns the system resolver's
    // port-53 egress; those processes are not "bypassing" anything.
    private static readonly HashSet<string> SystemResolverProcesses =
        new(StringComparer.OrdinalIgnoreCase) { "svchost.exe", "system", "system idle process", string.Empty };

    /// <summary>
    /// Opt-in (default off) detector: a process that talks DNS itself — direct
    /// port-53 to a public resolver, or a known DoH endpoint — is dodging the
    /// system resolver (and therefore the hosts-file blocklist). Deduped once per
    /// process+kind so a browser rotating resolvers alerts only once.
    /// </summary>
    private void MaybeAlertDnsBypass(ConnectionInfo info, string category)
    {
        if (!string.Equals(info.Direction, "outbound", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        var process = info.Process ?? string.Empty;
        if (SystemResolverProcesses.Contains(process.Trim()))
        {
            return;
        }

        string kind;
        if (string.Equals(category, "DoH/DoT", StringComparison.Ordinal))
        {
            kind = "DoH/DoT";
        }
        else if (info.RemotePort == 53
                 && System.Net.IPAddress.TryParse(info.RemoteAddress, out var ip)
                 && SsrfGuard.IsPublic(ip))
        {
            kind = "direct DNS (port 53)";
        }
        else
        {
            return;
        }

        if (!Db.IsAlertTypeSurfaced("dns_bypass"))
        {
            return;
        }

        if (_dnsBypassAlerted.Add($"{process}|{kind}", Clock.UtcNow))
        {
            Db.AddAlert(
                "dns_bypass",
                "warning",
                "App bypassing system DNS",
                process.Length != 0 ? process : info.RemoteAddress,
                $"{(process.Length != 0 ? process : "a process")} used {kind} to {info.RemoteAddress}:{info.RemotePort}, bypassing the system resolver and the hosts blocklist.",
                action: "dns_bypass",
                process: process);
        }
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

        MaybeAlertDnsBypass(info, category);

        var country = GeoIp.Lookup(info.RemoteAddress);
        var asn = Asn.Lookup(info.RemoteAddress);
        var host = ResolveKnownHost(info.RemoteAddress);
        MaybeAlertFirstNetworkActivity(info, host);
        var threat = Threats.Contains(info.RemoteAddress);
        var fwStatus = threat ? "THREAT"
            : DirectIp.IsDirect(info.RemoteAddress, Clock.Now) ? "DIRECT-IP"
            : string.Empty;
        if (threat)
        {
            Db.AddAlert(
                "threat_hit",
                "critical",
                "Threat-intel IP contacted",
                info.RemoteAddress,
                $"{info.Process} opened {info.Protocol} {info.RemoteAddress}:{info.RemotePort}",
                action: "threat_connection",
                process: info.Process);
        }

        if (recordHistory && !Db.IsHistoryPersistenceExcluded(info.Process, host))
        {
            Db.RecordConnection(new ConnHistoryRow(
                Clock.Now.ToString("o", System.Globalization.CultureInfo.InvariantCulture),
                info.Process, info.Pid, info.Protocol, info.RemoteAddress, info.RemotePort,
                country, fwStatus, host, asn));
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
            Asn = asn,
            FwStatus = fwStatus,
            Service = LookupService?.Invoke(info.Pid) ?? string.Empty,
            Ts = Timestamp.FromDateTime(Clock.UtcNow),
        });
    }

    private void MaybeAlertFirstNetworkActivity(ConnectionInfo info, string host)
    {
        var path = (info.ProcessPath ?? string.Empty).Trim();
        var process = (info.Process ?? string.Empty).Trim();
        var fileIdentity = ResolveBinaryIdentity(path);
        var identity = fileIdentity?.Sha256.Length > 0 ? "sha256:" + fileIdentity.Sha256
            : path.Length != 0 ? "path:" + path.ToLowerInvariant()
            : "process:" + process.ToLowerInvariant();
        if (identity.EndsWith(':') || !Db.TryRecordBinaryNetworkFirstSeen(new BinaryNetworkFirstSeenRow(
                identity, process, path, fileIdentity?.Sha256 ?? string.Empty,
                fileIdentity?.Signer ?? string.Empty, host.Length != 0 ? host : info.RemoteAddress,
                Clock.UtcNow.ToString("o", System.Globalization.CultureInfo.InvariantCulture))))
            return;

        if (!Db.IsAlertTypeSurfaced("first_network_activity")) return;
        var destination = host.Length != 0 ? host : info.RemoteAddress;
        var purpose = host.Length != 0 ? DomainPurpose.Lookup(host) : string.Empty;
        Db.AddAlert("first_network_activity", "info", "First network activity",
            process.Length != 0 ? process : path,
            $"{process} first contacted {destination}:{info.RemotePort} over {info.Protocol}. " +
            (purpose.Length != 0 ? $"Purpose: {purpose}. " : string.Empty) +
            $"Identity: {(fileIdentity?.Sha256.Length > 0 ? "SHA-256 " + fileIdentity.Sha256 : identity)}. Binary hash changes are treated as a new identity; repeated paths/hashes are deduplicated.",
            action: "first_network_activity", process: process);
    }

    private FileIdentity? ResolveBinaryIdentity(string path)
    {
        if (path.Length == 0 || !File.Exists(path)) return null;
        try
        {
            var file = new FileInfo(path);
            var key = $"{path}|{file.Length}|{file.LastWriteTimeUtc.Ticks}";
            lock (_binaryIdentityGate)
            {
                if (_binaryIdentityCache.TryGetValue(key, out var cached)) return cached;
            }
            var computed = FirewallIdentity.Compute(path);
            lock (_binaryIdentityGate)
            {
                // Keyed by path|size|mtime, so binary churn over long uptime
                // accretes stale entries; drop the cache when it exceeds the cap
                // (a pure perf cache — recomputing a hash is cheap).
                if (_binaryIdentityCache.Count >= BinaryIdentityCacheCap)
                {
                    _binaryIdentityCache.Clear();
                }

                _binaryIdentityCache[key] = computed;
            }

            return computed;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.Cryptography.CryptographicException)
        {
            return null;
        }
    }

    /// <summary>
    /// The best known host for an IP: the fast in-memory ETW cache first, then
    /// the persistent resolved-host store (survives restarts). Empty when the
    /// IP has never been resolved.
    /// </summary>
    public string ResolveKnownHost(string ip)
    {
        var live = ResolvedIps.Lookup(ip, Clock.Now);
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

        var now = Clock.Now;
        ResolvedIps.Record(d, addresses, now);
        if (!Db.IsHistoryPersistenceExcluded(null, d))
            ActivityPersistence.EnqueueResolvedHosts(addresses.Select(a => (a, d)), "dns");
        DomainFirewall.ObserveResolution(d, addresses);

        // NET-199: a public registrable domain answering with a private-LAN
        // address is the DNS-rebinding signature. Alert-only (split-horizon DNS
        // is a legitimate producer); the alert type is user-mutable.
        var rebind = DnsRebindDetector.PrivateAnswersForPublicDomain(d, addresses);
        if (rebind.Count != 0)
        {
            Db.AddAlert(
                "dns_rebind",
                "warning",
                "Public domain resolved to a private address",
                d,
                $"{d} resolved to {string.Join(", ", rebind)} — a public name pointing at your LAN can be DNS rebinding.",
                action: "dns_rebind");
        }
    }

    public Task FlushActivityPersistenceAsync(CancellationToken cancellationToken = default) =>
        ActivityPersistence.FlushAsync(cancellationToken);

    private void OnAlertRaised(AlertNotification notification)
    {
        // Only surfaced (opt-in-enabled) alerts are forwarded; log-only types stay
        // local. Bus.Publish is non-blocking, so this never stalls AddAlert.
        if (notification.Surfaced)
        {
            Bus.Publish(notification);
        }
    }

    public void Dispose()
    {
        Db.AlertRaised -= OnAlertRaised;
        // Signal shutdown FIRST so fire-and-forget background work linked to
        // ShutdownToken stops before the engines it touches are disposed.
        try { _shutdown.Cancel(); } catch (AggregateException) { /* callbacks throwing on cancel are benign */ }
        _shutdown.Dispose();
        Intel?.Dispose();
        FirewallDrift.Dispose();
        ProxyBaseline?.Dispose();
        SecureRules.Dispose();
        Consent.Dispose();
        GeoIp.Dispose();
        Asn.Dispose();
        Lists?.Dispose();
        IpBlocklists?.Dispose();
        Schedules.Dispose();
        DomainFirewall.Dispose();
        EnforcementPause.Dispose();
        (CaptivePortalProbe as IDisposable)?.Dispose();
        TempAllows.Dispose();
        TempBlocks.Dispose();
        ActivityPersistence.Dispose();
        ResolverHealth.Dispose();
        Ai.Dispose();
        Db.Dispose();
    }
}
