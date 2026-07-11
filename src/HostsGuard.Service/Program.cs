using System.Runtime.Versioning;
using HostsGuard.Data;
using HostsGuard.Ipc;
using HostsGuard.Service;
using HostsGuard.Windows;

[assembly: SupportedOSPlatform("windows")]

// HostsGuard elevated engine service. Owns all privileged mutation and exposes
// the gRPC control surface over the ACL'd named pipe.

var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
var baseDir = Path.Combine(programData, "HostsGuard");
// Lock the data dir down BEFORE any state file is created (the DB, consent
// state, threat list, and backups are all read back and trusted by the
// elevated service). Best-effort: a non-elevated dev/console run cannot
// re-DACL a dir it doesn't own, so never let this crash startup.
try
{
    HostsAcl.HardenDirectory(baseDir);
}
catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or InvalidOperationException)
{
    Directory.CreateDirectory(baseDir);
    Console.WriteLine($"HostsGuard: could not harden {baseDir} ACL ({ex.Message}); continuing.");
}

var dbPath = Path.Combine(baseDir, "hostsguard.db");
var handshakePath = Path.Combine(baseDir, "session_token");

var hosts = new HostsEngine(HostsEngine.DefaultHostsPath);
var db = HostsDatabase.OpenWithRecovery(dbPath, out var quarantinedDb);
if (quarantinedDb is not null)
{
    Console.WriteLine($"HostsGuard: state database was unreadable and was quarantined to {quarantinedDb}; a fresh database was created.");
}

var firewall = new FirewallEngine();
var identity = new FirewallIdentity(Path.Combine(baseDir, "fw_identities.json"));
var dns = new DnsConfig();
using var listFetcher = new HttpListFetcher();
var defender = new DefenderConfig();
using var state = new ServiceState(hosts, db, firewall, identity, dns, baseDir, listFetcher, defender,
    flowTerminator: new FlowTerminator(),
    lanSurfaceStore: new RegistryLanAttackSurfaceStore());
state.DomainFirewall.StartPeriodic();

// One-time on start: consolidate any legacy per-vendor category sections
// ("Snapchat Tracking", "LinkedIn CDN", …) into the canonical taxonomy.
// Idempotent — writes nothing once the file is normalized. Best-effort: an
// AV hold on the hosts file must never block the service from starting.
try
{
    hosts.NormalizeCategorySections(
        HostsGuard.Core.DomainCategories.Canonicalize,
        HostsGuard.Core.DomainCategories.Lookup,
        HostsGuard.Core.DomainCategories.Canonical);
}
catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
{
    Console.WriteLine($"HostsGuard: category normalization skipped ({ex.Message}).");
}

using var hostsTamper = new HostsTamperWatch(hosts);
hostsTamper.ExternalChangeDetected += (_, e) =>
{
    db.LogEvent("hosts", "external_tamper", details: $"{e.Path}; sha512={e.Sha512Hex}", reason: "tamper");
    db.AddAlert(
        "hosts_tamper",
        "critical",
        "Hosts file changed externally",
        e.Path,
        $"The hosts file changed outside HostsGuard. SHA-512: {e.Sha512Hex}",
        action: "external_change");
};
hostsTamper.Start();
if (HostsTamperWatch.CheckRegistryTamper() is { } redirected)
{
    db.LogEvent("hosts", "registry_tamper", details: redirected, reason: "tamper");
    db.AddAlert(
        "hosts_tamper",
        "critical",
        "Hosts registry path changed",
        "Tcpip DataBasePath",
        $"The TCP/IP DataBasePath registry value points to '{redirected}'.",
        action: "registry_redirect");
}

using var connectionFeed = new ConnectionFeed(state);
connectionFeed.Start();
state.ConnectionMonitorActive = true;

// Blocklist intelligence: download the reference index on first start
// (post-install) or when older than a week; refreshes weekly after that.
state.Intel?.StartIfStale();

// Real-time DNS monitor (ETW): feeds the activity feed + 24h sparkline, and
// drives CNAME-cloak reactive blocking (NET-075). Elevation-gated; degrades
// cleanly to the connection feed when unavailable.
using var dnsMonitor = new DnsMonitor();
dnsMonitor.DnsObserved += (_, e) => state.RecordDns(e.Domain, pid: e.Pid);
dnsMonitor.DnsResolved += (_, e) =>
{
    state.CnameCloak.Evaluate(e.QueryName, e.Cnames);
    // Feed the direct-IP heuristic (NET-076): resolved addresses are "known
    // good" — a later connection to a public IP never resolved is direct-to-IP.
    state.DirectIp.RecordResolved(e.Addresses, DateTime.Now);
    // Remember which site each IP belongs to (in-memory cache + persistent
    // store) so the live-connections view shows the domain next to the raw
    // remote address, now and after a restart.
    state.RememberResolution(e.QueryName, e.Addresses);
};
var dnsStatus = dnsMonitor.Start();
state.DnsMonitorActive = dnsStatus == DnsMonitorStatus.Started;
db.LogEvent("dns", "monitor_start", details: dnsStatus.ToString());

// Per-app byte counters (NET-070): ETW kernel NetworkTCPIP → per-minute DB
// buckets. Elevation-gated like the DNS monitor; history recording via the
// connection feed works regardless.
using var bandwidthMonitor = new BandwidthMonitor();
var bandwidthStatus = bandwidthMonitor.Start();
// NET-108: resolveHost maps a connection's remote IP → its resolved domain
// (ETW forward-DNS cache → persistent store) so bytes attribute to a domain.
using var bandwidth = new BandwidthAggregator(db, bandwidthMonitor, resolveHost: state.ResolveKnownHost);
bandwidth.QuotaEnforcer = state.QuotaEnforcer;
if (bandwidthStatus == DnsMonitorStatus.Started)
{
    bandwidth.Start();
}

state.Bandwidth = bandwidth;
db.LogEvent("bandwidth", "monitor_start", details: bandwidthStatus.ToString());

// TLS SNI capture (NET-109): driver-free raw-socket ClientHello sniffing so
// HTTPS connections resolved over DoH still show a hostname. Opt-in (privacy +
// AV friendly): created always, started only when the persisted flag is on.
using var sniSniffer = new SniSniffer(
    obs => state.RecordSni(obs),
    message => db.LogEvent("sni", "capture_log", details: message));
state.Sni = sniSniffer;
if (db.GetMeta("sni_capture") == "on")
{
    var sniStatus = sniSniffer.Start();
    db.LogEvent("sni", "capture_start", details: sniStatus.ToString());
}

// svchost per-service attribution (NET-073): SCM enumeration, cached; feeds
// both the live connection stream and the consent prompt.
var serviceAttribution = new ServiceAttribution();
state.LookupService = serviceAttribution.DisplayFor;
state.Consent.LookupSoleService = serviceAttribution.SoleOwner;
// Child-process auto-allow (NET-093): resolve a PID's parent so a trusted
// parent's verdict can inherit to its direct children.
state.Consent.LookupParent = ProcessTree.GetParent;
state.Consent.LookupCommandLine = ProcessCommandLine.Read;

// Automatic network-profile switching (NET-083): fingerprint the joined
// network and apply its mapped profile on change.
var networkIdentity = new NetworkIdentity();
state.NetworkIdentity = networkIdentity;
var policyForSwitch = new PolicyServiceImpl(state);
using var networkWatcher = new NetworkProfileWatcher(state, networkIdentity,
    profile => policyForSwitch.ApplyProfile(profile, "network_profile_switched"));
networkWatcher.Start();

// VPN-presence kill-switch (NET-119): force default-outbound Block whenever the
// chosen VPN adapter drops, restore on reconnect. Opt-in; the monitor self-checks
// its persisted enable flag, so Start() is a no-op until the user turns it on.
using var killSwitch = new KillSwitchMonitor(firewall, db, NetworkAdapters.IsUp, baseDir);
state.KillSwitch = killSwitch;
state.EnforcementPause.IsKillSwitchEngaged = () => killSwitch.IsEngaged;
killSwitch.BeforeEngage = state.EnforcementPause.SuspendForKillSwitch;
killSwitch.AfterEngage = () => state.FlowTeardown.CloseInternetForKillSwitch();
killSwitch.AfterRelease = state.EnforcementPause.TryResumeAfterKillSwitch;
killSwitch.Start();

// Per-app VPN binding (NET-157): opt-in per-program rules block only active
// non-selected interfaces, leaving default outbound and hosts-file blocks alone.
using var appVpnBindings = new AppVpnBindingCoordinator(firewall, db, NetworkAdapters.List);
state.AppVpnBindings = appVpnBindings;
appVpnBindings.Start();

// WFC-parity consent pipeline: Security 5157/5152 → broker → UI prompt.
var devicePaths = new DevicePathMapper();
using var blockedWatch = new BlockedConnectionWatch(
    devicePaths,
    blocked => state.Consent.OnBlocked(blocked),
    message => db.LogEvent("consent", "watch_log", details: message));
state.Consent.ArmDetection = () =>
{
    var auditOn = BlockedConnectionWatch.EnableAuditPolicy(
        message => db.LogEvent("consent", "audit_log", details: message));
    var watching = blockedWatch.Start();
    return auditOn && watching;
};
state.Consent.DisarmDetection = blockedWatch.Stop;
// Privileged bootstrap (WFCP-000c): if the persisted mode wants detection,
// re-arm it now; failures degrade to a logged, disarmed state.
state.Consent.ResumeFromPersistedMode();

// Optional headless JSON-RPC/OpenAPI loopback (NET-044). OFF by default; only
// starts when HG_LOOPBACK_API is truthy. Token minted to the ACL-locked dir.
LoopbackApi? loopbackApi = null;
if (LoopbackApi.IsEnabled())
{
    try
    {
        var apiToken = LoopbackApi.EnsureToken(baseDir);
        loopbackApi = new LoopbackApi(state, apiToken, LoopbackApi.PortFromEnv());
        loopbackApi.Start();
        db.LogEvent("loopback", "api_start", details: $"127.0.0.1:{LoopbackApi.PortFromEnv()}");
    }
    catch (Exception ex) when (ex is System.Net.HttpListenerException or InvalidOperationException)
    {
        db.LogEvent("loopback", "api_start_failed", details: ex.Message);
        Console.WriteLine($"HostsGuard: loopback API could not start ({ex.Message}); continuing without it.");
    }
}

// Outbound event webhooks (NET-044b). The deliverer always subscribes to the
// engine-event stream but only POSTs when webhooks.json (ACL-locked dir) has a
// URL — so enabling webhooks via the loopback API takes effect without a
// restart (the config object is shared). Signed with X-HG-Signature.
using var webhookHttp = WebhookDeliverer.CreateHttpClient();
using var webhooks = new WebhookDeliverer(state.Webhooks, WebhookDeliverer.HttpSender(webhookHttp),
    message => db.LogEvent("webhook", "delivery", details: message));
webhooks.Start(state.Bus);
if (state.Webhooks.Enabled)
{
    db.LogEvent("webhook", "start", details: $"{state.Webhooks.Urls.Count} endpoint(s)");
}

// Mint a per-session token and publish it to the ACL'd handshake file.
var token = SessionToken.Generate();
SessionToken.WriteHandshake(handshakePath, token);

var app = ServiceHost.Build(state, token);

// Run as a Windows Service when hosted by the SCM; as a console otherwise.
app.Lifetime.ApplicationStopping.Register(() =>
{
    // Never leave the firewall in default-block after we stop — restore the
    // user's pre-arm posture (the persisted mode still re-arms on restart).
    state.Consent.RestorePostureOnShutdown();
    Console.WriteLine("HostsGuard service stopping.");
});
Console.WriteLine($"HostsGuard service listening on named pipe '{NamedPipeSecurity.PipeName}'.");
if (loopbackApi is not null)
{
    Console.WriteLine($"HostsGuard loopback API on http://127.0.0.1:{LoopbackApi.PortFromEnv()} (token in {baseDir}\\loopback_token).");
}

await app.RunAsync();
loopbackApi?.Dispose();
