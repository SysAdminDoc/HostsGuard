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
var db = new HostsDatabase(dbPath);
var firewall = new FirewallEngine();
var identity = new FirewallIdentity(Path.Combine(baseDir, "fw_identities.json"));
var dns = new DnsConfig();
using var listFetcher = new HttpListFetcher();
var defender = new DefenderConfig();
using var state = new ServiceState(hosts, db, firewall, identity, dns, baseDir, listFetcher, defender);
using var connectionFeed = new ConnectionFeed(state);
connectionFeed.Start();

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
};
var dnsStatus = dnsMonitor.Start();
db.LogEvent("dns", "monitor_start", details: dnsStatus.ToString());

// Per-app byte counters (NET-070): ETW kernel NetworkTCPIP → per-minute DB
// buckets. Elevation-gated like the DNS monitor; history recording via the
// connection feed works regardless.
using var bandwidthMonitor = new BandwidthMonitor();
var bandwidthStatus = bandwidthMonitor.Start();
using var bandwidth = new BandwidthAggregator(db, bandwidthMonitor);
if (bandwidthStatus == DnsMonitorStatus.Started)
{
    bandwidth.Start();
}

state.Bandwidth = bandwidth;
db.LogEvent("bandwidth", "monitor_start", details: bandwidthStatus.ToString());

// svchost per-service attribution (NET-073): SCM enumeration, cached; feeds
// both the live connection stream and the consent prompt.
var serviceAttribution = new ServiceAttribution();
state.LookupService = serviceAttribution.DisplayFor;
state.Consent.LookupSoleService = serviceAttribution.SoleOwner;

// Automatic network-profile switching (NET-083): fingerprint the joined
// network and apply its mapped profile on change.
var networkIdentity = new NetworkIdentity();
state.NetworkIdentity = networkIdentity;
var policyForSwitch = new PolicyServiceImpl(state);
using var networkWatcher = new NetworkProfileWatcher(state, networkIdentity,
    profile => policyForSwitch.ApplyProfile(profile, "network_profile_switched"));
networkWatcher.Start();

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
await app.RunAsync();
