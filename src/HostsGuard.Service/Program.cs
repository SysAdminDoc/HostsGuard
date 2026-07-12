using System.Runtime.Versioning;
using System.Text.Json;
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

// NET-187: if a hash-verified installer was staged, apply it now — the manifest
// is consumed before launch so a crashing installer can never loop the service.
var installedVersion = typeof(ServiceState).Assembly.GetName().Version?.ToString() ?? "0.0.0";
var updateResult = SelfUpdater.ApplyPendingOnStart(baseDir, installedVersion, db);
if (updateResult.StartsWith("applying", StringComparison.Ordinal))
{
    Console.WriteLine($"HostsGuard: {updateResult} — the installer will restart the service.");
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

// NET-188: on startup, adopt any hand edits made while the service was stopped —
// dedupe/organize the file and import new sink-block domains as managed rows.
// Best-effort: an AV hold must never block startup.
if (state.Adoption.Enabled)
{
    try
    {
        var startupAdopt = state.Adoption.AdoptNow("startup");
        if (startupAdopt.Adopted != 0 || startupAdopt.Organized != 0)
        {
            Console.WriteLine($"HostsGuard: adopted {startupAdopt.Adopted} manual hosts entries, organized {startupAdopt.Organized}.");
        }
    }
    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
    {
        Console.WriteLine($"HostsGuard: manual-edit adoption skipped ({ex.Message}).");
    }
}

using var hostsTamper = new HostsTamperWatch(hosts);
hostsTamper.ExternalChangeDetected += (_, e) =>
{
    db.LogEvent("hosts", "external_tamper", details: $"{e.Path}; sha512={e.Sha512Hex}", reason: "tamper");

    // NET-188: when adoption is enabled and the edit is a plain set of hand-added
    // block entries (no domain→real-IP redirect), import them instead of alarming.
    // A redirect to a routable IP is a hijack signal — keep the critical alert.
    if (state.Adoption.Enabled)
    {
        try
        {
            var outcome = state.Adoption.AdoptNow("external_edit");
            hostsTamper.AcceptCurrentState(); // our organize-rewrite isn't a fresh tamper
            if (!outcome.HasSuspiciousRedirect)
            {
                if (outcome.Adopted != 0 || outcome.Organized != 0)
                {
                    db.AddAlert(
                        "hosts_tamper",
                        "info",
                        "Manual hosts edits adopted",
                        e.Path,
                        $"Imported {outcome.Adopted} hand-added {(outcome.Adopted == 1 ? "entry" : "entries")} "
                            + $"and organized {outcome.Organized} into categories.",
                        action: "manual_adopted");
                }

                return;
            }

            db.AddAlert(
                "hosts_tamper",
                "critical",
                "Hosts file redirect detected",
                e.Path,
                $"A hand edit mapped {outcome.Suspicious} domain(s) to a real IP address (a redirect, not a block). "
                    + $"SHA-512: {e.Sha512Hex}",
                action: "external_change");
            return;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            db.LogEvent("hosts", "adopt_failed", details: ex.Message, reason: "manual_edit");
            // fall through to the tamper alert below
        }
    }

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

// Baseline-and-diff the broader DNS-path registry surface (DoH policy, NetBIOS,
// name-server overrides) the hosts watch can't see. First run records the
// baseline; later runs alert on each changed value, then re-baseline so an
// acknowledged change doesn't re-fire every startup.
try
{
    var dnsSnapshot = DnsRegistryBaseline.Snapshot();
    var storedBaseline = db.GetMeta("dns_registry_baseline");
    if (string.IsNullOrEmpty(storedBaseline))
    {
        db.SetMeta("dns_registry_baseline", JsonSerializer.Serialize(dnsSnapshot));
    }
    else
    {
        var baseline = JsonSerializer.Deserialize<Dictionary<string, string>>(storedBaseline)
            ?? new Dictionary<string, string>();
        foreach (var change in DnsRegistryBaseline.Diff(baseline, dnsSnapshot))
        {
            db.LogEvent("dns", "registry_tamper", details: $"{change.Key}: '{change.Before}' -> '{change.After}'", reason: "tamper");
            db.AddAlert(
                "hosts_tamper",
                "critical",
                "DNS registry key changed",
                change.Key,
                $"The DNS-relevant registry value '{change.Key}' changed from '{change.Before}' to '{change.After}'.",
                action: "registry_redirect");
        }

        db.SetMeta("dns_registry_baseline", JsonSerializer.Serialize(dnsSnapshot));
    }
}
catch (Exception ex) when (ex is JsonException or IOException or InvalidOperationException)
{
    db.LogEvent("dns", "registry_baseline_failed", details: ex.Message);
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
using var bandwidthMonitor = new BandwidthMonitor(endpointObserver: info =>
{
    connectionFeed.Observe(info);
}, endpointObserverError: ex =>
    db.LogEvent("bandwidth", "endpoint_observer_error", details: $"{ex.GetType().Name}: {ex.Message}"));
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

// NET-180: redacted rotating file log with W3C TraceId/SpanId, so a GUI action
// can be followed from the app's log into this service's handling of it.
using var serviceLog = HostsGuard.Diagnostics.Logging.CreateFileLogger(Path.Combine(baseDir, "logs"));
var app = ServiceHost.Build(state, token,
    rpcLog: (method, traceId) => serviceLog.Information("rpc {Method} handled (trace {TraceId})", method, traceId));

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
