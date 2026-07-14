using System.Reflection;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using HostsGuard.Contracts;
using HostsGuard.Core;
using HostsGuard.Ipc;
using HostsGuard.Windows;

[assembly: SupportedOSPlatform("windows")]

// HostsGuard console entry: block/allow/unblock/status/export/mode over the
// service pipe, plus release-smoke (NET-054) and the uninstaller's cleanup.

return args.Length == 0 ? Usage() : (args[0].ToLowerInvariant() switch
{
    "status" => await StatusAsync(),
    "block" => await DomainOpAsync(args, (c, r) => c.BlockAsync(r).ResponseAsync),
    "allow" => await DomainOpAsync(args, (c, r) => c.AllowAsync(r).ResponseAsync),
    "unblock" => await DomainOpAsync(args, (c, r) => c.UnblockAsync(r).ResponseAsync),
    "temp-block" => await TempBlockAsync(args),
    "block-app" => await ProgramOpAsync(args, block: true),
    "unblock-app" => await ProgramOpAsync(args, block: false),
    "firewall-packages" or "packages" => await ListPackagesAsync(args),
    "firewall-analyze" => await AnalyzeFirewallRulesAsync(args),
    "firewall-cleanup" => await CleanupFirewallRulesAsync(args),
    "firewall-rule" => await FirewallRuleAuthoringAsync(args),
    "block-package" => await PackageOpAsync(args, "Block"),
    "allow-package" => await PackageOpAsync(args, "Allow"),
    "unblock-package" => await PackageOpAsync(args, "Delete"),
    "explain" => await ExplainAsync(args),
    "export" => await ExportAsync(args.Length > 1 ? args[1] : "hostsguard_export.json"),
    "export-policy" => await ExportPolicyAsync(args.Length > 1 ? args[1] : "hostsguard_policy.json"),
    "import-policy" => await ImportPolicyAsync(args),
    "validate-policy" => ValidatePolicy(args),
    "events" => await EventsAsync(args),
    "listeners" => await ListListenersAsync(args),
    "traffic-profile" => await TrafficProfileAsync(args),
    "support-bundle" => await SupportBundleAsync(args),
    "snapshot" => await FullStateSnapshotAsync(args),
    "usage" => await UsageAsync(args),
    "usage-quota" => await UsageQuotaAsync(args),
    "history-privacy" => await HistoryPrivacyAsync(args),
    "dns-cache" => await DnsCacheAsync(args),
    "dns-inspect" => await DnsInspectAsync(args),
    "resolver-health" => await ResolverHealthAsync(args),
    "profile-match" => await ProfileMatchAsync(args),
    "captive-portal" => await CaptivePortalAsync(args),
    "dns-flush-entry" => await DnsFlushEntryAsync(args),
    "dga-check" => DgaCheck(args),
    "idn-homograph" => await IdnHomographAsync(args),
    "proxy" => await ProxyBaselineAsync(args),
    "adopt-hosts" => await AdoptHostsAsync(args),
    "blocklists" => await BlocklistsAsync(args),
    "ip-blocklists" => await IpBlocklistsAsync(args),
    "mode" => await ModeAsync(args.Length > 1 ? args[1] : null),
    "secure-rules" => await SecureRulesAsync(args),
    "update" => await UpdateAsync(args),
    "safe-posture" => await SafePostureAsync(),
    "safe-posture-smoke" => await SafePostureSmokeAsync(),
    "release-smoke" => await ReleaseSmokeAsync(),
    "uninstall-cleanup" => UninstallCleanup(),
    "--version" or "version" => Version(),
    "help" or "--help" or "-h" or "-?" or "/?" => UsageOk(),
    _ => Usage(),
});

// Asking for help is a success; falling into usage from a bad command is not.
static int UsageOk()
{
    Usage();
    return 0;
}

static int Usage()
{
    Console.WriteLine("""
        HostsGuard CLI

        usage:
          HostsGuard.Cli status
          HostsGuard.Cli block <domain> [reason]
          HostsGuard.Cli allow <domain> [reason]
          HostsGuard.Cli unblock <domain>
          HostsGuard.Cli temp-block <domain> <minutes>
          HostsGuard.Cli temp-block list
          HostsGuard.Cli block-app <exe-path> [out|in]
          HostsGuard.Cli unblock-app <exe-path> [out|in]
          HostsGuard.Cli firewall-packages [--search text]
          HostsGuard.Cli firewall-analyze [--kind name] [--remediation name] [--search text]
                               [--cleanup-eligible] [--export path.csv|path.json]
          HostsGuard.Cli firewall-cleanup preview --analysis-hash SHA256 --name HG_Rule [--name HG_Other]
          HostsGuard.Cli firewall-cleanup apply --analysis-hash SHA256 --preview-hash SHA256 --name HG_Rule [--name HG_Other]
          HostsGuard.Cli firewall-rule interfaces
          HostsGuard.Cli firewall-rule create|edit --name Rule [--direction in|out] [--action allow|block]
                               [--protocol tcp|udp|any|icmpv4|icmpv6] [--local-ports ports]
                               [--remote-ports ports] [--interfaces alias,alias] [--remote-addresses list]
                               [--program path] [--enabled|--disabled]
          HostsGuard.Cli block-package <package-family-name|sid> [out|in]
          HostsGuard.Cli allow-package <package-family-name|sid> [out|in]
          HostsGuard.Cli unblock-package <package-family-name|sid> [out|in]
          HostsGuard.Cli explain <domain|ip|process|exe> [--domain d] [--ip a] [--program path]
                              [--package pfn] [--package-sid sid] [--process name]
                              [--port n] [--proto tcp|udp] [--direction out|in]
          HostsGuard.Cli export [path.json]
          HostsGuard.Cli export-policy [path.json]
          HostsGuard.Cli import-policy [--preview] <path.json>
          HostsGuard.Cli import-policy --restore-checkpoint
          HostsGuard.Cli validate-policy <path.json> | validate-policy --emit-schema [path]
          HostsGuard.Cli events [--limit N] [--offset N] [--search text] [--since ISO] [--until ISO]
                               [--action name] [--reason name] [--domain text] [--process text]
                               [--category name] [--export path.csv]
          HostsGuard.Cli listeners [--protocol tcp|udp] [--port N] [--process text]
                               [--risk low|medium|high] [--export path.csv|path.json]
          HostsGuard.Cli traffic-profile [path.json|path.csv] [--format json|csv] [--limit N]
                               [--since ISO] [--until ISO] [--process app] [--action name]
                               [--protocol tcp|udp]
          HostsGuard.Cli support-bundle [--limit N] [--since ISO] [--until ISO]
                               [--process app] [--action name] [--protocol tcp|udp]
          HostsGuard.Cli snapshot create
          HostsGuard.Cli snapshot list
          HostsGuard.Cli snapshot preview <snapshot-id>
          HostsGuard.Cli snapshot restore <snapshot-id> --sha256 <previewed-sha256>
          HostsGuard.Cli usage [--days N] [--limit N] [--search text] [--app process] [--domain domain]
          HostsGuard.Cli usage-quota list
          HostsGuard.Cli usage-quota set --scope app|domain --match value --limit 1GB [--days 30] [--disabled] [--block|--no-block]
          HostsGuard.Cli usage-quota delete --id N
          HostsGuard.Cli usage-quota reset
          HostsGuard.Cli usage-quota export [path.csv|path.json] [--days N] [--scope app|domain] [--match value]
          HostsGuard.Cli history-privacy list
          HostsGuard.Cli history-privacy add|delete --scope app|domain --match value
          HostsGuard.Cli dns-cache [--limit N] [--search text]
          HostsGuard.Cli dns-inspect <domain> [--json]
          HostsGuard.Cli resolver-health [--run] [--host name] [--schedule off|minutes] [--json]
          HostsGuard.Cli profile-match [current|list] [--json]
          HostsGuard.Cli profile-match set --profile name [--label text] [--gateway-mac mac]
                               [--ssid name] [--interface name] [--dns-suffix suffix]
                               [--vpn any|present|absent] [--fingerprint id]
          HostsGuard.Cli profile-match delete <list-index>
          HostsGuard.Cli captive-portal [--json] [--pause 5|15|60]
          HostsGuard.Cli dns-flush-entry <cached-name>
          HostsGuard.Cli dga-check <domain> [--json]
          HostsGuard.Cli idn-homograph [status|enable|disable]
          HostsGuard.Cli proxy [status|accept-baseline]
          HostsGuard.Cli adopt-hosts [status|now|on|off]
          HostsGuard.Cli blocklists [list|stats|refresh]
          HostsGuard.Cli blocklists preview <name> <https-url>
          HostsGuard.Cli blocklists import <name> <https-url>
          HostsGuard.Cli blocklists preview-file <name> <path>
          HostsGuard.Cli blocklists import-file <name> <path>
          HostsGuard.Cli blocklists disable|enable|remove|rollback <name>
          HostsGuard.Cli blocklists recover-connectivity [exact-ncsi-domain ...]
          HostsGuard.Cli ip-blocklists [list|refresh]
          HostsGuard.Cli ip-blocklists import <name> <https-url>
          HostsGuard.Cli ip-blocklists disable|enable|remove|rollback <name>
          HostsGuard.Cli mode [normal|notify|learning]
          HostsGuard.Cli secure-rules [status|enable|disable]
          HostsGuard.Cli secure-rules accept|rearm <HG_rule_name>
          HostsGuard.Cli update [check|stage]
          HostsGuard.Cli update stage --path <feed-matching-installer.exe> [--sha256 <hash>]
          HostsGuard.Cli update health --expected <version> [--timeout <seconds>]
          HostsGuard.Cli safe-posture
          HostsGuard.Cli safe-posture-smoke
          HostsGuard.Cli release-smoke
          HostsGuard.Cli uninstall-cleanup

        The CLI talks to HostsGuardSvc over the local authenticated pipe.
        If the service is unavailable, start HostsGuard or restart HostsGuardSvc.
        """);
    return 1;
}

static int Version()
{
    Console.WriteLine(InformationalVersion());
    return 0;
}

static async Task<int> SecureRulesAsync(string[] args)
{
    var action = args.Length > 1 ? args[1].Trim().ToLowerInvariant() : "status";
    if (action is "accept" or "rearm" && args.Length < 3)
    {
        Console.Error.WriteLine($"Usage: secure-rules {action} <HG_rule_name>");
        return 1;
    }

    if (action is not ("status" or "enable" or "disable" or "accept" or "rearm"))
    {
        Console.Error.WriteLine("Usage: secure-rules [status|enable|disable] | secure-rules accept|rearm <HG_rule_name>");
        return 1;
    }

    return await RunCommandAsync(async channel =>
    {
        var client = new FirewallControl.FirewallControlClient(channel);
        if (action is "enable" or "disable")
        {
            var ack = await client.SetSecureRulesAsync(new SecureRulesRequest { Enabled = action == "enable" });
            Console.WriteLine(ack.Message);
            if (!ack.Ok)
            {
                return 2;
            }
        }
        else if (action is "accept" or "rearm")
        {
            var ack = await client.ResolveSecureRuleConflictAsync(new SecureRuleConflictRequest
            {
                Name = args[2],
                Action = action,
            });
            Console.WriteLine(ack.Message);
            if (!ack.Ok)
            {
                return 2;
            }
        }

        var status = await client.GetSecureRulesAsync(new Empty());
        Console.WriteLine($"Secure Rules: {(status.Enabled ? "armed" : "off")} · tracked={status.Tracked} · quarantined={status.Quarantined}");
        foreach (var conflict in status.Conflicts.OrderBy(c => c.Name, StringComparer.Ordinal))
        {
            Console.WriteLine($"  {conflict.Name}: quarantined after {conflict.RestoreAttempts} restores at {conflict.DetectedAt}");
            Console.WriteLine($"    live:    {conflict.LiveEvidence}");
            Console.WriteLine($"    tracked: {conflict.TrackedEvidence}");
        }

        return 0;
    });
}

static string InformationalVersion()
    => Assembly.GetExecutingAssembly().GetCustomAttribute<AssemblyInformationalVersionAttribute>()
           ?.InformationalVersion.Split('+')[0]
       ?? "unknown";

static (Grpc.Net.Client.GrpcChannel Channel, string Error) Connect()
{
    try
    {
        var handshake = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "HostsGuard", "session_token");
        var token = SessionToken.ReadHandshake(handshake);
        return (NamedPipeChannel.Create(token), string.Empty);
    }
    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or DirectoryNotFoundException or FileNotFoundException)
    {
        return (null!, $"service handshake unavailable - start or restart HostsGuardSvc. Details: {ex.Message}");
    }
}

static void PrintServiceUnavailable(string detail)
    => Console.Error.WriteLine(
        $"Couldn't reach HostsGuardSvc. Start or restart the service, then retry. Details: {detail}");

static int PrintRpcFailure(Grpc.Core.RpcException ex)
{
    if (ex.StatusCode is Grpc.Core.StatusCode.Unavailable or Grpc.Core.StatusCode.DeadlineExceeded
        or Grpc.Core.StatusCode.Cancelled or Grpc.Core.StatusCode.Unauthenticated)
    {
        PrintServiceUnavailable(ex.Status.Detail);
        return 3;
    }

    if (ex.StatusCode is Grpc.Core.StatusCode.Unimplemented)
    {
        Console.Error.WriteLine("HostsGuardSvc is older than this CLI and does not support this command. "
            + "Install the matching HostsGuard service or restart HostsGuardSvc after updating, then retry.");
        return 2;
    }

    var detail = ex.Status.Detail;
    Console.Error.WriteLine(detail.Length != 0 && detail != "Exception was thrown by handler."
        ? $"HostsGuardSvc rejected the command ({ex.StatusCode}): {detail}"
        : $"HostsGuardSvc hit an internal error while handling this command ({ex.StatusCode}). "
          + "The service is still running; export a support bundle for details.");
    return 2;
}

// Shared command wrapper: connect to the service, run the body against the
// channel, and map connect/RPC failures to the standard messages + exit codes.
static async Task<int> RunCommandAsync(Func<Grpc.Net.Client.GrpcChannel, Task<int>> body)
{
    var (channel, error) = Connect();
    if (channel is null)
    {
        PrintServiceUnavailable(error);
        return 3;
    }

    using (channel)
    {
        try
        {
            return await body(channel);
        }
        catch (Grpc.Core.RpcException ex)
        {
            return PrintRpcFailure(ex);
        }
    }
}

static async Task<int> StatusAsync()
{
    return await RunCommandAsync(async channel =>
    {
        var status = await new HostsGuard.Contracts.Diagnostics.DiagnosticsClient(channel).GetStatusAsync(new Empty());
        Console.WriteLine($"service:      v{status.Version} (elevated: {status.Elevated}, uptime {status.UptimeSeconds}s)");
        Console.WriteLine($"hosts:        {status.HostsBlocked} blocked entries");
        if (status.HostsOverScaleThreshold)
        {
            Console.WriteLine($"  warning:    {status.HostsBlocked} hosts entries can slow system DNS; consider firewall IP rules for very large lists");
        }
        Console.WriteLine($"database:     {status.DbBlocked} blocked, {status.DbAllowed} allowed, {status.FeedTotal} feed rows");
        Console.WriteLine($"monitors:     dns={(status.DnsMonitorActive ? "on" : "off")} connections={(status.ConnectionMonitorActive ? "on" : "off")} sni={(status.SniMonitorActive ? "on" : "off")} bandwidth={(status.BandwidthMonitorActive ? "on" : "off")}");
        foreach (var source in status.ObservationSources)
        {
            var interval = source.IncompleteSince.Length == 0 ? "complete" : $"incomplete-since={source.IncompleteSince}";
            Console.WriteLine($"observe {source.Source}: {source.State} lost={source.LossCount} gaps={source.GapCount} restarts={source.RestartCount} {interval} transition={source.LastTransitionAt} ({source.Detail})");
        }
        Console.WriteLine($"health:       pending-consent={status.PendingConsent} dropped-writes={status.PersistenceDroppedWrites} kill-switch={(status.KillSwitchEngaged ? "engaged" : "off")} secure-rules={(status.SecureRulesArmed ? "armed" : "off")}");
        var schemaNote = status.SchemaVersionOnDisk == status.SchemaVersion ? "ok" : $"MISMATCH (code {status.SchemaVersion})";
        Console.WriteLine($"database ver: schema {status.SchemaVersionOnDisk} ({schemaNote})");
        Console.WriteLine($"runtime:      .NET {status.RuntimeVersion}, SQLite {status.SqliteVersion}");
        Console.WriteLine($"memory:       working={FormatBytes(status.ProcessWorkingSetBytes)} private={FormatBytes(status.ProcessPrivateBytes)} managed={FormatBytes(status.GcHeapBytes)} gc-committed={FormatBytes(status.GcCommittedBytes)} fragmented={FormatBytes(status.GcFragmentedBytes)}");
        Console.WriteLine($"memory inputs: sni-adapters={status.SniCaptureAdapters} cached-firewall-packages={status.FirewallCachedPackages}");
        var mode = await new Consent.ConsentClient(channel).GetModeAsync(new Empty());
        Console.WriteLine($"filtering:    {mode.Mode}{(mode.DetectionArmed ? " (detection armed)" : string.Empty)}");
        return 0;
    });
}

static async Task<int> DomainOpAsync(string[] args, Func<HostsControl.HostsControlClient, DomainRequest, Task<Ack>> op)
{
    if (args.Length < 2)
    {
        Console.Error.WriteLine("Missing domain.");
        return Usage();
    }

    return await RunCommandAsync(async channel =>
    {
        var request = new DomainRequest
        {
            Domain = args[1],
            Reason = args.Length > 2 ? args[2] : string.Empty,
            Source = "cli",
        };
        var ack = await op(new HostsControl.HostsControlClient(channel), request);
        Console.WriteLine(ack.Message);
        return ack.Ok ? 0 : 2;
    });
}

static async Task<int> ProxyBaselineAsync(string[] args)
{
    var action = args.Length > 1 ? args[1].ToLowerInvariant() : "status";
    if (action is not ("status" or "check" or "accept-baseline"))
    {
        Console.Error.WriteLine("usage: HostsGuard.Cli proxy [status|accept-baseline]");
        return 1;
    }

    return await RunCommandAsync(async channel =>
    {
        var client = new HostsGuard.Contracts.Diagnostics.DiagnosticsClient(channel);
        if (action == "accept-baseline")
        {
            var ack = await client.AcceptProxyBaselineAsync(new Empty());
            Console.WriteLine(ack.Message);
            return ack.Ok ? 0 : 2;
        }

        var report = await client.InspectProxyBaselineAsync(new Empty());
        Console.WriteLine(report.Message.Length == 0
            ? report.BaselineExists
                ? report.Changed ? "proxy/PAC baseline changed" : "proxy/PAC baseline unchanged"
                : "no accepted proxy/PAC baseline"
            : report.Message);
        foreach (var entry in report.Entries)
        {
            var identity = entry.Sid.Length == 0 ? "machine" : entry.Sid;
            var baseline = entry.BaselinePresent ? entry.BaselineValue : "<not recorded>";
            var current = entry.CurrentPresent ? entry.CurrentValue : "<not set>";
            var marker = entry.Changed ? "CHANGED" : "ok";
            Console.WriteLine($"{marker,-7} {entry.Scope,-8} {identity} {entry.Setting}: {baseline} -> {current}");
        }

        return report.Changed ? 2 : 0;
    });
}

// Temp-block: block a domain for N minutes with auto-revert, or list pending windows.
static async Task<int> TempBlockAsync(string[] args)
{
    if (args.Length > 1 && string.Equals(args[1], "list", StringComparison.OrdinalIgnoreCase))
    {
        return await RunCommandAsync(async channel =>
        {
            var client = new HostsControl.HostsControlClient(channel);
            var list = await client.ListTempBlocksAsync(new Empty());
            if (list.Entries.Count == 0)
            {
                Console.WriteLine("no pending temp-blocks");
                return 0;
            }

            foreach (var e in list.Entries)
            {
                Console.WriteLine($"{e.Domain,-40} until {e.Expires.ToDateTime().ToLocalTime():yyyy-MM-dd HH:mm}");
            }

            return 0;
        });
    }

    if (args.Length < 3 || !int.TryParse(args[2], out var minutes) || minutes < 1)
    {
        Console.Error.WriteLine("usage: temp-block <domain> <minutes>  |  temp-block list");
        return Usage();
    }

    return await RunCommandAsync(async channel =>
    {
        var client = new HostsControl.HostsControlClient(channel);
        var ack = await client.TempBlockAsync(new TempBlockRequest { Domain = args[1], Minutes = minutes, Source = "cli" });
        Console.WriteLine(ack.Message);
        return ack.Ok ? 0 : 2;
    });
}

// NET-188: adopt hand-edited hosts entries into the managed DB.
static async Task<int> AdoptHostsAsync(string[] args)
{
    var sub = (args.Length > 1 ? args[1] : "status").ToLowerInvariant();
    return await RunCommandAsync(async channel =>
    {
        var client = new HostsControl.HostsControlClient(channel);
        switch (sub)
        {
            case "now":
                var result = await client.AdoptHostsEntriesAsync(new Empty());
                Console.WriteLine(result.Message);
                return result.Ok ? 0 : 2;
            case "on":
            case "off":
                var ack = await client.SetHostsAdoptionAsync(new HostsAdoptionRequest { Enabled = sub == "on" });
                Console.WriteLine(ack.Message);
                return ack.Ok ? 0 : 2;
            case "status":
                var status = await client.GetHostsAdoptionStatusAsync(new Empty());
                Console.WriteLine($"automatic adoption: {(status.Enabled ? "on" : "off")}");
                Console.WriteLine($"unadopted manual entries: {status.Unadopted}");
                Console.WriteLine($"last run: {(status.LastRun.Length == 0 ? "never" : status.LastRun)}");
                if (status.LastResult.Length != 0)
                {
                    Console.WriteLine($"last result: {status.LastResult}");
                }

                return 0;
            default:
                Console.Error.WriteLine($"unknown adopt-hosts subcommand '{sub}' (use status|now|on|off)");
                return 2;
        }
    });
}

static async Task<int> ExplainAsync(string[] args)
{
    if (args.Length < 2)
    {
        Console.Error.WriteLine("Missing target.");
        return Usage();
    }

    var request = BuildExplainRequest(args);
    return await RunCommandAsync(async channel =>
    {
        var explanation = await new FirewallControl.FirewallControlClient(channel).ExplainDecisionAsync(request);
        Console.WriteLine($"{explanation.Verdict}: {explanation.Summary}");
        Console.WriteLine($"next: {explanation.NextSafeAction}");
        foreach (var step in explanation.Steps)
        {
            Console.WriteLine($"{step.Order}. [{step.Outcome}] {step.Layer} - {step.Owner}");
            Console.WriteLine($"   {step.Detail}");
            if (!string.IsNullOrWhiteSpace(step.NextAction))
            {
                Console.WriteLine($"   action: {step.NextAction}");
            }
        }

        return explanation.Verdict == "Unknown" ? 2 : 0;
    });
}

static DecisionExplainRequest BuildExplainRequest(string[] args)
{
    var request = new DecisionExplainRequest { Target = args[1] };
    ApplyTarget(request, args[1]);
    for (var i = 2; i < args.Length; i++)
    {
        var key = args[i].Trim().ToLowerInvariant();
        if (!key.StartsWith("--", StringComparison.Ordinal))
        {
            continue;
        }

        var value = i + 1 < args.Length ? args[++i] : string.Empty;
        switch (key)
        {
            case "--domain":
                request.Domain = value;
                break;
            case "--ip":
            case "--addr":
            case "--remote":
                request.RemoteAddr = value;
                break;
            case "--program":
            case "--path":
                request.ProgramPath = value;
                if (string.IsNullOrWhiteSpace(request.Process))
                {
                    request.Process = Path.GetFileName(value);
                }

                break;
            case "--package":
            case "--pfn":
                request.PackageFamilyName = value;
                break;
            case "--package-sid":
                request.PackageSid = value;
                break;
            case "--process":
            case "--app":
                request.Process = value;
                break;
            case "--port":
                if (int.TryParse(value, out var port))
                {
                    request.RemotePort = port;
                }

                break;
            case "--proto":
            case "--protocol":
                request.Protocol = value;
                break;
            case "--direction":
            case "--dir":
                request.Direction = value;
                break;
            case "--signer":
                request.Signer = value;
                break;
            case "--service":
                request.Service = value;
                break;
        }
    }

    return request;
}

static void ApplyTarget(DecisionExplainRequest request, string target)
{
    var t = (target ?? string.Empty).Trim();
    if (t.Length == 0)
    {
        return;
    }

    if (Domains.LooksLikeDomain(t))
    {
        request.Domain = t;
    }
    else if (IPAddress.TryParse(t, out _))
    {
        request.RemoteAddr = t;
    }
    else if (LooksLikePath(t))
    {
        request.ProgramPath = t;
        request.Process = Path.GetFileName(t);
    }
    else
    {
        request.Process = t;
    }
}

static bool LooksLikePath(string target) =>
    target.Contains('\\', StringComparison.Ordinal) ||
    target.Contains('/', StringComparison.Ordinal) ||
    target.Contains(':', StringComparison.Ordinal);

// NET-114: block/unblock a program's outbound (or inbound) via the HG_ firewall
// rule. block-app creates it (BlockProgram); unblock-app deletes the same-named
// rule, mirroring the service's HG_BlockApp_<stem>_<dir> naming.
static async Task<int> ProgramOpAsync(string[] args, bool block)
{
    if (args.Length < 2 || string.IsNullOrWhiteSpace(args[1]))
    {
        Console.Error.WriteLine("Missing program path.");
        return Usage();
    }

    var path = args[1];
    var dir = args.Length > 2 && args[2].Trim().ToLowerInvariant() is "in" or "inbound" ? "In" : "Out";

    return await RunCommandAsync(async channel =>
    {
        var fw = new FirewallControl.FirewallControlClient(channel);
        Ack ack;
        if (block)
        {
            ack = await fw.BlockProgramAsync(new FirewallProgramRequest { ProgramPath = path, Direction = dir });
        }
        else
        {
            var name = $"HG_BlockApp_{Path.GetFileNameWithoutExtension(path)}_{dir}";
            ack = await fw.DeleteRuleAsync(new RuleNameRequest { Name = name });
        }

        Console.WriteLine(ack.Message);
        return ack.Ok ? 0 : 2;
    });
}

static async Task<int> ListPackagesAsync(string[] args)
{
    var search = string.Empty;
    for (var i = 1; i < args.Length; i++)
    {
        if (args[i] is "--search" or "-s")
        {
            search = i + 1 < args.Length ? args[++i] : string.Empty;
        }
        else if (search.Length == 0)
        {
            search = args[i];
        }
    }

    return await RunCommandAsync(async channel =>
    {
        var list = await new FirewallControl.FirewallControlClient(channel).ListAppPackagesAsync(new Empty());
        var rows = list.Packages
            .Where(p => search.Length == 0 ||
                p.DisplayName.Contains(search, StringComparison.OrdinalIgnoreCase) ||
                p.PackageFamilyName.Contains(search, StringComparison.OrdinalIgnoreCase) ||
                p.PackageSid.Contains(search, StringComparison.OrdinalIgnoreCase) ||
                p.PackageFullName.Contains(search, StringComparison.OrdinalIgnoreCase))
            .OrderBy(p => string.IsNullOrWhiteSpace(p.DisplayName) ? p.PackageFamilyName : p.DisplayName, StringComparer.OrdinalIgnoreCase)
            .ToList();

        foreach (var package in rows)
        {
            var label = string.IsNullOrWhiteSpace(package.DisplayName) ? package.PackageFamilyName : package.DisplayName;
            Console.WriteLine($"{label}");
            Console.WriteLine($"  pfn: {package.PackageFamilyName}");
            Console.WriteLine($"  sid: {package.PackageSid}");
            if (!string.IsNullOrWhiteSpace(package.PackageFullName))
            {
                Console.WriteLine($"  full: {package.PackageFullName}");
            }
        }

        Console.WriteLine($"{rows.Count} package(s)");
        return 0;
    });
}

static async Task<int> PackageOpAsync(string[] args, string action)
{
    if (args.Length < 2 || string.IsNullOrWhiteSpace(args[1]))
    {
        Console.Error.WriteLine("Missing package family name or package SID.");
        return Usage();
    }

    var package = args[1].Trim();
    var dir = args.Length > 2 && args[2].Trim().ToLowerInvariant() is "in" or "inbound" ? "In" : "Out";
    var token = FwRuleMapper.RuleToken(package);
    return await RunCommandAsync(async channel =>
    {
        var fw = new FirewallControl.FirewallControlClient(channel);
        if (action == "Delete")
        {
            var deleted = 0;
            foreach (var ruleName in new[] { $"HG_Package_Block_{token}_{dir}", $"HG_Package_Allow_{token}_{dir}" })
            {
                var ack = await fw.DeleteRuleAsync(new RuleNameRequest { Name = ruleName });
                if (ack.Ok)
                {
                    deleted++;
                }
            }

            Console.WriteLine(deleted == 0 ? "No matching package rule was removed." : $"Removed {deleted} package rule(s).");
            return deleted == 0 ? 2 : 0;
        }

        var request = new FirewallRule
        {
            Name = $"HG_Package_{action}_{token}_{dir}",
            Direction = dir,
            Action = action,
            Enabled = true,
            RemoteAddr = "Any",
            Protocol = "Any",
        };
        if (IsPackageSid(package))
        {
            request.PackageSid = package;
        }
        else
        {
            request.PackageFamilyName = package;
        }

        var create = await fw.CreateRuleAsync(request);
        Console.WriteLine(create.Message);
        return create.Ok ? 0 : 2;
    });
}

static bool IsPackageSid(string value) => value.Trim().StartsWith("S-1-", StringComparison.OrdinalIgnoreCase);

static async Task<int> AnalyzeFirewallRulesAsync(string[] args)
{
    var request = new FirewallRuleAnalysisRequest();
    string? exportPath = null;
    for (var i = 1; i < args.Length; i++)
    {
        var arg = args[i];
        if (TryReadOptionValue(args, ref i, arg, "--kind", out var value)) request.Kind = value;
        else if (TryReadOptionValue(args, ref i, arg, "--remediation", out value)) request.Remediation = value;
        else if (TryReadOptionValue(args, ref i, arg, "--search", out value)) request.Search = value;
        else if (TryReadOptionValue(args, ref i, arg, "--export", out value)) exportPath = value;
        else if (arg == "--cleanup-eligible") request.CleanupEligibleOnly = true;
        else
        {
            Console.Error.WriteLine($"Unknown firewall-analyze option: {arg}");
            return 1;
        }
    }

    return await RunCommandAsync(async channel =>
    {
        var result = await new FirewallControl.FirewallControlClient(channel).AnalyzeRulesAsync(request);
        if (!string.IsNullOrEmpty(exportPath))
        {
            var content = Path.GetExtension(exportPath).Equals(".json", StringComparison.OrdinalIgnoreCase)
                ? JsonSerializer.Serialize(new
                {
                    analysis_hash = result.AnalysisHash,
                    local_policy_modify_state = result.LocalPolicyModifyState,
                    active_profiles = result.ActiveProfiles,
                    rules_analyzed = result.RulesAnalyzed,
                    findings = result.Findings.Select(static finding => new
                    {
                        kind = finding.Kind,
                        rule_name = finding.RuleName,
                        related_rule_name = finding.RelatedRuleName,
                        canonical_fingerprint = finding.CanonicalFingerprint,
                        reason = finding.Reason,
                        remediation = finding.Remediation,
                        cleanup_eligible = finding.CleanupEligible,
                    }),
                }, new JsonSerializerOptions { WriteIndented = true })
                : BuildFirewallAnalysisCsv(result.Findings);
            try
            {
                await File.WriteAllTextAsync(exportPath, content);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
            {
                Console.Error.WriteLine($"Couldn't write '{exportPath}': {ex.Message}");
                return 2;
            }

            Console.WriteLine($"exported {result.Findings.Count} firewall findings to {Path.GetFullPath(exportPath)}");
            Console.WriteLine($"analysis-hash: {result.AnalysisHash}");
            return 0;
        }

        Console.WriteLine($"firewall analysis: {result.Findings.Count} findings across {result.RulesAnalyzed} rules");
        Console.WriteLine($"policy: {result.LocalPolicyModifyState}; active profiles: {string.Join(',', result.ActiveProfiles)}");
        Console.WriteLine($"analysis-hash: {result.AnalysisHash}");
        Console.WriteLine("kind\trule\trelated\tremediation\tcleanup\treason");
        foreach (var finding in result.Findings)
        {
            Console.WriteLine($"{finding.Kind}\t{finding.RuleName}\t{finding.RelatedRuleName}\t{finding.Remediation}\t{finding.CleanupEligible}\t{finding.Reason}");
        }

        return 0;
    });
}

static async Task<int> CleanupFirewallRulesAsync(string[] args)
{
    if (args.Length < 2 || args[1].ToLowerInvariant() is not ("preview" or "apply"))
    {
        Console.Error.WriteLine("Usage: firewall-cleanup preview|apply --analysis-hash SHA256 [--preview-hash SHA256] --name HG_Rule");
        return 1;
    }

    var request = new FirewallRuleCleanupRequest { Preview = args[1].Equals("preview", StringComparison.OrdinalIgnoreCase) };
    for (var i = 2; i < args.Length; i++)
    {
        var arg = args[i];
        if (TryReadOptionValue(args, ref i, arg, "--analysis-hash", out var value)) request.AnalysisHash = value;
        else if (TryReadOptionValue(args, ref i, arg, "--preview-hash", out value)) request.PreviewHash = value;
        else if (TryReadOptionValue(args, ref i, arg, "--name", out value)) request.SelectedNames.Add(value);
        else
        {
            Console.Error.WriteLine($"Unknown firewall-cleanup option: {arg}");
            return 1;
        }
    }

    if (request.SelectedNames.Count == 0 || string.IsNullOrWhiteSpace(request.AnalysisHash) ||
        (!request.Preview && string.IsNullOrWhiteSpace(request.PreviewHash)))
    {
        Console.Error.WriteLine("Cleanup requires selected --name values and an analysis hash; apply also requires the preview hash.");
        return 1;
    }

    return await RunCommandAsync(async channel =>
    {
        var result = await new FirewallControl.FirewallControlClient(channel).ApplyRuleCleanupAsync(request);
        Console.WriteLine(result.Message);
        Console.WriteLine($"analysis-hash: {result.AnalysisHash}");
        Console.WriteLine($"preview-hash: {result.PreviewHash}");
        if (result.RejectedNames.Count != 0) Console.WriteLine($"rejected: {string.Join(", ", result.RejectedNames)}");
        return result.Ok ? 0 : 2;
    });
}

static async Task<int> FirewallRuleAuthoringAsync(string[] args)
{
    var action = args.Length > 1 ? args[1].ToLowerInvariant() : string.Empty;
    if (action == "interfaces")
    {
        if (args.Length != 2) return Usage();
        return await RunCommandAsync(async channel =>
        {
            var list = await new FirewallControl.FirewallControlClient(channel).ListInterfaceAliasesAsync(new Empty());
            Console.WriteLine("up\talias\ttype\tdescription");
            foreach (var item in list.Interfaces)
                Console.WriteLine($"{(item.IsUp ? "yes" : "no")}\t{item.Alias}\t{item.InterfaceType}\t{item.Description}");
            return 0;
        });
    }

    if (action is not ("create" or "edit"))
    {
        Console.Error.WriteLine("Usage: firewall-rule create|edit --name Rule [authoring options], or firewall-rule interfaces");
        return 1;
    }

    var options = new Dictionary<string, string>(StringComparer.Ordinal);
    var enabled = (bool?)null;
    for (var i = 2; i < args.Length; i++)
    {
        var arg = args[i];
        if (arg == "--enabled") enabled = true;
        else if (arg == "--disabled") enabled = false;
        else
        {
            var names = new[] { "--name", "--direction", "--action", "--protocol", "--local-ports",
                "--remote-ports", "--interfaces", "--remote-addresses", "--program" };
            var matched = false;
            foreach (var name in names)
            {
                if (!TryReadOptionValue(args, ref i, arg, name, out var value)) continue;
                options[name] = value;
                matched = true;
                break;
            }

            if (!matched)
            {
                Console.Error.WriteLine($"Unknown firewall-rule option: {arg}");
                return 1;
            }
        }
    }

    if (!options.TryGetValue("--name", out var ruleName) || string.IsNullOrWhiteSpace(ruleName))
    {
        Console.Error.WriteLine("firewall-rule create/edit requires --name.");
        return 1;
    }

    return await RunCommandAsync(async channel =>
    {
        var client = new FirewallControl.FirewallControlClient(channel);
        FirewallRule request;
        if (action == "edit")
        {
            var rules = await client.ListRulesAsync(new Empty());
            var lookupName = ruleName.StartsWith(FwRuleMapper.HostsGuardPrefix, StringComparison.Ordinal)
                ? ruleName
                : FwRuleMapper.HostsGuardPrefix + ruleName;
            var current = rules.Rules.FirstOrDefault(rule => rule.Name.Equals(lookupName, StringComparison.Ordinal));
            if (current is null)
            {
                Console.Error.WriteLine($"Rule '{lookupName}' was not found.");
                return 2;
            }

            request = current.Clone();
            ruleName = lookupName;
        }
        else
        {
            request = new FirewallRule
            {
                Name = ruleName,
                Direction = "Out",
                Action = "Block",
                Protocol = "Any",
                RemoteAddr = "Any",
                LocalPorts = "Any",
                RemotePorts = "Any",
                Interfaces = "Any",
                Enabled = true,
            };
        }

        request.Name = ruleName;
        if (options.TryGetValue("--direction", out var value)) request.Direction = value;
        if (options.TryGetValue("--action", out value)) request.Action = value;
        if (options.TryGetValue("--protocol", out value)) request.Protocol = value;
        if (options.TryGetValue("--local-ports", out value)) request.LocalPorts = value;
        if (options.TryGetValue("--remote-ports", out value)) request.RemotePorts = value;
        if (options.TryGetValue("--interfaces", out value)) request.Interfaces = value;
        if (options.TryGetValue("--remote-addresses", out value)) request.RemoteAddr = value;
        if (options.TryGetValue("--program", out value)) request.Program = value;
        if (enabled is { } state) request.Enabled = state;

        var ack = action == "create" ? await client.CreateRuleAsync(request) : await client.UpdateRuleAsync(request);
        Console.WriteLine(ack.Message);
        return ack.Ok ? 0 : 2;
    });
}

static async Task<int> ExportAsync(string path)
{
    return await RunCommandAsync(async channel =>
    {
        var list = await new HostsControl.HostsControlClient(channel).ListDomainsAsync(new ListDomainsRequest());
        var rows = list.Domains.Select(d => new
        {
            domain = d.Domain,
            status = d.Status,
            source = d.Source,
            reason = d.Reason,
            hits = d.Hits,
            notes = d.Notes,
        });
        var json = JsonSerializer.Serialize(rows, new JsonSerializerOptions { WriteIndented = true });
        try
        {
            await File.WriteAllTextAsync(path, json);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            Console.Error.WriteLine($"Couldn't write '{path}': {ex.Message}");
            return 2;
        }

        Console.WriteLine($"exported {list.Domains.Count} domains to {Path.GetFullPath(path)}");
        return 0;
    });
}

// NET-089: export the whole machine policy as one versioned JSON document.
static async Task<int> ExportPolicyAsync(string path)
{
    return await RunCommandAsync(async channel =>
    {
        var doc = await new Policy.PolicyClient(channel).ExportPolicyAsync(new Empty());
        try
        {
            await File.WriteAllTextAsync(path, doc.Json);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            Console.Error.WriteLine($"Couldn't write '{path}': {ex.Message}");
            return 2;
        }

        Console.WriteLine($"exported policy to {Path.GetFullPath(path)}");
        return 0;
    });
}

// Validate a portable-policy document against the generated JSON Schema without a
// running service. `validate-policy --emit-schema [path]` publishes the schema.
static int ValidatePolicy(string[] args)
{
    if (args.Length > 1 && args[1] == "--emit-schema")
    {
        var schema = HostsGuard.Diagnostics.PortablePolicySchema.SchemaJson();
        var outPath = args.Length > 2 ? args[2] : null;
        if (outPath is null)
        {
            Console.WriteLine(schema);
            return 0;
        }

        try
        {
            File.WriteAllText(outPath, schema);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            Console.Error.WriteLine($"Couldn't write '{outPath}': {ex.Message}");
            return 2;
        }

        Console.WriteLine($"wrote policy schema to {Path.GetFullPath(outPath)}");
        return 0;
    }

    if (args.Length < 2)
    {
        Console.Error.WriteLine("Usage: validate-policy <path> | validate-policy --emit-schema [path]");
        return 1;
    }

    string json;
    try
    {
        json = File.ReadAllText(args[1]);
    }
    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
    {
        Console.Error.WriteLine($"could not read '{args[1]}': {ex.Message}");
        return 1;
    }

    var errors = HostsGuard.Diagnostics.PortablePolicySchema.Validate(json);
    if (errors.Count == 0)
    {
        Console.WriteLine("policy document is valid");
        return 0;
    }

    Console.Error.WriteLine($"{errors.Count} validation error(s):");
    foreach (var error in errors)
    {
        var where = error.Pointer.Length == 0 ? "(root)" : error.Pointer;
        Console.Error.WriteLine($"  {where}: {error.Message}");
    }

    return 2;
}

// NET-089: reconstruct a machine's policy from an exported JSON document.
static async Task<int> ImportPolicyAsync(string[] args)
{
    if (args.Length < 2)
    {
        Console.Error.WriteLine("Missing policy file. Usage: import-policy [--preview] <path.json>");
        return Usage();
    }

    return await RunCommandAsync(async channel =>
    {
        var client = new Policy.PolicyClient(channel);
        if (args[1].Equals("--restore-checkpoint", StringComparison.OrdinalIgnoreCase))
        {
            return PrintPolicyImportResult(await client.RestorePolicyCheckpointAsync(new Empty()));
        }

        var preview = false;
        var pathIndex = 1;
        if (args[1].Equals("--preview", StringComparison.OrdinalIgnoreCase))
        {
            preview = true;
            pathIndex = 2;
        }

        if (args.Length <= pathIndex)
        {
            Console.Error.WriteLine("Missing policy file. Usage: import-policy [--preview] <path.json>");
            return 1;
        }

        var path = args[pathIndex];
        string json;
        try
        {
            json = await File.ReadAllTextAsync(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            Console.Error.WriteLine($"Couldn't read '{path}': {ex.Message}");
            return 2;
        }

        var result = preview
            ? await client.PreviewPolicyImportAsync(new ImportPolicyRequest { Json = json, Preview = true })
            : await client.ImportPolicyAsync(new ImportPolicyRequest { Json = json });
        return PrintPolicyImportResult(result);
    });
}

static int PrintPolicyImportResult(ImportPolicyResult result)
{
    Console.WriteLine(result.Message);
    Console.WriteLine($"  added:      {result.Added}");
    Console.WriteLine($"  changed:    {result.Changed}");
    Console.WriteLine($"  removed:    {result.Removed}");
    if (result.CheckpointId != 0)
    {
        Console.WriteLine($"  checkpoint: {result.CheckpointId}");
    }

    foreach (var line in result.Summary)
    {
        Console.WriteLine($"  {line}");
    }

    return result.Ok ? 0 : 2;
}

static async Task<int> EventsAsync(string[] args)
{
    var request = new EventLogRequest { Limit = 200 };
    string? exportPath = null;
    for (var i = 1; i < args.Length; i++)
    {
        var arg = args[i];
        if (!TryReadOptionValue(args, ref i, arg, "--limit", out var value) || !int.TryParse(value, out var limit))
        {
            if (arg.StartsWith("--limit", StringComparison.Ordinal))
            {
                Console.Error.WriteLine("Invalid --limit value.");
                return 1;
            }
        }
        else
        {
            request.Limit = limit;
            continue;
        }

        if (TryReadOptionValue(args, ref i, arg, "--offset", out value))
        {
            if (!int.TryParse(value, out var offset))
            {
                Console.Error.WriteLine("Invalid --offset value.");
                return 1;
            }

            request.Offset = offset;
            continue;
        }

        if (TryReadOptionValue(args, ref i, arg, "--search", out value))
        {
            request.Search = value;
            continue;
        }

        if (TryReadOptionValue(args, ref i, arg, "--since", out value))
        {
            request.Since = value;
            continue;
        }

        if (TryReadOptionValue(args, ref i, arg, "--until", out value))
        {
            request.Until = value;
            continue;
        }

        if (TryReadOptionValue(args, ref i, arg, "--action", out value))
        {
            request.Action = value;
            continue;
        }

        if (TryReadOptionValue(args, ref i, arg, "--reason", out value))
        {
            request.Reason = value;
            continue;
        }

        if (TryReadOptionValue(args, ref i, arg, "--domain", out value))
        {
            request.Domain = value;
            continue;
        }

        if (TryReadOptionValue(args, ref i, arg, "--process", out value))
        {
            request.Process = value;
            continue;
        }

        if (TryReadOptionValue(args, ref i, arg, "--category", out value))
        {
            request.Category = value;
            continue;
        }

        if (TryReadOptionValue(args, ref i, arg, "--export", out value))
        {
            exportPath = value;
            request.Redact = true;
            continue;
        }

        if (string.Equals(arg, "--redact", StringComparison.Ordinal))
        {
            request.Redact = true;
            continue;
        }

        Console.Error.WriteLine($"Unknown events option: {arg}");
        return 1;
    }

    return await RunCommandAsync(async channel =>
    {
        var list = await new Monitoring.MonitoringClient(channel).ListEventsAsync(request);
        if (!string.IsNullOrEmpty(exportPath))
        {
            try
            {
                await File.WriteAllTextAsync(exportPath, BuildEventsCsv(list.Entries));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
            {
                Console.Error.WriteLine($"Couldn't write '{exportPath}': {ex.Message}");
                return 2;
            }

            Console.WriteLine($"exported {list.Entries.Count} of {list.Total} redacted events to {Path.GetFullPath(exportPath)}");
            return 0;
        }

        Console.WriteLine($"events: {list.Entries.Count} of {list.Total} (offset {list.Offset}){(list.Redacted ? " redacted" : string.Empty)}");
        Console.WriteLine("when\tcategory\taction\treason\tdomain\tprocess\tdetails");
        foreach (var e in list.Entries)
        {
            Console.WriteLine($"{e.Ts}\t{e.Category}\t{e.Action}\t{e.Reason}\t{e.Domain}\t{e.Process}\t{e.Details}");
        }

        return 0;
    });
}

static async Task<int> ListListenersAsync(string[] args)
{
    string? protocol = null;
    string? process = null;
    string? risk = null;
    string? exportPath = null;
    int? port = null;
    for (var i = 1; i < args.Length; i++)
    {
        var arg = args[i];
        if (TryReadOptionValue(args, ref i, arg, "--protocol", out var value))
        {
            protocol = value.Trim().ToUpperInvariant();
            if (protocol is not ("TCP" or "UDP"))
            {
                Console.Error.WriteLine("Invalid --protocol value; use tcp or udp.");
                return 1;
            }
        }
        else if (TryReadOptionValue(args, ref i, arg, "--port", out value))
        {
            if (!int.TryParse(value, out var parsed) || parsed is < 1 or > 65535)
            {
                Console.Error.WriteLine("Invalid --port value; use 1-65535.");
                return 1;
            }

            port = parsed;
        }
        else if (TryReadOptionValue(args, ref i, arg, "--process", out value))
        {
            process = value.Trim();
        }
        else if (TryReadOptionValue(args, ref i, arg, "--risk", out value))
        {
            risk = value.Trim().ToLowerInvariant();
            if (risk is not ("low" or "medium" or "high"))
            {
                Console.Error.WriteLine("Invalid --risk value; use low, medium, or high.");
                return 1;
            }
        }
        else if (TryReadOptionValue(args, ref i, arg, "--export", out value))
        {
            exportPath = value;
        }
        else
        {
            Console.Error.WriteLine($"Unknown listeners option: {arg}");
            return 1;
        }
    }

    return await RunCommandAsync(async channel =>
    {
        var response = await new Monitoring.MonitoringClient(channel).ListListenersAsync(new Empty());
        var rows = response.Listeners
            .Where(r => protocol is null || string.Equals(r.Protocol, protocol, StringComparison.OrdinalIgnoreCase))
            .Where(r => port is null || r.LocalPort == port)
            .Where(r => string.IsNullOrEmpty(process) || r.Process.Contains(process, StringComparison.OrdinalIgnoreCase)
                || r.Service.Contains(process, StringComparison.OrdinalIgnoreCase)
                || r.Package.Contains(process, StringComparison.OrdinalIgnoreCase))
            .Where(r => risk is null || string.Equals(r.Risk, risk, StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(r => ListenerRiskRank(r.Risk))
            .ThenBy(r => r.LocalPort)
            .ThenBy(r => r.Protocol, StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (!string.IsNullOrEmpty(exportPath))
        {
            var content = Path.GetExtension(exportPath).Equals(".json", StringComparison.OrdinalIgnoreCase)
                ? JsonSerializer.Serialize(rows.Select(ListenerExportRow), new JsonSerializerOptions { WriteIndented = true })
                : BuildListenersCsv(rows);
            try
            {
                await File.WriteAllTextAsync(exportPath, content);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
            {
                Console.Error.WriteLine($"Couldn't write '{exportPath}': {ex.Message}");
                return 2;
            }

            Console.WriteLine($"exported {rows.Count} listener exposures to {Path.GetFullPath(exportPath)}");
            return 0;
        }

        Console.WriteLine($"listeners: {rows.Count} of {response.Listeners.Count}");
        Console.WriteLine("risk\tprotocol\tlocal\tbind\tprofiles\tcoverage\tprocess/service/package\treason");
        foreach (var row in rows)
        {
            var identity = new[] { row.Process, row.Service, row.Package }.FirstOrDefault(v => !string.IsNullOrWhiteSpace(v)) ?? "?";
            Console.WriteLine($"{row.Risk}\t{row.Protocol}\t{FormatLocalEndpoint(row)}\t{row.BindScope}\t{row.ActiveProfiles}\t{row.Coverage}\t{identity}\t{row.Reason}");
        }

        return 0;
    });
}

static int ListenerRiskRank(string risk) => risk.ToLowerInvariant() switch
{
    "high" => 3,
    "medium" => 2,
    _ => 1,
};

static string FormatLocalEndpoint(HostsGuard.Contracts.ListenerExposure row)
    => row.LocalAddress.Contains(':', StringComparison.Ordinal)
        ? $"[{row.LocalAddress}]:{row.LocalPort}"
        : $"{row.LocalAddress}:{row.LocalPort}";

static object ListenerExportRow(HostsGuard.Contracts.ListenerExposure row) => new
{
    protocol = row.Protocol,
    local_address = row.LocalAddress,
    local_port = row.LocalPort,
    process = row.Process,
    pid = row.Pid,
    service = row.Service,
    package = row.Package,
    bind_scope = row.BindScope,
    active_profiles = row.ActiveProfiles,
    coverage = row.Coverage,
    risk = row.Risk,
    reason = row.Reason,
};

static async Task<int> TrafficProfileAsync(string[] args)
{
    var request = new TrafficProfileRequest();
    var exportPath = "traffic_profile.json";
    var pathSet = false;
    for (var i = 1; i < args.Length; i++)
    {
        var arg = args[i];
        string value;
        if (!arg.StartsWith("--", StringComparison.Ordinal) && !pathSet)
        {
            exportPath = arg;
            pathSet = true;
            continue;
        }

        if (TryReadOptionValue(args, ref i, arg, "--limit", out value) &&
            int.TryParse(value, out var limit))
        {
            request.Limit = limit;
            continue;
        }

        if (TryReadOptionValue(args, ref i, arg, "--since", out value))
        {
            request.Since = value;
            continue;
        }

        if (TryReadOptionValue(args, ref i, arg, "--until", out value))
        {
            request.Until = value;
            continue;
        }

        if (TryReadOptionValue(args, ref i, arg, "--process", out value) ||
            TryReadOptionValue(args, ref i, arg, "--app", out value))
        {
            request.Process = value;
            continue;
        }

        if (TryReadOptionValue(args, ref i, arg, "--action", out value))
        {
            request.Action = value;
            continue;
        }

        if (TryReadOptionValue(args, ref i, arg, "--protocol", out value) ||
            TryReadOptionValue(args, ref i, arg, "--proto", out value))
        {
            request.Protocol = value;
            continue;
        }

        if (TryReadOptionValue(args, ref i, arg, "--format", out value))
        {
            request.Format = value;
            continue;
        }

        Console.Error.WriteLine($"Unknown traffic-profile option: {arg}");
        return 1;
    }

    if (string.IsNullOrWhiteSpace(request.Format))
    {
        request.Format = Path.GetExtension(exportPath).Equals(".csv", StringComparison.OrdinalIgnoreCase)
            ? "csv"
            : "json";
    }

    return await RunCommandAsync(async channel =>
    {
        var profile = await new Monitoring.MonitoringClient(channel).ExportTrafficProfileAsync(request);
        try
        {
            await File.WriteAllTextAsync(exportPath, profile.Content);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            Console.Error.WriteLine($"Couldn't write '{exportPath}': {ex.Message}");
            return 2;
        }

        Console.WriteLine($"exported redacted {profile.Format} traffic profile to {Path.GetFullPath(exportPath)}");
        Console.WriteLine($"{profile.ConnectionCount} connections, {profile.EventCount} events; {profile.NoPayloadGuarantee}");
        return 0;
    });
}

static async Task<int> SupportBundleAsync(string[] args)
{
    var request = new SupportBundleRequest();
    for (var i = 1; i < args.Length; i++)
    {
        var arg = args[i];
        string value;
        if (TryReadOptionValue(args, ref i, arg, "--limit", out value) &&
            int.TryParse(value, out var limit))
        {
            request.Limit = limit;
            continue;
        }

        if (TryReadOptionValue(args, ref i, arg, "--since", out value))
        {
            request.Since = value;
            continue;
        }

        if (TryReadOptionValue(args, ref i, arg, "--until", out value))
        {
            request.Until = value;
            continue;
        }

        if (TryReadOptionValue(args, ref i, arg, "--process", out value) ||
            TryReadOptionValue(args, ref i, arg, "--app", out value))
        {
            request.Process = value;
            continue;
        }

        if (TryReadOptionValue(args, ref i, arg, "--action", out value))
        {
            request.Action = value;
            continue;
        }

        if (TryReadOptionValue(args, ref i, arg, "--protocol", out value) ||
            TryReadOptionValue(args, ref i, arg, "--proto", out value))
        {
            request.Protocol = value;
            continue;
        }

        Console.Error.WriteLine($"Unknown support-bundle option: {arg}");
        return 1;
    }

    return await RunCommandAsync(async channel =>
    {
        var ack = await new HostsGuard.Contracts.Diagnostics.DiagnosticsClient(channel)
            .ExportSupportBundleAsync(request);
        Console.WriteLine(ack.Message);
        if (ack.Ok)
        {
            Console.WriteLine("traffic_profile.json/csv are redacted metadata only; no packet payloads are captured or exported.");
        }

        return ack.Ok ? 0 : 2;
    });
}

static async Task<int> ProfileMatchAsync(string[] args)
{
    var action = args.Length > 1 && !args[1].StartsWith("--", StringComparison.Ordinal)
        ? args[1].ToLowerInvariant()
        : "list";
    var json = args.Contains("--json", StringComparer.Ordinal);

    return await RunCommandAsync(async channel =>
    {
        var policy = new Policy.PolicyClient(channel);
        if (action == "current")
        {
            var current = await policy.GetCurrentNetworkAsync(new Empty());
            PrintCurrentNetwork(current, json);
            return current.Online ? 0 : 2;
        }

        if (action == "list")
        {
            var current = await policy.GetCurrentNetworkAsync(new Empty());
            var map = await policy.GetNetworkProfilesAsync(new Empty());
            if (json)
            {
                Console.WriteLine(JsonSerializer.Serialize(new
                {
                    current = CurrentNetworkExport(current),
                    precedence = "most predicates; gateway/fingerprint, SSID, DNS suffix, interface, VPN; profile/label ordinal",
                    rules = map.Entries.Select((entry, index) => NetworkProfileExport(entry, index)),
                }, new JsonSerializerOptions { WriteIndented = true }));
                return 0;
            }

            PrintCurrentNetwork(current, false);
            Console.WriteLine("precedence: most predicates, then gateway/fingerprint > SSID > DNS suffix > interface > VPN");
            Console.WriteLine("index\tprofile\tlabel\tcriteria");
            foreach (var (entry, index) in map.Entries.Select((entry, index) => (entry, index)))
            {
                Console.WriteLine($"{index}\t{entry.Profile}\t{entry.Label}\t{DescribeNetworkCriteria(entry)}");
            }

            if (map.Entries.Count == 0)
            {
                Console.WriteLine("No automatic profile rules; manual profile switching remains available.");
            }

            return 0;
        }

        if (action == "delete")
        {
            if (args.Length < 3 || !int.TryParse(args[2], out var index) || index < 0)
            {
                Console.Error.WriteLine("usage: HostsGuard.Cli profile-match delete <list-index>");
                return 1;
            }

            var map = await policy.GetNetworkProfilesAsync(new Empty());
            if (index >= map.Entries.Count)
            {
                Console.Error.WriteLine($"profile-match index {index} does not exist; run 'profile-match list' first");
                return 1;
            }

            var request = map.Entries[index].Clone();
            request.Profile = string.Empty;
            var ack = await policy.SetNetworkProfileAsync(request);
            Console.WriteLine(ack.Message);
            return ack.Ok ? 0 : 2;
        }

        if (action != "set")
        {
            Console.Error.WriteLine("profile-match action must be current, list, set, or delete");
            return 1;
        }

        var requestRule = new NetworkProfileEntry();
        string? vpn = null;
        for (var i = 2; i < args.Length; i++)
        {
            var arg = args[i];
            if (TryReadOptionValue(args, ref i, arg, "--profile", out var value)) requestRule.Profile = value;
            else if (TryReadOptionValue(args, ref i, arg, "--label", out value)) requestRule.Label = value;
            else if (TryReadOptionValue(args, ref i, arg, "--gateway-mac", out value)) requestRule.GatewayMac = value;
            else if (TryReadOptionValue(args, ref i, arg, "--ssid", out value)) requestRule.Ssid = value;
            else if (TryReadOptionValue(args, ref i, arg, "--interface", out value)) requestRule.InterfaceName = value;
            else if (TryReadOptionValue(args, ref i, arg, "--dns-suffix", out value)) requestRule.DnsSuffix = value;
            else if (TryReadOptionValue(args, ref i, arg, "--fingerprint", out value)) requestRule.Fingerprint = value;
            else if (TryReadOptionValue(args, ref i, arg, "--vpn", out value)) vpn = value.ToLowerInvariant();
            else
            {
                Console.Error.WriteLine($"unknown profile-match option: {arg}");
                return 1;
            }
        }

        if (string.IsNullOrWhiteSpace(requestRule.Profile))
        {
            Console.Error.WriteLine("--profile is required");
            return 1;
        }

        if (vpn is "present") requestRule.VpnPresent = true;
        else if (vpn is "absent") requestRule.VpnPresent = false;
        else if (vpn is not null and not "any")
        {
            Console.Error.WriteLine("--vpn must be any, present, or absent");
            return 1;
        }

        if (string.IsNullOrWhiteSpace(requestRule.Label))
        {
            requestRule.Label = requestRule.Profile;
        }

        if (NetworkProfilePredicateCount(requestRule) == 0)
        {
            Console.Error.WriteLine("at least one match criterion is required");
            return 1;
        }

        var setAck = await policy.SetNetworkProfileAsync(requestRule);
        Console.WriteLine(setAck.Message);
        return setAck.Ok ? 0 : 2;
    });
}

static async Task<int> CaptivePortalAsync(string[] args)
{
    var json = false;
    int? pauseMinutes = null;
    for (var i = 1; i < args.Length; i++)
    {
        var arg = args[i];
        if (arg == "--json")
        {
            json = true;
        }
        else if (TryReadOptionValue(args, ref i, arg, "--pause", out var value) &&
                 int.TryParse(value, out var parsed))
        {
            pauseMinutes = parsed;
        }
        else
        {
            Console.Error.WriteLine($"unknown captive-portal option: {arg}");
            return 1;
        }
    }

    if (pauseMinutes.HasValue && pauseMinutes.Value is not (5 or 15 or 60))
    {
        Console.Error.WriteLine("--pause must be 5, 15, or 60 minutes");
        return 1;
    }

    return await RunCommandAsync(async channel =>
    {
        var diagnostics = new HostsGuard.Contracts.Diagnostics.DiagnosticsClient(channel);
        var status = await diagnostics.CheckCaptivePortalAsync(new Empty());
        if (!pauseMinutes.HasValue)
        {
            if (json)
            {
                Console.WriteLine(JsonSerializer.Serialize(new
                {
                    state = status.State,
                    probe_url = status.ProbeUrl,
                    http_status = status.HttpStatus,
                    redirected = status.Redirected,
                    observed_host = status.ObservedHost,
                    detail = status.Detail,
                    pause_available = status.PauseAvailable,
                    allowed_pause_minutes = status.AllowedPauseMinutes,
                    checked_at = status.CheckedAt?.ToDateTime().ToString("O"),
                    enforcement_changed = status.EnforcementChanged,
                }, new JsonSerializerOptions { WriteIndented = true }));
            }
            else
            {
                Console.WriteLine($"state: {status.State}");
                Console.WriteLine($"detail: {status.Detail}");
                if (status.HttpStatus > 0) Console.WriteLine($"HTTP: {status.HttpStatus}");
                if (status.ObservedHost.Length != 0) Console.WriteLine($"observed host: {status.ObservedHost}");
                Console.WriteLine("enforcement changed: no");
                Console.WriteLine(status.PauseAvailable
                    ? $"timed pause available: {string.Join(", ", status.AllowedPauseMinutes)} minutes"
                    : "timed pause available: no");
            }

            return status.State == "unavailable" ? 2 : 0;
        }

        var minutes = pauseMinutes.Value;
        if (!status.PauseAvailable || !status.AllowedPauseMinutes.Contains(minutes))
        {
            Console.Error.WriteLine($"timed pause refused: captive portal state is '{status.State}'");
            return 2;
        }

        var ack = await new FirewallControl.FirewallControlClient(channel)
            .PauseEnforcementAsync(new EnforcementPauseRequest { Minutes = minutes });
        if (json)
        {
            Console.WriteLine(JsonSerializer.Serialize(new
            {
                probe_state = status.State,
                pause_minutes = minutes,
                ok = ack.Ok,
                message = ack.Message,
                auto_resume = true,
            }, new JsonSerializerOptions { WriteIndented = true }));
        }
        else
        {
            Console.WriteLine(ack.Message);
            if (ack.Ok) Console.WriteLine("enforcement will resume automatically when the timed pause expires");
        }

        return ack.Ok ? 0 : 2;
    });
}

static void PrintCurrentNetwork(CurrentNetwork current, bool json)
{
    if (json)
    {
        Console.WriteLine(JsonSerializer.Serialize(CurrentNetworkExport(current),
            new JsonSerializerOptions { WriteIndented = true }));
        return;
    }

    Console.WriteLine(current.Online
        ? $"current: {current.Label}; {DescribeCurrentNetworkCriteria(current)}"
        : "current: offline or unavailable");
}

static object CurrentNetworkExport(CurrentNetwork current) => new
{
    online = current.Online,
    label = current.Label,
    fingerprint = current.Fingerprint,
    gateway_mac = current.GatewayMac,
    ssid = current.Ssid,
    interface_name = current.InterfaceName,
    dns_suffix = current.DnsSuffix,
    vpn_present = current.VpnPresent,
};

static object NetworkProfileExport(NetworkProfileEntry entry, int index) => new
{
    index,
    profile = entry.Profile,
    label = entry.Label,
    fingerprint = entry.Fingerprint,
    gateway_mac = entry.GatewayMac,
    ssid = entry.Ssid,
    interface_name = entry.InterfaceName,
    dns_suffix = entry.DnsSuffix,
    vpn_present = entry.HasVpnPresent ? entry.VpnPresent : (bool?)null,
    predicate_count = NetworkProfilePredicateCount(entry),
};

static int NetworkProfilePredicateCount(NetworkProfileEntry entry) =>
    Present(entry.Fingerprint) + Present(entry.GatewayMac) + Present(entry.Ssid) +
    Present(entry.InterfaceName) + Present(entry.DnsSuffix) + (entry.HasVpnPresent ? 1 : 0);

static string DescribeNetworkCriteria(NetworkProfileEntry entry)
{
    var parts = new List<string>();
    AddPart(parts, "gateway", entry.GatewayMac);
    AddPart(parts, "fingerprint", entry.Fingerprint);
    AddPart(parts, "ssid", entry.Ssid);
    AddPart(parts, "dns", entry.DnsSuffix);
    AddPart(parts, "interface", entry.InterfaceName);
    if (entry.HasVpnPresent) parts.Add($"vpn={(entry.VpnPresent ? "present" : "absent")}");
    return string.Join(", ", parts);
}

static string DescribeCurrentNetworkCriteria(CurrentNetwork current)
{
    var parts = new List<string>();
    AddPart(parts, "gateway", current.GatewayMac);
    AddPart(parts, "fingerprint", current.Fingerprint);
    AddPart(parts, "ssid", current.Ssid);
    AddPart(parts, "dns", current.DnsSuffix);
    AddPart(parts, "interface", current.InterfaceName);
    parts.Add($"vpn={(current.VpnPresent ? "present" : "absent")}");
    return string.Join(", ", parts);
}

static void AddPart(List<string> parts, string name, string value)
{
    if (Present(value) != 0) parts.Add($"{name}={value}");
}

static int Present(string value) => string.IsNullOrWhiteSpace(value) ? 0 : 1;

static bool TryReadOptionValue(string[] args, ref int index, string arg, string name, out string value)
{
    value = string.Empty;
    if (arg.StartsWith(name + "=", StringComparison.Ordinal))
    {
        value = arg[(name.Length + 1)..];
        return value.Length != 0;
    }

    if (!string.Equals(arg, name, StringComparison.Ordinal))
    {
        return false;
    }

    if (index + 1 >= args.Length)
    {
        return false;
    }

    value = args[++index];
    return value.Length != 0;
}

static async Task<int> UsageAsync(string[] args)
{
    var request = new UsageRollupRequest { Days = 30, Limit = 200 };
    for (var i = 1; i < args.Length; i++)
    {
        var arg = args[i];
        if (TryReadOptionValue(args, ref i, arg, "--days", out var value))
        {
            if (!int.TryParse(value, out var days))
            {
                Console.Error.WriteLine("Invalid --days value.");
                return 1;
            }

            request.Days = days;
            continue;
        }

        if (TryReadOptionValue(args, ref i, arg, "--limit", out value))
        {
            if (!int.TryParse(value, out var limit))
            {
                Console.Error.WriteLine("Invalid --limit value.");
                return 1;
            }

            request.Limit = limit;
            continue;
        }

        if (TryReadOptionValue(args, ref i, arg, "--search", out value))
        {
            request.Search = value;
            continue;
        }

        if (TryReadOptionValue(args, ref i, arg, "--app", out value) ||
            TryReadOptionValue(args, ref i, arg, "--process", out value))
        {
            request.Process = value;
            continue;
        }

        if (TryReadOptionValue(args, ref i, arg, "--domain", out value))
        {
            request.Domain = value;
            continue;
        }

        Console.Error.WriteLine($"Unknown usage option: {arg}");
        return 1;
    }

    return await RunCommandAsync(async channel =>
    {
        var list = await new Monitoring.MonitoringClient(channel).GetUsageRollupsAsync(request);
        Console.WriteLine($"usage: {list.Entries.Count} rows (retention {list.RetentionDays} days)");
        Console.WriteLine("day\tprocess\tdomain\tsent\treceived\ttotal");
        foreach (var e in list.Entries)
        {
            Console.WriteLine($"{e.Day}\t{e.Process}\t{e.Domain}\t{FormatBytes(e.Sent)}\t{FormatBytes(e.Recv)}\t{FormatBytes(e.Total)}");
        }

        return 0;
    });
}

static async Task<int> UsageQuotaAsync(string[] args)
{
    var subcommand = args.Length > 1 ? args[1].ToLowerInvariant() : "list";
    return await RunCommandAsync(async channel =>
    {
        var client = new Monitoring.MonitoringClient(channel);
        try
        {
            return subcommand switch
            {
                "list" => await UsageQuotaListAsync(client),
                "set" => await UsageQuotaSetAsync(client, args),
                "delete" or "remove" => await UsageQuotaDeleteAsync(client, args),
                "reset" => await UsageQuotaResetAsync(client),
                "export" => await UsageQuotaExportAsync(client, args),
                _ => UsageQuotaHelp(subcommand),
            };
        }
        catch (IOException ex)
        {
            Console.Error.WriteLine($"File error: {ex.Message}");
            return 2;
        }
        catch (UnauthorizedAccessException ex)
        {
            Console.Error.WriteLine($"File error: {ex.Message}");
            return 2;
        }
    });
}

static async Task<int> UsageQuotaListAsync(Monitoring.MonitoringClient client)
{
    var list = await client.GetUsageQuotaRulesAsync(new Empty());
    Console.WriteLine($"usage quotas: {list.Rules.Count} rule{(list.Rules.Count == 1 ? string.Empty : "s")}");
    Console.WriteLine("id\tscope\tmatch\tenabled\twindow\tused\tlimit\tblock\tblocked_since\tlast_alerted");
    foreach (var rule in list.Rules.OrderBy(r => r.Scope, StringComparer.OrdinalIgnoreCase)
                 .ThenBy(r => r.Match, StringComparer.OrdinalIgnoreCase))
    {
        var block = rule.BlockOnExceed ? (rule.BlockActive ? "BLOCKED" : "armed") : "off";
        Console.WriteLine($"{rule.Id}\t{rule.Scope}\t{rule.Match}\t{rule.Enabled}\t{rule.WindowDays}d\t{FormatBytes(rule.UsedBytes)}\t{FormatBytes(rule.LimitBytes)}\t{block}\t{rule.BlockedSince}\t{rule.LastAlertedAt}");
    }

    return 0;
}

static async Task<int> UsageQuotaSetAsync(Monitoring.MonitoringClient client, string[] args)
{
    var scope = string.Empty;
    var match = string.Empty;
    long limitBytes = 0;
    var days = 30;
    var enabled = true;
    var blockOnExceed = false;
    for (var i = 2; i < args.Length; i++)
    {
        var arg = args[i];
        if (TryReadOptionValue(args, ref i, arg, "--scope", out var value))
        {
            scope = value;
            continue;
        }

        if (TryReadOptionValue(args, ref i, arg, "--match", out value))
        {
            match = value;
            continue;
        }

        if (TryReadOptionValue(args, ref i, arg, "--app", out value) ||
            TryReadOptionValue(args, ref i, arg, "--process", out value))
        {
            scope = "app";
            match = value;
            continue;
        }

        if (TryReadOptionValue(args, ref i, arg, "--domain", out value))
        {
            scope = "domain";
            match = value;
            continue;
        }

        if (TryReadOptionValue(args, ref i, arg, "--limit", out value))
        {
            if (!TryParseBytes(value, out limitBytes))
            {
                Console.Error.WriteLine("Invalid --limit value. Use bytes or KB/MB/GB/TB, e.g. 750MB.");
                return 1;
            }

            continue;
        }

        if (TryReadOptionValue(args, ref i, arg, "--days", out value))
        {
            if (!int.TryParse(value, out days))
            {
                Console.Error.WriteLine("Invalid --days value.");
                return 1;
            }

            continue;
        }

        if (string.Equals(arg, "--disabled", StringComparison.OrdinalIgnoreCase))
        {
            enabled = false;
            continue;
        }

        if (string.Equals(arg, "--block", StringComparison.OrdinalIgnoreCase))
        {
            blockOnExceed = true;
            continue;
        }

        if (string.Equals(arg, "--no-block", StringComparison.OrdinalIgnoreCase))
        {
            blockOnExceed = false;
            continue;
        }

        Console.Error.WriteLine($"Unknown usage-quota set option: {arg}");
        return 1;
    }

    if (scope.Length == 0 || match.Length == 0 || limitBytes <= 0)
    {
        Console.Error.WriteLine("Usage: usage-quota set --scope app|domain --match value --limit 1GB [--days 30] [--disabled] [--block|--no-block]");
        return 1;
    }

    var ack = await client.SetUsageQuotaRuleAsync(new UsageQuotaRule
    {
        Scope = scope,
        Match = match,
        LimitBytes = limitBytes,
        WindowDays = days,
        Enabled = enabled,
        BlockOnExceed = blockOnExceed,
    });
    Console.WriteLine(ack.Message);
    return ack.Ok ? 0 : 2;
}

static async Task<int> UsageQuotaDeleteAsync(Monitoring.MonitoringClient client, string[] args)
{
    var request = new UsageQuotaRule();
    for (var i = 2; i < args.Length; i++)
    {
        var arg = args[i];
        if (TryReadOptionValue(args, ref i, arg, "--id", out var value))
        {
            if (!long.TryParse(value, out var id))
            {
                Console.Error.WriteLine("Invalid --id value.");
                return 1;
            }

            request.Id = id;
            continue;
        }

        if (TryReadOptionValue(args, ref i, arg, "--scope", out value))
        {
            request.Scope = value;
            continue;
        }

        if (TryReadOptionValue(args, ref i, arg, "--match", out value))
        {
            request.Match = value;
            continue;
        }

        if (TryReadOptionValue(args, ref i, arg, "--app", out value) ||
            TryReadOptionValue(args, ref i, arg, "--process", out value))
        {
            request.Scope = "app";
            request.Match = value;
            continue;
        }

        if (TryReadOptionValue(args, ref i, arg, "--domain", out value))
        {
            request.Scope = "domain";
            request.Match = value;
            continue;
        }

        Console.Error.WriteLine($"Unknown usage-quota delete option: {arg}");
        return 1;
    }

    if (request.Id <= 0 && (request.Scope.Length == 0 || request.Match.Length == 0))
    {
        Console.Error.WriteLine("Usage: usage-quota delete --id N");
        return 1;
    }

    var ack = await client.DeleteUsageQuotaRuleAsync(request);
    Console.WriteLine(ack.Message);
    return ack.Ok ? 0 : 2;
}

static async Task<int> UsageQuotaResetAsync(Monitoring.MonitoringClient client)
{
    var ack = await client.ResetUsageQuotaHistoryAsync(new Empty());
    Console.WriteLine(ack.Message);
    return ack.Ok ? 0 : 2;
}

static async Task<int> UsageQuotaExportAsync(Monitoring.MonitoringClient client, string[] args)
{
    var request = new UsageQuotaHistoryRequest { Days = 30, Format = "csv" };
    var path = string.Empty;
    for (var i = 2; i < args.Length; i++)
    {
        var arg = args[i];
        if (TryReadOptionValue(args, ref i, arg, "--days", out var value))
        {
            if (!int.TryParse(value, out var days))
            {
                Console.Error.WriteLine("Invalid --days value.");
                return 1;
            }

            request.Days = days;
            continue;
        }

        if (TryReadOptionValue(args, ref i, arg, "--scope", out value))
        {
            request.Scope = value;
            continue;
        }

        if (TryReadOptionValue(args, ref i, arg, "--match", out value))
        {
            request.Match = value;
            continue;
        }

        if (TryReadOptionValue(args, ref i, arg, "--app", out value) ||
            TryReadOptionValue(args, ref i, arg, "--process", out value))
        {
            request.Scope = "app";
            request.Match = value;
            continue;
        }

        if (TryReadOptionValue(args, ref i, arg, "--domain", out value))
        {
            request.Scope = "domain";
            request.Match = value;
            continue;
        }

        if (TryReadOptionValue(args, ref i, arg, "--format", out value))
        {
            request.Format = value;
            continue;
        }

        if (!arg.StartsWith("-", StringComparison.Ordinal) && path.Length == 0)
        {
            path = arg;
            continue;
        }

        Console.Error.WriteLine($"Unknown usage-quota export option: {arg}");
        return 1;
    }

    if (path.Length == 0)
    {
        path = string.Equals(request.Format, "json", StringComparison.OrdinalIgnoreCase)
            ? "usage_quota_history.json"
            : "usage_quota_history.csv";
    }

    if (path.EndsWith(".json", StringComparison.OrdinalIgnoreCase))
    {
        request.Format = "json";
    }

    var export = await client.ExportUsageQuotaHistoryAsync(request);
    if (path == "-")
    {
        Console.Write(export.Content);
    }
    else
    {
        await File.WriteAllTextAsync(path, export.Content);
        Console.WriteLine($"exported usage quota history to {path}");
    }

    return 0;
}

static int UsageQuotaHelp(string subcommand)
{
    Console.Error.WriteLine($"Unknown usage-quota command: {subcommand}");
    Console.Error.WriteLine("Usage: usage-quota list|set|delete|reset|export");
    return 1;
}

static async Task<int> HistoryPrivacyAsync(string[] args)
{
    var action = args.Length > 1 ? args[1].ToLowerInvariant() : "list";
    var scope = string.Empty;
    var match = string.Empty;
    for (var i = 2; i < args.Length; i++)
    {
        if (TryReadOptionValue(args, ref i, args[i], "--scope", out var value)) scope = value;
        else if (TryReadOptionValue(args, ref i, args[i], "--match", out value)) match = value;
        else { Console.Error.WriteLine($"Unknown history-privacy option: {args[i]}"); return 1; }
    }

    if (action is not "list" && (scope.Length == 0 || match.Length == 0))
    {
        Console.Error.WriteLine("Usage: history-privacy add|delete --scope app|domain --match value");
        return 1;
    }

    return await RunCommandAsync(async channel =>
    {
        var client = new Monitoring.MonitoringClient(channel);
        if (action == "list")
        {
            var list = await client.ListHistoryPrivacyExclusionsAsync(new Empty());
            Console.WriteLine(list.Disclosure);
            foreach (var row in list.Exclusions) Console.WriteLine($"{row.Scope}\t{row.Match}\t{row.Added}");
            return 0;
        }
        var request = new HistoryPrivacyExclusion { Scope = scope, Match = match };
        var ack = action switch
        {
            "add" or "set" => await client.SetHistoryPrivacyExclusionAsync(request),
            "delete" or "remove" => await client.DeleteHistoryPrivacyExclusionAsync(request),
            _ => new Ack { Ok = false, Message = "Usage: history-privacy list|add|delete" },
        };
        Console.WriteLine(ack.Message);
        return ack.Ok ? 0 : 2;
    });
}

static async Task<int> DnsCacheAsync(string[] args)
{
    var request = new DnsCacheRequest { Limit = 500 };
    for (var i = 1; i < args.Length; i++)
    {
        var arg = args[i];
        if (TryReadOptionValue(args, ref i, arg, "--limit", out var value))
        {
            if (!int.TryParse(value, out var limit))
            {
                Console.Error.WriteLine("Invalid --limit value.");
                return 1;
            }

            request.Limit = limit;
            continue;
        }

        if (TryReadOptionValue(args, ref i, arg, "--search", out value))
        {
            request.Search = value;
            continue;
        }

        Console.Error.WriteLine($"Unknown dns-cache option: {arg}");
        return 1;
    }

    return await RunCommandAsync(async channel =>
    {
        var list = await new DnsControl.DnsControlClient(channel).ListCacheAsync(request);
        if (!list.Available)
        {
            Console.Error.WriteLine(list.Message);
            return 2;
        }

        Console.WriteLine($"dns-cache: {list.Entries.Count} rows");
        Console.WriteLine("name\ttype\trole\tdata\tflags");
        foreach (var e in list.Entries)
        {
            Console.WriteLine($"{e.Name}\t{e.Type}\t{e.PrivacyRole}\t{e.DataLength}\t0x{e.Flags:X8}");
        }

        return 0;
    });
}

static async Task<int> ResolverHealthAsync(string[] args)
{
    var run = false;
    var json = false;
    var host = string.Empty;
    int? scheduleMinutes = null;
    var disableSchedule = false;

    for (var i = 1; i < args.Length; i++)
    {
        var arg = args[i];
        if (arg.Equals("--run", StringComparison.OrdinalIgnoreCase))
        {
            run = true;
            continue;
        }

        if (arg.Equals("--json", StringComparison.OrdinalIgnoreCase))
        {
            json = true;
            continue;
        }

        if (TryReadOptionValue(args, ref i, arg, "--host", out var value))
        {
            host = value;
            run = true;
            continue;
        }

        if (TryReadOptionValue(args, ref i, arg, "--schedule", out value))
        {
            if (value.Equals("off", StringComparison.OrdinalIgnoreCase))
            {
                disableSchedule = true;
                continue;
            }

            if (!int.TryParse(value, out var minutes) || minutes is < 15 or > 1_440)
            {
                Console.Error.WriteLine("--schedule must be off or an interval from 15 to 1440 minutes.");
                return 1;
            }

            scheduleMinutes = minutes;
            continue;
        }

        Console.Error.WriteLine($"Unknown resolver-health option: {arg}");
        return 1;
    }

    if (disableSchedule && scheduleMinutes.HasValue)
    {
        Console.Error.WriteLine("Specify one --schedule value: off or an interval.");
        return 1;
    }

    return await RunCommandAsync(async channel =>
    {
        var client = new DnsControl.DnsControlClient(channel);
        ResolverHealthReport report;
        if (disableSchedule || scheduleMinutes.HasValue)
        {
            report = await client.SetResolverHealthScheduleAsync(new ResolverHealthScheduleRequest
            {
                Enabled = !disableSchedule,
                IntervalMinutes = scheduleMinutes ?? 60,
            });
        }
        else if (run)
        {
            report = await client.RunResolverHealthAsync(new ResolverHealthRequest { Host = host });
        }
        else
        {
            report = await client.GetResolverHealthAsync(new Empty());
        }

        if (json)
        {
            Console.WriteLine(JsonSerializer.Serialize(new
            {
                host = report.Host,
                source = report.Source,
                checked_at = report.CheckedAt,
                running = report.Running,
                schedule_enabled = report.ScheduleEnabled,
                schedule_interval_minutes = report.ScheduleIntervalMinutes,
                next_scheduled_at = report.NextScheduledAt,
                message = report.Message,
                entries = report.Entries.Select(static entry => new
                {
                    adapter_id = entry.AdapterId,
                    adapter = entry.AdapterName,
                    endpoint = entry.Endpoint,
                    protocol = entry.Protocol,
                    a_status = entry.AStatus,
                    a_count = entry.ACount,
                    a_detail = entry.ADetail,
                    aaaa_status = entry.AaaaStatus,
                    aaaa_count = entry.AaaaCount,
                    aaaa_detail = entry.AaaaDetail,
                    rtt_ms = entry.RttAvailable ? entry.RttMs : (int?)null,
                    tls_status = entry.TlsStatus,
                    certificate_failure = entry.TlsStatus.Equals("certificate_failure", StringComparison.OrdinalIgnoreCase),
                    error = entry.Error,
                    success = entry.Success,
                }),
            }, new JsonSerializerOptions { WriteIndented = true }));
            return 0;
        }

        Console.WriteLine($"resolver-health: host={TextOrUnavailable(report.Host)} source={TextOrUnavailable(report.Source)} checked={TextOrUnavailable(report.CheckedAt)} running={report.Running.ToString().ToLowerInvariant()}");
        Console.WriteLine($"schedule: {(report.ScheduleEnabled ? $"every {report.ScheduleIntervalMinutes} min" : "off")} next={TextOrUnavailable(report.NextScheduledAt)}");
        Console.WriteLine("adapter\tendpoint\tprotocol\tA\tAAAA\tRTT\tTLS/certificate\tresult");
        foreach (var entry in report.Entries)
        {
            var a = AddressResult(entry.AStatus, entry.ACount, entry.ADetail);
            var aaaa = AddressResult(entry.AaaaStatus, entry.AaaaCount, entry.AaaaDetail);
            var rtt = entry.RttAvailable ? $"{entry.RttMs} ms" : "unavailable";
            var result = entry.Success ? "healthy" : TextOrUnavailable(entry.Error);
            Console.WriteLine($"{TextOrUnavailable(entry.AdapterName)}\t{entry.Endpoint}\t{entry.Protocol}\t{a}\t{aaaa}\t{rtt}\t{TextOrUnavailable(entry.TlsStatus)}\t{result}");
        }

        if (!string.IsNullOrWhiteSpace(report.Message))
        {
            Console.WriteLine(report.Message);
        }

        Console.WriteLine("read-only: resolver health checks never change system DNS settings");
        return 0;
    });
}

static string AddressResult(string status, int count, string detail) =>
    status.Equals("available", StringComparison.OrdinalIgnoreCase)
        ? $"available ({count})"
        : string.IsNullOrWhiteSpace(detail) ? TextOrUnavailable(status) : detail;

static string TextOrUnavailable(string value) => string.IsNullOrWhiteSpace(value) ? "unavailable" : value;

static async Task<int> DnsFlushEntryAsync(string[] args)
{
    if (args.Length < 2)
    {
        Console.Error.WriteLine("Missing cached DNS name.");
        return Usage();
    }

    return await RunCommandAsync(async channel =>
    {
        var ack = await new DnsControl.DnsControlClient(channel)
            .FlushCacheEntryAsync(new DnsCacheEntryRequest { Name = args[1] });
        Console.WriteLine(ack.Message);
        return ack.Ok ? 0 : 2;
    });
}

static async Task<int> DnsInspectAsync(string[] args)
{
    if (args.Length is < 2 or > 3 ||
        (args.Length == 3 && !args[2].Equals("--json", StringComparison.OrdinalIgnoreCase)))
    {
        Console.Error.WriteLine("Usage: dns-inspect <domain> [--json]");
        return 1;
    }

    return await RunCommandAsync(async channel =>
    {
        var result = await new DnsControl.DnsControlClient(channel)
            .InspectAsync(new DomainRequest { Domain = args[1] });
        if (args.Length == 3)
        {
            Console.WriteLine(JsonSerializer.Serialize(new
            {
                domain = args[1],
                service_binding_query_available = result.ServiceBindingQueryAvailable,
                service_binding_message = result.ServiceBindingMessage,
                ech_advertised = result.EchAdvertised,
                ech_observed_locally = result.EchObserved,
                ech_observation_count_global_unattributable = result.EchObservationCount,
                records = result.ServiceBindings.Select(static record => new
                {
                    owner = record.OwnerName,
                    type = record.DnsType,
                    ttl_seconds = record.TtlSeconds,
                    priority = record.Priority,
                    target = record.Target,
                    alias_mode = record.AliasMode,
                    ech_advertised = record.EchAdvertised,
                    malformed = record.Malformed,
                    diagnostic = record.Diagnostic,
                    parameters = record.Parameters.Select(static parameter => new
                    {
                        key = parameter.Key,
                        name = parameter.Name,
                        value = parameter.Value,
                    }),
                }),
            }, new JsonSerializerOptions { WriteIndented = true }));
        }
        else
        {
            Console.WriteLine($"direct HTTPS/SVCB query: {(result.ServiceBindingQueryAvailable ? "available" : "unavailable")} - {result.ServiceBindingMessage}");
            Console.WriteLine($"ECH advertised by this name: {(result.EchAdvertised ? "yes" : "no")}");
            Console.WriteLine($"ECH observed locally: {(result.EchObserved ? "yes" : "no")} ({result.EchObservationCount} global, unattributable observation(s))");
            Console.WriteLine("owner\ttype\tttl\tpriority\tmode\ttarget\tECH\tparameters\tparse");
            foreach (var record in result.ServiceBindings)
            {
                var parameters = string.Join(";", record.Parameters.Select(static parameter => $"{parameter.Name}={parameter.Value}"));
                Console.WriteLine($"{record.OwnerName}\t{record.DnsType}\t{record.TtlSeconds}\t{record.Priority}\t{(record.AliasMode ? "alias" : "service")}\t{record.Target}\t{(record.EchAdvertised ? "advertised" : "not-advertised")}\t{parameters}\t{(record.Malformed ? record.Diagnostic : "ok")}");
            }
        }

        return result.ServiceBindingQueryAvailable ? 0 : 2;
    });
}

static async Task<int> IdnHomographAsync(string[] args)
{
    var action = args.Length > 1 ? args[1].Trim().ToLowerInvariant() : "status";
    if (args.Length > 2 || action is not ("status" or "enable" or "disable"))
    {
        Console.Error.WriteLine("Usage: idn-homograph [status|enable|disable]");
        return 1;
    }

    return await RunCommandAsync(async channel =>
    {
        var client = new DnsControl.DnsControlClient(channel);
        if (action != "status")
        {
            var ack = await client.SetIdnHomographAsync(new IdnHomographRequest { Enabled = action == "enable" });
            Console.WriteLine(ack.Message);
            if (!ack.Ok) return 2;
        }

        var status = await client.GetIdnHomographStatusAsync(new Empty());
        Console.WriteLine($"IDN homograph detection: {(status.Enabled ? "enabled" : "disabled")}");
        Console.WriteLine($"corpus: {status.CorpusSize} local domains; standard: {status.Standard}");
        Console.WriteLine("report-only: detections create alerts and never block domains automatically");
        return 0;
    });
}

static int DgaCheck(string[] args)
{
    if (args.Length is < 2 or > 3 || (args.Length == 3 && !args[2].Equals("--json", StringComparison.OrdinalIgnoreCase)))
    {
        Console.Error.WriteLine("Usage: dga-check <domain> [--json]");
        return 1;
    }

    var score = DgaHeuristic.Analyze(args[1]);
    if (args.Length == 3)
    {
        Console.WriteLine(JsonSerializer.Serialize(score, new JsonSerializerOptions { WriteIndented = true }));
    }
    else
    {
        Console.WriteLine(FormattableString.Invariant($"DGA score: {score.Score:F2}/{score.DecisionThreshold:F2} ({(score.IsAlgorithmic ? "algorithmic-looking" : "not algorithmic-looking")})"));
        Console.WriteLine(FormattableString.Invariant($"label: {score.RegistrableLabel} ({score.LabelLength} chars); reason: {score.Reason}; model: {score.Version}"));
        Console.WriteLine(FormattableString.Invariant($"entropy: {score.Entropy:F3} (threshold {score.EntropyThreshold:F3})"));
        Console.WriteLine(FormattableString.Invariant($"vowel ratio: {score.VowelRatio:P1} (low below {score.VowelRatioThreshold:P1})"));
        Console.WriteLine(FormattableString.Invariant($"digit ratio: {score.DigitRatio:P1} (high at {score.DigitRatioThreshold:P1})"));
        Console.WriteLine(FormattableString.Invariant($"max consonant run: {score.MaxConsonantRun} (high at {score.ConsonantRunThreshold})"));
        Console.WriteLine("report-only: this diagnostic never blocks a domain");
    }

    return score.IsValidDomain ? 0 : 2;
}

static async Task<int> FullStateSnapshotAsync(string[] args)
{
    var action = args.Length > 1 ? args[1].ToLowerInvariant() : "list";
    return await RunCommandAsync(async channel =>
    {
        var client = new Recovery.RecoveryClient(channel);
        switch (action)
        {
            case "create":
            {
                if (args.Length != 2)
                {
                    Console.Error.WriteLine("Usage: snapshot create");
                    return 1;
                }

                var snapshot = await client.CreateFullStateSnapshotAsync(new Empty());
                PrintSnapshot(snapshot);
                return snapshot.Verified ? 0 : 2;
            }
            case "list":
            {
                var list = await client.ListFullStateSnapshotsAsync(new Empty());
                if (list.Snapshots.Count == 0)
                {
                    Console.WriteLine("No full-state snapshots.");
                    return 0;
                }

                foreach (var snapshot in list.Snapshots)
                {
                    PrintSnapshot(snapshot);
                }

                return 0;
            }
            case "preview":
            {
                if (args.Length != 3)
                {
                    Console.Error.WriteLine("Usage: snapshot preview <snapshot-id>");
                    return 1;
                }

                var preview = await client.PreviewFullStateRestoreAsync(new FullStateSnapshotRef
                {
                    SnapshotId = args[2],
                });
                PrintRestorePreview(preview);
                return preview.Ok ? 0 : 2;
            }
            case "restore":
            {
                if (args.Length != 5 || !args[3].Equals("--sha256", StringComparison.OrdinalIgnoreCase)
                    || args[4].Length != 64 || !args[4].All(Uri.IsHexDigit))
                {
                    Console.Error.WriteLine("Usage: snapshot restore <snapshot-id> --sha256 <previewed-sha256>");
                    return 1;
                }

                var preview = await client.PreviewFullStateRestoreAsync(new FullStateSnapshotRef
                {
                    SnapshotId = args[2],
                });
                PrintRestorePreview(preview);
                if (!preview.Ok)
                {
                    return 2;
                }

                if (!preview.Sha256.Equals(args[4], StringComparison.OrdinalIgnoreCase))
                {
                    Console.Error.WriteLine("Snapshot changed after the supplied hash was reviewed; restore refused.");
                    return 2;
                }

                var ack = await client.RestoreFullStateSnapshotAsync(new FullStateRestoreRequest
                {
                    SnapshotId = preview.SnapshotId,
                    ExpectedSha256 = preview.Sha256,
                    CreatePreRestore = true,
                });
                Console.WriteLine(ack.Message);
                return ack.Ok ? 0 : 2;
            }
            default:
                Console.Error.WriteLine("Usage: snapshot create|list|preview|restore");
                return 1;
        }
    });

    static void PrintSnapshot(FullStateSnapshot snapshot)
    {
        Console.WriteLine(snapshot.SnapshotId);
        Console.WriteLine($"  created={snapshot.Created} version={snapshot.AppVersion} schema={snapshot.SchemaVersion} size={FormatBytes(snapshot.SizeBytes)}");
        Console.WriteLine($"  sha256={snapshot.Sha256} verified={snapshot.Verified.ToString().ToLowerInvariant()}");
        foreach (var component in snapshot.Components)
        {
            Console.WriteLine($"  component: {component}");
        }
    }

    static void PrintRestorePreview(FullStateRestorePreview preview)
    {
        Console.WriteLine(preview.Message);
        if (!preview.Ok)
        {
            return;
        }

        Console.WriteLine($"snapshot={preview.SnapshotId} sha256={preview.Sha256}");
        Console.WriteLine($"target-version={preview.AppVersion} target-schema={preview.SchemaVersion}");
        foreach (var change in preview.Changes)
        {
            Console.WriteLine($"  {change}");
        }
    }
}

static string BuildEventsCsv(IEnumerable<EventLogEntry> rows)
{
    var sb = new System.Text.StringBuilder();
    CsvExport.AppendRow(sb, "When", "Category", "Action", "Reason", "Domain", "Process", "Details");
    foreach (var e in rows)
    {
        CsvExport.AppendRow(sb, e.Ts, e.Category, e.Action, e.Reason, e.Domain, e.Process, e.Details);
    }

    return sb.ToString();
}

static string BuildListenersCsv(IEnumerable<HostsGuard.Contracts.ListenerExposure> rows)
{
    var sb = new System.Text.StringBuilder();
    CsvExport.AppendRow(sb, "Protocol", "LocalAddress", "LocalPort", "Process", "Pid", "Service",
        "Package", "BindScope", "ActiveProfiles", "Coverage", "Risk", "Reason");
    foreach (var row in rows)
    {
        CsvExport.AppendRow(sb, row.Protocol, row.LocalAddress,
            row.LocalPort.ToString(System.Globalization.CultureInfo.InvariantCulture), row.Process,
            row.Pid.ToString(System.Globalization.CultureInfo.InvariantCulture), row.Service, row.Package,
            row.BindScope, row.ActiveProfiles, row.Coverage, row.Risk, row.Reason);
    }

    return sb.ToString();
}

static string BuildFirewallAnalysisCsv(IEnumerable<HostsGuard.Contracts.FirewallRuleAnalysisFinding> findings)
{
    var sb = new System.Text.StringBuilder();
    CsvExport.AppendRow(sb, "Kind", "Rule", "RelatedRule", "CanonicalFingerprint", "Reason", "Remediation", "CleanupEligible");
    foreach (var finding in findings)
    {
        CsvExport.AppendRow(sb, finding.Kind, finding.RuleName, finding.RelatedRuleName,
            finding.CanonicalFingerprint, finding.Reason, finding.Remediation,
            finding.CleanupEligible ? "true" : "false");
    }

    return sb.ToString();
}

static string FormatBytes(long bytes)
{
    string[] units = ["B", "KB", "MB", "GB", "TB"];
    double value = Math.Max(0, bytes);
    var unit = 0;
    while (value >= 1024 && unit < units.Length - 1)
    {
        value /= 1024;
        unit++;
    }

    return string.Create(System.Globalization.CultureInfo.InvariantCulture, $"{value:0.#} {units[unit]}");
}

static bool TryParseBytes(string text, out long bytes)
{
    bytes = 0;
    if (string.IsNullOrWhiteSpace(text))
    {
        return false;
    }

    var value = text.Trim();
    var unit = string.Empty;
    var numberEnd = value.Length;
    while (numberEnd > 0 && char.IsLetter(value[numberEnd - 1]))
    {
        numberEnd--;
    }

    if (numberEnd <= 0)
    {
        return false;
    }

    unit = value[numberEnd..].Trim().ToUpperInvariant();
    var numberText = value[..numberEnd].Trim();
    if (!decimal.TryParse(numberText, System.Globalization.NumberStyles.Float,
            System.Globalization.CultureInfo.InvariantCulture, out var parsed) || parsed <= 0)
    {
        return false;
    }

    var multiplier = unit switch
    {
        "" or "B" => 1m,
        "K" or "KB" => 1024m,
        "M" or "MB" => 1024m * 1024m,
        "G" or "GB" => 1024m * 1024m * 1024m,
        "T" or "TB" => 1024m * 1024m * 1024m * 1024m,
        _ => 0m,
    };
    if (multiplier <= 0)
    {
        return false;
    }

    var total = parsed * multiplier;
    if (total > long.MaxValue)
    {
        return false;
    }

    bytes = (long)Math.Ceiling(total);
    return bytes > 0;
}

static async Task<int> BlocklistsAsync(string[] args)
{
    var subcommand = args.Length > 1 ? args[1].ToLowerInvariant() : "list";
    return await RunCommandAsync(async channel =>
    {
        var client = new ListControl.ListControlClient(channel);
        switch (subcommand)
        {
            case "list":
                var sources = await client.ListBlocklistSourcesAsync(new Empty());
                Console.WriteLine("name\tsubscribed\tenabled\thealth\tdomains\towned\tprevious\tattempt\tcheckpoint\thits_30d\turl");
                foreach (var s in sources.Sources.OrderBy(s => s.Name, StringComparer.OrdinalIgnoreCase))
                {
                    Console.WriteLine($"{s.Name}\t{s.Subscribed}\t{s.Enabled}\t{SourceHealth(s)}\t{s.DomainCount}\t{s.OwnedDomainCount}\t{s.PreviousDomainCount}\t{s.LastAttemptDomainCount}\t{s.RollbackCheckpointId}\t{s.Hits30D}\t{s.Url}");
                }

                return 0;
            case "stats":
                var stats = await client.ListBlocklistSourcesAsync(new Empty());
                Console.WriteLine("name\thealth\thits_30d\towned\tdomains\tprevious\tcheckpoint\tenabled");
                foreach (var s in stats.Sources
                             .Where(s => s.Subscribed)
                             .OrderByDescending(s => s.Hits30D)
                             .ThenBy(s => s.Name, StringComparer.OrdinalIgnoreCase))
                {
                    Console.WriteLine($"{s.Name}\t{SourceHealth(s)}\t{s.Hits30D}\t{s.OwnedDomainCount}\t{s.DomainCount}\t{s.PreviousDomainCount}\t{s.RollbackCheckpointId}\t{s.Enabled}");
                }

                return 0;
            case "refresh":
                return PrintBlocklistResult(await client.RefreshBlocklistsAsync(new Empty()));
            case "preview":
            case "import":
                if (args.Length < 4)
                {
                    Console.Error.WriteLine($"Usage: blocklists {subcommand} <name> <https-url>");
                    return 1;
                }

                var request = new BlocklistRequest { Name = args[2], Url = args[3] };
                return PrintBlocklistResult(subcommand == "preview"
                    ? await client.PreviewBlocklistAsync(request)
                    : await client.ImportBlocklistAsync(request));
            case "preview-file":
            case "import-file":
                if (args.Length < 4)
                {
                    Console.Error.WriteLine($"Usage: blocklists {subcommand} <name> <path-to-hosts-or-adblock-file>");
                    return 1;
                }

                byte[] content;
                try
                {
                    content = await File.ReadAllBytesAsync(args[3]);
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
                {
                    Console.Error.WriteLine($"could not read '{args[3]}': {ex.Message}");
                    return 1;
                }

                if (content.Length > BlocklistCatalog.MaxBlocklistBytes)
                {
                    Console.Error.WriteLine($"'{args[3]}' exceeds the {BlocklistCatalog.MaxBlocklistBytes / (1024 * 1024)} MB import cap");
                    return 1;
                }

                var contentRequest = new BlocklistContentRequest
                {
                    Name = args[2],
                    Content = Google.Protobuf.ByteString.CopyFrom(content),
                };
                return PrintBlocklistResult(subcommand == "preview-file"
                    ? await client.PreviewBlocklistContentAsync(contentRequest)
                    : await client.ImportBlocklistContentAsync(contentRequest));
            case "disable":
            case "enable":
                if (args.Length < 3)
                {
                    Console.Error.WriteLine($"Usage: blocklists {subcommand} <name>");
                    return 1;
                }

                var toggle = await client.SetBlocklistEnabledAsync(new BlocklistToggleRequest
                {
                    Name = args[2],
                    Enabled = subcommand == "enable",
                });
                Console.WriteLine(toggle.Message);
                return toggle.Ok ? 0 : 2;
            case "remove":
                if (args.Length < 3)
                {
                    Console.Error.WriteLine("Usage: blocklists remove <name>");
                    return 1;
                }

                var ack = await client.RemoveBlocklistSubscriptionAsync(new BlocklistRequest { Name = args[2] });
                Console.WriteLine(ack.Message);
                return ack.Ok ? 0 : 2;
            case "rollback":
                if (args.Length < 3)
                {
                    Console.Error.WriteLine("Usage: blocklists rollback <name>");
                    return 1;
                }

                var rollback = await client.RestoreBlocklistCheckpointAsync(new BlocklistRequest { Name = args[2] });
                Console.WriteLine(rollback.Message);
                return rollback.Ok ? 0 : 2;
            case "recover-connectivity":
                var recoveryRequest = new WindowsConnectivityRecoveryRequest();
                recoveryRequest.Domains.AddRange(args.Skip(2));
                var recovery = await client.RecoverWindowsConnectivityAsync(recoveryRequest);
                Console.WriteLine(recovery.Message);
                foreach (var domain in recovery.RecoveredDomains) Console.WriteLine($"  recovered: {domain}");
                foreach (var domain in recovery.RejectedDomains) Console.WriteLine($"  rejected:  {domain}");
                return recovery.Ok ? 0 : 2;
            default:
                Console.Error.WriteLine($"Unknown blocklists command: {subcommand}");
                return 1;
        }
    });
}

static async Task<int> IpBlocklistsAsync(string[] args)
{
    var subcommand = args.Length > 1 ? args[1].ToLowerInvariant() : "list";
    return await RunCommandAsync(async channel =>
    {
        var client = new ListControl.ListControlClient(channel);
        switch (subcommand)
        {
            case "list":
                var sources = await client.ListIpBlocklistsAsync(new Empty());
                Console.WriteLine("name\tenabled\thealth\taddresses\trules\tprevious\ttruncated\tlast_refresh\turl");
                foreach (var s in sources.Sources.OrderBy(s => s.Name, StringComparer.OrdinalIgnoreCase))
                {
                    var health = s.HealthStatus.Length != 0 ? s.HealthStatus : "new";
                    Console.WriteLine($"{s.Name}\t{s.Enabled}\t{health}\t{s.AddressCount}\t{s.RuleCount}\t{s.PreviousAddressCount}\t{s.Truncated}\t{s.LastRefresh}\t{s.Url}");
                }

                return 0;
            case "refresh":
                return PrintIpBlocklistResult(await client.RefreshIpBlocklistsAsync(new Empty()));
            case "import":
                if (args.Length < 4)
                {
                    Console.Error.WriteLine("Usage: ip-blocklists import <name> <https-url>");
                    return 1;
                }

                return PrintIpBlocklistResult(
                    await client.ImportIpBlocklistAsync(new BlocklistRequest { Name = args[2], Url = args[3] }));
            case "disable":
            case "enable":
                if (args.Length < 3)
                {
                    Console.Error.WriteLine($"Usage: ip-blocklists {subcommand} <name>");
                    return 1;
                }

                var toggle = await client.SetIpBlocklistEnabledAsync(new BlocklistToggleRequest
                {
                    Name = args[2],
                    Enabled = subcommand == "enable",
                });
                Console.WriteLine(toggle.Message);
                return toggle.Ok ? 0 : 2;
            case "remove":
                if (args.Length < 3)
                {
                    Console.Error.WriteLine("Usage: ip-blocklists remove <name>");
                    return 1;
                }

                var ack = await client.RemoveIpBlocklistAsync(new BlocklistRequest { Name = args[2] });
                Console.WriteLine(ack.Message);
                return ack.Ok ? 0 : 2;
            case "rollback":
                if (args.Length < 3)
                {
                    Console.Error.WriteLine("Usage: ip-blocklists rollback <name>");
                    return 1;
                }

                return PrintIpBlocklistResult(
                    await client.RollbackIpBlocklistAsync(new BlocklistRequest { Name = args[2] }));
            default:
                Console.Error.WriteLine($"Unknown ip-blocklists command: {subcommand}");
                return 1;
        }
    });
}

static int PrintIpBlocklistResult(IpBlocklistResult result)
{
    Console.WriteLine(result.Message);
    Console.WriteLine($"  addresses:  {result.Total}");
    Console.WriteLine($"  rules:      {result.Rules}");
    Console.WriteLine($"  duplicates: {result.Duplicates}");
    Console.WriteLine($"  invalid:    {result.Invalid}");
    Console.WriteLine($"  unsafe:     {result.Unsafe}");
    if (result.Truncated)
    {
        Console.WriteLine("  truncated:  True");
    }

    if (result.Guarded != 0 || result.Failed != 0)
    {
        Console.WriteLine($"  guarded:    {result.Guarded}");
        Console.WriteLine($"  failed:     {result.Failed}");
    }

    if (result.Warning.Length != 0)
    {
        Console.WriteLine($"  warning:    {result.Warning}");
    }

    return result.Ok ? 0 : 2;
}

static int PrintBlocklistResult(BlocklistResult result)
{
    Console.WriteLine(result.Message);
    Console.WriteLine($"  total:       {result.Total}");
    Console.WriteLine($"  added:       {result.Added}");
    Console.WriteLine($"  duplicates:  {result.Duplicates}");
    Console.WriteLine($"  invalid:     {result.Invalid}");
    Console.WriteLine($"  stripped:    {result.ModifiersStripped}");
    Console.WriteLine($"  hijack:      {result.HijackFlagged}");
    Console.WriteLine($"  allowlisted: {result.AllowlistOverrides}");
    if (result.Removed != 0 || result.Preserved != 0)
    {
        Console.WriteLine($"  removed:     {result.Removed}");
        Console.WriteLine($"  preserved:   {result.Preserved}");
    }

    if (result.Guarded != 0 || result.Failed != 0)
    {
        Console.WriteLine($"  guarded:     {result.Guarded}");
        Console.WriteLine($"  failed:      {result.Failed}");
    }

    if (result.CheckpointId != 0)
    {
        Console.WriteLine($"  checkpoint:  {result.CheckpointId}");
    }

    if (result.Warning.Length != 0)
    {
        Console.WriteLine($"  warning:     {result.Warning}");
    }

    foreach (var warning in result.ConnectivityWarnings)
    {
        Console.WriteLine($"  NCSI warning: {warning.Domain} ({warning.ProbeKind}, {warning.Era}) - {warning.Reason}");
        Console.WriteLine("    deliberate import is allowed; recover with: blocklists recover-connectivity " + warning.Domain);
    }

    return result.Ok ? 0 : 2;
}

static string SourceHealth(BlocklistSource source) =>
    string.IsNullOrWhiteSpace(source.HealthStatus) ? "new" : source.HealthStatus;

static async Task<int> ModeAsync(string? requested)
{
    if (requested is not null && requested is not ("normal" or "notify" or "learning"))
    {
        Console.Error.WriteLine("Invalid mode. Use normal, notify, or learning.");
        return 1;
    }

    return await RunCommandAsync(async channel =>
    {
        var consent = new Consent.ConsentClient(channel);
        if (requested is null)
        {
            var mode = await consent.GetModeAsync(new Empty());
            Console.WriteLine($"{mode.Mode}{(mode.DetectionArmed ? " (detection armed)" : string.Empty)}");
            return 0;
        }

        var ack = await consent.SetModeAsync(new FilteringMode { Mode = requested });
        Console.WriteLine(ack.Message);
        return ack.Ok ? 0 : 2;
    });
}

// NET-187: SHA-256-verified self-update — check the release feed, stage a
// hash-verified installer (remote or local), applied on the next restart.
static async Task<int> UpdateAsync(string[] args)
{
    var subcommand = args.Length > 1 ? args[1].ToLowerInvariant() : "check";
    if (subcommand == "health")
    {
        return await UpdateHealthAsync(args);
    }

    return await RunCommandAsync(async channel =>
    {
        var client = new HostsGuard.Contracts.Diagnostics.DiagnosticsClient(channel);
        switch (subcommand)
        {
            case "check":
            case "status":
                var status = await client.GetUpdateStatusAsync(new Empty());
                Console.WriteLine($"installed:  {status.InstalledVersion}");
                Console.WriteLine($"latest:     {(status.LatestVersion.Length != 0 ? status.LatestVersion : "(unknown)")}");
                Console.WriteLine($"available:  {status.UpdateAvailable}");
                if (status.StagedVersion.Length != 0)
                {
                    Console.WriteLine($"staged:     {status.StagedVersion} (sha256 {status.StagedSha256}, at {status.StagedAt}) — applies on next service restart");
                }

                if (status.LastError.Length != 0)
                {
                    Console.WriteLine($"last error: {status.LastError}");
                }

                return status.LastError.Length == 0 ? 0 : 2;
            case "stage":
                var request = new StageUpdateRequest();
                for (var i = 2; i < args.Length; i++)
                {
                    var arg = args[i];
                    if (TryReadOptionValue(args, ref i, arg, "--path", out var value))
                    {
                        request.LocalPath = value;
                        continue;
                    }

                    if (TryReadOptionValue(args, ref i, arg, "--sha256", out value))
                    {
                        request.Sha256 = value;
                        continue;
                    }

                    Console.Error.WriteLine($"Unknown update stage option: {arg}");
                    return 1;
                }

                var ack = await client.StageUpdateAsync(request);
                Console.WriteLine(ack.Message);
                return ack.Ok ? 0 : 2;
            default:
                Console.Error.WriteLine($"Unknown update command: {subcommand}");
                return 1;
        }
    });
}

// Installer-only, read-only verification. It retries service startup, then
// proves the exact service version, DB schema, and readable firewall/filtering
// posture without calling any mutating RPC.
static async Task<int> UpdateHealthAsync(string[] args)
{
    var expected = string.Empty;
    var timeoutSeconds = 30;
    for (var i = 2; i < args.Length; i++)
    {
        var arg = args[i];
        if (TryReadOptionValue(args, ref i, arg, "--expected", out var value))
        {
            expected = value;
            continue;
        }

        if (TryReadOptionValue(args, ref i, arg, "--timeout", out value) &&
            int.TryParse(value, out timeoutSeconds) && timeoutSeconds is >= 1 and <= 120)
        {
            continue;
        }

        Console.Error.WriteLine($"Unknown or invalid update health option: {arg}");
        return 1;
    }

    if (expected.Length == 0)
    {
        Console.Error.WriteLine("update health requires --expected <version>");
        return 1;
    }

    var deadline = DateTime.UtcNow.AddSeconds(timeoutSeconds);
    string lastError = "service did not become reachable";
    do
    {
        var (channel, connectError) = Connect();
        if (channel is null)
        {
            lastError = connectError;
            await Task.Delay(250);
            continue;
        }

        using (channel)
        {
            try
            {
                var callDeadline = DateTime.UtcNow.AddSeconds(3);
                var status = await new HostsGuard.Contracts.Diagnostics.DiagnosticsClient(channel)
                    .GetStatusAsync(new Empty(), deadline: callDeadline);
                var posture = await new FirewallControl.FirewallControlClient(channel)
                    .GetPostureAsync(new Empty(), deadline: callDeadline);
                var mode = await new Consent.ConsentClient(channel)
                    .GetModeAsync(new Empty(), deadline: callDeadline);

                var failures = new List<string>();
                if (!VersionsEqual(status.Version, expected))
                {
                    failures.Add($"service version {status.Version} != expected {expected}");
                }

                if (status.SchemaVersion <= 0 || status.SchemaVersionOnDisk != status.SchemaVersion)
                {
                    failures.Add($"database schema {status.SchemaVersionOnDisk} != code {status.SchemaVersion}");
                }

                if (!posture.Available || posture.Profiles.Count == 0)
                {
                    failures.Add("firewall posture is unavailable or has no profiles");
                }

                if (mode.Mode is not ("normal" or "notify" or "learning"))
                {
                    failures.Add($"filtering mode '{mode.Mode}' is invalid");
                }

                if (status.RuntimeVersion.Length == 0 || status.SqliteVersion.Length == 0)
                {
                    failures.Add("runtime or SQLite health metadata is missing");
                }

                if (failures.Count != 0)
                {
                    foreach (var failure in failures)
                    {
                        Console.Error.WriteLine($"FAIL: {failure}");
                    }

                    return 2;
                }

                Console.WriteLine($"OK: service {status.Version}; schema {status.SchemaVersion}; " +
                    $"{posture.Profiles.Count} firewall profiles; filtering {mode.Mode}; posture unchanged");
                return 0;
            }
            catch (Grpc.Core.RpcException ex) when (
                ex.StatusCode is Grpc.Core.StatusCode.Unavailable or
                    Grpc.Core.StatusCode.DeadlineExceeded or
                    Grpc.Core.StatusCode.Cancelled or
                    Grpc.Core.StatusCode.Unauthenticated)
            {
                lastError = $"{ex.StatusCode}: {ex.Status.Detail}";
            }
        }

        await Task.Delay(250);
    }
    while (DateTime.UtcNow < deadline);

    Console.Error.WriteLine($"FAIL: update health timed out after {timeoutSeconds} seconds ({lastError})");
    return 3;

    static bool VersionsEqual(string actual, string expectedVersion)
    {
        static Version? Parse(string value)
        {
            var core = value.Trim().TrimStart('v', 'V');
            var metadata = core.IndexOfAny(['-', '+']);
            if (metadata >= 0)
            {
                core = core[..metadata];
            }

            return System.Version.TryParse(core, out var parsed) ? parsed : null;
        }

        var left = Parse(actual);
        var right = Parse(expectedVersion);
        return left is not null && right is not null &&
            left.Major == right.Major && left.Minor == right.Minor && left.Build == right.Build;
    }
}

// NET-054: pre-release smoke — runtime, dependency versions, service
// reachability, signing status. Exit non-zero only when the binary itself is
// unhealthy; an absent service is reported but expected on build machines.
static async Task<int> SafePostureAsync()
{
    var (channel, error) = Connect();
    if (channel is null)
    {
        PrintServiceUnavailable(error);
        return 3;
    }

    using (channel)
    {
        var failures = 0;
        var consent = new Consent.ConsentClient(channel);
        var fw = new FirewallControl.FirewallControlClient(channel);
        var dns = new DnsControl.DnsControlClient(channel);

        await Apply("filtering mode", () => consent.SetModeAsync(new FilteringMode { Mode = "normal" }).ResponseAsync);
        try
        {
            var status = await fw.GetKillSwitchAsync(new Empty());
            await Apply("VPN kill-switch", () => fw.SetKillSwitchAsync(new KillSwitchRequest
            {
                Enabled = false,
                Adapter = status.Adapter,
            }).ResponseAsync);
        }
        catch (Grpc.Core.RpcException ex)
        {
            Console.WriteLine($"VPN kill-switch: failed ({ex.Status.Detail})");
            failures++;
        }

        await Apply("global outbound", () => fw.SetGlobalModeAsync(new GlobalModeRequest { Mode = "allow-all" }).ResponseAsync);
        await Apply("default outbound", () => fw.SetDefaultOutboundAsync(new OutboundRequest { Block = false }).ResponseAsync);
        await Apply("encrypted DNS firewall blocks", () => fw.UnblockEncryptedDnsAsync(new Empty()).ResponseAsync);
        await Apply("QUIC firewall block", () => fw.UnblockQuicAsync(new Empty()).ResponseAsync);
        await Apply("CNAME-cloak reactive blocking", () => dns.SetCnameCloakAsync(new CnameCloakRequest { Enabled = false }).ResponseAsync);
        await Apply("TCP flow teardown", () => fw.SetFlowTeardownAsync(new FlowTeardownRequest { Enabled = false }).ResponseAsync);

        Console.WriteLine("hosts-file blocks: left unchanged");
        return failures == 0 ? 0 : 2;

        async Task Apply(string label, Func<Task<Ack>> action)
        {
            try
            {
                var ack = await action();
                Console.WriteLine($"{label}: {ack.Message}");
                if (!ack.Ok)
                {
                    failures++;
                }
            }
            catch (Grpc.Core.RpcException ex)
            {
                Console.WriteLine($"{label}: failed ({ex.Status.Detail})");
                failures++;
            }
        }
    }
}

static async Task<int> SafePostureSmokeAsync()
{
    return await RunCommandAsync(async channel =>
    {
        var failures = new List<string>();
        var diagnostics = new HostsGuard.Contracts.Diagnostics.DiagnosticsClient(channel);
        var consent = new Consent.ConsentClient(channel);
        var fw = new FirewallControl.FirewallControlClient(channel);
        var dns = new DnsControl.DnsControlClient(channel);

        var status = await diagnostics.GetStatusAsync(new Empty());
        var mode = await consent.GetModeAsync(new Empty());
        var posture = await fw.GetPostureAsync(new Empty());
        var doh = await dns.GetDohStatusAsync(new Empty());
        var teardown = await fw.GetFlowTeardownAsync(new Empty());
        var killSwitch = await fw.GetKillSwitchAsync(new Empty());

        Console.WriteLine("HostsGuard safe-posture-smoke");
        Console.WriteLine($"  hosts-file blocks: {status.HostsBlocked} (unchanged by this check)");
        Check(mode.Mode == "normal", $"filtering mode: {mode.Mode}", "filtering mode is not normal");
        Check(!mode.DetectionArmed, "detection: disarmed", "detection is armed");
        Check(
            posture.Available && posture.Profiles.Count != 0 && !posture.Lockdown && posture.Profiles.All(p => !p.OutboundBlock),
            "default outbound: Allow on all profiles",
            "default outbound is not Allow on every profile");
        Check(!doh.BlockingActive, "encrypted DNS blocks: off", "encrypted DNS blocks are active");
        Check(!doh.QuicBlocked, "QUIC block: off", "QUIC block is active");
        Check(!doh.CnameCloak, "CNAME-cloak blocking: off", "CNAME-cloak blocking is active");
        Check(!teardown.Enabled, "TCP flow teardown: off", "TCP flow teardown is enabled");
        Check(!killSwitch.Enabled && !killSwitch.Engaged, "VPN kill-switch: off", "VPN kill-switch is enabled or engaged");

        if (failures.Count == 0)
        {
            Console.WriteLine("OK: safe network posture is installed");
            return 0;
        }

        foreach (var failure in failures)
        {
            Console.WriteLine($"FAIL: {failure}");
        }

        return 2;

        void Check(bool ok, string pass, string fail)
        {
            Console.WriteLine($"{(ok ? "OK" : "FAIL")}: {(ok ? pass : fail)}");
            if (!ok)
            {
                failures.Add(fail);
            }
        }
    });
}

static async Task<int> ReleaseSmokeAsync()
{
    var healthy = true;
    Console.WriteLine("HostsGuard release-smoke");
    Console.WriteLine($"  version:   {InformationalVersion()}");
    Console.WriteLine($"  runtime:   {RuntimeInformation.FrameworkDescription} ({RuntimeInformation.ProcessArchitecture})");

    foreach (var (label, type) in new (string, Type)[]
    {
        ("grpc:     ", typeof(Grpc.Net.Client.GrpcChannel)),
        ("protobuf: ", typeof(Google.Protobuf.IMessage)),
    })
    {
        try
        {
            var assembly = type.Assembly.GetName();
            Console.WriteLine($"  {label}{assembly.Name} {assembly.Version}");
        }
        catch (FileLoadException ex)
        {
            Console.WriteLine($"  {label}FAILED to load — {ex.Message}");
            healthy = false;
        }
    }

    var exe = Environment.ProcessPath;
    if (exe is not null)
    {
        try
        {
            // SYSLIB0057 has no managed replacement for signed-file signer
            // extraction (see FirewallIdentity.Compute) — suppress until removal.
#pragma warning disable SYSLIB0057
            using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(exe));
#pragma warning restore SYSLIB0057
            Console.WriteLine($"  signing:   signed by {cert.Subject}");
        }
        catch (CryptographicException)
        {
            Console.WriteLine("  signing:   UNSIGNED (SmartScreen warnings expected)");
        }
    }

    var (channel, error) = Connect();
    if (channel is null)
    {
        Console.WriteLine($"  service:   not reachable ({error})");
    }
    else
    {
        using (channel)
        {
            try
            {
                var status = await new HostsGuard.Contracts.Diagnostics.DiagnosticsClient(channel).GetStatusAsync(
                    new Empty(), deadline: DateTime.UtcNow.AddSeconds(5));
                Console.WriteLine($"  service:   reachable — v{status.Version}, uptime {status.UptimeSeconds}s");
            }
            catch (Grpc.Core.RpcException ex)
            {
                Console.WriteLine($"  service:   not reachable ({ex.StatusCode})");
            }
        }
    }

    Console.WriteLine(healthy ? "OK" : "FAILED");
    return healthy ? 0 : 2;
}

// Uninstaller hook (WFCP-000a): remove every HG_ firewall rule, restore the
// default-outbound posture the consent broker saved, and drop the handshake.
// Runs elevated (the uninstaller context); direct COM, no service required.
static int UninstallCleanup()
{
    var dataDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "HostsGuard");
    try
    {
        var engine = new FirewallEngine();

        // Restore posture first: if detection was armed, the saved prior wins.
        var statePath = Path.Combine(dataDir, "consent_state.json");
        if (File.Exists(statePath))
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(statePath));
            var mode = doc.RootElement.TryGetProperty("Mode", out var m) ? m.GetString() : "normal";
            if (mode is "notify" or "learning")
            {
                var priorBlock = doc.RootElement.TryGetProperty("PriorOutboundBlock", out var prior) &&
                    prior.ValueKind == JsonValueKind.Object &&
                    prior.EnumerateObject().All(p => p.Value.ValueKind == JsonValueKind.True);
                engine.SetDefaultOutboundBlock(priorBlock);
                Console.WriteLine($"restored default outbound: {(priorBlock ? "Block" : "Allow")}");
            }

            File.Delete(statePath);
        }

        var removed = 0;
        foreach (var rule in engine.ListRules().Where(r => r.Name.StartsWith("HG_", StringComparison.Ordinal)))
        {
            if (engine.DeleteRule(rule.Name))
            {
                removed++;
            }
        }

        Console.WriteLine($"removed {removed} HostsGuard firewall rules");

        var handshake = Path.Combine(dataDir, "session_token");
        if (File.Exists(handshake))
        {
            File.Delete(handshake);
        }

        return 0;
    }
    catch (Exception ex) when (ex is COMException or UnauthorizedAccessException or IOException or JsonException)
    {
        Console.Error.WriteLine($"cleanup incomplete: {ex.Message}");
        return 2;
    }
}
