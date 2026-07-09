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
    "block-app" => await ProgramOpAsync(args, block: true),
    "unblock-app" => await ProgramOpAsync(args, block: false),
    "firewall-packages" or "packages" => await ListPackagesAsync(args),
    "block-package" => await PackageOpAsync(args, "Block"),
    "allow-package" => await PackageOpAsync(args, "Allow"),
    "unblock-package" => await PackageOpAsync(args, "Delete"),
    "explain" => await ExplainAsync(args),
    "export" => await ExportAsync(args.Length > 1 ? args[1] : "hostsguard_export.json"),
    "export-policy" => await ExportPolicyAsync(args.Length > 1 ? args[1] : "hostsguard_policy.json"),
    "import-policy" => await ImportPolicyAsync(args),
    "events" => await EventsAsync(args),
    "traffic-profile" => await TrafficProfileAsync(args),
    "support-bundle" => await SupportBundleAsync(args),
    "usage" => await UsageAsync(args),
    "usage-quota" => await UsageQuotaAsync(args),
    "dns-cache" => await DnsCacheAsync(args),
    "dns-flush-entry" => await DnsFlushEntryAsync(args),
    "blocklists" => await BlocklistsAsync(args),
    "mode" => await ModeAsync(args.Length > 1 ? args[1] : null),
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
          HostsGuard.Cli block-app <exe-path> [out|in]
          HostsGuard.Cli unblock-app <exe-path> [out|in]
          HostsGuard.Cli firewall-packages [--search text]
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
          HostsGuard.Cli events [--limit N] [--offset N] [--search text] [--since ISO] [--until ISO]
                               [--action name] [--reason name] [--domain text] [--process text]
                               [--category name] [--export path.csv]
          HostsGuard.Cli traffic-profile [path.json|path.csv] [--format json|csv] [--limit N]
                               [--since ISO] [--until ISO] [--process app] [--action name]
                               [--protocol tcp|udp]
          HostsGuard.Cli support-bundle [--limit N] [--since ISO] [--until ISO]
                               [--process app] [--action name] [--protocol tcp|udp]
          HostsGuard.Cli usage [--days N] [--limit N] [--search text] [--app process] [--domain domain]
          HostsGuard.Cli usage-quota list
          HostsGuard.Cli usage-quota set --scope app|domain --match value --limit 1GB [--days 30] [--disabled]
          HostsGuard.Cli usage-quota delete --id N
          HostsGuard.Cli usage-quota reset
          HostsGuard.Cli usage-quota export [path.csv|path.json] [--days N] [--scope app|domain] [--match value]
          HostsGuard.Cli dns-cache [--limit N] [--search text]
          HostsGuard.Cli dns-flush-entry <cached-name>
          HostsGuard.Cli blocklists [list|stats|refresh]
          HostsGuard.Cli blocklists preview <name> <https-url>
          HostsGuard.Cli blocklists import <name> <https-url>
          HostsGuard.Cli blocklists disable|enable|remove|rollback <name>
          HostsGuard.Cli mode [normal|notify|learning]
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

static async Task<int> StatusAsync()
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
            var status = await new HostsGuard.Contracts.Diagnostics.DiagnosticsClient(channel).GetStatusAsync(new Empty());
            Console.WriteLine($"service:      v{status.Version} (elevated: {status.Elevated}, uptime {status.UptimeSeconds}s)");
            Console.WriteLine($"hosts:        {status.HostsBlocked} blocked entries");
            Console.WriteLine($"database:     {status.DbBlocked} blocked, {status.DbAllowed} allowed, {status.FeedTotal} feed rows");
            Console.WriteLine($"monitors:     dns={(status.DnsMonitorActive ? "on" : "off")} connections={(status.ConnectionMonitorActive ? "on" : "off")}");
            var mode = await new Consent.ConsentClient(channel).GetModeAsync(new Empty());
            Console.WriteLine($"filtering:    {mode.Mode}{(mode.DetectionArmed ? " (detection armed)" : string.Empty)}");
            return 0;
        }
        catch (Grpc.Core.RpcException ex)
        {
            PrintServiceUnavailable(ex.Status.Detail);
            return 3;
        }
    }
}

static async Task<int> DomainOpAsync(string[] args, Func<HostsControl.HostsControlClient, DomainRequest, Task<Ack>> op)
{
    if (args.Length < 2)
    {
        Console.Error.WriteLine("Missing domain.");
        return Usage();
    }

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
            var request = new DomainRequest
            {
                Domain = args[1],
                Reason = args.Length > 2 ? args[2] : string.Empty,
                Source = "cli",
            };
            var ack = await op(new HostsControl.HostsControlClient(channel), request);
            Console.WriteLine(ack.Message);
            return ack.Ok ? 0 : 2;
        }
        catch (Grpc.Core.RpcException ex)
        {
            PrintServiceUnavailable(ex.Status.Detail);
            return 3;
        }
    }
}

static async Task<int> ExplainAsync(string[] args)
{
    if (args.Length < 2)
    {
        Console.Error.WriteLine("Missing target.");
        return Usage();
    }

    var request = BuildExplainRequest(args);
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
        }
        catch (Grpc.Core.RpcException ex)
        {
            PrintServiceUnavailable(ex.Status.Detail);
            return 3;
        }
    }
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
        }
        catch (Grpc.Core.RpcException ex)
        {
            PrintServiceUnavailable(ex.Status.Detail);
            return 3;
        }
    }
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
        }
        catch (Grpc.Core.RpcException ex)
        {
            PrintServiceUnavailable(ex.Status.Detail);
            return 3;
        }
    }
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
        }
        catch (Grpc.Core.RpcException ex)
        {
            PrintServiceUnavailable(ex.Status.Detail);
            return 3;
        }
    }
}

static bool IsPackageSid(string value) => value.Trim().StartsWith("S-1-", StringComparison.OrdinalIgnoreCase);

static async Task<int> ExportAsync(string path)
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
        }
        catch (Grpc.Core.RpcException ex)
        {
            PrintServiceUnavailable(ex.Status.Detail);
            return 3;
        }
    }
}

// NET-089: export the whole machine policy as one versioned JSON document.
static async Task<int> ExportPolicyAsync(string path)
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
        }
        catch (Grpc.Core.RpcException ex)
        {
            PrintServiceUnavailable(ex.Status.Detail);
            return 3;
        }
    }
}

// NET-089: reconstruct a machine's policy from an exported JSON document.
static async Task<int> ImportPolicyAsync(string[] args)
{
    if (args.Length < 2)
    {
        Console.Error.WriteLine("Missing policy file. Usage: import-policy [--preview] <path.json>");
        return Usage();
    }

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
        }
        catch (Grpc.Core.RpcException ex)
        {
            PrintServiceUnavailable(ex.Status.Detail);
            return 3;
        }
    }
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
        }
        catch (Grpc.Core.RpcException ex)
        {
            PrintServiceUnavailable(ex.Status.Detail);
            return 3;
        }
    }
}

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
        }
        catch (Grpc.Core.RpcException ex)
        {
            PrintServiceUnavailable(ex.Status.Detail);
            return 3;
        }
    }
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
            var ack = await new HostsGuard.Contracts.Diagnostics.DiagnosticsClient(channel)
                .ExportSupportBundleAsync(request);
            Console.WriteLine(ack.Message);
            if (ack.Ok)
            {
                Console.WriteLine("traffic_profile.json/csv are redacted metadata only; no packet payloads are captured or exported.");
            }

            return ack.Ok ? 0 : 2;
        }
        catch (Grpc.Core.RpcException ex)
        {
            PrintServiceUnavailable(ex.Status.Detail);
            return 3;
        }
    }
}

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
            var list = await new Monitoring.MonitoringClient(channel).GetUsageRollupsAsync(request);
            Console.WriteLine($"usage: {list.Entries.Count} rows (retention {list.RetentionDays} days)");
            Console.WriteLine("day\tprocess\tdomain\tsent\treceived\ttotal");
            foreach (var e in list.Entries)
            {
                Console.WriteLine($"{e.Day}\t{e.Process}\t{e.Domain}\t{FormatBytes(e.Sent)}\t{FormatBytes(e.Recv)}\t{FormatBytes(e.Total)}");
            }

            return 0;
        }
        catch (Grpc.Core.RpcException ex)
        {
            PrintServiceUnavailable(ex.Status.Detail);
            return 3;
        }
    }
}

static async Task<int> UsageQuotaAsync(string[] args)
{
    var subcommand = args.Length > 1 ? args[1].ToLowerInvariant() : "list";
    var (channel, error) = Connect();
    if (channel is null)
    {
        PrintServiceUnavailable(error);
        return 3;
    }

    using (channel)
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
        catch (Grpc.Core.RpcException ex)
        {
            PrintServiceUnavailable(ex.Status.Detail);
            return 3;
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
    }
}

static async Task<int> UsageQuotaListAsync(Monitoring.MonitoringClient client)
{
    var list = await client.GetUsageQuotaRulesAsync(new Empty());
    Console.WriteLine($"usage quotas: {list.Rules.Count} rule{(list.Rules.Count == 1 ? string.Empty : "s")}");
    Console.WriteLine("id\tscope\tmatch\tenabled\twindow\tused\tlimit\tlast_alerted");
    foreach (var rule in list.Rules.OrderBy(r => r.Scope, StringComparer.OrdinalIgnoreCase)
                 .ThenBy(r => r.Match, StringComparer.OrdinalIgnoreCase))
    {
        Console.WriteLine($"{rule.Id}\t{rule.Scope}\t{rule.Match}\t{rule.Enabled}\t{rule.WindowDays}d\t{FormatBytes(rule.UsedBytes)}\t{FormatBytes(rule.LimitBytes)}\t{rule.LastAlertedAt}");
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

        Console.Error.WriteLine($"Unknown usage-quota set option: {arg}");
        return 1;
    }

    if (scope.Length == 0 || match.Length == 0 || limitBytes <= 0)
    {
        Console.Error.WriteLine("Usage: usage-quota set --scope app|domain --match value --limit 1GB [--days 30] [--disabled]");
        return 1;
    }

    var ack = await client.SetUsageQuotaRuleAsync(new UsageQuotaRule
    {
        Scope = scope,
        Match = match,
        LimitBytes = limitBytes,
        WindowDays = days,
        Enabled = enabled,
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
        }
        catch (Grpc.Core.RpcException ex)
        {
            PrintServiceUnavailable(ex.Status.Detail);
            return 3;
        }
    }
}

static async Task<int> DnsFlushEntryAsync(string[] args)
{
    if (args.Length < 2)
    {
        Console.Error.WriteLine("Missing cached DNS name.");
        return Usage();
    }

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
            var ack = await new DnsControl.DnsControlClient(channel)
                .FlushCacheEntryAsync(new DnsCacheEntryRequest { Name = args[1] });
            Console.WriteLine(ack.Message);
            return ack.Ok ? 0 : 2;
        }
        catch (Grpc.Core.RpcException ex)
        {
            PrintServiceUnavailable(ex.Status.Detail);
            return 3;
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
                default:
                    Console.Error.WriteLine($"Unknown blocklists command: {subcommand}");
                    return 1;
            }
        }
        catch (Grpc.Core.RpcException ex)
        {
            PrintServiceUnavailable(ex.Status.Detail);
            return 3;
        }
    }
}

static int PrintBlocklistResult(BlocklistResult result)
{
    Console.WriteLine(result.Message);
    Console.WriteLine($"  total:       {result.Total}");
    Console.WriteLine($"  added:       {result.Added}");
    Console.WriteLine($"  duplicates:  {result.Duplicates}");
    Console.WriteLine($"  invalid:     {result.Invalid}");
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
        }
        catch (Grpc.Core.RpcException ex)
        {
            PrintServiceUnavailable(ex.Status.Detail);
            return 3;
        }
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
        }
        catch (Grpc.Core.RpcException ex)
        {
            PrintServiceUnavailable(ex.Status.Detail);
            return 3;
        }
    }
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
