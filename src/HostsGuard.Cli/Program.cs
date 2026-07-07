using System.Reflection;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using HostsGuard.Contracts;
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
    "export" => await ExportAsync(args.Length > 1 ? args[1] : "hostsguard_export.json"),
    "export-policy" => await ExportPolicyAsync(args.Length > 1 ? args[1] : "hostsguard_policy.json"),
    "import-policy" => await ImportPolicyAsync(args),
    "events" => await EventsAsync(args),
    "mode" => await ModeAsync(args.Length > 1 ? args[1] : null),
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
          HostsGuard.Cli export [path.json]
          HostsGuard.Cli export-policy [path.json]
          HostsGuard.Cli import-policy <path.json>
          HostsGuard.Cli events [--limit N] [--offset N] [--search text] [--since ISO] [--until ISO]
                               [--action name] [--reason name] [--domain text] [--process text]
                               [--category name] [--export path.csv]
          HostsGuard.Cli mode [normal|notify|learning]
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
        Console.Error.WriteLine("Missing policy file. Usage: import-policy <path.json>");
        return Usage();
    }

    var path = args[1];
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
            var result = await new Policy.PolicyClient(channel).ImportPolicyAsync(new ImportPolicyRequest { Json = json });
            Console.WriteLine(result.Message);
            foreach (var line in result.Summary)
            {
                Console.WriteLine($"  {line}");
            }

            return result.Ok ? 0 : 2;
        }
        catch (Grpc.Core.RpcException ex)
        {
            PrintServiceUnavailable(ex.Status.Detail);
            return 3;
        }
    }
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

static string BuildEventsCsv(IEnumerable<EventLogEntry> rows)
{
    var sb = new System.Text.StringBuilder();
    sb.Append("When,Category,Action,Reason,Domain,Process,Details\r\n");
    foreach (var e in rows)
    {
        sb.Append(Csv(e.Ts)).Append(',')
          .Append(Csv(e.Category)).Append(',')
          .Append(Csv(e.Action)).Append(',')
          .Append(Csv(e.Reason)).Append(',')
          .Append(Csv(e.Domain)).Append(',')
          .Append(Csv(e.Process)).Append(',')
          .Append(Csv(e.Details)).Append("\r\n");
    }

    return sb.ToString();

    static string Csv(string? value)
    {
        value ??= string.Empty;
        return value.IndexOfAny(new[] { ',', '"', '\n', '\r' }) >= 0
            ? "\"" + value.Replace("\"", "\"\"", StringComparison.Ordinal) + "\""
            : value;
    }
}

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
