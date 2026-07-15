using Grpc.Core;
using Grpc.Net.Client;
using HostsGuard.Contracts;

namespace HostsGuard.Cli;

internal enum CliExitCode
{
    Success = 0,
    Usage = 1,
    CommandRejected = 2,
    ServiceUnavailable = 3,
}

internal sealed record CliCommandContract(string Name, params string[] Aliases);

internal static class CliCommandCatalog
{
    public static IReadOnlyList<CliCommandContract> Commands { get; } =
    [
        new("status"),
        new("block"),
        new("allow"),
        new("unblock"),
        new("temp-block"),
        new("block-app"),
        new("unblock-app"),
        new("firewall-packages", "packages"),
        new("firewall-analyze"),
        new("firewall-cleanup"),
        new("firewall-rule"),
        new("block-package"),
        new("allow-package"),
        new("unblock-package"),
        new("explain"),
        new("export"),
        new("export-policy"),
        new("import-policy"),
        new("validate-policy"),
        new("events"),
        new("listeners"),
        new("traffic-profile"),
        new("support-bundle"),
        new("snapshot"),
        new("usage"),
        new("usage-quota"),
        new("history-privacy"),
        new("dns-cache"),
        new("dns-inspect"),
        new("resolver-health"),
        new("encrypted-resolver"),
        new("profile-match"),
        new("captive-portal"),
        new("dns-flush-entry"),
        new("dga-check"),
        new("idn-homograph"),
        new("proxy"),
        new("adopt-hosts"),
        new("blocklists"),
        new("ip-blocklists"),
        new("mode"),
        new("secure-rules"),
        new("update"),
        new("safe-posture"),
        new("safe-posture-smoke"),
        new("release-smoke"),
        new("uninstall-cleanup"),
        new("purge-local-data"),
        new("version", "--version"),
    ];

    public static IReadOnlySet<string> HelpAliases { get; } =
        new HashSet<string>(["help", "--help", "-h", "-?", "/?"], StringComparer.OrdinalIgnoreCase);

    public static string? Resolve(string verb)
    {
        verb = verb.Trim();
        foreach (var command in Commands)
        {
            if (command.Name.Equals(verb, StringComparison.OrdinalIgnoreCase) ||
                command.Aliases.Any(alias => alias.Equals(verb, StringComparison.OrdinalIgnoreCase)))
            {
                return command.Name;
            }
        }

        return null;
    }
}

internal static class CliCommandRouter
{
    public static async Task<int> RunAsync(
        string[] args,
        IReadOnlyDictionary<string, Func<string[], Task<int>>> handlers,
        Func<int> usage,
        Func<int> help)
    {
        ArgumentNullException.ThrowIfNull(args);
        ArgumentNullException.ThrowIfNull(handlers);
        ArgumentNullException.ThrowIfNull(usage);
        ArgumentNullException.ThrowIfNull(help);

        ValidateHandlers(handlers);
        if (args.Length == 0)
        {
            return usage();
        }

        if (CliCommandCatalog.HelpAliases.Contains(args[0]))
        {
            return help();
        }

        var command = CliCommandCatalog.Resolve(args[0]);
        return command is null ? usage() : await handlers[command](args);
    }

    private static void ValidateHandlers(IReadOnlyDictionary<string, Func<string[], Task<int>>> handlers)
    {
        var expected = CliCommandCatalog.Commands.Select(command => command.Name)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var actual = handlers.Keys.ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (!expected.SetEquals(actual))
        {
            var missing = string.Join(", ", expected.Except(actual).Order(StringComparer.Ordinal));
            var extra = string.Join(", ", actual.Except(expected).Order(StringComparer.Ordinal));
            throw new InvalidOperationException($"CLI handler table mismatch; missing=[{missing}] extra=[{extra}]");
        }
    }
}

internal delegate (GrpcChannel? Channel, string Error) CliChannelFactory();

internal sealed class CliRpcRunner(CliChannelFactory channelFactory, TextWriter error)
{
    public async Task<int> RunAsync(Func<GrpcChannel, Task<int>> body)
    {
        ArgumentNullException.ThrowIfNull(body);
        var (channel, detail) = channelFactory();
        if (channel is null)
        {
            WriteServiceUnavailable(error, detail);
            return (int)CliExitCode.ServiceUnavailable;
        }

        using (channel)
        {
            try
            {
                return await body(channel);
            }
            catch (RpcException ex)
            {
                return WriteRpcFailure(error, ex);
            }
        }
    }

    public static void WriteServiceUnavailable(TextWriter error, string detail)
        => error.WriteLine(
            $"Couldn't reach HostsGuardSvc. Start or restart the service, then retry. Details: {detail}");

    public static int WriteRpcFailure(TextWriter error, RpcException ex)
    {
        if (ex.StatusCode is StatusCode.Unavailable or StatusCode.DeadlineExceeded
            or StatusCode.Cancelled or StatusCode.Unauthenticated)
        {
            WriteServiceUnavailable(error, ex.Status.Detail);
            return (int)CliExitCode.ServiceUnavailable;
        }

        if (ex.StatusCode is StatusCode.Unimplemented)
        {
            error.WriteLine("HostsGuardSvc is older than this CLI and does not support this command. "
                + "Install the matching HostsGuard service or restart HostsGuardSvc after updating, then retry.");
            return (int)CliExitCode.CommandRejected;
        }

        var detail = ex.Status.Detail;
        error.WriteLine(detail.Length != 0 && detail != "Exception was thrown by handler."
            ? $"HostsGuardSvc rejected the command ({ex.StatusCode}): {detail}"
            : $"HostsGuardSvc hit an internal error while handling this command ({ex.StatusCode}). "
              + "The service is still running; export a support bundle for details.");
        return (int)CliExitCode.CommandRejected;
    }
}

internal interface ICliFileSystem
{
    string ReadAllText(string path);

    void WriteAllText(string path, string contents);

    string GetFullPath(string path);
}

internal sealed class SystemCliFileSystem : ICliFileSystem
{
    public static readonly SystemCliFileSystem Instance = new();

    private SystemCliFileSystem()
    {
    }

    public string ReadAllText(string path) => File.ReadAllText(path);

    public void WriteAllText(string path, string contents) => File.WriteAllText(path, contents);

    public string GetFullPath(string path) => Path.GetFullPath(path);
}

internal static class CliPolicyCommands
{
    public static int Validate(
        string[] args,
        ICliFileSystem fileSystem,
        TextWriter output,
        TextWriter error)
    {
        if (args.Length > 1 && args[1] == "--emit-schema")
        {
            var schema = HostsGuard.Diagnostics.PortablePolicySchema.SchemaJson();
            var outPath = args.Length > 2 ? args[2] : null;
            if (outPath is null)
            {
                output.WriteLine(schema);
                return (int)CliExitCode.Success;
            }

            try
            {
                fileSystem.WriteAllText(outPath, schema);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
            {
                error.WriteLine($"Couldn't write '{outPath}': {ex.Message}");
                return (int)CliExitCode.CommandRejected;
            }

            output.WriteLine($"wrote policy schema to {fileSystem.GetFullPath(outPath)}");
            return (int)CliExitCode.Success;
        }

        if (args.Length < 2)
        {
            error.WriteLine("Usage: validate-policy <path> | validate-policy --emit-schema [path]");
            return (int)CliExitCode.Usage;
        }

        string json;
        try
        {
            json = fileSystem.ReadAllText(args[1]);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            error.WriteLine($"could not read '{args[1]}': {ex.Message}");
            return (int)CliExitCode.Usage;
        }

        var errors = HostsGuard.Diagnostics.PortablePolicySchema.Validate(json);
        if (errors.Count == 0)
        {
            output.WriteLine("policy document is valid");
            return (int)CliExitCode.Success;
        }

        error.WriteLine($"{errors.Count} validation error(s):");
        foreach (var validationError in errors)
        {
            var where = validationError.Pointer.Length == 0 ? "(root)" : validationError.Pointer;
            error.WriteLine($"  {where}: {validationError.Message}");
        }

        return (int)CliExitCode.CommandRejected;
    }
}

internal static class CliRequestFactory
{
    public static DomainRequest Domain(string[] args) => new()
    {
        Domain = args[1],
        Reason = args.Length > 2 ? args[2] : string.Empty,
        Source = "cli",
    };

    public static FirewallProgramRequest Program(string path, string direction) => new()
    {
        ProgramPath = path,
        Direction = direction,
    };

    public static string ProgramRuleName(string path, string direction)
        => $"HG_BlockApp_{Path.GetFileNameWithoutExtension(path)}_{direction}";

    public static FirewallRule Package(string package, string action, string direction)
    {
        var rule = new FirewallRule
        {
            Name = $"HG_Package_{action}_{HostsGuard.Core.FwRuleMapper.RuleToken(package)}_{direction}",
            Direction = direction,
            Action = action,
            Enabled = true,
            RemoteAddr = "Any",
            Protocol = "Any",
        };
        if (package.Trim().StartsWith("S-1-", StringComparison.OrdinalIgnoreCase))
        {
            rule.PackageSid = package;
        }
        else
        {
            rule.PackageFamilyName = package;
        }

        return rule;
    }
}

internal interface ICliClock
{
    DateTime UtcNow { get; }

    Task Delay(TimeSpan duration);
}

internal sealed class SystemCliClock : ICliClock
{
    public static readonly SystemCliClock Instance = new();

    private SystemCliClock()
    {
    }

    public DateTime UtcNow => DateTime.UtcNow;

    public Task Delay(TimeSpan duration) => Task.Delay(duration);
}

internal static class CliRuntime
{
    public static ICliClock Clock { get; set; } = SystemCliClock.Instance;
}
