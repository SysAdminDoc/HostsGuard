using System.Diagnostics;
using FluentAssertions;
using Grpc.Core;
using Grpc.Net.Client;
using HostsGuard.Cli;

[assembly: CollectionBehavior(DisableTestParallelization = true)]

namespace HostsGuard.Cli.Tests;

public sealed class CliCommandContractTests
{
    [Fact]
    public async Task Every_canonical_verb_and_alias_routes_through_the_command_table()
    {
        var invoked = string.Empty;
        var handlers = Handlers(name =>
        {
            invoked = name;
            return (int)CliExitCode.Success;
        });

        foreach (var contract in CliCommandCatalog.Commands)
        {
            (await CliCommandRouter.RunAsync([contract.Name], handlers, Usage, Help)).Should().Be(0);
            invoked.Should().Be(contract.Name);

            foreach (var alias in contract.Aliases)
            {
                invoked = string.Empty;
                (await CliCommandRouter.RunAsync([alias], handlers, Usage, Help)).Should().Be(0);
                invoked.Should().Be(contract.Name);
            }
        }
    }

    [Fact]
    public async Task Help_is_success_while_empty_and_unknown_forms_are_usage_errors()
    {
        var handlers = Handlers(_ => 0);
        foreach (var alias in CliCommandCatalog.HelpAliases)
        {
            (await CliCommandRouter.RunAsync([alias], handlers, Usage, Help)).Should().Be((int)CliExitCode.Success);
        }

        (await CliCommandRouter.RunAsync([], handlers, Usage, Help)).Should().Be((int)CliExitCode.Usage);
        (await CliCommandRouter.RunAsync(["not-a-command"], handlers, Usage, Help)).Should().Be((int)CliExitCode.Usage);
    }

    [Theory]
    [InlineData(CliExitCode.Success)]
    [InlineData(CliExitCode.Usage)]
    [InlineData(CliExitCode.CommandRejected)]
    [InlineData(CliExitCode.ServiceUnavailable)]
    internal async Task Handler_exit_code_classes_are_preserved(CliExitCode expected)
    {
        var handlers = Handlers(name => name == "status" ? (int)expected : 0);

        (await CliCommandRouter.RunAsync(["status"], handlers, Usage, Help)).Should().Be((int)expected);
    }

    [Fact]
    public async Task Missing_or_extra_handlers_fail_before_dispatch()
    {
        var handlers = Handlers(_ => 0);
        handlers.Remove("status");
        handlers["invented"] = _ => Task.FromResult(0);

        var act = () => CliCommandRouter.RunAsync(["help"], handlers, Usage, Help);

        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*missing=[status]*extra=[invented]*");
    }

    [Fact]
    public async Task Built_cli_help_and_invalid_command_keep_the_public_exit_contract()
    {
        var help = await RunCliAsync("--help");
        help.ExitCode.Should().Be((int)CliExitCode.Success);
        help.Output.Should().Contain("HostsGuard CLI").And.Contain("HostsGuard.Cli release-smoke");
        help.Error.Should().BeEmpty();

        var invalid = await RunCliAsync("not-a-command");
        invalid.ExitCode.Should().Be((int)CliExitCode.Usage);
        invalid.Output.Should().Be(help.Output);
        invalid.Error.Should().BeEmpty();
    }

    private static Dictionary<string, Func<string[], Task<int>>> Handlers(Func<string, int> result)
        => CliCommandCatalog.Commands.ToDictionary(
            command => command.Name,
            command => new Func<string[], Task<int>>(_ => Task.FromResult(result(command.Name))),
            StringComparer.OrdinalIgnoreCase);

    private static int Usage() => (int)CliExitCode.Usage;

    private static int Help() => (int)CliExitCode.Success;

    private static async Task<(int ExitCode, string Output, string Error)> RunCliAsync(string argument)
    {
        var assembly = typeof(CliCommandCatalog).Assembly.Location;
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = "dotnet",
                Arguments = $"\"{assembly}\" {argument}",
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                WindowStyle = ProcessWindowStyle.Hidden,
            },
        };
        process.Start().Should().BeTrue();
        var output = process.StandardOutput.ReadToEndAsync();
        var error = process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(30));
        return (process.ExitCode, await output, await error);
    }
}

public sealed class CliRpcRunnerTests
{
    [Fact]
    public async Task Missing_pipe_fails_with_the_stable_service_unavailable_contract()
    {
        using var error = new StringWriter();
        var bodyCalled = false;
        var runner = new CliRpcRunner(() => (null, "handshake missing"), error);

        var code = await runner.RunAsync(_ =>
        {
            bodyCalled = true;
            return Task.FromResult(0);
        });

        code.Should().Be((int)CliExitCode.ServiceUnavailable);
        bodyCalled.Should().BeFalse();
        error.ToString().Should().Contain("Couldn't reach HostsGuardSvc").And.Contain("handshake missing");
    }

    [Theory]
    [InlineData(StatusCode.Unauthenticated, CliExitCode.ServiceUnavailable, "Couldn't reach HostsGuardSvc")]
    [InlineData(StatusCode.Unimplemented, CliExitCode.CommandRejected, "older than this CLI")]
    [InlineData(StatusCode.InvalidArgument, CliExitCode.CommandRejected, "rejected the command")]
    internal async Task Rpc_statuses_map_without_a_live_service(
        StatusCode status,
        CliExitCode expected,
        string expectedError)
    {
        using var error = new StringWriter();
        var runner = new CliRpcRunner(Channel, error);

        var code = await runner.RunAsync(_ =>
            throw new RpcException(new Status(status, "contract fixture")));

        code.Should().Be((int)expected);
        error.ToString().Should().Contain(expectedError);
    }

    private static (GrpcChannel Channel, string Error) Channel()
        => (GrpcChannel.ForAddress("http://localhost"), string.Empty);
}

public sealed class CliPolicyCommandTests
{
    [Fact]
    public void Read_failure_is_a_usage_error_with_the_path_and_no_output()
    {
        var files = new FakeFileSystem { ReadError = new IOException("disk unavailable") };
        using var output = new StringWriter();
        using var error = new StringWriter();

        var code = CliPolicyCommands.Validate(["validate-policy", "broken.json"], files, output, error);

        code.Should().Be((int)CliExitCode.Usage);
        output.ToString().Should().BeEmpty();
        error.ToString().Should().Contain("broken.json").And.Contain("disk unavailable");
    }

    [Fact]
    public void Schema_write_failure_is_rejected_without_claiming_success()
    {
        var files = new FakeFileSystem { WriteError = new UnauthorizedAccessException("read-only") };
        using var output = new StringWriter();
        using var error = new StringWriter();

        var code = CliPolicyCommands.Validate(["validate-policy", "--emit-schema", "schema.json"], files, output, error);

        code.Should().Be((int)CliExitCode.CommandRejected);
        output.ToString().Should().BeEmpty();
        error.ToString().Should().Contain("schema.json").And.Contain("read-only");
    }

    [Fact]
    public void Schema_emission_uses_the_injected_filesystem_and_console()
    {
        var files = new FakeFileSystem();
        using var output = new StringWriter();
        using var error = new StringWriter();

        var code = CliPolicyCommands.Validate(["validate-policy", "--emit-schema", "schema.json"], files, output, error);

        code.Should().Be((int)CliExitCode.Success);
        files.Files["schema.json"].Should().Contain("\"Version\"").And.Contain("\"Domains\"");
        output.ToString().Should().Contain(@"C:\fixture\schema.json");
        error.ToString().Should().BeEmpty();
    }

    private sealed class FakeFileSystem : ICliFileSystem
    {
        public Dictionary<string, string> Files { get; } = new(StringComparer.Ordinal);

        public Exception? ReadError { get; init; }

        public Exception? WriteError { get; init; }

        public string ReadAllText(string path)
        {
            if (ReadError is not null) throw ReadError;
            return Files[path];
        }

        public void WriteAllText(string path, string contents)
        {
            if (WriteError is not null) throw WriteError;
            Files[path] = contents;
        }

        public string GetFullPath(string path) => @"C:\fixture\" + path;
    }
}

public sealed class CliRequestFactoryTests
{
    [Fact]
    public void Domain_program_and_package_requests_preserve_cli_mapping()
    {
        var domain = CliRequestFactory.Domain(["block", "ads.example", "tracking"]);
        domain.Domain.Should().Be("ads.example");
        domain.Reason.Should().Be("tracking");
        domain.Source.Should().Be("cli");

        var program = CliRequestFactory.Program(@"C:\Apps\Browser.exe", "In");
        program.ProgramPath.Should().Be(@"C:\Apps\Browser.exe");
        program.Direction.Should().Be("In");
        CliRequestFactory.ProgramRuleName(program.ProgramPath, program.Direction)
            .Should().Be("HG_BlockApp_Browser_In");

        var pfn = CliRequestFactory.Package("Contoso.App_123", "Block", "Out");
        pfn.PackageFamilyName.Should().Be("Contoso.App_123");
        pfn.PackageSid.Should().BeEmpty();
        pfn.Name.Should().StartWith("HG_Package_Block_").And.EndWith("_Out");

        var sid = CliRequestFactory.Package("S-1-15-2-123", "Allow", "In");
        sid.PackageSid.Should().Be("S-1-15-2-123");
        sid.PackageFamilyName.Should().BeEmpty();
        sid.Action.Should().Be("Allow");
    }

    [Fact]
    public async Task Runtime_clock_is_replaceable_for_retry_contracts()
    {
        var original = CliRuntime.Clock;
        var clock = new FakeClock(new DateTime(2026, 7, 14, 12, 0, 0, DateTimeKind.Utc));
        try
        {
            CliRuntime.Clock = clock;
            await CliRuntime.Clock.Delay(TimeSpan.FromMilliseconds(250));

            CliRuntime.Clock.UtcNow.Should().Be(new DateTime(2026, 7, 14, 12, 0, 0, 250, DateTimeKind.Utc));
        }
        finally
        {
            CliRuntime.Clock = original;
        }
    }

    private sealed class FakeClock(DateTime utcNow) : ICliClock
    {
        public DateTime UtcNow { get; private set; } = utcNow;

        public Task Delay(TimeSpan duration)
        {
            UtcNow += duration;
            return Task.CompletedTask;
        }
    }
}
