using System.Runtime.Versioning;
using FluentAssertions;
using Grpc.Core;
using HostsGuard.Contracts;
using HostsGuard.Data;
using HostsGuard.Ipc;
using HostsGuard.Windows;
using Microsoft.AspNetCore.Builder;
using Microsoft.Data.Sqlite;
using Xunit;

namespace HostsGuard.Service.Tests;

/// <summary>
/// NET-061 gRPC message-boundary fuzz: oversize payloads are refused at the
/// transport or the application cap (never applied), malformed domain bytes get
/// typed errors, and the service keeps answering afterwards — a bad client
/// can't wedge the pipe.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class GrpcBoundaryTests : IAsyncLifetime
{
    private string _dir = null!;
    private WebApplication _app = null!;
    private ServiceState _state = null!;
    private string _pipe = null!;
    private string _token = null!;

    public async Task InitializeAsync()
    {
        _dir = Path.Combine(Path.GetTempPath(), "hg_boundary_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        var hostsPath = Path.Combine(_dir, "hosts");
        File.WriteAllText(hostsPath, "# hosts\n");
        _state = new ServiceState(new HostsEngine(hostsPath), new HostsDatabase(Path.Combine(_dir, "hostsguard.db")));
        _token = SessionToken.Generate();
        _pipe = "HostsGuard.BoundaryTest." + Guid.NewGuid().ToString("N");
        _app = ServiceHost.Build(_state, _token, _pipe);
        await _app.StartAsync();
    }

    public async Task DisposeAsync()
    {
        await _app.DisposeAsync();
        _state.Dispose();
        SqliteConnection.ClearAllPools();
        try { Directory.Delete(_dir, true); } catch (IOException) { /* best effort */ }
    }

    [Fact]
    public async Task Oversize_hosts_payload_is_refused_and_never_written()
    {
        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var hosts = new HostsControl.HostsControlClient(channel);
        var before = (await hosts.GetHostsTextAsync(new Empty())).Text;

        // 6 MB exceeds the gRPC receive limit (4 MB default) and approaches the
        // app-level 10 MB cap — either layer may refuse, but the payload must
        // never land in the hosts file.
        var huge = new string('a', 6 * 1024 * 1024);
        var refused = false;
        try
        {
            var ack = await hosts.SetHostsTextAsync(new HostsText { Text = huge });
            refused = !ack.Ok && ack.ErrorCode.StartsWith("hostsguard.error.v1/", StringComparison.Ordinal);
        }
        catch (RpcException ex)
        {
            refused = ex.StatusCode is StatusCode.ResourceExhausted or StatusCode.InvalidArgument or StatusCode.Internal;
        }

        refused.Should().BeTrue("an oversize payload must be refused with a typed failure");
        (await hosts.GetHostsTextAsync(new Empty())).Text.Should().Be(before);
    }

    [Fact]
    public async Task Malformed_domain_bytes_get_typed_errors_and_the_pipe_survives()
    {
        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var hosts = new HostsControl.HostsControlClient(channel);

        var rng = new Random(4010);
        var nasty = new[]
        {
            "bad\0null.example.com",
            "line\nbreak.example.com",
            new string('x', 5000) + ".example.com",
            "‮rtl.example.com",
            "..", ".", " ", "\t",
            "a b c.example.com",
        };
        foreach (var domain in nasty)
        {
            var ack = await hosts.BlockAsync(new DomainRequest { Domain = domain });
            ack.Ok.Should().BeFalse($"'{domain.Replace('\0', '?')}' must not be accepted");
            ack.ErrorCode.Should().Be("hostsguard.error.v1/invalid_domain");
        }

        for (var i = 0; i < 100; i++)
        {
            var junk = new string(Enumerable.Range(0, rng.Next(1, 40))
                .Select(_ => (char)rng.Next(33, 300)).ToArray());
            var ack = await hosts.BlockAsync(new DomainRequest { Domain = junk });
            // Total: junk either validates as a domain or fails typed — never faults.
            if (!ack.Ok)
            {
                ack.ErrorCode.Should().StartWith("hostsguard.error.v1/");
            }
        }

        // The pipe is still healthy after the abuse.
        (await hosts.BlockAsync(new DomainRequest { Domain = "post-fuzz.example.com" })).Ok.Should().BeTrue();
    }
}
