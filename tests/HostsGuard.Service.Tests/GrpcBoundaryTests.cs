using System.Runtime.Versioning;
using FluentAssertions;
using Grpc.Core;
using HostsGuard.Contracts;
using HostsGuard.Core;
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
        _state = new ServiceState(
            new HostsEngine(hostsPath),
            new HostsDatabase(Path.Combine(_dir, "hostsguard.db")),
            dataDir: _dir,
            listFetcher: new FakeListFetcher());
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

        // ListControl gets a narrow exception for local blocklists. Every other
        // service remains at gRPC's 4 MiB default.
        var huge = new string('a', (4 * 1024 * 1024) + 1);
        var act = async () => await hosts.SetHostsTextAsync(new HostsText { Text = huge });

        (await act.Should().ThrowAsync<RpcException>()).Which.StatusCode
            .Should().Be(StatusCode.ResourceExhausted);
        (await hosts.GetHostsTextAsync(new Empty())).Text.Should().Be(before);
    }

    [Fact]
    public async Task Local_blocklist_transport_honors_the_exact_application_cap()
    {
        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var lists = new ListControl.ListControlClient(channel);

        foreach (var size in new[] { (4 * 1024 * 1024) + 1, BlocklistCatalog.MaxBlocklistBytes })
        {
            var response = await lists.PreviewBlocklistContentAsync(
                new BlocklistContentRequest
                {
                    Name = $"boundary-{size}",
                    Content = CommentPayload(size),
                },
                deadline: DateTime.UtcNow.AddSeconds(60));

            response.Ok.Should().BeTrue($"{size:N0} content bytes are inside the documented limit");
            response.ErrorCode.Should().BeEmpty();
        }
    }

    [Fact]
    public async Task Local_blocklist_rejects_one_byte_over_the_application_cap_in_the_handler()
    {
        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var lists = new ListControl.ListControlClient(channel);

        var response = await lists.PreviewBlocklistContentAsync(
            new BlocklistContentRequest
            {
                Name = "one-byte-over",
                Content = CommentPayload(BlocklistCatalog.MaxBlocklistBytes + 1),
            },
            deadline: DateTime.UtcNow.AddSeconds(60));

        response.Ok.Should().BeFalse();
        response.ErrorCode.Should().Be("hostsguard.error.v1/content_too_large");
        response.Message.Should().Contain("exceeds");
    }

    private static Google.Protobuf.ByteString CommentPayload(int size)
    {
        var payload = new byte[size];
        payload.AsSpan().Fill((byte)'x');
        payload[0] = (byte)'#';
        return Google.Protobuf.UnsafeByteOperations.UnsafeWrap(payload);
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
