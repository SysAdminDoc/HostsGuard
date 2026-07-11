using System.Runtime.Versioning;
using FluentAssertions;
using Grpc.Core;
using Grpc.Core.Interceptors;
using HostsGuard.Contracts;
using HostsGuard.Ipc;
using Microsoft.AspNetCore.Builder;
using Xunit;

namespace HostsGuard.Ipc.Tests;

/// <summary>Minimal Diagnostics implementation for the transport round-trip test.</summary>
file sealed class FakeDiagnostics : Diagnostics.DiagnosticsBase
{
    public override Task<ServiceStatus> GetStatus(Empty request, ServerCallContext context) =>
        Task.FromResult(new ServiceStatus { Version = "test-1.0", Elevated = true, HostsBlocked = 7 });
}

[SupportedOSPlatform("windows")]
public class NamedPipeRoundTripTests : IAsyncLifetime
{
    private WebApplication _app = null!;
    private string _pipe = null!;
    private string _token = null!;

    public async Task InitializeAsync()
    {
        _token = SessionToken.Generate();
        _pipe = "HostsGuard.Test." + Guid.NewGuid().ToString("N");
        _app = NamedPipeServer.Build(_token, app => app.MapGrpcService<FakeDiagnostics>(), _pipe);
        await _app.StartAsync();
    }

    public async Task DisposeAsync() => await _app.DisposeAsync();

    [Fact]
    public async Task Round_trip_succeeds_with_correct_token()
    {
        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var client = new Diagnostics.DiagnosticsClient(channel);

        var status = await client.GetStatusAsync(new Empty());

        status.Version.Should().Be("test-1.0");
        status.Elevated.Should().BeTrue();
        status.HostsBlocked.Should().Be(7);
    }

    [Fact]
    public async Task Wrong_token_is_rejected_unauthenticated()
    {
        using var channel = NamedPipeChannel.Create(SessionToken.Generate(), _pipe);
        var client = new Diagnostics.DiagnosticsClient(channel);

        var act = async () => await client.GetStatusAsync(new Empty());

        (await act.Should().ThrowAsync<RpcException>()).Which.StatusCode.Should().Be(StatusCode.Unauthenticated);
    }
}

/// <summary>
/// NET-180: a client call and its server-side handling share one W3C TraceId
/// across the pipe, so a GUI action can be followed into the service's log.
/// </summary>
[SupportedOSPlatform("windows")]
public class RpcCorrelationTests : IAsyncLifetime
{
    private WebApplication _app = null!;
    private string _pipe = null!;
    private string _token = null!;
    private readonly List<(string Method, string TraceId)> _serverCalls = new();

    public async Task InitializeAsync()
    {
        _token = SessionToken.Generate();
        _pipe = "HostsGuard.Test." + Guid.NewGuid().ToString("N");
        _app = NamedPipeServer.Build(
            _token,
            app => app.MapGrpcService<FakeDiagnostics>(),
            _pipe,
            rpcLog: (method, traceId) =>
            {
                lock (_serverCalls)
                {
                    _serverCalls.Add((method, traceId));
                }
            });
        await _app.StartAsync();
    }

    public async Task DisposeAsync() => await _app.DisposeAsync();

    [Fact]
    public async Task Client_and_server_share_the_call_trace_id()
    {
        var clientCalls = new List<(string Method, string TraceId)>();
        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var invoker = channel.Intercept(new ClientCorrelationInterceptor((m, t) => clientCalls.Add((m, t))));
        var client = new Diagnostics.DiagnosticsClient(invoker);

        var status = await client.GetStatusAsync(new Empty());

        status.Version.Should().Be("test-1.0");
        clientCalls.Should().ContainSingle();
        clientCalls[0].TraceId.Should().NotBeNullOrEmpty()
            .And.NotBe(new string('0', 32), "an all-zero trace id is the unset sentinel");
        lock (_serverCalls)
        {
            _serverCalls.Should().ContainSingle(c => c.TraceId == clientCalls[0].TraceId,
                "the server must adopt the traceparent header the client sent");
        }
    }

    [Fact]
    public async Task Uncorrelated_clients_still_get_a_server_trace_id()
    {
        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var client = new Diagnostics.DiagnosticsClient(channel); // no client interceptor

        await client.GetStatusAsync(new Empty());

        lock (_serverCalls)
        {
            _serverCalls.Should().NotBeEmpty();
            _serverCalls[^1].TraceId.Should().NotBeNullOrEmpty();
        }
    }
}
