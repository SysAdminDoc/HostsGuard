using System.Runtime.Versioning;
using FluentAssertions;
using Grpc.Core;
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
