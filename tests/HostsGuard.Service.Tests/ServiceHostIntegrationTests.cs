using System.Runtime.Versioning;
using FluentAssertions;
using Grpc.Core;
using HostsGuard.Contracts;
using HostsGuard.Data;
using HostsGuard.Ipc;
using HostsGuard.Service;
using HostsGuard.Windows;
using Microsoft.AspNetCore.Builder;
using Microsoft.Data.Sqlite;
using Xunit;

namespace HostsGuard.Service.Tests;

/// <summary>
/// Exercises the real production hosting graph: the service impls wired to a live
/// HostsEngine + HostsDatabase, served over the ACL'd named-pipe gRPC transport,
/// driven by a real client. This is the NET-010 "a UI can query GetStatus" +
/// end-to-end Block round-trip proof, sans the SCM install/reboot (which needs
/// elevation and is out of scope for a unit run).
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class ServiceHostIntegrationTests : IAsyncLifetime
{
    private string _dir = null!;
    private WebApplication _app = null!;
    private ServiceState _state = null!;
    private string _pipe = null!;
    private string _token = null!;

    public async Task InitializeAsync()
    {
        _dir = Path.Combine(Path.GetTempPath(), "hg_svc_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        var hostsPath = Path.Combine(_dir, "hosts");
        File.WriteAllText(hostsPath, "# hosts\n127.0.0.1 keepserver\n");

        _state = new ServiceState(new HostsEngine(hostsPath), new HostsDatabase(Path.Combine(_dir, "hostsguard.db")));
        _token = SessionToken.Generate();
        _pipe = "HostsGuard.SvcTest." + Guid.NewGuid().ToString("N");
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
    public async Task GetStatus_reports_engine_state()
    {
        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var diag = new HostsGuard.Contracts.Diagnostics.DiagnosticsClient(channel);

        var status = await diag.GetStatusAsync(new Empty());

        status.Version.Should().NotBeNullOrEmpty();
        status.HostsBlocked.Should().Be(0);
    }

    [Fact]
    public async Task Block_round_trips_through_engine_db_and_status()
    {
        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var hosts = new HostsControl.HostsControlClient(channel);
        var diag = new HostsGuard.Contracts.Diagnostics.DiagnosticsClient(channel);

        var ack = await hosts.BlockAsync(new DomainRequest { Domain = "ads.example.com", Source = "manual" });
        ack.Ok.Should().BeTrue();

        // Hosts file now contains the block; status + DB reflect it.
        _state.Hosts.GetBlocked().Should().Contain("ads.example.com");
        (await diag.GetStatusAsync(new Empty())).HostsBlocked.Should().Be(1);

        var list = await hosts.ListDomainsAsync(new ListDomainsRequest { Status = "blocked" });
        list.Domains.Should().Contain(d => d.Domain == "ads.example.com" && d.Reason == "manual");

        // Custom non-managed line preserved by the engine.
        _state.Hosts.GetLines().Should().Contain(l => l.Contains("keepserver"));
    }

    [Fact]
    public async Task Invalid_domain_returns_typed_error()
    {
        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var hosts = new HostsControl.HostsControlClient(channel);

        var ack = await hosts.BlockAsync(new DomainRequest { Domain = "not a domain" });

        ack.Ok.Should().BeFalse();
        ack.ErrorCode.Should().Be("hostsguard.error.v1/invalid_domain");
    }

    [Fact]
    public async Task Unauthorized_client_is_rejected()
    {
        using var channel = NamedPipeChannel.Create(SessionToken.Generate(), _pipe);
        var diag = new HostsGuard.Contracts.Diagnostics.DiagnosticsClient(channel);

        var act = async () => await diag.GetStatusAsync(new Empty());

        (await act.Should().ThrowAsync<RpcException>()).Which.StatusCode.Should().Be(StatusCode.Unauthenticated);
    }
}
