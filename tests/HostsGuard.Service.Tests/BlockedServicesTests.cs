using System.Runtime.Versioning;
using FluentAssertions;
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
/// NET-032: one-click service toggles + the Windows telemetry preset with
/// self-owned revert and manual-whitelist precedence.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class BlockedServicesTests : IAsyncLifetime
{
    private string _dir = null!;
    private WebApplication _app = null!;
    private ServiceState _state = null!;
    private string _pipe = null!;
    private string _token = null!;

    public async Task InitializeAsync()
    {
        _dir = Path.Combine(Path.GetTempPath(), "hg_svcs_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        var hostsPath = Path.Combine(_dir, "hosts");
        File.WriteAllText(hostsPath, "# hosts\n");

        _state = new ServiceState(new HostsEngine(hostsPath), new HostsDatabase(Path.Combine(_dir, "hostsguard.db")), dataDir: _dir);
        _token = SessionToken.Generate();
        _pipe = "HostsGuard.SvcsTest." + Guid.NewGuid().ToString("N");
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

    private Policy.PolicyClient Client(Grpc.Net.Client.GrpcChannel ch) => new(ch);

    [Fact]
    public async Task Toggle_blocks_and_unblocks_the_service_set()
    {
        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var policy = Client(channel);

        var on = await policy.ToggleServiceAsync(new ServiceToggleRequest { Service = "YouTube", Block = true });
        on.Ok.Should().BeTrue();
        _state.Hosts.GetBlocked().Should().Contain("youtube.com").And.Contain("googlevideo.com");

        var states = await policy.ListServicesAsync(new Empty());
        states.Services.Should().Contain(s => s.Name == "YouTube" && s.Blocked);

        var off = await policy.ToggleServiceAsync(new ServiceToggleRequest { Service = "YouTube", Block = false });
        off.Ok.Should().BeTrue();
        _state.Hosts.GetBlocked().Should().NotContain("youtube.com");
        (await policy.ListServicesAsync(new Empty())).Services.Should().Contain(s => s.Name == "YouTube" && !s.Blocked);
    }

    [Fact]
    public async Task Unblock_only_reverts_rows_the_toggle_created()
    {
        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var policy = Client(channel);
        var hosts = new HostsControl.HostsControlClient(channel);

        // youtube.com was blocked manually BEFORE the toggle.
        await hosts.BlockAsync(new DomainRequest { Domain = "youtube.com", Source = "manual" });
        await policy.ToggleServiceAsync(new ServiceToggleRequest { Service = "YouTube", Block = true });
        await policy.ToggleServiceAsync(new ServiceToggleRequest { Service = "YouTube", Block = false });

        // The manual block survives the service revert.
        _state.Hosts.GetBlocked().Should().Contain("youtube.com");
        _state.Hosts.GetBlocked().Should().NotContain("googlevideo.com");
    }

    [Fact]
    public async Task Manual_whitelist_wins_over_the_toggle()
    {
        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var hosts = new HostsControl.HostsControlClient(channel);
        await hosts.AllowAsync(new DomainRequest { Domain = "t.co", Source = "manual" });

        await Client(channel).ToggleServiceAsync(new ServiceToggleRequest { Service = "X (Twitter)", Block = true });

        _state.Hosts.GetBlocked().Should().NotContain("t.co");
        _state.Db.GetDomainStatus("t.co").Should().Be("whitelisted");
        _state.Hosts.GetBlocked().Should().Contain("twitter.com");
    }

    [Fact]
    public async Task Telemetry_preset_blocks_endpoints_and_carries_defender_note()
    {
        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var policy = Client(channel);

        var states = await policy.ListServicesAsync(new Empty());
        states.Services.Should().Contain(s =>
            s.Name == BlockedServices.TelemetryService && s.Note.Contains("Defender") && s.DomainCount == 28);

        var ack = await policy.ToggleServiceAsync(new ServiceToggleRequest
        {
            Service = BlockedServices.TelemetryService,
            Block = true,
        });

        ack.Ok.Should().BeTrue();
        ack.Message.Should().Contain("HostsFileHijack");
        _state.Hosts.GetBlocked().Should().Contain("telemetry.microsoft.com").And.Contain("watson.microsoft.com");
    }

    [Fact]
    public async Task Unknown_service_returns_typed_error()
    {
        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var ack = await Client(channel).ToggleServiceAsync(new ServiceToggleRequest { Service = "MySpace", Block = true });

        ack.Ok.Should().BeFalse();
        ack.ErrorCode.Should().Be("hostsguard.error.v1/unknown_service");
    }
}
