using System.Runtime.Versioning;
using FluentAssertions;
using HostsGuard.Contracts;
using HostsGuard.Data;
using HostsGuard.Ipc;
using HostsGuard.Windows;
using Microsoft.AspNetCore.Builder;
using Microsoft.Data.Sqlite;
using Xunit;

namespace HostsGuard.Service.Tests;

/// <summary>
/// NET-034: named rule-set profiles — snapshot, switch with hosts reconcile,
/// pre-switch safety snapshot, and delete.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class ProfileTests : IAsyncLifetime
{
    private string _dir = null!;
    private WebApplication _app = null!;
    private ServiceState _state = null!;
    private string _pipe = null!;
    private string _token = null!;

    public async Task InitializeAsync()
    {
        _dir = Path.Combine(Path.GetTempPath(), "hg_prof_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        var hostsPath = Path.Combine(_dir, "hosts");
        File.WriteAllText(hostsPath, "# hosts\n");

        _state = new ServiceState(new HostsEngine(hostsPath), new HostsDatabase(Path.Combine(_dir, "hostsguard.db")), dataDir: _dir);
        _token = SessionToken.Generate();
        _pipe = "HostsGuard.ProfTest." + Guid.NewGuid().ToString("N");
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
    public async Task Save_switch_and_reconcile_round_trip()
    {
        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var hosts = new HostsControl.HostsControlClient(channel);
        var policy = new Policy.PolicyClient(channel);

        // Work profile: two blocks, one whitelist.
        await hosts.BlockAsync(new DomainRequest { Domain = "social.example.com" });
        await hosts.BlockAsync(new DomainRequest { Domain = "games.example.com" });
        await hosts.AllowAsync(new DomainRequest { Domain = "docs.example.com" });
        (await policy.SaveProfileAsync(new ProfileRequest { Name = "Work" })).Ok.Should().BeTrue();

        // Home profile: only one block.
        await hosts.UnblockAsync(new DomainRequest { Domain = "games.example.com" });
        await hosts.UnblockAsync(new DomainRequest { Domain = "social.example.com" });
        await hosts.BlockAsync(new DomainRequest { Domain = "worksite.example.com" });
        (await policy.SaveProfileAsync(new ProfileRequest { Name = "Home" })).Ok.Should().BeTrue();

        // Switch back to Work: hosts + DB reconcile to the Work set.
        var ack = await policy.SwitchProfileAsync(new ProfileRequest { Name = "Work" });
        ack.Ok.Should().BeTrue();
        _state.Hosts.GetBlocked().Should().BeEquivalentTo("social.example.com", "games.example.com");
        _state.Db.GetDomainStatus("docs.example.com").Should().Be("whitelisted");
        _state.Db.GetDomainStatus("worksite.example.com").Should().BeNull();

        var list = await policy.ListProfilesAsync(new Empty());
        list.Active.Should().Be("Work");
        list.Names.Should().Contain(new[] { "Work", "Home" });
        list.Names.Should().Contain("(previous)"); // pre-switch safety snapshot
    }

    [Fact]
    public async Task Switching_to_unknown_profile_is_a_typed_error()
    {
        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var ack = await new Policy.PolicyClient(channel).SwitchProfileAsync(new ProfileRequest { Name = "Ghost" });

        ack.Ok.Should().BeFalse();
        ack.ErrorCode.Should().Be("hostsguard.error.v1/unknown_profile");
    }

    [Fact]
    public async Task Delete_removes_the_profile_and_clears_active()
    {
        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var policy = new Policy.PolicyClient(channel);
        await policy.SaveProfileAsync(new ProfileRequest { Name = "Temp" });
        await policy.SwitchProfileAsync(new ProfileRequest { Name = "Temp" });

        (await policy.DeleteProfileAsync(new ProfileRequest { Name = "Temp" })).Ok.Should().BeTrue();

        var list = await policy.ListProfilesAsync(new Empty());
        list.Names.Should().NotContain("Temp");
        list.Active.Should().BeEmpty();
    }
}
