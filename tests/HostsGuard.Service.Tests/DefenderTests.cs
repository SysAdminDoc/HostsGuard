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

internal sealed class FakeDefender : IDefender
{
    public bool Available { get; set; } = true;

    public List<string> Exclusions { get; } = new();

    public bool RefuseAdd { get; set; }

    public bool IsAvailable() => Available;

    public IReadOnlyList<string> GetExclusionPaths() => Exclusions;

    public bool AddExclusion(string path)
    {
        if (RefuseAdd)
        {
            return false;
        }

        Exclusions.Add(path);
        return true;
    }
}

/// <summary>NET-036: Defender exclusion add + revert-detection heuristic.</summary>
[SupportedOSPlatform("windows")]
public sealed class DefenderTests : IAsyncLifetime
{
    private string _dir = null!;
    private WebApplication _app = null!;
    private ServiceState _state = null!;
    private FakeDefender _defender = null!;
    private string _pipe = null!;
    private string _token = null!;
    private string _hostsPath = null!;

    public async Task InitializeAsync()
    {
        _dir = Path.Combine(Path.GetTempPath(), "hg_def_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        _hostsPath = Path.Combine(_dir, "hosts");
        File.WriteAllText(_hostsPath, "# hosts\n");

        _defender = new FakeDefender();
        _state = new ServiceState(
            new HostsEngine(_hostsPath),
            new HostsDatabase(Path.Combine(_dir, "hostsguard.db")),
            dataDir: _dir,
            defender: _defender);
        _token = SessionToken.Generate();
        _pipe = "HostsGuard.DefTest." + Guid.NewGuid().ToString("N");
        _app = ServiceHost.Build(_state, _token, _pipe);
        await _app.StartAsync();
    }

    public async Task DisposeAsync()
    {
        await _app.DisposeAsync();
        _state.Dispose();
        try { Directory.Delete(_dir, true); } catch (IOException) { /* best effort */ }
    }

    [Fact]
    public async Task Exclusion_add_round_trips_and_is_idempotent()
    {
        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var hosts = new HostsControl.HostsControlClient(channel);
        var diag = new HostsGuard.Contracts.Diagnostics.DiagnosticsClient(channel);

        (await diag.GetDefenderStatusAsync(new Empty())).HostsExcluded.Should().BeFalse();

        var ack = await hosts.AddDefenderExclusionAsync(new Empty());
        ack.Ok.Should().BeTrue();
        _defender.Exclusions.Should().ContainSingle().Which.Should().Be(_hostsPath);

        (await diag.GetDefenderStatusAsync(new Empty())).HostsExcluded.Should().BeTrue();

        // Second call is a no-op, not a duplicate.
        (await hosts.AddDefenderExclusionAsync(new Empty())).Message.Should().Contain("already");
        _defender.Exclusions.Should().ContainSingle();
    }

    [Fact]
    public async Task Unavailable_defender_is_a_typed_error()
    {
        _defender.Available = false;
        using var channel = NamedPipeChannel.Create(_token, _pipe);

        var ack = await new HostsControl.HostsControlClient(channel).AddDefenderExclusionAsync(new Empty());

        ack.Ok.Should().BeFalse();
        ack.ErrorCode.Should().Be("hostsguard.error.v1/defender_unavailable");
    }

    [Fact]
    public async Task Revert_heuristic_fires_when_hosts_lost_its_blocks()
    {
        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var hosts = new HostsControl.HostsControlClient(channel);
        var diag = new HostsGuard.Contracts.Diagnostics.DiagnosticsClient(channel);
        await hosts.BlockAsync(new DomainRequest { Domain = "telemetry.microsoft.com" });

        (await diag.GetDefenderStatusAsync(new Empty())).PossibleRevert.Should().BeFalse();

        // Simulate Defender remediation: hosts file reset behind our back.
        File.WriteAllText(_hostsPath, "# hosts\n");
        _state.Hosts.Read();

        var status = await diag.GetDefenderStatusAsync(new Empty());
        status.PossibleRevert.Should().BeTrue();
        status.Guidance.Should().Contain("HostsFileHijack");
    }
}
