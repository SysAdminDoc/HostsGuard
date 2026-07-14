using System.Runtime.Versioning;
using FluentAssertions;
using Grpc.Core;
using HostsGuard.Contracts;
using HostsGuard.Data;
using HostsGuard.Windows;
using Microsoft.Data.Sqlite;
using Xunit;

namespace HostsGuard.Service.Tests;

/// <summary>
/// NET-110: when the settings lock is armed, posture-WEAKENING hosts mutations
/// (Allow/Unblock/SetHostsText/EmergencyReset/TempAllow/Reconcile) are refused,
/// while posture-STRENGTHENING ones (Block/BlockRoot) always proceed — "locked
/// means can't weaken, can always strengthen."
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class HostsLockGatingTests : IDisposable
{
    private readonly string _dir;
    private readonly ServiceState _state;
    private readonly HostsControlServiceImpl _hosts;

    public HostsLockGatingTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "hg_lockgate_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        File.WriteAllText(Path.Combine(_dir, "hosts"), "# hosts\n");
        _state = new ServiceState(
            new HostsEngine(Path.Combine(_dir, "hosts")),
            new HostsDatabase(Path.Combine(_dir, "hostsguard.db")),
            dataDir: _dir);
        _hosts = new HostsControlServiceImpl(_state);
    }

    private const string Locked = "hostsguard.error.v1/locked";

    // The hosts handlers never read the ServerCallContext, so null is safe here.
    private static ServerCallContext Ctx => null!;

    [Fact]
    public async Task Armed_lock_refuses_weakening_but_allows_blocking()
    {
        _state.Lock.Enable("s3cret");

        // Strengthening still works.
        (await _hosts.Block(new DomainRequest { Domain = "ads.example.com" }, Ctx)).Ok.Should().BeTrue();
        (await _hosts.BlockRoot(new DomainRequest { Domain = "sub.tracker.example.com" }, Ctx)).Ok.Should().BeTrue();

        // Weakening is refused with the locked error code.
        (await _hosts.Allow(new DomainRequest { Domain = "ads.example.com" }, Ctx)).ErrorCode.Should().Be(Locked);
        (await _hosts.Unblock(new DomainRequest { Domain = "ads.example.com" }, Ctx)).ErrorCode.Should().Be(Locked);
        (await _hosts.TempAllow(new TempAllowRequest { Domain = "ads.example.com", Minutes = 5 }, Ctx)).ErrorCode.Should().Be(Locked);
        (await _hosts.SetHostsText(new HostsText { Text = "# wiped\n" }, Ctx)).ErrorCode.Should().Be(Locked);
        (await _hosts.EmergencyReset(new Empty(), Ctx)).ErrorCode.Should().Be(Locked);
        (await _hosts.Reconcile(new ReconcileRequest(), Ctx)).ErrorCode.Should().Be(Locked);

        // The block survived every weakening attempt.
        _state.Hosts.GetBlocked().Should().Contain("ads.example.com");
    }

    [Fact]
    public async Task Unlocking_restores_weakening()
    {
        await _hosts.Block(new DomainRequest { Domain = "ads.example.com" }, Ctx);
        _state.Lock.Enable("s3cret");
        _state.Lock.Unlock("s3cret", 5, DateTime.UtcNow);

        (await _hosts.Allow(new DomainRequest { Domain = "ads.example.com" }, Ctx)).Ok.Should().BeTrue();
        _state.Db.GetDomainStatus("ads.example.com").Should().Be("whitelisted");
    }

    public void Dispose()
    {
        _state.Dispose();
        try { Directory.Delete(_dir, true); } catch (IOException) { /* best effort */ }
    }
}
