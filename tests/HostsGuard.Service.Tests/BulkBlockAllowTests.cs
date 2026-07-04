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
/// NET-105: BlockMany/AllowMany apply a whole selection in one DB update + one
/// hosts-file reconcile, skip invalid domains, and AllowMany (weakening) respects
/// the settings lock (NET-110).
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class BulkBlockAllowTests : IDisposable
{
    private readonly string _dir;
    private readonly ServiceState _state;
    private readonly HostsControlServiceImpl _hosts;
    private static ServerCallContext Ctx => null!;

    public BulkBlockAllowTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "hg_bulk_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        File.WriteAllText(Path.Combine(_dir, "hosts"), "# hosts\n");
        _state = new ServiceState(
            new HostsEngine(Path.Combine(_dir, "hosts")),
            new HostsDatabase(Path.Combine(_dir, "hostsguard.db")),
            dataDir: _dir);
        _hosts = new HostsControlServiceImpl(_state);
    }

    private static BulkDomainsRequest Req(params string[] domains)
    {
        var r = new BulkDomainsRequest { Source = "test" };
        r.Domains.AddRange(domains);
        return r;
    }

    [Fact]
    public async Task BlockMany_blocks_valid_domains_and_skips_invalid()
    {
        var result = await _hosts.BlockMany(Req("ads.example.com", "track.example.com", "not a domain", "ads.example.com"), Ctx);

        result.Ok.Should().BeTrue();
        result.Total.Should().Be(2);   // deduped + invalid dropped
        result.Applied.Should().Be(2); // both newly written
        _state.Hosts.GetBlocked().Should().Contain(new[] { "ads.example.com", "track.example.com" });
    }

    [Fact]
    public async Task AllowMany_whitelists_and_removes_from_hosts()
    {
        await _hosts.BlockMany(Req("ads.example.com", "keep.example.com"), Ctx);
        var result = await _hosts.AllowMany(Req("ads.example.com"), Ctx);

        result.Ok.Should().BeTrue();
        _state.Db.GetDomainStatus("ads.example.com").Should().Be("whitelisted");
        _state.Hosts.GetBlocked().Should().NotContain("ads.example.com");
        _state.Hosts.GetBlocked().Should().Contain("keep.example.com"); // untouched
    }

    [Fact]
    public async Task AllowMany_is_refused_when_the_lock_is_armed()
    {
        await _hosts.BlockMany(Req("ads.example.com"), Ctx);
        _state.Lock.Enable("s3cret");

        var result = await _hosts.AllowMany(Req("ads.example.com"), Ctx);

        result.Ok.Should().BeFalse();
        result.ErrorCode.Should().Be("hostsguard.error.v1/locked");
        _state.Hosts.GetBlocked().Should().Contain("ads.example.com"); // still blocked
    }

    public void Dispose()
    {
        _state.Dispose();
        SqliteConnection.ClearAllPools();
        try { Directory.Delete(_dir, true); } catch (IOException) { /* best effort */ }
    }
}
