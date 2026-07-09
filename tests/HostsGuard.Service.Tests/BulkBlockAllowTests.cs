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

    [Fact]
    public async Task BlockMany_keeps_database_unchanged_when_hosts_file_is_held()
    {
        using var hold = new FileStream(Path.Combine(_dir, "hosts"), FileMode.Open, FileAccess.Read, FileShare.Read);

        var result = await _hosts.BlockMany(Req("locked.example.com"), Ctx);

        result.Ok.Should().BeFalse();
        result.ErrorCode.Should().Be("hostsguard.error.v1/hosts_locked");
        _state.Hosts.GetBlocked().Should().NotContain("locked.example.com");
        _state.Db.GetDomainStatus("locked.example.com").Should().BeNull();
    }

    [Fact]
    public async Task AllowMany_keeps_database_unchanged_when_hosts_file_is_held()
    {
        await _hosts.BlockMany(Req("keep-blocked.example.com"), Ctx);
        using var hold = new FileStream(Path.Combine(_dir, "hosts"), FileMode.Open, FileAccess.Read, FileShare.Read);

        var result = await _hosts.AllowMany(Req("keep-blocked.example.com"), Ctx);

        result.Ok.Should().BeFalse();
        result.ErrorCode.Should().Be("hostsguard.error.v1/hosts_locked");
        _state.Db.GetDomainStatus("keep-blocked.example.com").Should().Be("blocked");
        _state.Hosts.GetBlocked().Should().Contain("keep-blocked.example.com");
    }

    [Fact]
    public async Task BlockMany_preserves_allowlist_wins_during_reconcile()
    {
        _state.Db.AddDomain("keep-allowed.example.com", "whitelisted", "manual");

        var result = await _hosts.BlockMany(Req("keep-allowed.example.com", "new-block.example.com"), Ctx);

        result.Ok.Should().BeTrue();
        _state.Db.GetDomainStatus("keep-allowed.example.com").Should().Be("whitelisted");
        _state.Hosts.GetBlocked().Should().NotContain("keep-allowed.example.com");
        _state.Hosts.GetBlocked().Should().Contain("new-block.example.com");
    }

    [Fact]
    public async Task BlockMany_logs_a_bounded_domain_preview_for_auditability()
    {
        await _hosts.BlockMany(Req("ads.example.com", "track.example.com"), Ctx);

        var ev = _state.Db.GetLog(1).Should().ContainSingle().Subject;
        ev.Action.Should().Be("block_many");
        ev.Details.Should().Contain("2 domains");
        ev.Details.Should().Contain("ads.example.com");
        ev.Details.Should().Contain("track.example.com");
    }

    [Fact]
    public async Task BlockRoot_uses_the_request_source_for_provenance()
    {
        await _hosts.BlockRoot(new DomainRequest { Domain = "cdn.example.com", Source = "feed" }, Ctx);

        _state.Db.GetDomains(status: "blocked")
            .Should().ContainSingle(r => r.Domain == "example.com" && r.Source == "feed");
    }

    public void Dispose()
    {
        _state.Dispose();
        SqliteConnection.ClearAllPools();
        try { Directory.Delete(_dir, true); } catch (IOException) { /* best effort */ }
    }
}
