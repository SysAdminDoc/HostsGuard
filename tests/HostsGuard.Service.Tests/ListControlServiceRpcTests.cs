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
/// Direct in-proc RPC tests for <see cref="ListControlServiceImpl"/> — request
/// validation and error-code mapping for the blocklist/allowlist/IP-blocklist
/// handler layer, which the coordinator-level tests do not exercise. A fake list
/// fetcher wires the coordinators so the not-found/no-checkpoint paths run.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class ListControlServiceRpcTests : IDisposable
{
    private readonly string _dir;
    private readonly ServiceState _state;
    private readonly ListControlServiceImpl _lists;

    public ListControlServiceRpcTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "hg_listrpc_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        File.WriteAllText(Path.Combine(_dir, "hosts"), "# hosts\n");
        _state = new ServiceState(
            new HostsEngine(Path.Combine(_dir, "hosts")),
            new HostsDatabase(Path.Combine(_dir, "hostsguard.db")),
            firewall: new FakeFirewallEngine(),
            dataDir: _dir,
            listFetcher: new FakeListFetcher());
        _lists = new ListControlServiceImpl(_state);
    }

    private static ServerCallContext Ctx => null!;

    [Fact]
    public async Task Blocklist_name_is_required()
    {
        (await _lists.SetBlocklistEnabled(new BlocklistToggleRequest { Name = "  ", Enabled = true }, Ctx))
            .ErrorCode.Should().Be("hostsguard.error.v1/invalid_source");
        (await _lists.RemoveBlocklistSubscription(new BlocklistRequest { Name = "" }, Ctx))
            .ErrorCode.Should().Be("hostsguard.error.v1/invalid_source");
        (await _lists.RestoreBlocklistCheckpoint(new BlocklistRequest { Name = "" }, Ctx))
            .ErrorCode.Should().Be("hostsguard.error.v1/invalid_source");
    }

    [Fact]
    public async Task Restore_without_a_checkpoint_reports_no_checkpoint()
    {
        (await _lists.RestoreBlocklistCheckpoint(new BlocklistRequest { Name = "never-subscribed" }, Ctx))
            .ErrorCode.Should().Be("hostsguard.error.v1/no_checkpoint");
    }

    [Fact]
    public async Task Allowlists_reject_non_https_and_round_trip_https()
    {
        (await _lists.SetAllowlists(new AllowlistUrls { Urls = { "http://insecure.example/allow.txt" } }, Ctx))
            .ErrorCode.Should().Be("hostsguard.error.v1/invalid_source");

        (await _lists.SetAllowlists(new AllowlistUrls { Urls = { "https://good.example/allow.txt" } }, Ctx))
            .Ok.Should().BeTrue();
        (await _lists.GetAllowlists(new Empty(), Ctx)).Urls.Should().Contain("https://good.example/allow.txt");
    }

    [Fact]
    public async Task Ip_blocklist_name_is_required_and_unknown_reports_not_found()
    {
        (await _lists.SetIpBlocklistEnabled(new BlocklistToggleRequest { Name = "", Enabled = true }, Ctx))
            .ErrorCode.Should().Be("hostsguard.error.v1/invalid_source");
        (await _lists.RemoveIpBlocklist(new BlocklistRequest { Name = "" }, Ctx))
            .ErrorCode.Should().Be("hostsguard.error.v1/invalid_source");
        (await _lists.RollbackIpBlocklist(new BlocklistRequest { Name = "" }, Ctx))
            .ErrorCode.Should().Be("hostsguard.error.v1/invalid_source");

        // A well-formed name for a source that was never subscribed → not_found.
        (await _lists.SetIpBlocklistEnabled(new BlocklistToggleRequest { Name = "ghost-ips", Enabled = false }, Ctx))
            .ErrorCode.Should().Be("hostsguard.error.v1/not_found");
    }

    [Fact]
    public async Task ListIpBlocklists_starts_empty()
        => (await _lists.ListIpBlocklists(new Empty(), Ctx)).Sources.Should().BeEmpty();

    public void Dispose()
    {
        _state.Dispose();
        SqliteConnection.ClearAllPools();
        try { Directory.Delete(_dir, true); } catch (IOException) { /* best effort */ }
    }
}
