using System.Runtime.Versioning;
using FluentAssertions;
using HostsGuard.Data;
using HostsGuard.Windows;
using Microsoft.Data.Sqlite;
using Xunit;

namespace HostsGuard.Service.Tests;

/// <summary>
/// NET-075 CNAME-cloak reactive blocking: a first-party host that aliases to a
/// blocked tracker is blocked; disarmed/already-blocked/no-blocked-cname are
/// no-ops. The setting persists.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class CnameCloakGuardTests : IDisposable
{
    private readonly string _dir;
    private readonly HostsEngine _hosts;
    private readonly HostsDatabase _db;

    public CnameCloakGuardTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "hg_cname_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        var hostsPath = Path.Combine(_dir, "hosts");
        File.WriteAllText(hostsPath, "# hosts\n");
        _hosts = new HostsEngine(hostsPath);
        _db = new HostsDatabase(Path.Combine(_dir, "hostsguard.db"));
    }

    public void Dispose()
    {
        _db.Dispose();
        try { Directory.Delete(_dir, true); } catch (IOException) { /* best effort */ }
    }

    [Fact]
    public void Blocks_the_fronting_host_when_a_cname_is_blocked()
    {
        _hosts.Block("cdn.tracker.example");
        var guard = new CnameCloakGuard(_hosts, _db);
        guard.SetEnabled(true);

        var trigger = guard.Evaluate("metrics.firstparty.com", new[] { "cdn.tracker.example" });

        trigger.Should().Be("cdn.tracker.example");
        _hosts.GetBlocked().Should().Contain("metrics.firstparty.com");
        _db.GetDomains(status: "blocked").Should().Contain(d => d.Domain == "metrics.firstparty.com" && d.Source == "cname-cloak");
    }

    [Fact]
    public void Disarmed_guard_does_nothing()
    {
        _hosts.Block("cdn.tracker.example");
        var guard = new CnameCloakGuard(_hosts, _db); // default off

        guard.Evaluate("metrics.firstparty.com", new[] { "cdn.tracker.example" }).Should().BeNull();
        _hosts.GetBlocked().Should().NotContain("metrics.firstparty.com");
    }

    [Fact]
    public void No_op_when_no_cname_is_blocked_or_host_already_blocked()
    {
        var guard = new CnameCloakGuard(_hosts, _db);
        guard.SetEnabled(true);

        // No blocked CNAME.
        guard.Evaluate("app.firstparty.com", new[] { "cdn.clean.example" }).Should().BeNull();
        _hosts.GetBlocked().Should().NotContain("app.firstparty.com");

        // Query name already blocked → nothing to do.
        _hosts.Block("already.blocked.com");
        guard.Evaluate("already.blocked.com", new[] { "cdn.clean.example" }).Should().BeNull();
    }

    [Fact]
    public void Enabled_setting_persists_across_a_restart()
    {
        new CnameCloakGuard(_hosts, _db).SetEnabled(true);
        new CnameCloakGuard(_hosts, _db).Enabled.Should().BeTrue();
    }
}
