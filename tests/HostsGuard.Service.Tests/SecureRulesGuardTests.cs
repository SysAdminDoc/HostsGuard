using System.Runtime.Versioning;
using FluentAssertions;
using HostsGuard.Core;
using HostsGuard.Data;
using Microsoft.Data.Sqlite;
using Xunit;

namespace HostsGuard.Service.Tests;

/// <summary>
/// NET-072 Secure-Rules tamper-guard: recreate deleted HG_ rules, re-enable
/// disabled ones, only ever touch HG_ rules, and no-op when disarmed. Uses the
/// in-memory FakeFirewallEngine from FirewallControlServiceTests.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class SecureRulesGuardTests : IDisposable
{
    private readonly string _dir;
    private readonly HostsDatabase _db;
    private readonly FakeFirewallEngine _fw = new();

    public SecureRulesGuardTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "hg_secure_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        _db = new HostsDatabase(Path.Combine(_dir, "hostsguard.db"));
    }

    public void Dispose()
    {
        _db.Dispose();
        SqliteConnection.ClearAllPools();
        try { Directory.Delete(_dir, true); } catch (IOException) { /* best effort */ }
    }

    private void Track(string name)
    {
        _fw.CreateRule(new FwRule(name, "Out", "Block", true, "203.0.113.9", "Any", string.Empty, "hostsguard"));
        _db.UpsertFwState(name, "Out", "Block", "203.0.113.9", "Any", string.Empty);
    }

    [Fact]
    public void Disarmed_guard_reverts_nothing()
    {
        using var guard = new SecureRulesGuard(_fw, _db);
        Track("HG_Block_a");
        _fw.Rules.Remove("HG_Block_a");

        guard.Reconcile().Should().Be(0);
        _fw.Rules.Should().NotContainKey("HG_Block_a");
    }

    [Fact]
    public void Recreates_a_deleted_hg_rule_and_re_enables_a_disabled_one()
    {
        using var guard = new SecureRulesGuard(_fw, _db);
        Track("HG_Block_deleted");
        Track("HG_Block_disabled");
        guard.SetEnabled(true);

        // Tamper: delete one rule, disable the other.
        _fw.Rules.Remove("HG_Block_deleted");
        _fw.Rules["HG_Block_disabled"] = _fw.Rules["HG_Block_disabled"] with { Enabled = false };

        var reverts = guard.Reconcile();

        reverts.Should().Be(2);
        _fw.Rules.Should().ContainKey("HG_Block_deleted");
        _fw.Rules["HG_Block_deleted"].RemoteAddr.Should().Be("203.0.113.9"); // restored from tracked state
        _fw.Rules["HG_Block_disabled"].Enabled.Should().BeTrue();
    }

    [Fact]
    public void Never_touches_non_hg_rules()
    {
        using var guard = new SecureRulesGuard(_fw, _db);
        // A system rule the user disabled — not ours, must be left alone.
        _fw.CreateRule(new FwRule("CoreNet-Something", "Out", "Allow", false, "Any", "Any", string.Empty, "system"));
        guard.SetEnabled(true);

        guard.Reconcile().Should().Be(0);
        _fw.Rules["CoreNet-Something"].Enabled.Should().BeFalse(); // untouched
    }

    [Fact]
    public void Enabled_setting_persists_across_a_restart()
    {
        using (var guard = new SecureRulesGuard(_fw, _db))
        {
            guard.SetEnabled(true);
        }

        using var reopened = new SecureRulesGuard(_fw, _db);
        reopened.Enabled.Should().BeTrue();
    }
}
