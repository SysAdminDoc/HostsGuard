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
        try { Directory.Delete(_dir, true); } catch (IOException) { /* best effort */ }
    }

    private void Track(string name)
    {
        _fw.CreateRule(new FwRule(name, "Out", "Block", true, "203.0.113.9", "Any", string.Empty, "hostsguard"));
        _db.UpsertFwState(name, "Out", "Block", "203.0.113.9", "Any", string.Empty);
    }

    private void DeleteAndReconcile(SecureRulesGuard guard, string name)
    {
        _fw.Rules.Remove(name);
        guard.Reconcile();
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
    public void Repeated_restores_quarantine_only_the_conflicting_rule_and_raise_one_evidenced_alert()
    {
        var now = new DateTimeOffset(2026, 7, 14, 12, 0, 0, TimeSpan.Zero);
        using var guard = new SecureRulesGuard(_fw, _db, () => now, Timeout.InfiniteTimeSpan);
        Track("HG_Block_loop");
        Track("HG_Block_unrelated");
        guard.SetEnabled(true);

        for (var i = 0; i < SecureRulesGuard.RestoreLimit; i++)
        {
            DeleteAndReconcile(guard, "HG_Block_loop");
            guard.Reconcile().Should().Be(0, "a healthy observation must not erase restores still inside the rolling window");
            now = now.AddMinutes(1);
        }

        _fw.Rules.Remove("HG_Block_loop");
        _fw.Rules.Remove("HG_Block_unrelated");
        guard.Reconcile().Should().Be(1);

        _fw.Rules.Should().NotContainKey("HG_Block_loop");
        _fw.Rules.Should().ContainKey("HG_Block_unrelated");
        var conflict = guard.Conflicts.Should().ContainSingle().Subject;
        conflict.Name.Should().Be("HG_Block_loop");
        conflict.RestoreAttempts.Should().Be(SecureRulesGuard.RestoreLimit);
        conflict.LiveEvidence.Should().Be("missing");
        conflict.TrackedEvidence.Should().Contain("remote=203.0.113.9");

        guard.Reconcile();
        var alert = _db.GetAlerts(new AlertFilter(Type: "secure_rules_conflict")).Rows.Should().ContainSingle().Subject;
        alert.Severity.Should().Be("critical");
        alert.Details.Should().Contain("Live: missing").And.Contain("tracked:").And.Contain("10 minutes");
    }

    [Fact]
    public void Restore_counter_expires_after_the_documented_window()
    {
        var now = new DateTimeOffset(2026, 7, 14, 12, 0, 0, TimeSpan.Zero);
        using var guard = new SecureRulesGuard(_fw, _db, () => now, Timeout.InfiniteTimeSpan);
        Track("HG_Block_expiring");
        guard.SetEnabled(true);

        for (var i = 0; i < SecureRulesGuard.RestoreLimit; i++)
        {
            DeleteAndReconcile(guard, "HG_Block_expiring");
            now = now.AddMinutes(1);
        }

        now = now.Add(SecureRulesGuard.RestoreWindow);
        DeleteAndReconcile(guard, "HG_Block_expiring");

        _fw.Rules.Should().ContainKey("HG_Block_expiring");
        guard.Conflicts.Should().BeEmpty();
    }

    [Fact]
    public void Quarantine_survives_restart_and_accept_foreign_state_stops_tracking()
    {
        var now = new DateTimeOffset(2026, 7, 14, 12, 0, 0, TimeSpan.Zero);
        Track("HG_Block_accept");
        using (var guard = new SecureRulesGuard(_fw, _db, () => now, Timeout.InfiniteTimeSpan))
        {
            guard.SetEnabled(true);
            for (var i = 0; i < SecureRulesGuard.RestoreLimit; i++)
            {
                DeleteAndReconcile(guard, "HG_Block_accept");
            }

            _fw.Rules.Remove("HG_Block_accept");
            guard.Reconcile();
            guard.Conflicts.Should().ContainSingle();
        }

        using var reopened = new SecureRulesGuard(_fw, _db, () => now, Timeout.InfiniteTimeSpan);
        reopened.Conflicts.Should().ContainSingle(c => c.Name == "HG_Block_accept");
        reopened.AcceptForeignState("HG_Block_accept").Should().BeTrue();
        reopened.AcceptForeignState("HG_Block_accept").Should().BeFalse();
        _db.GetFwStateNames().Should().NotContain("HG_Block_accept");
        _fw.Rules.Should().NotContainKey("HG_Block_accept");
        reopened.Conflicts.Should().BeEmpty();
    }

    [Fact]
    public void Rearm_clears_quarantine_and_immediately_restores_the_tracked_rule()
    {
        var now = new DateTimeOffset(2026, 7, 14, 12, 0, 0, TimeSpan.Zero);
        using var guard = new SecureRulesGuard(_fw, _db, () => now, Timeout.InfiniteTimeSpan);
        Track("HG_Block_rearm");
        guard.SetEnabled(true);
        for (var i = 0; i < SecureRulesGuard.RestoreLimit; i++)
        {
            DeleteAndReconcile(guard, "HG_Block_rearm");
        }

        _fw.Rules.Remove("HG_Block_rearm");
        guard.Reconcile();
        guard.Conflicts.Should().ContainSingle();

        guard.Rearm("HG_Block_rearm").Should().BeTrue();
        guard.Rearm("HG_Block_rearm").Should().BeFalse();
        _fw.Rules.Should().ContainKey("HG_Block_rearm");
        guard.Conflicts.Should().BeEmpty();
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

    [Fact]
    public void Dispose_is_idempotent_and_drains_without_throwing()
    {
        var guard = new SecureRulesGuard(_fw, _db);
        guard.SetEnabled(true);
        guard.Dispose();
        Action second = () => guard.Dispose();
        second.Should().NotThrow();
    }

    [Fact]
    public void Reconcile_after_db_dispose_throws_the_type_the_timer_path_swallows()
    {
        // NET-167: prove the DB fails fast with ObjectDisposedException — the
        // exact type ReconcileFromTimer catches — instead of an opaque SQLite
        // error, so a shutdown-time tick can never crash a background thread.
        using var guard = new SecureRulesGuard(_fw, _db);
        Track("HG_Block_x");
        guard.SetEnabled(true);

        _db.Dispose();

        ((Action)(() => guard.Reconcile())).Should().Throw<ObjectDisposedException>();
    }
}
