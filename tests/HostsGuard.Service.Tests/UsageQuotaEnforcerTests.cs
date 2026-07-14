using System.Runtime.Versioning;
using FluentAssertions;
using HostsGuard.Data;
using HostsGuard.Windows;
using Microsoft.Data.Sqlite;
using Xunit;

namespace HostsGuard.Service.Tests;

/// <summary>
/// NET-172: opt-in usage-budget enforcement — crossing the rolling-window
/// limit applies a scoped block (hosts entry / HG_QuotaBlock_* rules), the
/// block auto-clears when the window slides back under the limit, and
/// disable/delete/reset lift it in one step. Defaults OFF.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class UsageQuotaEnforcerTests : IDisposable
{
    private readonly string _dir;
    private readonly HostsDatabase _db;
    private readonly HostsEngine _hosts;
    private readonly FakeFirewallEngine _firewall = new();
    private readonly UsageQuotaEnforcer _enforcer;
    private static readonly DateTime Today = new(2026, 7, 10, 12, 0, 0);

    public UsageQuotaEnforcerTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "hg_quota_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        var hostsPath = Path.Combine(_dir, "hosts");
        File.WriteAllText(hostsPath, "# hosts\n");
        _hosts = new HostsEngine(hostsPath);
        _db = new HostsDatabase(Path.Combine(_dir, "hostsguard.db"));
        _enforcer = new UsageQuotaEnforcer(_db, _hosts, _firewall,
            processPathResolver: name => name == "syncer"
                ? new[] { @"C:\Tools\syncer.exe" }
                : Array.Empty<string>());
    }

    private IReadOnlyList<string> QuotaRules() =>
        _firewall.Rules.Keys.Where(k => k.StartsWith("HG_QuotaBlock_", StringComparison.Ordinal)).ToList();

    [Fact]
    public void Domain_quota_blocks_on_exceed_and_auto_clears_when_the_window_slides()
    {
        _db.UpsertUsageQuotaRule("domain", "cdn.example.com", limitBytes: 100, windowDays: 2, enabled: true, blockOnExceed: true);
        _db.AddUsageRollup("cdn.example.com", "chrome", Today.Date, 90, 60);

        _enforcer.Sweep(Today);

        _db.GetDomainStatus("cdn.example.com").Should().Be("blocked");
        _db.GetDomainSource("cdn.example.com").Should().Be(UsageQuotaEnforcer.DomainSource);
        _hosts.GetBlocked().Should().Contain("cdn.example.com");
        var rule = _db.GetUsageQuotaRules().Single();
        rule.BlockedSince.Should().NotBeEmpty();

        // Two days later the 2-day window no longer contains the usage.
        _enforcer.Sweep(Today.AddDays(3));

        _db.GetDomainStatus("cdn.example.com").Should().BeNull();
        _hosts.GetBlocked().Should().NotContain("cdn.example.com");
        _db.GetUsageQuotaRules().Single().BlockedSince.Should().BeEmpty();
    }

    [Fact]
    public void App_quota_blocks_the_resolved_executable_paths()
    {
        _db.UpsertUsageQuotaRule("app", "syncer", limitBytes: 100, windowDays: 7, enabled: true, blockOnExceed: true);
        _db.AddUsageRollup("api.example.com", "syncer", Today.Date, 200, 0);

        _enforcer.Sweep(Today);

        var names = QuotaRules();
        names.Should().HaveCount(1);
        var rule = _firewall.Rules[names.Single()];
        rule.Action.Should().Be("Block");
        rule.Direction.Should().Be("Out");
        rule.Program.Should().Be(@"C:\Tools\syncer.exe");
        _db.GetUsageQuotaRules().Single().BlockedRules.Should().Be(names.Single());
    }

    [Fact]
    public void App_quota_with_no_running_process_stays_pending()
    {
        _db.UpsertUsageQuotaRule("app", "ghost", limitBytes: 100, windowDays: 7, enabled: true, blockOnExceed: true);
        _db.AddUsageRollup("api.example.com", "ghost", Today.Date, 200, 0);

        _enforcer.Sweep(Today);

        QuotaRules().Should().BeEmpty();
        _db.GetUsageQuotaRules().Single().BlockedSince.Should().BeEmpty(); // retried next sweep
    }

    [Fact]
    public void Rules_without_block_on_exceed_only_alert()
    {
        _db.UpsertUsageQuotaRule("domain", "cdn.example.com", limitBytes: 100, windowDays: 2, enabled: true);
        _db.AddUsageRollup("cdn.example.com", "chrome", Today.Date, 500, 0);

        _enforcer.Sweep(Today);

        _db.GetDomainStatus("cdn.example.com").Should().BeNull();
        QuotaRules().Should().BeEmpty();
    }

    [Fact]
    public void Manual_whitelist_wins_over_enforcement()
    {
        _db.AddDomain("keep.example.com", "whitelisted", "manual");
        _db.UpsertUsageQuotaRule("domain", "keep.example.com", limitBytes: 100, windowDays: 2, enabled: true, blockOnExceed: true);
        _db.AddUsageRollup("keep.example.com", "chrome", Today.Date, 500, 0);

        _enforcer.Sweep(Today);

        _db.GetDomainStatus("keep.example.com").Should().Be("whitelisted");
        _db.GetUsageQuotaRules().Single().BlockedSince.Should().BeEmpty();
    }

    [Fact]
    public void Disabling_block_on_exceed_lifts_an_active_block()
    {
        _db.UpsertUsageQuotaRule("app", "syncer", limitBytes: 100, windowDays: 7, enabled: true, blockOnExceed: true);
        _db.AddUsageRollup("api.example.com", "syncer", Today.Date, 200, 0);
        _enforcer.Sweep(Today);
        QuotaRules().Should().HaveCount(1);

        _db.UpsertUsageQuotaRule("app", "syncer", limitBytes: 100, windowDays: 7, enabled: true, blockOnExceed: false);
        _enforcer.Sweep(Today);

        QuotaRules().Should().BeEmpty();
        _db.GetUsageQuotaRules().Single().BlockedSince.Should().BeEmpty();
    }

    [Fact]
    public void Clear_all_blocks_reverts_domain_and_app_blocks()
    {
        _db.UpsertUsageQuotaRule("domain", "cdn.example.com", limitBytes: 100, windowDays: 7, enabled: true, blockOnExceed: true);
        _db.UpsertUsageQuotaRule("app", "syncer", limitBytes: 100, windowDays: 7, enabled: true, blockOnExceed: true);
        _db.AddUsageRollup("cdn.example.com", "chrome", Today.Date, 500, 0);
        _db.AddUsageRollup("api.example.com", "syncer", Today.Date, 500, 0);
        _enforcer.Sweep(Today);
        QuotaRules().Should().HaveCount(1);
        _hosts.GetBlocked().Should().Contain("cdn.example.com");

        var cleared = _enforcer.ClearAllBlocks("test reset");

        cleared.Should().Be(2);
        QuotaRules().Should().BeEmpty();
        _hosts.GetBlocked().Should().NotContain("cdn.example.com");
        _db.GetUsageQuotaRules().Should().OnlyContain(r => r.BlockedSince.Length == 0);
    }

    [Fact]
    public void A_manual_domain_block_is_never_reverted_by_clear()
    {
        _hosts.Block("manual.example.com");
        _db.AddDomain("manual.example.com", "blocked", "manual");
        _db.UpsertUsageQuotaRule("domain", "manual.example.com", limitBytes: 100, windowDays: 7, enabled: true, blockOnExceed: true);
        _db.AddUsageRollup("manual.example.com", "chrome", Today.Date, 500, 0);
        _enforcer.Sweep(Today);

        _db.GetDomainSource("manual.example.com").Should().Be("manual"); // ownership untouched
        _enforcer.ClearAllBlocks("test");

        _db.GetDomainStatus("manual.example.com").Should().Be("blocked");
        _hosts.GetBlocked().Should().Contain("manual.example.com");
    }

    [Fact]
    public void Quota_re_blocks_after_a_pre_existing_block_is_manually_deleted()
    {
        // Domain is blocked manually first; the quota is over the limit but the
        // block is already in place, so the quota leaves ownership alone.
        _hosts.Block("cdn.example.com");
        _db.AddDomain("cdn.example.com", "blocked", "manual");
        _db.UpsertUsageQuotaRule("domain", "cdn.example.com", limitBytes: 100, windowDays: 2, enabled: true, blockOnExceed: true);
        _db.AddUsageRollup("cdn.example.com", "chrome", Today.Date, 500, 0);
        _enforcer.Sweep(Today);
        _db.GetDomainSource("cdn.example.com").Should().Be("manual"); // ownership untouched

        // The user manually deletes that block while still over the limit.
        _hosts.Unblock("cdn.example.com");
        _db.RemoveDomain("cdn.example.com");
        _db.GetDomainStatus("cdn.example.com").Should().BeNull();

        // The next sweep must re-derive real state and re-apply the block (now
        // quota-owned) instead of trusting a stale blockedSince and lapsing.
        _enforcer.Sweep(Today);

        _db.GetDomainStatus("cdn.example.com").Should().Be("blocked");
        _db.GetDomainSource("cdn.example.com").Should().Be(UsageQuotaEnforcer.DomainSource);
        _hosts.GetBlocked().Should().Contain("cdn.example.com");
    }

    public void Dispose()
    {
        _db.Dispose();
        try
        {
            Directory.Delete(_dir, recursive: true);
        }
        catch (IOException)
        {
        }
    }
}
