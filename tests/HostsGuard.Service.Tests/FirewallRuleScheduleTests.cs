using System.Runtime.Versioning;
using FluentAssertions;
using HostsGuard.Core;
using HostsGuard.Data;
using HostsGuard.Windows;
using Microsoft.Data.Sqlite;
using Xunit;

namespace HostsGuard.Service.Tests;

/// <summary>NET-084: time-of-day enable/disable of firewall rules via the scheduler.</summary>
[SupportedOSPlatform("windows")]
public sealed class FirewallRuleScheduleTests : IDisposable
{
    private readonly string _dir;
    private readonly HostsEngine _hosts;
    private readonly HostsDatabase _db;
    private readonly FakeFirewallEngine _fw = new();
    private readonly ScheduleEnforcer _enforcer;

    public FirewallRuleScheduleTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "hg_fwsched_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        var hostsPath = Path.Combine(_dir, "hosts");
        File.WriteAllText(hostsPath, "# hosts\n");
        _hosts = new HostsEngine(hostsPath);
        _db = new HostsDatabase(Path.Combine(_dir, "hostsguard.db"));
        _enforcer = new ScheduleEnforcer(_hosts, _db, _fw, Timeout.InfiniteTimeSpan);
        _fw.CreateRule(new FwRule("HG_Block_Game", "Out", "Block", true, "Any", "Any", @"C:\game.exe", "hostsguard"));
    }

    public void Dispose()
    {
        _enforcer.Dispose();
        _db.Dispose();
        SqliteConnection.ClearAllPools();
        try
        {
            Directory.Delete(_dir, true);
        }
        catch (IOException)
        {
            // best effort
        }
    }

    // Wednesday 2026-07-01 (day index 2 in the proto convention Mon=0).
    private static readonly DateTime Wednesday = new(2026, 7, 1, 0, 0, 0);

    private void Schedule(string target, string days, string start, string end) =>
        _db.SetSchedules([(target, days, start, end)]);

    [Fact]
    public void Rule_is_enabled_inside_its_window_and_disabled_outside()
    {
        Schedule("fw:HG_Block_Game", "2", "09:00", "17:00");

        _enforcer.SweepAt(Wednesday.AddHours(12));   // noon — inside
        _fw.Rules["HG_Block_Game"].Enabled.Should().BeTrue();

        _enforcer.SweepAt(Wednesday.AddHours(20));    // 8pm — outside
        _fw.Rules["HG_Block_Game"].Enabled.Should().BeFalse();
    }

    [Fact]
    public void Overnight_window_crosses_midnight()
    {
        Schedule("fw:HG_Block_Game", "2", "22:00", "06:00");

        _enforcer.SweepAt(Wednesday.AddHours(23));    // 11pm — inside
        _fw.Rules["HG_Block_Game"].Enabled.Should().BeTrue();

        _enforcer.SweepAt(Wednesday.AddHours(12));     // noon — outside
        _fw.Rules["HG_Block_Game"].Enabled.Should().BeFalse();
    }

    [Fact]
    public void Wrong_day_disables_the_rule()
    {
        Schedule("fw:HG_Block_Game", "0", "00:00", "23:59"); // Monday only

        _enforcer.SweepAt(Wednesday.AddHours(12));
        _fw.Rules["HG_Block_Game"].Enabled.Should().BeFalse();
    }

    [Fact]
    public void Non_hostsguard_rules_are_never_touched()
    {
        _fw.CreateRule(new FwRule("SystemRule", "Out", "Allow", true, "Any", "Any", "", "system"));
        Schedule("fw:SystemRule", "2", "09:00", "17:00");

        _enforcer.SweepAt(Wednesday.AddHours(20)); // outside window
        _fw.Rules["SystemRule"].Enabled.Should().BeTrue(); // untouched
    }

    [Fact]
    public void Domain_schedules_still_work_alongside_fw_schedules()
    {
        _db.SetSchedules(
        [
            ("ads.example.com", "2", "09:00", "17:00"),
            ("fw:HG_Block_Game", "2", "09:00", "17:00"),
        ]);

        _enforcer.SweepAt(Wednesday.AddHours(12));

        _hosts.GetBlocked().Should().Contain("ads.example.com");
        _fw.Rules["HG_Block_Game"].Enabled.Should().BeTrue();
    }
}
