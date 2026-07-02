using System.Runtime.Versioning;
using FluentAssertions;
using HostsGuard.Contracts;
using HostsGuard.Data;
using HostsGuard.Windows;
using Microsoft.Data.Sqlite;
using Xunit;

namespace HostsGuard.Service.Tests;

/// <summary>NET-079: the settings lock and its enforcement on mutating RPCs.</summary>
[SupportedOSPlatform("windows")]
public sealed class SettingsLockTests : IDisposable
{
    private readonly string _dir;
    private readonly ServiceState _state;
    private readonly FakeFirewallEngine _fw = new();

    public SettingsLockTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "hg_lock_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        var hostsPath = Path.Combine(_dir, "hosts");
        File.WriteAllText(hostsPath, "# hosts\n");
        _state = new ServiceState(new HostsEngine(hostsPath), new HostsDatabase(Path.Combine(_dir, "hostsguard.db")),
            firewall: _fw, dataDir: _dir);
    }

    public void Dispose()
    {
        _state.Dispose();
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

    [Fact]
    public void Enable_requires_a_reasonable_password()
    {
        _state.Lock.Enable("ab").Ok.Should().BeFalse();
        _state.Lock.Enable("goodpass").Ok.Should().BeTrue();
        _state.Lock.Enabled.Should().BeTrue();
    }

    [Fact]
    public void Locked_state_tracks_timed_unlock()
    {
        var now = DateTime.UtcNow;
        _state.Lock.Enable("pw12");

        _state.Lock.IsLocked(now).Should().BeTrue();
        _state.Lock.Unlock("pw12", 5, now).Ok.Should().BeTrue();
        _state.Lock.IsLocked(now.AddMinutes(3)).Should().BeFalse();  // inside window
        _state.Lock.IsLocked(now.AddMinutes(6)).Should().BeTrue();   // window elapsed
    }

    [Fact]
    public void Unlock_and_disable_reject_wrong_password()
    {
        _state.Lock.Enable("pw12");
        _state.Lock.Unlock("nope", 5, DateTime.UtcNow).Ok.Should().BeFalse();
        _state.Lock.Disable("nope").Ok.Should().BeFalse();
        _state.Lock.Disable("pw12").Ok.Should().BeTrue();
        _state.Lock.Enabled.Should().BeFalse();
    }

    [Fact]
    public void Lock_survives_a_reload_from_disk()
    {
        _state.Lock.Enable("persist1");
        var reloaded = new SettingsLock(_dir);

        reloaded.Enabled.Should().BeTrue();
        reloaded.IsLocked(DateTime.UtcNow).Should().BeTrue();  // timed-unlock is not persisted
        reloaded.Unlock("persist1", 1, DateTime.UtcNow).Ok.Should().BeTrue();
    }

    [Fact]
    public async Task Locked_service_refuses_mode_and_rule_changes()
    {
        _state.Lock.Enable("locked1");
        var consent = new ConsentServiceImpl(_state);
        var firewall = new FirewallControlServiceImpl(_state);

        (await consent.SetMode(new FilteringMode { Mode = "notify" }, null!)).ErrorCode.Should().Contain("locked");
        (await firewall.SetGlobalMode(new GlobalModeRequest { Mode = "block-all" }, null!)).ErrorCode.Should().Contain("locked");
        (await firewall.DeleteRule(new RuleNameRequest { Name = "HG_Test" }, null!)).ErrorCode.Should().Contain("locked");

        // After a timed unlock the same calls proceed (mode actually switches).
        _state.Lock.Unlock("locked1", 5, DateTime.UtcNow);
        (await consent.SetMode(new FilteringMode { Mode = "notify" }, null!)).Ok.Should().BeTrue();
    }
}
