using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text.Json;
using FluentAssertions;
using HostsGuard.Contracts;
using HostsGuard.Core;
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
    public void Enable_never_replaces_an_armed_password()
    {
        var now = new DateTime(2026, 7, 14, 12, 0, 0, DateTimeKind.Utc);
        _state.Lock.Enable("original-password").Ok.Should().BeTrue();

        var replacement = _state.Lock.Enable("attacker-password");

        replacement.Ok.Should().BeFalse();
        replacement.ErrorCode.Should().Be("lock_already_enabled");
        _state.Lock.Unlock("original-password", 5, now).Ok.Should().BeTrue();
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
        var now = new DateTime(2026, 7, 14, 12, 0, 0, DateTimeKind.Utc);
        _state.Lock.Enable("pw12");
        _state.Lock.Unlock("nope", 5, now).Ok.Should().BeFalse();
        _state.Lock.Disable("nope", now.AddSeconds(1)).Ok.Should().BeFalse();
        _state.Lock.Disable("pw12", now.AddSeconds(3)).Ok.Should().BeTrue();
        _state.Lock.Enabled.Should().BeFalse();
    }

    [Fact]
    public void Wrong_passwords_use_a_bounded_non_blocking_throttle_and_success_resets_it()
    {
        var now = new DateTime(2026, 7, 14, 12, 0, 0, DateTimeKind.Utc);
        _state.Lock.Enable("correct-password");

        var first = _state.Lock.Unlock("wrong", 5, now);
        first.RetryAfterSeconds.Should().Be(1);
        first.ReportSecurityEvent.Should().BeFalse();
        var second = _state.Lock.Unlock("wrong", 5, now = now.AddSeconds(first.RetryAfterSeconds));
        second.RetryAfterSeconds.Should().Be(2);
        second.ReportSecurityEvent.Should().BeFalse();
        var third = _state.Lock.Unlock("wrong", 5, now = now.AddSeconds(second.RetryAfterSeconds));
        third.RetryAfterSeconds.Should().Be(4);
        third.ReportSecurityEvent.Should().BeTrue();

        var throttled = _state.Lock.Unlock("correct-password", 5, now);
        throttled.ErrorCode.Should().Be("lock_throttled");
        throttled.ReportSecurityEvent.Should().BeFalse();
        throttled.RetryAfterSeconds.Should().Be(4);
        throttled.RetryAfterSeconds.Should().BeLessThanOrEqualTo((int)SettingsLock.MaxRetryDelay.TotalSeconds);

        now = now.AddSeconds(throttled.RetryAfterSeconds);
        _state.Lock.Unlock("correct-password", 5, now).Ok.Should().BeTrue();
        var status = _state.Lock.GetStatus(now);
        status.FailedAttempts.Should().Be(0);
        status.RetryAfterSeconds.Should().Be(0);
    }

    [Fact]
    public void Corrupt_persisted_state_fails_closed_and_reports_an_admin_recovery_path()
    {
        var corruptDir = Path.Combine(_dir, "corrupt");
        Directory.CreateDirectory(corruptDir);
        var statePath = Path.Combine(corruptDir, "lock_state.json");
        File.WriteAllText(statePath, "{ not valid json");

        var loaded = new SettingsLock(corruptDir);
        var status = loaded.GetStatus(DateTime.UtcNow);

        status.Enabled.Should().BeTrue();
        status.Locked.Should().BeTrue();
        status.Degraded.Should().BeTrue();
        status.Message.Should().Contain("Stop HostsGuardSvc").And.Contain("lock_state.json");
        loaded.Enable("replacement-password").ErrorCode.Should().Be("lock_state_corrupt");
        loaded.Unlock("replacement-password", 5, DateTime.UtcNow).ErrorCode.Should().Be("lock_state_corrupt");
        loaded.Disable("replacement-password", DateTime.UtcNow).ErrorCode.Should().Be("lock_state_corrupt");
        File.ReadAllText(statePath).Should().Be("{ not valid json");
    }

    [Fact]
    public void Service_startup_surfaces_one_corrupt_lock_alert_without_unlocking()
    {
        var corruptDir = Path.Combine(_dir, "corrupt_service");
        Directory.CreateDirectory(corruptDir);
        File.WriteAllText(Path.Combine(corruptDir, "hosts"), "# hosts\n");
        File.WriteAllText(Path.Combine(corruptDir, "lock_state.json"), "{ not valid json");
        using var state = new ServiceState(
            new HostsEngine(Path.Combine(corruptDir, "hosts")),
            new HostsDatabase(Path.Combine(corruptDir, "hostsguard.db")),
            dataDir: corruptDir);

        state.GateWhenLocked().Should().NotBeNull();
        var alert = state.Db.GetAlerts(new AlertFilter(Type: "settings_lock_security"))
            .Rows.Should().ContainSingle().Subject;
        alert.Severity.Should().Be("critical");
        alert.Action.Should().Be("state_corrupt");
        alert.Details.Should().Contain("lock_state.json");
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
    public void Successful_unlock_upgrades_a_legacy_hash_on_disk()
    {
        const string password = "legacy-password";
        var salt = Enumerable.Range(0, 16).Select(i => (byte)i).ToArray();
        var hash = Rfc2898DeriveBytes.Pbkdf2(
            password,
            salt,
            PasswordHash.MinimumAcceptedIterations,
            HashAlgorithmName.SHA256,
            32);
        var legacy = $"pbkdf2_sha256${PasswordHash.MinimumAcceptedIterations}${Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}";
        File.WriteAllText(
            Path.Combine(_dir, "lock_state.json"),
            JsonSerializer.Serialize(new { Enabled = true, Hash = legacy }));
        var loaded = new SettingsLock(_dir);

        loaded.Unlock(password, 5, DateTime.UtcNow).Ok.Should().BeTrue();

        using var document = JsonDocument.Parse(File.ReadAllText(Path.Combine(_dir, "lock_state.json")));
        var upgraded = document.RootElement.GetProperty("Hash").GetString();
        upgraded.Should().StartWith($"pbkdf2_sha256${PasswordHash.Iterations}$");
        upgraded.Should().NotBe(legacy);
        PasswordHash.Verify(password, upgraded, out var needsRehash).Should().BeTrue();
        needsRehash.Should().BeFalse();
    }

    [Fact]
    public void Wrong_password_does_not_upgrade_a_legacy_hash()
    {
        const string legacy = "pbkdf2_sha256$210000$AAECAwQFBgcICQoLDA0ODw==$dwuexifK4Fe/1NquYoJuiWZKOFaR+Cy7JI8GAbc+U/4=";
        var path = Path.Combine(_dir, "lock_state.json");
        File.WriteAllText(path, JsonSerializer.Serialize(new { Enabled = true, Hash = legacy }));
        var loaded = new SettingsLock(_dir);

        loaded.Unlock("wrong-password", 5, DateTime.UtcNow).Ok.Should().BeFalse();

        using var document = JsonDocument.Parse(File.ReadAllText(path));
        document.RootElement.GetProperty("Hash").GetString().Should().Be(legacy);
    }

    [Fact]
    public async Task Locked_service_refuses_mode_and_rule_changes()
    {
        _state.Lock.Enable("locked1");
        var consent = new ConsentServiceImpl(_state);
        var firewall = new FirewallControlServiceImpl(_state);
        var dns = new DnsControlServiceImpl(_state);

        (await consent.SetMode(new FilteringMode { Mode = "notify" }, null!)).ErrorCode.Should().Contain("locked");
        (await consent.Decide(new ConnectionDecision(), null!)).ErrorCode.Should().Contain("locked");
        (await consent.ApplyBaseline(new Empty(), null!)).ErrorCode.Should().Contain("locked");
        (await consent.ReviewLearned(new LearnedReviewRequest(), null!)).ErrorCode.Should().Contain("locked");
        (await firewall.SetGlobalMode(new GlobalModeRequest { Mode = "block-all" }, null!)).ErrorCode.Should().Contain("locked");
        (await firewall.PauseEnforcement(new EnforcementPauseRequest { Minutes = 5 }, null!)).ErrorCode.Should().Contain("locked");
        (await firewall.DeleteRule(new RuleNameRequest { Name = "HG_Test" }, null!)).ErrorCode.Should().Contain("locked");
        (await firewall.SetRuleEnabled(new RuleEnabledRequest { Name = "HG_Test", Enabled = false }, null!)).ErrorCode.Should().Contain("locked");
        (await firewall.SetFlowTeardown(new FlowTeardownRequest { Enabled = false }, null!)).ErrorCode.Should().Contain("locked");
        (await firewall.UnblockQuic(new Empty(), null!)).ErrorCode.Should().Contain("locked");
        (await firewall.UnblockEncryptedDns(new Empty(), null!)).ErrorCode.Should().Contain("locked");
        (await firewall.RebindRule(new RebindRequest(), null!)).ErrorCode.Should().Contain("locked");
        (await firewall.SetSecureRules(new SecureRulesRequest { Enabled = false }, null!)).ErrorCode.Should().Contain("locked");
        (await dns.SetCnameCloak(new CnameCloakRequest { Enabled = false }, null!)).ErrorCode.Should().Contain("locked");

        // Protective emergency actions remain available without weakening the lock.
        (await firewall.BlockIp(new FirewallIpRequest { Address = "203.0.113.10", Direction = "out" }, null!)).Ok.Should().BeTrue();
        (await firewall.BlockQuic(new Empty(), null!)).Ok.Should().BeTrue();

        // After a timed unlock the same calls proceed (mode actually switches).
        _state.Lock.Unlock("locked1", 5, DateTime.UtcNow);
        (await consent.SetMode(new FilteringMode { Mode = "notify" }, null!)).Ok.Should().BeTrue();
    }
}
