using System.Runtime.Versioning;
using FluentAssertions;
using Grpc.Core;
using HostsGuard.Contracts;
using HostsGuard.Core;
using HostsGuard.Data;
using HostsGuard.Windows;
using Microsoft.Data.Sqlite;
using Xunit;

namespace HostsGuard.Service.Tests;

/// <summary>
/// Direct in-proc RPC tests for <see cref="PolicyServiceImpl"/> — request
/// validation, error-code mapping, and lock-gating for the schedule/profile/lock/
/// network/portable-policy surface. Previously only the coordinators behind these
/// handlers were tested, not the handler layer itself.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class PolicyServiceTests : IDisposable
{
    private readonly string _dir;
    private readonly ServiceState _state;
    private readonly PolicyServiceImpl _policy;

    public PolicyServiceTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "hg_policy_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        File.WriteAllText(Path.Combine(_dir, "hosts"), "# hosts\n");
        _state = new ServiceState(
            new HostsEngine(Path.Combine(_dir, "hosts")),
            new HostsDatabase(Path.Combine(_dir, "hostsguard.db")),
            dataDir: _dir);
        _policy = new PolicyServiceImpl(_state);
    }

    // The policy handlers never read the ServerCallContext.
    private static ServerCallContext Ctx => null!;

    [Fact]
    public async Task SetSchedules_validates_target_time_and_days()
    {
        (await _policy.SetSchedules(new ScheduleList { Schedules = { new Schedule { Target = "", Start = "09:00", End = "17:00", Days = { 0 } } } }, Ctx))
            .ErrorCode.Should().Be("hostsguard.error.v1/invalid_schedule");
        (await _policy.SetSchedules(new ScheduleList { Schedules = { new Schedule { Target = "work", Start = "9am", End = "17:00", Days = { 0 } } } }, Ctx))
            .ErrorCode.Should().Be("hostsguard.error.v1/invalid_schedule");
        (await _policy.SetSchedules(new ScheduleList { Schedules = { new Schedule { Target = "work", Start = "09:00", End = "17:00", Days = { 9 } } } }, Ctx))
            .ErrorCode.Should().Be("hostsguard.error.v1/invalid_schedule");
    }

    [Fact]
    public async Task SetSchedules_round_trips_a_valid_schedule()
    {
        var ack = await _policy.SetSchedules(
            new ScheduleList { Schedules = { new Schedule { Target = "social", Start = "08:30", End = "18:00", Days = { 0, 1, 2 } } } }, Ctx);
        ack.Ok.Should().BeTrue();

        var s = (await _policy.GetSchedules(new Empty(), Ctx)).Schedules.Should().ContainSingle().Subject;
        s.Target.Should().Be("social");
        s.Start.Should().Be("08:30");
        s.Days.Should().BeEquivalentTo(new[] { 0, 1, 2 });
    }

    [Fact]
    public async Task Profile_crud_validates_names()
    {
        (await _policy.SaveProfile(new ProfileRequest { Name = "  " }, Ctx)).ErrorCode.Should().Be("hostsguard.error.v1/invalid_profile");
        (await _policy.SwitchProfile(new ProfileRequest { Name = "ghost" }, Ctx)).ErrorCode.Should().Be("hostsguard.error.v1/unknown_profile");
        (await _policy.DeleteProfile(new ProfileRequest { Name = "ghost" }, Ctx)).ErrorCode.Should().Be("hostsguard.error.v1/unknown_profile");

        (await _policy.SaveProfile(new ProfileRequest { Name = "evening" }, Ctx)).Ok.Should().BeTrue();
        (await _policy.ListProfiles(new Empty(), Ctx)).Names.Should().Contain("evening");
    }

    [Fact]
    public async Task Lock_lifecycle_and_locked_gating()
    {
        (await _policy.GetLockState(new Empty(), Ctx)).Enabled.Should().BeFalse();
        (await _policy.SetLock(new LockRequest { Action = "enable", Password = "s3cret" }, Ctx)).Ok.Should().BeTrue();
        (await _policy.GetLockState(new Empty(), Ctx)).Enabled.Should().BeTrue();

        var replacement = await _policy.SetLock(new LockRequest { Action = "enable", Password = "attacker" }, Ctx);
        replacement.ErrorCode.Should().Be("hostsguard.error.v1/lock_already_enabled");

        // Unknown lock action → lock error.
        (await _policy.SetLock(new LockRequest { Action = "sideways", Password = "s3cret" }, Ctx))
            .ErrorCode.Should().Be("hostsguard.error.v1/lock");

        // A policy mutation is gated before its own logic runs.
        (await _policy.SetSchedules(new ScheduleList(), Ctx))
            .ErrorCode.Should().Be("hostsguard.error.v1/locked");

        // Protective recovery remains callable; the independent no-relaxation
        // guard still refuses attempts to weaken the hosts-file ACL.
        (await _policy.SetHostsProtection(new HostsProtectionRequest { Enabled = false }, Ctx))
            .ErrorCode.Should().Be("hostsguard.error.v1/acl_relax_unsupported");
    }

    [Fact]
    public async Task Unlock_rejects_a_wrong_password()
    {
        await _policy.SetLock(new LockRequest { Action = "enable", Password = "correct-horse" }, Ctx);
        var bad = await _policy.Unlock(new LockRequest { Password = "wrong", Minutes = 5 }, Ctx);
        bad.Ok.Should().BeFalse();
        bad.ErrorCode.Should().Be("hostsguard.error.v1/lock");
    }

    [Fact]
    public async Task Repeated_lock_failures_raise_one_deduplicated_alert_and_success_resets_the_budget()
    {
        var now = new DateTime(2026, 7, 14, 12, 0, 0, DateTimeKind.Utc);
        var policy = new PolicyServiceImpl(_state, () => now);
        await policy.SetLock(new LockRequest { Action = "enable", Password = "correct-password" }, Ctx);

        (await policy.Unlock(new LockRequest { Password = "wrong" }, Ctx)).ErrorCode
            .Should().Be("hostsguard.error.v1/lock");
        now = now.AddSeconds(1);
        await policy.Unlock(new LockRequest { Password = "wrong" }, Ctx);
        now = now.AddSeconds(2);
        await policy.Unlock(new LockRequest { Password = "wrong" }, Ctx);

        var throttled = await policy.Unlock(new LockRequest { Password = "correct-password" }, Ctx);
        throttled.ErrorCode.Should().Be("hostsguard.error.v1/lock_throttled");
        var alert = _state.Db.GetAlerts(new AlertFilter(Type: "settings_lock_security"))
            .Rows.Should().ContainSingle().Subject;
        alert.Action.Should().Be("password_failures");
        alert.Details.Should().Contain("30 seconds").And.Contain("no protected posture changed");

        now = now.AddSeconds(4);
        (await policy.Unlock(new LockRequest { Password = "correct-password", Minutes = 5 }, Ctx)).Ok.Should().BeTrue();
        var status = await policy.GetLockState(new Empty(), Ctx);
        status.FailedAttempts.Should().Be(0);
        status.RetryAfterSeconds.Should().Be(0);
        status.Unlocked.Should().BeTrue();
    }

    [Fact]
    public async Task SetNetworkProfile_validates_criteria_and_profile()
    {
        (await _policy.SetNetworkProfile(new NetworkProfileEntry { Profile = "work" }, Ctx))
            .ErrorCode.Should().Be("hostsguard.error.v1/invalid_network");
        (await _policy.SetNetworkProfile(new NetworkProfileEntry { Profile = "work", Ssid = "CorpWifi" }, Ctx))
            .ErrorCode.Should().Be("hostsguard.error.v1/unknown_profile");
    }

    [Fact]
    public async Task ExportPolicy_round_trips_through_preview_and_bad_json_is_rejected()
    {
        var doc = await _policy.ExportPolicy(new Empty(), Ctx);
        doc.Json.Should().NotBeNullOrWhiteSpace();

        var preview = await _policy.PreviewPolicyImport(new ImportPolicyRequest { Json = doc.Json }, Ctx);
        preview.Ok.Should().BeTrue();
        preview.Preview.Should().BeTrue();

        var bad = await _policy.PreviewPolicyImport(new ImportPolicyRequest { Json = "{ not valid" }, Ctx);
        bad.Ok.Should().BeFalse();
        bad.ErrorCode.Should().Be("hostsguard.error.v1/invalid_policy");
    }

    [Fact]
    public async Task ImportPolicy_is_gated_when_locked()
    {
        await _policy.SetLock(new LockRequest { Action = "enable", Password = "s3cret" }, Ctx);
        var doc = await _policy.ExportPolicy(new Empty(), Ctx);

        var result = await _policy.ImportPolicy(new ImportPolicyRequest { Json = doc.Json }, Ctx);
        result.Ok.Should().BeFalse();
        result.ErrorCode.Should().Be("hostsguard.error.v1/locked");
    }

    [Theory]
    [InlineData("pbkdf2_sha256$2147483647$MDEyMzQ1Njc4OWFiY2RlZg==$MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")]
    [InlineData("pbkdf2_sha256$600000$MDEyMzQ1Njc4OWFiY2RlZg==$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    public async Task Policy_import_rejects_unsafe_lock_hash_before_mutation(string hash)
    {
        var json = $$"""
            {
              "Version": 1,
              "Domains": [ { "Domain": "must-not-import.example", "Status": "blocked", "Source": "test" } ],
              "Lock": { "Enabled": true, "Hash": "{{hash}}" }
            }
            """;

        var result = await _policy.ImportPolicy(new ImportPolicyRequest { Json = json }, Ctx);

        result.Ok.Should().BeFalse();
        result.ErrorCode.Should().Be("hostsguard.error.v1/invalid_policy");
        _state.Db.GetDomainStatus("must-not-import.example").Should().BeNull();
        _state.Lock.Enabled.Should().BeFalse();
        _state.Db.GetLatestPolicyImportCheckpoint().Should().BeNull();
    }

    public void Dispose()
    {
        _state.Dispose();
        SqliteConnection.ClearAllPools();
        try { Directory.Delete(_dir, true); } catch (IOException) { /* best effort */ }
    }
}
