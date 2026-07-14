using System.Runtime.Versioning;
using FluentAssertions;
using HostsGuard.Data;
using HostsGuard.Windows;
using Microsoft.Data.Sqlite;
using Xunit;

namespace HostsGuard.Service.Tests;

/// <summary>
/// NET-101: a time-boxed Learning window auto-reverts to Normal on expiry (checked
/// by the sweep), leaving the auto-allowed batch for review; an unbounded Learning
/// switch keeps the current behavior.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class LearningAutoLockTests : IDisposable
{
    private readonly string _dir;
    private readonly ServiceState _state;

    public LearningAutoLockTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "hg_autolock_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        File.WriteAllText(Path.Combine(_dir, "hosts"), "# hosts\n");
        _state = new ServiceState(
            new HostsEngine(Path.Combine(_dir, "hosts")),
            new HostsDatabase(Path.Combine(_dir, "hostsguard.db")),
            new FakeFirewallEngine(),
            dataDir: _dir);
    }

    [Fact]
    public void Bounded_learning_reverts_to_normal_on_expiry()
    {
        _state.Consent.SetMode(ConsentBroker.ModeLearning, learnMinutes: 15);
        _state.Consent.Mode.Should().Be(ConsentBroker.ModeLearning);
        _state.Consent.LearnMinutesRemaining.Should().BeInRange(1, 15);

        // Before expiry: still learning.
        _state.Consent.Sweep(DateTime.UtcNow);
        _state.Consent.Mode.Should().Be(ConsentBroker.ModeLearning);

        // After the window: the sweep auto-locks to Normal.
        _state.Consent.Sweep(DateTime.UtcNow.AddMinutes(16));
        _state.Consent.Mode.Should().Be(ConsentBroker.ModeNormal);
        _state.Consent.LearnMinutesRemaining.Should().Be(0);
    }

    [Fact]
    public void Unbounded_learning_never_auto_locks()
    {
        _state.Consent.SetMode(ConsentBroker.ModeLearning);
        _state.Consent.LearnMinutesRemaining.Should().Be(0);

        _state.Consent.Sweep(DateTime.UtcNow.AddHours(48));
        _state.Consent.Mode.Should().Be(ConsentBroker.ModeLearning);
    }

    [Fact]
    public void Bounded_window_persists_across_a_broker_restart()
    {
        _state.Consent.SetMode(ConsentBroker.ModeLearning, learnMinutes: 30);

        using var reloaded = new ConsentBroker(_state.Db, _state.Bus, null, null, _dir);
        reloaded.Mode.Should().Be(ConsentBroker.ModeLearning);
        reloaded.LearnMinutesRemaining.Should().BeInRange(1, 30);
        // The persisted deadline still auto-locks after it elapses.
        reloaded.Sweep(DateTime.UtcNow.AddMinutes(31));
        reloaded.Mode.Should().Be(ConsentBroker.ModeNormal);
    }

    public void Dispose()
    {
        _state.Dispose();
        try { Directory.Delete(_dir, true); } catch (IOException) { /* best effort */ }
    }
}
