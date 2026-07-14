using FluentAssertions;
using HostsGuard.Windows;

namespace HostsGuard.Windows.Tests;

public sealed class ObservationIntegrityTests
{
    [Fact]
    public void Loss_interval_recovers_without_erasing_counters()
    {
        var tracker = new ObservationIntegrityTracker(
            "dns_etw",
            new DateTime(2026, 7, 14, 12, 0, 0, DateTimeKind.Utc));

        tracker.Started();
        tracker.ObserveSourceLossTotal(7);
        var degraded = tracker.Snapshot();
        degraded.State.Should().Be(ObservationIntegrityState.Degraded);
        degraded.LossCount.Should().Be(7);
        degraded.IncompleteSinceUtc.Should().NotBeNull();

        tracker.ObserveSourceLossTotal(7);
        var recovered = tracker.Snapshot();
        recovered.State.Should().Be(ObservationIntegrityState.Healthy);
        recovered.LossCount.Should().Be(7);
        recovered.IncompleteSinceUtc.Should().BeNull();
    }

    [Fact]
    public void Restart_and_gap_counts_are_cumulative()
    {
        var tracker = new ObservationIntegrityTracker("network_etw");

        tracker.Started();
        tracker.Unavailable("pump failed");
        tracker.Started();
        tracker.RecordGap(3, "records unavailable");

        var snapshot = tracker.Snapshot();
        snapshot.RestartCount.Should().Be(1);
        snapshot.GapCount.Should().Be(4, "the pump interruption and three explicit gaps are distinct");
        snapshot.State.Should().Be(ObservationIntegrityState.Degraded);
    }
}
