using FluentAssertions;
using HostsGuard.App.Services;
using HostsGuard.Contracts;

namespace HostsGuard.App.Tests;

public sealed class ObservationIntegrityTextTests
{
    [Fact]
    public void Healthy_sources_do_not_add_a_feed_warning()
    {
        var status = Status(new ObservationSourceHealth
        {
            Source = "dns_etw",
            State = "healthy",
        });

        ObservationIntegrityText.ForFeed(status, "dns_etw").Should().BeEmpty();
    }

    [Fact]
    public void Incomplete_source_labels_interval_and_counters()
    {
        var status = Status(new ObservationSourceHealth
        {
            Source = "security_log",
            State = "degraded",
            LossCount = 2,
            GapCount = 9,
            RestartCount = 1,
            IncompleteSince = "2026-07-14T12:00:00.0000000Z",
            LastTransitionAt = "2026-07-14T12:00:00.0000000Z",
            Detail = "Security log rolled over",
        });

        var text = ObservationIntegrityText.ForFeed(status, "security_log");
        text.Should().Contain("Evidence is incomplete")
            .And.Contain("Security log")
            .And.Contain("lost 2")
            .And.Contain("gaps 9")
            .And.Contain("restarts 1")
            .And.Contain("rolled over");
    }

    private static ServiceStatus Status(params ObservationSourceHealth[] sources)
    {
        var status = new ServiceStatus();
        status.ObservationSources.AddRange(sources);
        return status;
    }
}
