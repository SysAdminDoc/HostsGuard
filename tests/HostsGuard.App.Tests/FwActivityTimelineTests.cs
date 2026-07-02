using FluentAssertions;
using HostsGuard.App.Services;
using HostsGuard.App.ViewModels;
using HostsGuard.Ipc;
using Xunit;

namespace HostsGuard.App.Tests;

/// <summary>
/// NET-022b per-app timeline: bucket math, top-N series selection, and the
/// polyline geometry stay inside the canvas. The client channel is lazy, so no
/// service is needed — nothing here touches the wire.
/// </summary>
public sealed class FwActivityTimelineTests
{
    private static FwActivityViewModel CreateVm() => new(
        new HostsServiceClient(NamedPipeChannel.Create(SessionToken.Generate(), "hg-timeline-none")),
        new FakeConfirm(true));

    [Fact]
    public void Timeline_selects_top_processes_and_orders_by_volume()
    {
        var vm = CreateVm();
        var now = new DateTime(2026, 7, 2, 12, 0, 0);
        for (var i = 0; i < 9; i++)
        {
            vm.RecordConnectionEvent(now.AddMinutes(-i), "chatty.exe");
        }

        vm.RecordConnectionEvent(now.AddMinutes(-2), "quiet.exe");
        for (var p = 0; p < 6; p++)
        {
            vm.RecordConnectionEvent(now.AddMinutes(-1), $"filler{p}.exe");
        }

        vm.RecomputeTimeline(now);

        vm.Timeline.Should().HaveCount(5); // capped at five series
        vm.Timeline[0].Name.Should().Be("chatty.exe");
        vm.Timeline[0].ColorIndex.Should().Be(0);
        vm.TimelineStatus.Should().Contain("Top 5 apps");
    }

    [Fact]
    public void Points_stay_inside_the_canvas_and_span_the_window()
    {
        var vm = CreateVm();
        var now = new DateTime(2026, 7, 2, 12, 0, 0);
        vm.RecordConnectionEvent(now, "app.exe");
        vm.RecordConnectionEvent(now.AddMinutes(-29), "app.exe");

        vm.RecomputeTimeline(now);

        var series = vm.Timeline.Should().ContainSingle().Subject;
        var points = series.PointsText.Split(' ')
            .Select(p => p.Split(','))
            .Select(xy => (X: double.Parse(xy[0], System.Globalization.CultureInfo.InvariantCulture),
                           Y: double.Parse(xy[1], System.Globalization.CultureInfo.InvariantCulture)))
            .ToList();

        points.Should().HaveCount(FwActivityViewModel.TimelineMinutes);
        points.Should().OnlyContain(p =>
            p.X >= 0 && p.X <= FwActivityViewModel.TimelineWidth &&
            p.Y >= 0 && p.Y <= FwActivityViewModel.TimelineHeight);
        points[0].X.Should().Be(0);
        points[^1].X.Should().Be(FwActivityViewModel.TimelineWidth);
    }

    [Fact]
    public void Events_older_than_the_window_fall_out()
    {
        var vm = CreateVm();
        var now = new DateTime(2026, 7, 2, 12, 0, 0);
        vm.RecordConnectionEvent(now.AddMinutes(-90), "stale.exe");
        vm.RecordConnectionEvent(now, "fresh.exe");

        vm.RecomputeTimeline(now);

        vm.Timeline.Select(s => s.Name).Should().ContainSingle().Which.Should().Be("fresh.exe");
    }

    [Fact]
    public void Empty_window_reports_no_activity()
    {
        var vm = CreateVm();

        vm.RecomputeTimeline(new DateTime(2026, 7, 2, 12, 0, 0));

        vm.Timeline.Should().BeEmpty();
        vm.TimelineStatus.Should().Be("No activity yet");
    }
}
