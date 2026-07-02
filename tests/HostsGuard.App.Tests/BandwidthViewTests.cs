using FluentAssertions;
using HostsGuard.App.Services;
using HostsGuard.App.ViewModels;
using HostsGuard.Contracts;
using HostsGuard.Ipc;
using Xunit;

namespace HostsGuard.App.Tests;

/// <summary>
/// NET-070 bandwidth view: byte humanization and the polyline series builder.
/// The client channel is lazy — nothing here touches the wire.
/// </summary>
public sealed class BandwidthViewTests
{
    private static FwActivityViewModel CreateVm() => new(
        new HostsServiceClient(NamedPipeChannel.Create(SessionToken.Generate(), "hg-bw-none")),
        new FakeConfirm(true));

    [Theory]
    [InlineData(0, "0 B")]
    [InlineData(512, "512 B")]
    [InlineData(1024, "1 KB")]
    [InlineData(1536, "1.5 KB")]
    [InlineData(1048576, "1 MB")]
    [InlineData(1467226030, "1.4 GB")]
    public void FormatBytes_humanizes(long bytes, string expected) =>
        FwActivityViewModel.FormatBytes(bytes).Should().Be(expected);

    [Fact]
    public void Inactive_counters_explain_themselves()
    {
        var vm = CreateVm();

        vm.BuildBandwidthSeries(new AppBandwidthList { CountersActive = false });

        vm.Bandwidth.Should().BeEmpty();
        vm.BandwidthStatus.Should().Contain("inactive");
    }

    [Fact]
    public void Series_build_polylines_with_legend_totals()
    {
        var vm = CreateVm();
        var list = new AppBandwidthList { CountersActive = true };
        var series = new AppBandwidthSeries { Process = "chrome", TotalSent = 2048, TotalRecv = 1048576 };
        series.Bytes.AddRange([0, 100, 200, 50]);
        list.Series.Add(series);

        vm.BuildBandwidthSeries(list);

        var s = vm.Bandwidth.Should().ContainSingle().Subject;
        s.Name.Should().Be("chrome");
        s.LegendText.Should().Be("↑2 KB ↓1 MB");
        s.PointsText.Split(' ').Should().HaveCount(4);
        vm.BandwidthStatus.Should().Contain("Top 1 apps");
    }
}
