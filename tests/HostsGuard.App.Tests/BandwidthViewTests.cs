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
        vm.BandwidthStatus.Should().Contain("Top 1 app").And.NotContain("Top 1 apps");
    }

    [Fact]
    public void Usage_rollup_row_formats_sent_received_and_total_bytes()
    {
        var row = new UsageRollupRowViewModel
        {
            Sent = 1024,
            Recv = 1536,
        };

        row.SentText.Should().Be("1 KB");
        row.RecvText.Should().Be("1.5 KB");
        row.Total.Should().Be(2560);
        row.TotalText.Should().Be("2.5 KB");
    }

    [Theory]
    [InlineData("1024", 1024)]
    [InlineData("1KB", 1024)]
    [InlineData("1.5MB", 1572864)]
    [InlineData("1GB", 1073741824)]
    public void Usage_quota_byte_parser_accepts_common_units(string text, long expected)
    {
        FwActivityViewModel.TryParseBytes(text, out var bytes).Should().BeTrue();
        bytes.Should().Be(expected);
    }

    [Fact]
    public void Usage_quota_row_formats_budget_state()
    {
        var row = new UsageQuotaRuleViewModel
        {
            LimitBytes = 1024 * 1024,
            UsedBytes = 512 * 1024,
            LastAlertedBytes = 512 * 1024,
            LastAlertedAt = "2026-07-08T12:00:00.0000000Z",
        };

        row.LimitText.Should().Be("1 MB");
        row.UsedText.Should().Be("512 KB");
        row.PercentText.Should().Be("50%");
        row.LastAlertedText.Should().Contain("512 KB");
    }

    [Fact]
    public void History_csv_has_a_header_and_rfc4180_quotes_fields_with_commas()
    {
        var rows = new[]
        {
            new HistoryRowViewModel
            {
                Ts = "2026-07-03T10:00:00", Process = "chrome", Pid = 42, Protocol = "TCP",
                Host = "cdn.example.com", RemoteAddr = "203.0.113.9", RemotePort = 443, Country = "US", FwStatus = "allowed",
            },
            new HistoryRowViewModel
            {
                Ts = "2026-07-03T10:01:00", Process = "Some App, Inc", Pid = 7, Protocol = "UDP",
                Host = "resolver.example.net", RemoteAddr = "198.51.100.4", RemotePort = 53, Country = "", FwStatus = "blocked",
            },
            new HistoryRowViewModel
            {
                Ts = "2026-07-03T10:02:00", Process = "=calc.exe", Pid = 8, Protocol = "TCP",
                Host = "  @example.net", RemoteAddr = "203.0.113.10", RemotePort = 443, Country = "US", FwStatus = "+allowed",
            },
        };

        var csv = FwActivityViewModel.BuildHistoryCsv(rows);
        var lines = csv.Split("\r\n", StringSplitOptions.RemoveEmptyEntries);

        lines[0].Should().Be("When,Process,PID,Protocol,Host,Remote,Port,Country,Firewall");
        lines[1].Should().Be("2026-07-03T10:00:00,chrome,42,TCP,cdn.example.com,203.0.113.9,443,US,allowed");
        // The process name with a comma is quoted so it stays one column.
        lines[2].Should().Contain("\"Some App, Inc\"");
        lines[3].Should().Be("2026-07-03T10:02:00,'=calc.exe,8,TCP,'  @example.net,203.0.113.10,443,US,'+allowed");
    }
}
