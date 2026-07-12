using FluentAssertions;
using HostsGuard.Service;
using Xunit;

namespace HostsGuard.Service.Tests;

public sealed class BlockedPortScanDetectorTests
{
    private static readonly DateTime Start = new(2026, 7, 12, 12, 0, 0, DateTimeKind.Utc);

    [Fact]
    public void Distinct_public_probes_cross_threshold_once_with_bounded_sample()
    {
        var detector = new BlockedPortScanDetector(threshold: 4, cooldown: TimeSpan.FromMinutes(1));

        detector.Observe("8.8.8.8", 21, Start).Should().BeNull();
        detector.Observe("8.8.8.8", 22, Start.AddSeconds(1)).Should().BeNull();
        detector.Observe("8.8.8.8", 23, Start.AddSeconds(2)).Should().BeNull();
        var detection = detector.Observe("8.8.8.8", 443, Start.AddSeconds(3));

        detection.Should().NotBeNull();
        detection!.DistinctPortCount.Should().Be(4);
        detection.SamplePorts.Should().Equal(21, 22, 23, 443);
        detector.Observe("8.8.8.8", 8080, Start.AddSeconds(4)).Should().BeNull();
    }

    [Fact]
    public void Repeated_same_port_never_counts_as_a_scan()
    {
        var detector = new BlockedPortScanDetector(threshold: 3, cooldown: TimeSpan.Zero);
        for (var i = 0; i < 20; i++)
        {
            detector.Observe("1.1.1.1", 443, Start.AddSeconds(i)).Should().BeNull();
        }
    }

    [Fact]
    public void Expired_ports_do_not_accumulate_across_windows()
    {
        var detector = new BlockedPortScanDetector(threshold: 3, window: TimeSpan.FromSeconds(5));
        detector.Observe("8.8.4.4", 20, Start).Should().BeNull();
        detector.Observe("8.8.4.4", 21, Start.AddSeconds(1)).Should().BeNull();
        detector.Observe("8.8.4.4", 22, Start.AddSeconds(7)).Should().BeNull();
    }

    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("10.0.0.1")]
    [InlineData("192.168.1.2")]
    [InlineData("169.254.1.1")]
    [InlineData("100.64.0.1")]
    [InlineData("192.0.2.1")]
    [InlineData("198.51.100.1")]
    [InlineData("203.0.113.1")]
    [InlineData("224.0.0.1")]
    [InlineData("::1")]
    [InlineData("fe80::1")]
    [InlineData("fc00::1")]
    [InlineData("ff02::1")]
    [InlineData("2001:db8::1")]
    public void Non_public_sources_are_excluded(string source)
    {
        var detector = new BlockedPortScanDetector(threshold: 2);
        detector.Observe(source, 80, Start).Should().BeNull();
        detector.Observe(source, 81, Start.AddSeconds(1)).Should().BeNull();
    }

    [Fact]
    public void New_scan_after_expiry_and_cooldown_can_alert_again()
    {
        var detector = new BlockedPortScanDetector(
            threshold: 2,
            window: TimeSpan.FromSeconds(5),
            cooldown: TimeSpan.FromSeconds(5));
        detector.Observe("9.9.9.9", 80, Start).Should().BeNull();
        detector.Observe("9.9.9.9", 81, Start.AddSeconds(1)).Should().NotBeNull();
        detector.Observe("9.9.9.9", 82, Start.AddSeconds(2)).Should().BeNull();
        detector.Observe("9.9.9.9", 90, Start.AddSeconds(10)).Should().BeNull();
        detector.Observe("9.9.9.9", 91, Start.AddSeconds(11)).Should().NotBeNull();
    }

    [Fact]
    public void Invalid_ports_and_addresses_are_ignored()
    {
        var detector = new BlockedPortScanDetector(threshold: 2);
        detector.Observe("not-an-ip", 80, Start).Should().BeNull();
        detector.Observe("8.8.8.8", 0, Start).Should().BeNull();
        detector.Observe("8.8.8.8", 65536, Start).Should().BeNull();
    }

    [Fact]
    public void Global_ipv6_sources_are_detected()
    {
        var detector = new BlockedPortScanDetector(threshold: 2);
        detector.Observe("2606:4700:4700::1111", 80, Start).Should().BeNull();
        detector.Observe("2606:4700:4700::1111", 443, Start.AddSeconds(1)).Should().NotBeNull();
    }

    [Fact]
    public void Port_and_source_caps_evict_oldest_state()
    {
        var detector = new BlockedPortScanDetector(
            threshold: 2,
            cooldown: TimeSpan.Zero,
            maxSources: 1,
            maxPortsPerSource: 2);
        detector.Observe("8.8.8.8", 10, Start).Should().BeNull();
        detector.Observe("8.8.8.8", 11, Start.AddSeconds(1)).Should().NotBeNull();
        var bounded = detector.Observe("8.8.8.8", 12, Start.AddSeconds(2));
        bounded.Should().NotBeNull();
        bounded!.DistinctPortCount.Should().Be(2);
        bounded.SamplePorts.Should().Equal(11, 12);

        detector.Observe("1.1.1.1", 20, Start.AddSeconds(3)).Should().BeNull();
        detector.Observe("8.8.8.8", 13, Start.AddSeconds(4)).Should().BeNull();
    }
}
