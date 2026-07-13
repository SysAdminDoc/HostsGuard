using System.Runtime.Versioning;
using FluentAssertions;
using HostsGuard.Windows;
using Xunit;

namespace HostsGuard.Windows.Tests;

[SupportedOSPlatform("windows")]
public class DnsMonitorTests
{
    [Theory]
    [InlineData(null, "A")]
    [InlineData(1, "A")]
    [InlineData((ushort)28, "AAAA")]
    [InlineData("16", "TXT")]
    [InlineData(5, "CNAME")]
    [InlineData(10, "NULL")]
    [InlineData(64, "SVCB")]
    [InlineData(65, "HTTPS")]
    [InlineData(99, "99")]
    public void Query_type_is_normalized_from_ETW_payload(object? value, string expected)
    {
        DnsMonitor.NormalizeQueryType(value).Should().Be(expected);
    }

    [Fact]
    public void Start_reports_status_without_throwing()
    {
        using var monitor = new DnsMonitor("HostsGuardDnsTest_" + Guid.NewGuid().ToString("N")[..8]);

        // Non-throwing regardless of elevation. Unelevated → RequiresElevation;
        // elevated → Started (a real ETW session). Either is a valid outcome.
        var status = monitor.Start();
        status.Should().BeOneOf(DnsMonitorStatus.RequiresElevation, DnsMonitorStatus.Started, DnsMonitorStatus.Unavailable);

        if (!DnsMonitor.IsElevated())
        {
            status.Should().Be(DnsMonitorStatus.RequiresElevation);
        }
    }
}
