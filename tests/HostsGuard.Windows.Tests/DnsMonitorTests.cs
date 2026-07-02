using System.Runtime.Versioning;
using FluentAssertions;
using HostsGuard.Windows;
using Xunit;

namespace HostsGuard.Windows.Tests;

[SupportedOSPlatform("windows")]
public class DnsMonitorTests
{
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
