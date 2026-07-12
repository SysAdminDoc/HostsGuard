using FluentAssertions;
using HostsGuard.Data;
using HostsGuard.Windows;
using Xunit;

namespace HostsGuard.Service.Tests;

public sealed class PortScanAlertMonitorTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), $"hostsguard-portscan-{Guid.NewGuid():N}");
    private readonly HostsDatabase _db;

    public PortScanAlertMonitorTests()
    {
        Directory.CreateDirectory(_dir);
        _db = new HostsDatabase(Path.Combine(_dir, "state.db"));
    }

    [Fact]
    public void Emits_one_alert_and_audit_row_before_consent_mode_can_filter_the_event()
    {
        var detector = new BlockedPortScanDetector(
            threshold: 3,
            window: TimeSpan.FromMinutes(1),
            cooldown: TimeSpan.FromMinutes(1));
        var monitor = new PortScanAlertMonitor(_db, detector);
        var first = DateTime.UtcNow;

        monitor.Observe(Inbound(first, 22)).Should().BeNull();
        monitor.Observe(Inbound(first.AddSeconds(1), 80)).Should().BeNull();
        monitor.Observe(Inbound(first.AddSeconds(2), 443)).Should().NotBeNull();
        monitor.Observe(Inbound(first.AddSeconds(3), 3389)).Should().BeNull();

        var alert = _db.GetAlerts(new AlertFilter(Type: "port_scan", SurfaceOnly: false)).Rows.Should().ContainSingle().Subject;
        alert.Subject.Should().Be("8.8.8.8");
        alert.Details.Should().Contain("3 distinct local ports").And.Contain("22, 80, 443");

        var audit = _db.GetEvents(new EventLogFilter(Action: "port_scan")).Rows.Should().ContainSingle().Subject;
        audit.Domain.Should().Be("8.8.8.8");
        audit.Details.ToLowerInvariant().Should().NotContain("payload");
    }

    [Fact]
    public void Ignores_outbound_and_invalid_local_endpoint_inputs()
    {
        var detector = new BlockedPortScanDetector(threshold: 2);
        var monitor = new PortScanAlertMonitor(_db, detector);
        var now = DateTime.UtcNow;

        monitor.Observe(Inbound(now, 0)).Should().BeNull();
        monitor.Observe(Inbound(now, 80) with { Direction = "Out" }).Should().BeNull();
        monitor.Observe(Inbound(now.AddSeconds(1), 443) with { Direction = "Out" }).Should().BeNull();

        _db.GetAlerts(new AlertFilter(Type: "port_scan", SurfaceOnly: false)).Rows.Should().BeEmpty();
    }

    private static BlockedConnection Inbound(DateTime timestamp, int localPort) => new(
        timestamp,
        @"C:\Windows\System32\svchost.exe",
        "In",
        "8.8.8.8",
        53123,
        "TCP",
        1200,
        5157,
        LocalAddress: "192.168.1.10",
        LocalPort: localPort);

    public void Dispose()
    {
        _db.Dispose();
        try { Directory.Delete(_dir, recursive: true); } catch (IOException) { }
    }
}
