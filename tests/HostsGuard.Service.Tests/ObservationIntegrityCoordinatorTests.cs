using FluentAssertions;
using HostsGuard.Data;
using HostsGuard.Windows;
using Microsoft.Data.Sqlite;

namespace HostsGuard.Service.Tests;

public sealed class ObservationIntegrityCoordinatorTests : IDisposable
{
    private readonly string _dir = Path.Combine(
        Path.GetTempPath(), "hg_observation_" + Guid.NewGuid().ToString("N"));
    private readonly HostsDatabase _db;

    public ObservationIntegrityCoordinatorTests()
    {
        Directory.CreateDirectory(_dir);
        _db = new HostsDatabase(Path.Combine(_dir, "db.sqlite"));
    }

    [Fact]
    public void Integrity_alerts_dedupe_and_include_actionable_remediation()
    {
        using var dns = new DnsMonitor("HostsGuardDnsIntegrityTest");
        using var network = new BandwidthMonitor("HostsGuardNetworkIntegrityTest");
        using var security = new BlockedConnectionWatch(new DevicePathMapper(), _ => { });
        using var coordinator = new ObservationIntegrityCoordinator(dns, network, security, _db);

        coordinator.ReportAuditPolicyLoss();
        coordinator.ReportAuditPolicyLoss();
        coordinator.ReportSecurityLogRollover(25);
        coordinator.ReportSecurityLogRollover(40);

        var alerts = _db.GetAlerts(new AlertFilter(
            Type: "observation_integrity",
            SurfaceOnly: false)).Rows;
        alerts.Should().HaveCount(2, "each unresolved integrity condition is one low-volume alert");
        alerts.Should().Contain(row => row.Subject == "security_audit_policy"
            && row.Details.Contains("Local Security Policy", StringComparison.Ordinal));
        alerts.Should().Contain(row => row.Subject == "security_log_rollover"
            && row.Details.Contains("40 Security-log record", StringComparison.Ordinal)
            && row.Details.Contains("maximum size", StringComparison.Ordinal));
    }

    public void Dispose()
    {
        _db.Dispose();
        SqliteConnection.ClearAllPools();
        try
        {
            Directory.Delete(_dir, recursive: true);
        }
        catch (IOException)
        {
            // Best-effort test cleanup.
        }
    }
}
