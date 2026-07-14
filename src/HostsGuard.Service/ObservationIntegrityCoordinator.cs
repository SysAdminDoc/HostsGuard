using HostsGuard.Data;
using HostsGuard.Windows;

namespace HostsGuard.Service;

/// <summary>
/// Periodically reconciles observation-source health. ETW pumps and the
/// Security-log watcher restart in-process; WFP audit-policy drift is repaired
/// and evidence-window loss is surfaced as deduplicated alerts.
/// </summary>
public sealed class ObservationIntegrityCoordinator : IDisposable
{
    private static readonly TimeSpan DefaultInterval = TimeSpan.FromSeconds(30);

    private readonly DnsMonitor _dns;
    private readonly BandwidthMonitor _network;
    private readonly BlockedConnectionWatch _security;
    private readonly HostsDatabase _db;
    private readonly TimeSpan _interval;
    private Timer? _timer;
    private int _checking;

    public ObservationIntegrityCoordinator(
        DnsMonitor dns,
        BandwidthMonitor network,
        BlockedConnectionWatch security,
        HostsDatabase db,
        TimeSpan? interval = null)
    {
        _dns = dns ?? throw new ArgumentNullException(nameof(dns));
        _network = network ?? throw new ArgumentNullException(nameof(network));
        _security = security ?? throw new ArgumentNullException(nameof(security));
        _db = db ?? throw new ArgumentNullException(nameof(db));
        _interval = interval ?? DefaultInterval;
    }

    public IReadOnlyList<ObservationIntegritySnapshot> Snapshot() =>
        new[] { _dns.Health, _network.Health, _security.Health };

    public void Start()
    {
        _timer ??= new Timer(_ => CheckNow(), null, _interval, _interval);
    }

    public void CheckNow()
    {
        if (Interlocked.Exchange(ref _checking, 1) != 0)
        {
            return;
        }

        try
        {
            _dns.EnsureStarted();
            _network.EnsureStarted();
            _security.EnsureStarted();

            var auditEnabled = BlockedConnectionWatch.IsAuditPolicyEnabled(LogAudit);
            _security.ReportAuditPolicy(auditEnabled);
            if (!auditEnabled)
            {
                ReportAuditPolicyLoss();

                var restored = BlockedConnectionWatch.EnableAuditPolicy(LogAudit)
                    && BlockedConnectionWatch.IsAuditPolicyEnabled(LogAudit);
                _security.ReportAuditPolicy(restored);
            }

            var rolledRecords = _security.ProbeLogWindow();
            if (rolledRecords > 0)
            {
                ReportSecurityLogRollover(rolledRecords);
            }

            // Reading snapshots reconciles TraceEventSession.EventsLost. The
            // next stable sample closes a loss interval without erasing totals.
            _ = _dns.Health;
            _ = _network.Health;
        }
        catch (Exception ex) when (ex is InvalidOperationException or UnauthorizedAccessException)
        {
            _db.LogEvent("observation", "integrity_check_failed", details: ex.Message);
        }
        finally
        {
            Interlocked.Exchange(ref _checking, 0);
        }
    }

    private void LogAudit(string message) =>
        _db.LogEvent("observation", "audit_policy", details: message);

    internal void ReportAuditPolicyLoss() => _db.AddAlert(
        "observation_integrity",
        "warning",
        "Blocked-connection evidence is incomplete",
        "security_audit_policy",
        "Windows Filtering Platform auditing was disabled. HostsGuard attempted to restore the required Connection and Packet Drop subcategories; verify Local Security Policy if this warning persists.",
        action: "restore_audit_policy");

    internal void ReportSecurityLogRollover(long rolledRecords) => _db.AddAlert(
        "observation_integrity",
        "warning",
        "Security-log history rolled over",
        "security_log_rollover",
        $"{rolledRecords} Security-log record(s) left the readable window. Live monitoring recovered, but that historical interval must be treated as incomplete. Increase the Security log maximum size or archive it when full.",
        action: "increase_security_log_size");

    public void Dispose()
    {
        Interlocked.Exchange(ref _timer, null)?.Dispose();
    }
}
