using System.Globalization;
using HostsGuard.Data;
using HostsGuard.Windows;

namespace HostsGuard.Service;

/// <summary>
/// Converts bounded, payload-free blocked-inbound scan detections into the
/// operator alert inbox and append-only audit ledger.
/// </summary>
internal sealed class PortScanAlertMonitor
{
    private readonly HostsDatabase _db;
    private readonly BlockedPortScanDetector _detector;

    public PortScanAlertMonitor(
        HostsDatabase db,
        BlockedPortScanDetector? detector = null)
    {
        _db = db ?? throw new ArgumentNullException(nameof(db));
        _detector = detector ?? new BlockedPortScanDetector();
    }

    public PortScanDetection? Observe(BlockedConnection blocked)
    {
        ArgumentNullException.ThrowIfNull(blocked);
        if (!string.Equals(blocked.Direction, "In", StringComparison.Ordinal))
        {
            return null;
        }

        var detection = _detector.Observe(blocked.RemoteAddress, blocked.LocalPort, blocked.TsUtc);
        if (detection is null)
        {
            return null;
        }

        var ports = string.Join(", ", detection.SamplePorts
            .Order()
            .Select(port => port.ToString(CultureInfo.InvariantCulture)));
        var details = $"Blocked attempts reached {detection.DistinctPortCount.ToString(CultureInfo.InvariantCulture)} distinct local ports; sampled ports: {ports}.";

        _db.AddAlert(
            "port_scan",
            "warning",
            "Blocked inbound port scan detected",
            detection.SourceAddress,
            details,
            action: "review_firewall_activity");
        _db.LogEvent(
            detection.SourceAddress,
            "port_scan",
            details: details,
            reason: "security",
            provenance: blocked.Provenance);
        return detection;
    }
}
