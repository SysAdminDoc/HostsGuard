using System.Globalization;
using System.Runtime.Versioning;
using HostsGuard.Data;

namespace HostsGuard.Service;

public sealed record ThreatHistoryRescanResult(
    int ScannedRows,
    int MatchingIndicators,
    int AlertsRaised);

/// <summary>
/// Alert-only retrospective matching after a successful threat-intelligence
/// refresh. Work is bounded to the newest 10,000 rows and 30 days even when
/// the operator retains more history; the database applies the shorter actual
/// retention and current privacy exclusions before returning any row.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class ThreatHistoryRescanCoordinator
{
    public const int MaxHistoryRows = 10_000;
    public const int MaxLookbackDays = 30;

    private readonly HostsDatabase _db;
    private readonly Func<string, bool> _isThreat;

    public ThreatHistoryRescanCoordinator(HostsDatabase db, Func<string, bool> isThreat)
    {
        _db = db ?? throw new ArgumentNullException(nameof(db));
        _isThreat = isThreat ?? throw new ArgumentNullException(nameof(isThreat));
    }

    public ThreatHistoryRescanResult Scan(DateTime now, CancellationToken cancellationToken)
    {
        var rows = _db.GetThreatIntelRescanHistory(now, MaxHistoryRows, MaxLookbackDays);
        var matchingIndicators = 0;
        var alertsRaised = 0;

        foreach (var group in rows
                     .Where(row => _isThreat(row.RemoteAddr))
                     .GroupBy(row => row.RemoteAddr, StringComparer.Ordinal))
        {
            cancellationToken.ThrowIfCancellationRequested();
            matchingIndicators++;
            var latest = group.First();
            var process = string.IsNullOrWhiteSpace(latest.Process) ? "unknown process" : latest.Process;
            var endpoint = $"{latest.RemoteAddr}:{latest.RemotePort.ToString(CultureInfo.InvariantCulture)}";
            if (_db.TryAddAlertOnce(
                    "threat_hit",
                    "critical",
                    "Retained connection matches refreshed threat intelligence",
                    latest.RemoteAddr,
                    $"A retained connection from {latest.Ts} shows {process} contacted {endpoint} over {latest.Protocol}. " +
                    "This retrospective finding is alert-only; HostsGuard did not create a block rule.",
                    action: "threat_connection",
                    process: latest.Process))
            {
                alertsRaised++;
            }
        }

        return new ThreatHistoryRescanResult(rows.Count, matchingIndicators, alertsRaised);
    }
}
