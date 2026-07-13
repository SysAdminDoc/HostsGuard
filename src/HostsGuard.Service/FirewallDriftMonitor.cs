using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using HostsGuard.Core;
using HostsGuard.Data;
using HostsGuard.Windows;

namespace HostsGuard.Service;

/// <summary>
/// Report-only full Windows Firewall drift baseline (NET-151). Unlike
/// SecureRulesGuard, this never changes firewall state; it snapshots all rules
/// and logs when foreign rules appear, change, or vanish.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class FirewallDriftMonitor : IDisposable
{
    private static readonly TimeSpan Interval = TimeSpan.FromSeconds(45);

    private readonly IFirewallEngine? _firewall;
    private readonly HostsDatabase _db;
    private readonly System.Threading.Timer _timer;
    private readonly object _gate = new();
    private bool _disposed;

    public FirewallDriftMonitor(IFirewallEngine? firewall, HostsDatabase db)
    {
        _firewall = firewall;
        _db = db ?? throw new ArgumentNullException(nameof(db));
        _timer = new System.Threading.Timer(_ => PollSafely(), null, TimeSpan.Zero, Interval);
    }

    public IReadOnlyList<FirewallRuleDriftRow> CaptureNow(IReadOnlyList<FwRule>? liveRules = null)
    {
        if (_firewall is null && liveRules is null)
        {
            return Array.Empty<FirewallRuleDriftRow>();
        }

        lock (_gate)
        {
            if (_disposed)
            {
                return Array.Empty<FirewallRuleDriftRow>();
            }

            // Package binary inventories can contain thousands of long paths and
            // are metadata rather than firewall enforcement state. The drift loop
            // runs every 45 seconds, so use the lightweight projection here and
            // reserve full inventories for explicit package-management requests.
            var rules = liveRules ?? _firewall!.ListRules(includePackageBinaries: false);
            var diffs = _db.SnapshotFirewallRules(rules);
            foreach (var diff in diffs.Where(d => !string.Equals(d.Source, "hostsguard", StringComparison.Ordinal)))
            {
                _db.LogEvent(
                    diff.Name,
                    diff.ChangeKind switch
                    {
                        "added" => EventTaxonomy.FwRuleAdded,
                        "changed" => EventTaxonomy.FwRuleChanged,
                        "vanished" => EventTaxonomy.FwRuleVanished,
                        _ => "fw_rule_drift",
                    },
                    process: diff.Program,
                    details: diff.Details,
                    reason: "firewall");
                _db.AddAlert(
                    "firewall_drift",
                    diff.ChangeKind == "added" ? "info" : "warning",
                    diff.ChangeKind switch
                    {
                        "added" => "Firewall rule appeared",
                        "changed" => "Firewall rule changed",
                        "vanished" => "Firewall rule vanished",
                        _ => "Firewall rule drift",
                    },
                    diff.Name,
                    diff.Details,
                    action: diff.ChangeKind,
                    process: diff.Program);
            }

            return diffs;
        }
    }

    private void PollSafely()
    {
        try
        {
            CaptureNow();
        }
        catch (Exception ex) when (ex is COMException or InvalidOperationException)
        {
            // Firewall COM can be temporarily unavailable during service start,
            // shutdown, or policy refresh. The next poll re-snapshots.
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            _disposed = true;
        }

        using var drained = new ManualResetEvent(false);
        if (_timer.Dispose(drained))
        {
            drained.WaitOne(TimeSpan.FromSeconds(5));
        }
    }
}
