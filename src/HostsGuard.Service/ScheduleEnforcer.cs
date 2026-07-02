using System.Runtime.Versioning;
using HostsGuard.Core;
using HostsGuard.Data;
using HostsGuard.Windows;

namespace HostsGuard.Service;

/// <summary>
/// Scheduled-blocking enforcement (weekly windows, cross-midnight supported by
/// Core.Scheduling). Inside a window the target is blocked with source
/// "schedule"; outside, only rows we own (source == "schedule") are reverted —
/// a manual block or whitelist always wins over the scheduler.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class ScheduleEnforcer : IDisposable
{
    private readonly HostsEngine _hosts;
    private readonly HostsDatabase _db;
    private readonly object _gate = new();
    private readonly Timer _timer;
    private bool _disposed;

    public ScheduleEnforcer(HostsEngine hosts, HostsDatabase db, TimeSpan? interval = null)
    {
        _hosts = hosts ?? throw new ArgumentNullException(nameof(hosts));
        _db = db ?? throw new ArgumentNullException(nameof(db));
        _timer = new Timer(_ => Sweep(), null, TimeSpan.Zero, interval ?? TimeSpan.FromSeconds(30));
    }

    /// <summary>Apply the current schedule set immediately (called after an edit).</summary>
    public void Kick() => Sweep();

    private void Sweep()
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            SweepAt(DateTime.Now);
        }
    }

    /// <summary>Deterministic core, exposed for tests.</summary>
    public void SweepAt(DateTime now)
    {
        var nowHhmm = now.ToString("HH\\:mm", System.Globalization.CultureInfo.InvariantCulture);
        var today = ((int)now.DayOfWeek + 6) % 7; // proto convention: 0=Mon .. 6=Sun
        var activeTargets = new HashSet<string>(StringComparer.Ordinal);

        foreach (var (target, days, start, end) in _db.GetSchedules())
        {
            var dayList = days.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Select(d => int.TryParse(d, out var v) ? v : -1)
                .ToHashSet();
            // Parity with the Python oracle: day membership and the (overnight-
            // aware) time window are checked independently.
            if (dayList.Contains(today) && Scheduling.InWindow(nowHhmm, start, end))
            {
                activeTargets.Add(target);
            }
        }

        foreach (var target in activeTargets)
        {
            // A manual whitelist wins over the scheduler.
            if (_db.GetDomainStatus(target) == "whitelisted" && _db.GetDomainSource(target) != "schedule")
            {
                continue;
            }

            if (_hosts.Block(target))
            {
                _db.AddDomain(target, "blocked", "schedule");
                _db.LogEvent(target, "blocked", details: "scheduled window", reason: "schedule");
            }
        }

        // Self-owned revert: only rows the scheduler created are unblocked.
        foreach (var row in _db.GetDomains(status: "blocked", source: "schedule"))
        {
            if (!activeTargets.Contains(row.Domain))
            {
                _hosts.Unblock(row.Domain);
                _db.RemoveDomain(row.Domain);
                _db.LogEvent(row.Domain, "unblocked", details: "scheduled window ended", reason: "schedule");
            }
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            _disposed = true;
            _timer.Dispose();
        }
    }
}
