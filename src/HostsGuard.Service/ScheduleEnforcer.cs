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
///
/// A target prefixed <c>fw:</c> (NET-084) schedules a firewall rule instead of
/// a domain: the named HG_ rule is enabled inside its window(s) and disabled
/// outside, so a rule can be time-of-day gated without deleting it.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class ScheduleEnforcer : IDisposable
{
    /// <summary>Prefix marking a schedule target as a firewall rule (NET-084).</summary>
    public const string FwTargetPrefix = "fw:";

    private readonly HostsEngine _hosts;
    private readonly HostsDatabase _db;
    private readonly IFirewallEngine? _firewall;
    private readonly object _gate = new();
    private readonly Timer _timer;
    private bool _disposed;

    public ScheduleEnforcer(HostsEngine hosts, HostsDatabase db, IFirewallEngine? firewall = null, TimeSpan? interval = null)
    {
        _hosts = hosts ?? throw new ArgumentNullException(nameof(hosts));
        _db = db ?? throw new ArgumentNullException(nameof(db));
        _firewall = firewall;
        var period = interval ?? TimeSpan.FromSeconds(30);
        var dueTime = period == Timeout.InfiniteTimeSpan ? Timeout.InfiniteTimeSpan : TimeSpan.Zero;
        _timer = new Timer(_ => Sweep(), null, dueTime, period);
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

        // Every firewall-rule target seen (in a window or not) so a rule with no
        // currently-active window is driven to disabled, not left as-is.
        var fwRulesSeen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var fwRulesActive = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var (target, days, start, end) in _db.GetSchedules())
        {
            var dayList = days.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Select(d => int.TryParse(d, out var v) ? v : -1)
                .ToHashSet();
            var inWindow = dayList.Contains(today) && Scheduling.InWindow(nowHhmm, start, end);

            if (target.StartsWith(FwTargetPrefix, StringComparison.Ordinal))
            {
                var rule = target[FwTargetPrefix.Length..];
                fwRulesSeen.Add(rule);
                if (inWindow)
                {
                    fwRulesActive.Add(rule);
                }

                continue;
            }

            // Parity with the Python oracle: day membership and the (overnight-
            // aware) time window are checked independently.
            if (inWindow)
            {
                activeTargets.Add(target);
            }
        }

        EnforceFirewallSchedules(fwRulesSeen, fwRulesActive);

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

    /// <summary>
    /// Drive each scheduled firewall rule to enabled inside a window, disabled
    /// outside (NET-084). Only HG_ rules are ever touched, and only when the
    /// live enabled-state differs, so we never fight a rule the user manages.
    /// </summary>
    private void EnforceFirewallSchedules(HashSet<string> seen, HashSet<string> active)
    {
        if (_firewall is not { } fw || seen.Count == 0)
        {
            return;
        }

        var live = fw.ListRules().ToDictionary(r => r.Name, StringComparer.Ordinal);
        foreach (var rule in seen)
        {
            if (!rule.StartsWith(Core.FwRuleMapper.HostsGuardPrefix, StringComparison.Ordinal) ||
                !live.TryGetValue(rule, out var current))
            {
                continue;
            }

            var wantEnabled = active.Contains(rule);
            if (current.Enabled != wantEnabled && fw.SetRuleEnabled(rule, wantEnabled))
            {
                _db.LogEvent(rule, wantEnabled ? "fw_enabled" : "fw_disabled",
                    details: wantEnabled ? "scheduled window" : "scheduled window ended", reason: "schedule");
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
