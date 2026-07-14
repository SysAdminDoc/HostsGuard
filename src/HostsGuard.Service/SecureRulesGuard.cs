using System.Runtime.Versioning;
using System.Text.Json;
using System.Threading;
using HostsGuard.Core;
using HostsGuard.Data;
using HostsGuard.Windows;

namespace HostsGuard.Service;

/// <summary>A Secure Rules conflict that has been quarantined from automatic recovery.</summary>
public sealed record SecureRuleConflict(
    string Name,
    string DetectedAt,
    int RestoreAttempts,
    string LiveEvidence,
    string TrackedEvidence);

/// <summary>
/// Secure-Rules tamper-guard (NET-072), modelled on Malwarebytes WFC's feature.
/// The elevated service protects HostsGuard's OWN rule set: every HG_ rule
/// tracked in <c>fw_state</c> is expected to exist and be enabled. Repeated
/// recovery of one rule is circuit-broken so foreign policy cannot create an
/// endless firewall tug-of-war. Other rules continue to be protected.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class SecureRulesGuard : IDisposable
{
    private const string MetaKey = "secure_rules";
    private const string QuarantineMetaKey = "secure_rules_quarantine_v1";
    internal const int RestoreLimit = 3;
    internal const int MaxStateEntries = 4096;
    internal static readonly TimeSpan RestoreWindow = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan DefaultInterval = TimeSpan.FromSeconds(45);

    private readonly IFirewallEngine? _firewall;
    private readonly HostsDatabase _db;
    private readonly Func<DateTimeOffset> _now;
    private readonly System.Threading.Timer _timer;
    private readonly object _gate = new();
    private readonly Dictionary<string, Queue<DateTimeOffset>> _restoreAttempts = new(StringComparer.Ordinal);
    private readonly Dictionary<string, SecureRuleConflict> _quarantines = new(StringComparer.Ordinal);
    private bool _enabled;
    private bool _disposed;

    public SecureRulesGuard(
        IFirewallEngine? firewall,
        HostsDatabase db,
        Func<DateTimeOffset>? now = null,
        TimeSpan? interval = null)
    {
        _firewall = firewall;
        _db = db ?? throw new ArgumentNullException(nameof(db));
        _now = now ?? (() => DateTimeOffset.Now);
        _enabled = _db.GetMeta(MetaKey) == "1";
        LoadQuarantines();
        var cadence = interval ?? DefaultInterval;
        _timer = new System.Threading.Timer(_ => ReconcileFromTimer(), null, cadence, cadence);
    }

    private void ReconcileFromTimer()
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }
        }

        try
        {
            Reconcile();
        }
        catch (Exception ex) when (ex is System.Runtime.InteropServices.COMException
            or ObjectDisposedException or InvalidOperationException)
        {
            // Firewall COM unavailable, or the DB was disposed during shutdown.
        }
    }

    public bool Enabled
    {
        get
        {
            lock (_gate)
            {
                return _enabled;
            }
        }
    }

    public (int ProtectedCount, IReadOnlyList<SecureRuleConflict> Conflicts) GetStatus()
    {
        lock (_gate)
        {
            var conflicts = _quarantines.Values.OrderBy(c => c.Name, StringComparer.Ordinal).ToArray();
            var protectedCount = Math.Max(0, _db.GetFwStateNames().Count - conflicts.Length);
            return (protectedCount, conflicts);
        }
    }

    /// <summary>Number of tracked HG_ rules currently receiving automatic protection.</summary>
    public int TrackedCount => GetStatus().ProtectedCount;

    public IReadOnlyList<SecureRuleConflict> Conflicts => GetStatus().Conflicts;

    public void SetEnabled(bool enabled)
    {
        lock (_gate)
        {
            _enabled = enabled;
        }

        _db.SetMeta(MetaKey, enabled ? "1" : "0");
        _db.LogEvent("firewall", enabled ? "secure_rules_on" : "secure_rules_off",
            details: enabled ? "tamper-guard armed for HG_ rules" : "tamper-guard disarmed");
        if (enabled)
        {
            Reconcile();
        }
    }

    /// <summary>
    /// Stop tracking a quarantined rule and accept its current foreign state.
    /// The live Windows Firewall rule is deliberately left unchanged.
    /// </summary>
    public bool AcceptForeignState(string name)
    {
        name = (name ?? string.Empty).Trim();
        lock (_gate)
        {
            if (!_enabled || !_quarantines.Remove(name))
            {
                return false;
            }

            _restoreAttempts.Remove(name);
            _db.RemoveFwState(name);
            PersistQuarantinesNoLock();
            _db.LogEvent(name, "secure_rules_foreign_state_accepted",
                details: "rule removed from Secure Rules tracking; live state unchanged", reason: "firewall");
            return true;
        }
    }

    /// <summary>Clear a rule's quarantine and immediately try its tracked state again.</summary>
    public bool Rearm(string name)
    {
        name = (name ?? string.Empty).Trim();
        lock (_gate)
        {
            if (!_quarantines.Remove(name))
            {
                return false;
            }

            _restoreAttempts.Remove(name);
            PersistQuarantinesNoLock();
            _db.LogEvent(name, "secure_rules_rearmed",
                details: "quarantine cleared; tracked rule recovery resumed", reason: "firewall");
        }

        Reconcile();
        return true;
    }

    /// <summary>
    /// Reconcile live firewall state against tracked HG_ rules. A rule is
    /// quarantined before a fourth restore within ten minutes. The three-entry
    /// rolling window expires naturally and attempt-counter state is bounded.
    /// </summary>
    public int Reconcile()
    {
        lock (_gate)
        {
            if (!_enabled || _firewall is not { } fw)
            {
                return 0;
            }

            var now = _now();
            PruneAttemptsNoLock(now);
            var trackedRows = _db.GetFwState()
                .Where(r => r.Name.StartsWith(FwRuleMapper.HostsGuardPrefix, StringComparison.Ordinal))
                .ToArray();
            var trackedNames = trackedRows.Select(r => r.Name).ToHashSet(StringComparer.Ordinal);
            var removedStaleQuarantine = false;
            foreach (var stale in _quarantines.Keys.Where(name => !trackedNames.Contains(name)).ToArray())
            {
                _quarantines.Remove(stale);
                _restoreAttempts.Remove(stale);
                removedStaleQuarantine = true;
            }

            if (removedStaleQuarantine)
            {
                PersistQuarantinesNoLock();
            }

            var live = fw.ListRules()
                .Where(r => r.Name.StartsWith(FwRuleMapper.HostsGuardPrefix, StringComparison.Ordinal))
                .GroupBy(r => r.Name, StringComparer.Ordinal)
                .ToDictionary(g => g.Key, g => g.First(), StringComparer.Ordinal);

            var reverts = 0;
            foreach (var tracked in trackedRows)
            {
                if (_quarantines.ContainsKey(tracked.Name))
                {
                    continue;
                }

                live.TryGetValue(tracked.Name, out var liveRule);
                if (liveRule is not null && liveRule.Enabled)
                {
                    continue;
                }

                var attempts = GetRecentAttemptCountNoLock(tracked.Name, now);
                if (attempts >= RestoreLimit)
                {
                    QuarantineNoLock(tracked, liveRule, attempts, now);
                    continue;
                }

                var restored = liveRule is null
                    ? fw.CreateRule(ToRule(tracked))
                    : fw.SetRuleEnabled(tracked.Name, true);
                if (!restored)
                {
                    continue;
                }

                reverts++;
                RememberRestoreNoLock(tracked.Name, now);
                _db.LogEvent(tracked.Name, "secure_rules_restored",
                    details: liveRule is null ? "recreated deleted HG_ rule" : "re-enabled disabled HG_ rule",
                    reason: "firewall");
            }

            return reverts;
        }
    }

    private void QuarantineNoLock(FwStateRow tracked, FwRule? liveRule, int attempts, DateTimeOffset now)
    {
        var conflict = new SecureRuleConflict(
            tracked.Name,
            now.ToString("o", System.Globalization.CultureInfo.InvariantCulture),
            attempts,
            DescribeLive(liveRule),
            DescribeTracked(tracked));
        _quarantines[tracked.Name] = conflict;
        PersistQuarantinesNoLock();
        _db.AddAlert(
            "secure_rules_conflict",
            "critical",
            "Secure Rules recovery quarantined",
            tracked.Name,
            $"Live: {conflict.LiveEvidence}; tracked: {conflict.TrackedEvidence}; " +
            $"{attempts} automatic restores occurred within {RestoreWindow.TotalMinutes:0} minutes. " +
            "Accept the foreign state or re-arm this rule after resolving the external policy.",
            action: "quarantined");
        _db.LogEvent(tracked.Name, "secure_rules_quarantined",
            details: $"live={conflict.LiveEvidence}; tracked={conflict.TrackedEvidence}; restores={attempts}",
            reason: "firewall");
    }

    private int GetRecentAttemptCountNoLock(string name, DateTimeOffset now)
    {
        if (!_restoreAttempts.TryGetValue(name, out var attempts))
        {
            return 0;
        }

        PruneQueue(attempts, now);
        if (attempts.Count == 0)
        {
            _restoreAttempts.Remove(name);
            return 0;
        }

        return attempts.Count;
    }

    private void RememberRestoreNoLock(string name, DateTimeOffset now)
    {
        if (!_restoreAttempts.TryGetValue(name, out var attempts))
        {
            if (_restoreAttempts.Count >= MaxStateEntries)
            {
                var oldest = _restoreAttempts.OrderBy(pair => pair.Value.Peek()).First().Key;
                _restoreAttempts.Remove(oldest);
            }

            attempts = new Queue<DateTimeOffset>();
            _restoreAttempts[name] = attempts;
        }

        attempts.Enqueue(now);
    }

    private void PruneAttemptsNoLock(DateTimeOffset now)
    {
        foreach (var (name, attempts) in _restoreAttempts.ToArray())
        {
            PruneQueue(attempts, now);
            if (attempts.Count == 0)
            {
                _restoreAttempts.Remove(name);
            }
        }
    }

    private static void PruneQueue(Queue<DateTimeOffset> attempts, DateTimeOffset now)
    {
        while (attempts.TryPeek(out var attempt) && now - attempt >= RestoreWindow)
        {
            attempts.Dequeue();
        }
    }

    private void LoadQuarantines()
    {
        try
        {
            var json = _db.GetMeta(QuarantineMetaKey);
            if (string.IsNullOrWhiteSpace(json))
            {
                return;
            }

            var tracked = _db.GetFwStateNames();
            var persisted = JsonSerializer.Deserialize<List<SecureRuleConflict>>(json) ?? [];
            foreach (var conflict in persisted
                .Where(c => !string.IsNullOrWhiteSpace(c.Name)
                    && c.Name.StartsWith(FwRuleMapper.HostsGuardPrefix, StringComparison.Ordinal)
                    && tracked.Contains(c.Name))
                .Take(MaxStateEntries))
            {
                _quarantines[conflict.Name] = conflict with
                {
                    DetectedAt = conflict.DetectedAt ?? string.Empty,
                    LiveEvidence = conflict.LiveEvidence ?? string.Empty,
                    TrackedEvidence = conflict.TrackedEvidence ?? string.Empty,
                };
            }
        }
        catch (JsonException)
        {
            // Corrupt optional metadata must not prevent service startup.
        }
    }

    private void PersistQuarantinesNoLock()
        => _db.SetMeta(QuarantineMetaKey, JsonSerializer.Serialize(
            _quarantines.Values.OrderBy(c => c.Name, StringComparer.Ordinal)));

    private static FwRule ToRule(FwStateRow tracked) => new(
        tracked.Name, tracked.Direction ?? "Out", tracked.Action ?? "Block", true,
        string.IsNullOrEmpty(tracked.RemoteAddr) ? "Any" : tracked.RemoteAddr,
        string.IsNullOrEmpty(tracked.Protocol) ? "Any" : tracked.Protocol,
        tracked.Program ?? string.Empty,
        "hostsguard",
        string.IsNullOrEmpty(tracked.RemotePorts) ? "Any" : tracked.RemotePorts,
        tracked.ServiceName ?? string.Empty,
        string.IsNullOrEmpty(tracked.LocalPorts) ? "Any" : tracked.LocalPorts,
        string.IsNullOrEmpty(tracked.Interfaces) ? "Any" : tracked.Interfaces,
        tracked.PackageFamilyName ?? string.Empty,
        tracked.PackageSid ?? string.Empty,
        tracked.PackageDisplayName ?? string.Empty,
        tracked.PackageFullName ?? string.Empty,
        tracked.PackageBinaries ?? string.Empty);

    private static string DescribeLive(FwRule? rule) => rule is null
        ? "missing"
        : $"enabled={rule.Enabled}; direction={rule.Direction}; action={rule.Action}; remote={rule.RemoteAddr}; " +
          $"protocol={rule.Protocol}; program={rule.Program}; remotePorts={rule.RemotePorts}";

    private static string DescribeTracked(FwStateRow rule)
        => $"enabled=true; direction={rule.Direction ?? "Out"}; action={rule.Action ?? "Block"}; " +
           $"remote={rule.RemoteAddr ?? "Any"}; protocol={rule.Protocol ?? "Any"}; " +
           $"program={rule.Program ?? string.Empty}; remotePorts={rule.RemotePorts ?? "Any"}";

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
