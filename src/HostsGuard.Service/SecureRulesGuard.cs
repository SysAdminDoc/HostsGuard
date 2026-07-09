using System.Runtime.Versioning;
using HostsGuard.Core;
using HostsGuard.Data;
using HostsGuard.Windows;

namespace HostsGuard.Service;

/// <summary>
/// Secure-Rules tamper-guard (NET-072), modelled on Malwarebytes WFC's feature.
/// The elevated service protects HostsGuard's OWN rule set: every HG_ rule
/// tracked in <c>fw_state</c> is expected to exist and be enabled. If one is
/// deleted or disabled behind our back (malware silencing a block, a stray
/// admin action), the guard recreates or re-enables it from the tracked state
/// and logs the revert. It never touches non-HG rules — the user's other
/// firewall configuration is left entirely alone. Opt-in and persisted.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class SecureRulesGuard : IDisposable
{
    private const string MetaKey = "secure_rules";
    private static readonly TimeSpan Interval = TimeSpan.FromSeconds(45);

    private readonly IFirewallEngine? _firewall;
    private readonly HostsDatabase _db;
    private readonly System.Threading.Timer _timer;
    private readonly object _gate = new();
    private bool _enabled;

    public SecureRulesGuard(IFirewallEngine? firewall, HostsDatabase db)
    {
        _firewall = firewall;
        _db = db ?? throw new ArgumentNullException(nameof(db));
        _enabled = _db.GetMeta(MetaKey) == "1";
        _timer = new System.Threading.Timer(_ => { try { Reconcile(); } catch (Exception ex) when (ex is System.Runtime.InteropServices.COMException) { } },
            null, Interval, Interval);
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

    /// <summary>Number of tracked HG_ rules currently protected.</summary>
    public int TrackedCount => _db.GetFwStateNames().Count;

    /// <summary>Enable or disable the guard; the setting persists across restarts.</summary>
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
    /// Reconcile live firewall state against the tracked HG_ rule set: recreate
    /// deleted rules, re-enable disabled ones. Returns the number of reverts.
    /// No-op when disarmed or no firewall engine is attached.
    /// </summary>
    public int Reconcile()
    {
        if (!Enabled || _firewall is not { } fw)
        {
            return 0;
        }

        var live = fw.ListRules()
            .Where(r => r.Name.StartsWith(FwRuleMapper.HostsGuardPrefix, StringComparison.Ordinal))
            .ToDictionary(r => r.Name, StringComparer.Ordinal);

        var reverts = 0;
        foreach (var tracked in _db.GetFwState())
        {
            if (!tracked.Name.StartsWith(FwRuleMapper.HostsGuardPrefix, StringComparison.Ordinal))
            {
                continue;
            }

            if (!live.TryGetValue(tracked.Name, out var liveRule))
            {
                // Deleted behind our back — recreate from tracked state.
                var rule = new FwRule(
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
                if (fw.CreateRule(rule))
                {
                    reverts++;
                    _db.LogEvent(tracked.Name, "secure_rules_restored", details: "recreated deleted HG_ rule", reason: "firewall");
                }
            }
            else if (!liveRule.Enabled)
            {
                // Disabled behind our back — re-enable.
                if (fw.SetRuleEnabled(tracked.Name, true))
                {
                    reverts++;
                    _db.LogEvent(tracked.Name, "secure_rules_restored", details: "re-enabled disabled HG_ rule", reason: "firewall");
                }
            }
        }

        return reverts;
    }

    public void Dispose() => _timer.Dispose();
}
