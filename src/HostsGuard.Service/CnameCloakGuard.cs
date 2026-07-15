using System.Runtime.Versioning;
using HostsGuard.Core;
using HostsGuard.Data;
using HostsGuard.Windows;

namespace HostsGuard.Service;

/// <summary>
/// CNAME-cloak defense (NET-075). Trackers evade hosts blocking by having a
/// first-party host (e.g. <c>metrics.example.com</c>) CNAME to a blocked tracker
/// domain — the browser resolves the first-party name, which isn't on the
/// blocklist, so the request goes through. HostsGuard already sees the full
/// resolution chain via the ETW DNS provider; when a resolved CNAME target is
/// blocked, this guard reactively adds the fronting query name to the hosts
/// block. Driver-free, opt-in, and logged. Uses the existing hosts engine — no
/// DNS forwarder required.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class CnameCloakGuard
{
    private const string MetaKey = "cname_cloak";

    private readonly HostsEngine _hosts;
    private readonly HostsDatabase _db;
    private readonly object _gate = new();
    private bool _enabled;

    public CnameCloakGuard(HostsEngine hosts, HostsDatabase db)
    {
        _hosts = hosts ?? throw new ArgumentNullException(nameof(hosts));
        _db = db ?? throw new ArgumentNullException(nameof(db));
        _enabled = _db.GetMeta(MetaKey) == "1";
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

    public void SetEnabled(bool enabled)
    {
        lock (_gate)
        {
            _enabled = enabled;
        }

        _db.SetMeta(MetaKey, enabled ? "1" : "0");
        _db.LogEvent("dns", enabled ? "cname_cloak_on" : "cname_cloak_off",
            details: enabled ? "CNAME-cloak reactive blocking armed" : "disarmed");
    }

    /// <summary>
    /// Evaluate a completed resolution: if the query name isn't already blocked
    /// but any of its CNAME targets is, block the query name (cname-cloak).
    /// Returns the blocked cname that triggered it, or null. No-op when disarmed.
    /// </summary>
    public string? Evaluate(string queryName, IEnumerable<string> cnames)
    {
        ArgumentNullException.ThrowIfNull(cnames);
        if (!Enabled || !Domains.LooksLikeDomain(queryName))
        {
            return null;
        }

        var blocked = _hosts.GetBlocked();
        if (blocked.Contains(queryName))
        {
            return null; // already covered
        }

        foreach (var cname in cnames)
        {
            if (!blocked.Contains(cname))
            {
                continue;
            }

            _hosts.Block(queryName);
            _db.AddDomain(queryName, "blocked", "cname-cloak", reason: "cname-cloak");
            var decidingSource = _db.GetDomainSource(cname);
            if (string.IsNullOrWhiteSpace(decidingSource))
            {
                var decidingList = _db.GetBlocklistsFor(cname).FirstOrDefault();
                decidingSource = string.IsNullOrWhiteSpace(decidingList) ? "cname-cloak" : $"list:{decidingList}";
            }

            _db.LogEvent(queryName, "blocked", details: $"CNAME-cloak: aliases to blocked {cname}",
                reason: "cname-cloak", matchedSource: decidingSource);
            return cname;
        }

        return null;
    }
}
