using System.Net;

namespace HostsGuard.Core;

/// <summary>
/// Remembers which domain each IP was resolved to (from the ETW DNS
/// resolution-completion event) so live connections can display the site a
/// remote address belongs to. Bounded, TTL'd, thread-safe. Unlike reverse
/// PTR, this reflects what the machine actually asked for — CDN IPs map to
/// the site name, not the CDN's infrastructure name.
/// </summary>
public sealed class ResolvedIpCache
{
    private const int Capacity = 16384;

    private readonly TimeSpan _ttl;
    private readonly object _gate = new();
    private readonly Dictionary<string, (string Domain, DateTime At)> _map = new(StringComparer.Ordinal);

    public ResolvedIpCache(TimeSpan? ttl = null) => _ttl = ttl ?? TimeSpan.FromHours(6);

    /// <summary>Record that <paramref name="domain"/> resolved to <paramref name="addresses"/>.</summary>
    public void Record(string domain, IEnumerable<string> addresses, DateTime now)
    {
        ArgumentNullException.ThrowIfNull(addresses);
        var d = (domain ?? string.Empty).ToLowerInvariant().Trim();
        if (d.Length == 0)
        {
            return;
        }

        lock (_gate)
        {
            foreach (var a in addresses)
            {
                if (IPAddress.TryParse(a, out _))
                {
                    _map[a] = (d, now);
                }
            }

            if (_map.Count > Capacity)
            {
                Prune(now);
            }
        }
    }

    /// <summary>The domain <paramref name="address"/> was most recently resolved as, or "".</summary>
    public string Lookup(string address, DateTime now)
    {
        lock (_gate)
        {
            if (_map.TryGetValue(address, out var hit))
            {
                if (now - hit.At <= _ttl)
                {
                    return hit.Domain;
                }

                _map.Remove(address);
            }

            return string.Empty;
        }
    }

    private void Prune(DateTime now)
    {
        foreach (var stale in _map.Where(kv => now - kv.Value.At > _ttl).Select(kv => kv.Key).ToList())
        {
            _map.Remove(stale);
        }

        // Still over capacity after TTL pruning: drop the oldest half.
        if (_map.Count > Capacity)
        {
            foreach (var key in _map.OrderBy(kv => kv.Value.At)
                         .Take(_map.Count - Capacity / 2).Select(kv => kv.Key).ToList())
            {
                _map.Remove(key);
            }
        }
    }
}
