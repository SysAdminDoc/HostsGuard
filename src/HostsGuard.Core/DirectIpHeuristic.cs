using System.Net;

namespace HostsGuard.Core;

/// <summary>
/// Flags outbound connections to a raw public IP with no preceding DNS lookup
/// (NET-076 block-P2P heuristic). Malware and P2P clients that dial hard-coded
/// IPs skip resolution; well-behaved apps resolve a name first. The service
/// records every DNS-resolved address (from the ETW resolution-completion
/// event) with a timestamp; a later connection to a public IP that was never
/// resolved within the lookback window is "direct". LAN/localhost never count.
/// Bounded and self-pruning; thread-safe.
/// </summary>
public sealed class DirectIpHeuristic
{
    private readonly TimeSpan _lookback;
    private readonly object _gate = new();
    private readonly Dictionary<string, DateTime> _resolved = new(StringComparer.Ordinal);

    public DirectIpHeuristic(TimeSpan? lookback = null) =>
        _lookback = lookback ?? TimeSpan.FromMinutes(10);

    /// <summary>Record a resolved A/AAAA address (a name mapped to it).</summary>
    public void RecordResolved(string address, DateTime now)
    {
        if (!IPAddress.TryParse(address, out _))
        {
            return;
        }

        lock (_gate)
        {
            _resolved[address] = now;
            if (_resolved.Count > 8192)
            {
                Prune(now);
            }
        }
    }

    /// <summary>Record several resolved addresses at once.</summary>
    public void RecordResolved(IEnumerable<string> addresses, DateTime now)
    {
        ArgumentNullException.ThrowIfNull(addresses);
        foreach (var a in addresses)
        {
            RecordResolved(a, now);
        }
    }

    /// <summary>
    /// True when <paramref name="remote"/> is a public IP that was never
    /// resolved within the lookback window — a direct-to-IP dial.
    /// </summary>
    public bool IsDirect(string remote, DateTime now)
    {
        if (!IPAddress.TryParse(remote, out var ip) || !NetworkScopes.IsInternet(ip))
        {
            return false;
        }

        lock (_gate)
        {
            if (_resolved.TryGetValue(remote, out var at))
            {
                if (now - at <= _lookback)
                {
                    return false; // resolved recently — not direct
                }

                _resolved.Remove(remote);
            }

            return true;
        }
    }

    private void Prune(DateTime now)
    {
        foreach (var stale in _resolved.Where(kv => now - kv.Value > _lookback).Select(kv => kv.Key).ToList())
        {
            _resolved.Remove(stale);
        }
    }
}
