namespace HostsGuard.Core;

/// <summary>
/// A thread-safe, memory-bounded "have I already alerted on this key?" set.
/// Replaces plain <see cref="HashSet{T}"/> dedup sets that grow one entry per
/// distinct key for the entire lifetime of the always-on LocalSystem service —
/// an unbounded leak when the key space is per-domain (e.g. one entry for every
/// domain the machine ever resolves).
/// <para>
/// <see cref="Add"/> returns <c>true</c> the first time a key is seen within the
/// retention window (a fresh occurrence worth alerting on) and <c>false</c> for a
/// duplicate, refreshing its recency. Entries older than the TTL, or beyond the
/// capacity cap, are evicted oldest-first so the set never grows without bound —
/// the same bounded/TTL discipline as <see cref="ResolvedIpCache"/>.
/// </para>
/// </summary>
public sealed class BoundedDedupSet
{
    private readonly int _capacity;
    private readonly TimeSpan _ttl;
    private readonly object _gate = new();
    private readonly Dictionary<string, DateTime> _seen;

    public BoundedDedupSet(int capacity = 8192, TimeSpan? ttl = null, StringComparer? comparer = null)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(capacity, 1);
        _capacity = capacity;
        _ttl = ttl ?? TimeSpan.FromHours(24);
        _seen = new Dictionary<string, DateTime>(comparer ?? StringComparer.Ordinal);
    }

    /// <summary>
    /// Records <paramref name="key"/> at <paramref name="now"/> and returns
    /// <c>true</c> if it was not already present within the retention window
    /// (a fresh occurrence). A duplicate returns <c>false</c> and refreshes the
    /// key's recency so persistently-active keys survive capacity eviction.
    /// </summary>
    public bool Add(string key, DateTime now)
    {
        ArgumentNullException.ThrowIfNull(key);
        lock (_gate)
        {
            if (_seen.TryGetValue(key, out var at) && now - at <= _ttl)
            {
                _seen[key] = now; // still a duplicate; keep it fresh
                return false;
            }

            _seen[key] = now;
            if (_seen.Count > _capacity)
            {
                Prune(now);
            }

            return true;
        }
    }

    /// <summary>Current retained key count (test/diagnostics visibility).</summary>
    public int Count
    {
        get { lock (_gate) { return _seen.Count; } }
    }

    private void Prune(DateTime now)
    {
        foreach (var stale in _seen.Where(kv => now - kv.Value > _ttl).Select(kv => kv.Key).ToList())
        {
            _seen.Remove(stale);
        }

        // Still over capacity after TTL pruning: drop the oldest half.
        if (_seen.Count > _capacity)
        {
            foreach (var key in _seen.OrderBy(kv => kv.Value)
                         .Take(_seen.Count - _capacity / 2).Select(kv => kv.Key).ToList())
            {
                _seen.Remove(key);
            }
        }
    }
}
