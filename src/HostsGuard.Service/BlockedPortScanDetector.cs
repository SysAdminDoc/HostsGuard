using System.Net;

namespace HostsGuard.Service;

public sealed record PortScanDetection(
    string SourceAddress,
    int DistinctPortCount,
    IReadOnlyList<int> SamplePorts,
    DateTime WindowStartUtc,
    DateTime ObservedAtUtc);

/// <summary>
/// Pure, bounded sliding-window detector for blocked inbound probes across
/// distinct local ports. Only globally routable sources participate.
/// </summary>
public sealed class BlockedPortScanDetector
{
    public const int DefaultThreshold = 8;
    public static readonly TimeSpan DefaultWindow = TimeSpan.FromSeconds(30);
    public static readonly TimeSpan DefaultCooldown = TimeSpan.FromMinutes(5);

    private readonly int _threshold;
    private readonly TimeSpan _window;
    private readonly TimeSpan _cooldown;
    private readonly int _maxSources;
    private readonly int _maxPortsPerSource;
    private readonly object _gate = new();
    private readonly Dictionary<string, SourceState> _sources = new(StringComparer.Ordinal);

    public BlockedPortScanDetector(
        int threshold = DefaultThreshold,
        TimeSpan? window = null,
        TimeSpan? cooldown = null,
        int maxSources = 4096,
        int maxPortsPerSource = 256)
    {
        _threshold = threshold >= 2 ? threshold : throw new ArgumentOutOfRangeException(nameof(threshold));
        _window = window ?? DefaultWindow;
        _cooldown = cooldown ?? DefaultCooldown;
        _maxSources = maxSources >= 1 ? maxSources : throw new ArgumentOutOfRangeException(nameof(maxSources));
        _maxPortsPerSource = maxPortsPerSource >= threshold
            ? maxPortsPerSource
            : throw new ArgumentOutOfRangeException(nameof(maxPortsPerSource));
        if (_window <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(window));
        if (_cooldown < TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(cooldown));
    }

    public PortScanDetection? Observe(string sourceAddress, int localPort, DateTime timestampUtc)
    {
        if (localPort is < 1 or > 65535 ||
            !IPAddress.TryParse(sourceAddress, out var parsed) ||
            !IsGloballyRoutableSource(parsed))
        {
            return null;
        }

        var now = timestampUtc.Kind == DateTimeKind.Utc
            ? timestampUtc
            : timestampUtc.ToUniversalTime();
        var key = parsed.ToString();
        lock (_gate)
        {
            PruneSources(now);
            if (!_sources.TryGetValue(key, out var state))
            {
                if (_sources.Count >= _maxSources)
                {
                    var oldest = _sources.MinBy(pair => pair.Value.LastSeenUtc).Key;
                    _sources.Remove(oldest);
                }

                state = new SourceState();
                _sources.Add(key, state);
            }

            state.LastSeenUtc = now;
            var cutoff = now - _window;
            foreach (var expired in state.Ports.Where(pair => pair.Value < cutoff).Select(pair => pair.Key).ToArray())
            {
                state.Ports.Remove(expired);
            }

            var isNewPort = !state.Ports.ContainsKey(localPort);
            state.Ports[localPort] = now;
            if (state.Ports.Count > _maxPortsPerSource)
            {
                var oldestPort = state.Ports.MinBy(pair => pair.Value).Key;
                state.Ports.Remove(oldestPort);
            }

            if (!isNewPort || state.Ports.Count < _threshold ||
                (state.LastAlertUtc is { } last && now - last < _cooldown))
            {
                return null;
            }

            state.LastAlertUtc = now;
            return new PortScanDetection(
                key,
                state.Ports.Count,
                state.Ports.Keys.Order().Take(16).ToArray(),
                state.Ports.Values.Min(),
                now);
        }
    }

    private static bool IsGloballyRoutableSource(IPAddress address)
    {
        if (!SsrfGuard.IsPublic(address))
        {
            return false;
        }

        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        var bytes = address.GetAddressBytes();
        if (bytes.Length == 4)
        {
            return bytes switch
            {
                [192, 0, 0, _] => false,                    // IETF protocol assignments
                [192, 0, 2, _] => false,                    // TEST-NET-1
                [198, 18 or 19, ..] => false,               // benchmark testing
                [198, 51, 100, _] => false,                 // TEST-NET-2
                [203, 0, 113, _] => false,                  // TEST-NET-3
                _ => true,
            };
        }

        // Public scan sources must be IPv6 global unicast (2000::/3), excluding
        // the documentation prefix which is intentionally non-routable.
        return bytes.Length == 16 &&
               (bytes[0] & 0xE0) == 0x20 &&
               !(bytes[0] == 0x20 && bytes[1] == 0x01 && bytes[2] == 0x0D && bytes[3] == 0xB8);
    }

    private void PruneSources(DateTime now)
    {
        var retention = _window + _cooldown;
        foreach (var stale in _sources
                     .Where(pair => now - pair.Value.LastSeenUtc > retention)
                     .Select(pair => pair.Key)
                     .ToArray())
        {
            _sources.Remove(stale);
        }
    }

    private sealed class SourceState
    {
        public Dictionary<int, DateTime> Ports { get; } = new();
        public DateTime LastSeenUtc { get; set; }
        public DateTime? LastAlertUtc { get; set; }
    }
}
