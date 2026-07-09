using System.Runtime.Versioning;
using HostsGuard.Core;

namespace HostsGuard.Service;

/// <summary>
/// Threat-intel IP overlay (Feodo Tracker botnet C2 list + any URLhaus host
/// IPs). The set persists to threat_ips.txt so a service restart keeps the
/// overlay until the next refresh; live connections to a listed IP surface as
/// "THREAT" in the FW Activity feed.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class ThreatIntel
{
    public const string FeodoUrl = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt";
    public const int MaxThreatListBytes = 5_000_000;

    private readonly string _path;
    private readonly object _refreshGate = new();

    // Replaced wholesale on refresh, never mutated after publish — so the
    // per-connection Contains hot path reads it lock-free and never waits on
    // the refresh's disk write.
    private volatile HashSet<string> _ips;

    public ThreatIntel(string dataDir)
    {
        _path = Path.Combine(dataDir ?? throw new ArgumentNullException(nameof(dataDir)), "threat_ips.txt");
        _ips = LoadFromDisk();
    }

    public int Count => _ips.Count;

    public bool Contains(string ip) => _ips.Contains(ip);

    public async Task<int> RefreshAsync(IListFetcher fetcher, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(fetcher);
        var text = await fetcher.FetchAsync(FeodoUrl, MaxThreatListBytes, ct);
        var parsed = DohResolvers.NormalizeIpSet(
            text.Split('\n').Select(l => l.Trim()).Where(l => l.Length != 0 && !l.StartsWith('#')));
        if (parsed.Count == 0)
        {
            throw new InvalidOperationException("threat-intel list contained no valid IPs");
        }

        // The gate serializes concurrent refreshes (swap + persist stay
        // consistent); readers never take it.
        lock (_refreshGate)
        {
            _ips = parsed;
            var tmp = _path + ".tmp";
            File.WriteAllLines(tmp, parsed.OrderBy(i => i, StringComparer.Ordinal));
            File.Move(tmp, _path, overwrite: true);
        }

        return parsed.Count;
    }

    private HashSet<string> LoadFromDisk()
    {
        try
        {
            if (File.Exists(_path))
            {
                return DohResolvers.NormalizeIpSet(File.ReadAllLines(_path));
            }
        }
        catch (IOException)
        {
            // Missing/unreadable cache — start empty until the next refresh.
        }

        return new HashSet<string>(StringComparer.Ordinal);
    }
}
