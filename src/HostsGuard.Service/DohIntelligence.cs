using System.Runtime.Versioning;
using System.Text.Json;
using System.Text.Json.Serialization;
using HostsGuard.Core;
using Microsoft.Win32;

namespace HostsGuard.Service;

/// <summary>Persisted DoH resolver state (doh_resolvers.json schema 1).</summary>
public sealed class DohState
{
    [JsonPropertyName("schema")]
    public int Schema { get; set; } = 1;

    [JsonPropertyName("updated")]
    public string Updated { get; set; } = string.Empty;

    [JsonPropertyName("source")]
    public string Source { get; set; } = "Built-in resolver defaults";

    [JsonPropertyName("sha256")]
    public string Sha256 { get; set; } = string.Empty;

    [JsonPropertyName("ips")]
    public List<string> Ips { get; set; } = new();
}

/// <summary>
/// DoH resolver intelligence store: doh_resolvers.json under the service data
/// dir (same schema as the Python build). Refresh merges the Windows
/// known-DoH-server registry list with an optional SHA-256-gated remote list;
/// any failure leaves the previous state file intact.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class DohIntelligence
{
    private const string DohWellKnownKey = @"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DohWellKnownServers";
    private static readonly TimeSpan DefaultCurrentIpsStatTtl = TimeSpan.FromSeconds(1);

    private readonly string _path;
    private readonly TimeSpan _currentIpsStatTtl;
    private readonly IClock _clock;
    private readonly object _gate = new();

    public DohIntelligence(string dataDir, TimeSpan? currentIpsStatTtl = null, IClock? clock = null)
    {
        _path = Path.Combine(dataDir ?? throw new ArgumentNullException(nameof(dataDir)), "doh_resolvers.json");
        var ttl = currentIpsStatTtl ?? DefaultCurrentIpsStatTtl;
        _currentIpsStatTtl = ttl > TimeSpan.Zero
            ? ttl
            : TimeSpan.Zero;
        _clock = clock ?? SystemClock.Instance;
    }

    public string FilePath => _path;

    public DohState Load()
    {
        lock (_gate)
        {
            try
            {
                if (File.Exists(_path))
                {
                    var state = JsonSerializer.Deserialize<DohState>(File.ReadAllText(_path));
                    if (state is not null)
                    {
                        state.Ips = DohResolvers.NormalizeIpSet(state.Ips).OrderBy(i => i, StringComparer.Ordinal).ToList();
                        return state;
                    }
                }
            }
            catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException)
            {
                // Corrupt/unreadable state falls back to defaults; the file on
                // disk is never overwritten except by a successful refresh.
            }

            return new DohState();
        }
    }

    private HashSet<string>? _ipCache;
    private DateTime _ipCacheStamp;
    private DateTime _ipCacheLastStatUtc;

    /// <summary>
    /// Built-in resolver IPs plus any learned/refreshed extras. Cached against
    /// the state file's write time — this runs on the per-connection hot path.
    /// </summary>
    public IReadOnlySet<string> CurrentIps()
    {
        lock (_gate)
        {
            var now = _clock.UtcNow;
            if (_ipCache is not null && now - _ipCacheLastStatUtc < _currentIpsStatTtl)
            {
                return _ipCache;
            }

            _ipCacheLastStatUtc = now;
            var stamp = File.Exists(_path) ? File.GetLastWriteTimeUtc(_path) : DateTime.MinValue;
            if (_ipCache is null || stamp != _ipCacheStamp)
            {
                var ips = new HashSet<string>(DohResolvers.NormalizeIpSet(DohResolvers.BuiltIn), StringComparer.Ordinal);
                ips.UnionWith(Load().Ips);
                _ipCache = ips;
                _ipCacheStamp = stamp;
            }

            return _ipCache;
        }
    }

    /// <summary>Replace persisted resolver intelligence from a trusted portable-policy import.</summary>
    public void Import(DohState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        state.Ips = DohResolvers.NormalizeIpSet(state.Ips).OrderBy(i => i, StringComparer.Ordinal).ToList();
        Save(state);
    }

    /// <summary>
    /// Refresh: Windows known DoH servers (registry) + an optional remote list.
    /// A remote URL requires the expected SHA-256; a mismatch throws and the
    /// prior state file survives untouched.
    /// </summary>
    public async Task<DohState> RefreshAsync(string url, string expectedSha256, IListFetcher fetcher, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(fetcher);
        var windows = WindowsKnownDohIps();
        var merged = new HashSet<string>(windows, StringComparer.Ordinal);
        var sources = new List<string>();
        if (windows.Count != 0)
        {
            sources.Add("Windows known DoH servers");
        }

        var actualHash = string.Empty;
        url = (url ?? string.Empty).Trim();
        if (url.Length != 0)
        {
            var payload = await fetcher.FetchAsync(url, DohResolvers.MaxResolverListBytes, ct);
            actualHash = DohResolvers.VerifySha256(payload, expectedSha256);
            var remote = DohResolvers.ParsePayload(payload);
            if (remote.Count == 0)
            {
                throw new InvalidOperationException("DoH resolver list contained no valid IP addresses");
            }

            merged.UnionWith(remote);
            sources.Add(url);
        }

        var state = new DohState
        {
            Updated = _clock.Now.ToString("o", System.Globalization.CultureInfo.InvariantCulture),
            Source = sources.Count != 0 ? string.Join(" + ", sources) : "Built-in resolver defaults",
            Sha256 = actualHash,
            Ips = merged.OrderBy(i => i, StringComparer.Ordinal).ToList(),
        };
        Save(state);
        return state;
    }

    private void Save(DohState state)
    {
        lock (_gate)
        {
            var dir = Path.GetDirectoryName(_path);
            if (!string.IsNullOrEmpty(dir))
            {
                Directory.CreateDirectory(dir);
            }

            var tmp = _path + ".tmp";
            File.WriteAllText(tmp, JsonSerializer.Serialize(state, new JsonSerializerOptions { WriteIndented = true }));
            File.Move(tmp, _path, overwrite: true);
            _ipCache = null;
            _ipCacheStamp = DateTime.MinValue;
            _ipCacheLastStatUtc = DateTime.MinValue;
        }
    }

    /// <summary>Browser/OS-known DoH server IPs from the Dnscache registry list.</summary>
    public static IReadOnlySet<string> WindowsKnownDohIps()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(DohWellKnownKey);
            return key is null
                ? new HashSet<string>(StringComparer.Ordinal)
                : DohResolvers.NormalizeIpSet(key.GetSubKeyNames());
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or IOException)
        {
            return new HashSet<string>(StringComparer.Ordinal);
        }
    }
}
