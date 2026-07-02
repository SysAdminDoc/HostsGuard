using System.Net;
using System.Runtime.Versioning;
using HostsGuard.Core;
using MaxMind.Db;

namespace HostsGuard.Service;

/// <summary>
/// Offline GeoIP: a DB-IP Lite country MMDB, memory-mapped via MaxMind.Db.
/// Refresh downloads the gzipped database with a streaming byte cap AND a
/// decompression cap, validates it loads, then swaps atomically — a bad
/// download can never replace a working database.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class GeoIpService : IDisposable
{
    public const int MaxGzipBytes = 40_000_000;
    public const int MaxMmdbBytes = 120_000_000;

    private readonly string _path;
    private readonly object _gate = new();
    private Reader? _reader;

    public GeoIpService(string dataDir)
    {
        _path = Path.Combine(dataDir ?? throw new ArgumentNullException(nameof(dataDir)), "geoip.mmdb");
        TryLoad();
    }

    public bool IsLoaded
    {
        get
        {
            lock (_gate)
            {
                return _reader is not null;
            }
        }
    }

    /// <summary>Default DB-IP Lite country database for the current month.</summary>
    public static string DefaultUrl
        => $"https://download.db-ip.com/free/dbip-country-lite-{DateTime.UtcNow:yyyy-MM}.mmdb.gz";

    /// <summary>ISO country code for an IP, or "" when unknown/unloaded.</summary>
    public string Lookup(string ip)
    {
        lock (_gate)
        {
            if (_reader is null || !IPAddress.TryParse(ip, out var address))
            {
                return string.Empty;
            }

            try
            {
                var record = _reader.Find<Dictionary<string, object>>(address);
                if (record is not null &&
                    record.TryGetValue("country", out var country) &&
                    country is Dictionary<string, object> c &&
                    c.TryGetValue("iso_code", out var iso))
                {
                    return iso?.ToString() ?? string.Empty;
                }
            }
            catch (InvalidDatabaseException)
            {
                return string.Empty;
            }

            return string.Empty;
        }
    }

    public async Task RefreshAsync(IListFetcher fetcher, string? url, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(fetcher);
        var compressed = await fetcher.FetchBytesAsync(url ?? DefaultUrl, MaxGzipBytes, ct);
        var mmdb = GzipLimited.Decompress(compressed, MaxMmdbBytes, "GeoIP MMDB");

        var tmp = _path + ".tmp";
        await File.WriteAllBytesAsync(tmp, mmdb, ct);

        // Validate before swapping in — a corrupt download never replaces a
        // working database.
        try
        {
            using var probe = new Reader(tmp, FileAccessMode.Memory);
        }
        catch (InvalidDatabaseException ex)
        {
            File.Delete(tmp);
            throw new InvalidOperationException($"downloaded GeoIP database is invalid: {ex.Message}", ex);
        }

        lock (_gate)
        {
            _reader?.Dispose();
            _reader = null;
            File.Move(tmp, _path, overwrite: true);
            TryLoad();
        }
    }

    private void TryLoad()
    {
        lock (_gate)
        {
            try
            {
                if (File.Exists(_path))
                {
                    _reader = new Reader(_path, FileAccessMode.MemoryMapped);
                }
            }
            catch (Exception ex) when (ex is InvalidDatabaseException or IOException)
            {
                _reader = null;
            }
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            _reader?.Dispose();
            _reader = null;
        }
    }
}
