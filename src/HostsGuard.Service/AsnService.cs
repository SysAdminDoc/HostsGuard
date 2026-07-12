using System.Globalization;
using System.Net;
using System.Runtime.Versioning;
using HostsGuard.Core;
using MaxMind.Db;

namespace HostsGuard.Service;

/// <summary>
/// Offline ASN attribution: a DB-IP IP-to-ASN Lite MMDB, memory-mapped via
/// MaxMind.Db — the same reader the country <see cref="GeoIpService"/> uses, so
/// there is zero cloud dependency. Refresh downloads the gzipped database with
/// streaming + decompression caps, validates it loads, then swaps atomically —
/// a bad download can never replace a working database. Absent DB → blank.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class AsnService : IDisposable
{
    public const int MaxGzipBytes = 40_000_000;
    public const int MaxMmdbBytes = 120_000_000;

    private readonly string _path;
    private readonly object _gate = new();
    private Reader? _reader;

    public AsnService(string dataDir)
    {
        _path = Path.Combine(dataDir ?? throw new ArgumentNullException(nameof(dataDir)), "asn.mmdb");
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

    /// <summary>Default DB-IP IP-to-ASN Lite database for the current month.</summary>
    public static string DefaultUrl
        => $"https://download.db-ip.com/free/dbip-asn-lite-{DateTime.UtcNow:yyyy-MM}.mmdb.gz";

    /// <summary>"AS15169 Google LLC" for an IP, or "" when unknown/unloaded.</summary>
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
                return Format(record);
            }
            catch (InvalidDatabaseException)
            {
                return string.Empty;
            }
        }
    }

    /// <summary>
    /// Render a DB-IP ASN record ("AS#### Org") from the raw MMDB dictionary.
    /// Static + record-driven so the formatting is unit-testable without an MMDB.
    /// </summary>
    public static string Format(IReadOnlyDictionary<string, object>? record)
    {
        if (record is null)
        {
            return string.Empty;
        }

        var number = record.TryGetValue("autonomous_system_number", out var n)
            ? Convert.ToInt64(n, CultureInfo.InvariantCulture)
            : 0;
        var org = record.TryGetValue("autonomous_system_organization", out var o)
            ? o?.ToString()?.Trim() ?? string.Empty
            : string.Empty;

        if (number <= 0 && org.Length == 0)
        {
            return string.Empty;
        }

        var asLabel = number > 0 ? $"AS{number.ToString(CultureInfo.InvariantCulture)}" : string.Empty;
        return string.Join(" ", new[] { asLabel, org }.Where(s => s.Length != 0));
    }

    public async Task RefreshAsync(IListFetcher fetcher, string? url, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(fetcher);
        var compressed = await fetcher.FetchBytesAsync(url ?? DefaultUrl, MaxGzipBytes, ct);
        var mmdb = GzipLimited.Decompress(compressed, MaxMmdbBytes, "ASN MMDB");

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
            throw new InvalidOperationException($"downloaded ASN database is invalid: {ex.Message}", ex);
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
