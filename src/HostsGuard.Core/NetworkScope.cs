using System.Net;
using System.Net.Sockets;
using System.Numerics;

namespace HostsGuard.Core;

/// <summary>Per-app network scope that a block rule can target (NET-076).</summary>
public enum NetworkScope
{
    /// <summary>Public/routable addresses (everything that isn't LAN or localhost).</summary>
    Internet,

    /// <summary>Private LAN ranges (RFC1918, link-local, ULA).</summary>
    Lan,

    /// <summary>Loopback only.</summary>
    Localhost,

    /// <summary>Inbound connections (direction-scoped, address-agnostic).</summary>
    Inbound,
}

/// <summary>
/// Address-set definitions for per-app scope blocks (NET-076), mirroring
/// Portmaster's block-Internet / block-LAN / block-localhost scopes. The LAN and
/// localhost sets are explicit CIDR lists the firewall COM engine accepts
/// verbatim; Internet is expressed as its own address list because Windows
/// firewall rules cannot negate, so "block Internet but allow LAN" is a rule
/// whose remote set is every routable range. Pure + classifiable for the
/// direct-IP heuristic.
/// </summary>
public static class NetworkScopes
{
    /// <summary>Loopback: 127.0.0.0/8 and ::1.</summary>
    public const string Localhost = "127.0.0.0/8,::1/128";

    /// <summary>Private LAN: RFC1918 + CGNAT + link-local + ULA.</summary>
    public const string Lan =
        "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,100.64.0.0/10,169.254.0.0/16,fc00::/7,fe80::/10";

    // The non-Internet IPv4 ranges as [start, end] (inclusive). This is the
    // single source of truth the firewall Internet set and IsLan() both derive
    // from, so a hand-typed CIDR list can never drift from the classifier.
    private static readonly (uint Start, uint End)[] ExcludedV4 =
    {
        Range(10, 0, 0, 0, 8),     // 10.0.0.0/8       RFC1918
        Range(100, 64, 0, 0, 10),  // 100.64.0.0/10    CGNAT
        Range(127, 0, 0, 0, 8),    // 127.0.0.0/8      loopback
        Range(169, 254, 0, 0, 16), // 169.254.0.0/16   link-local
        Range(172, 16, 0, 0, 12),  // 172.16.0.0/12    RFC1918
        Range(192, 168, 0, 0, 16), // 192.168.0.0/16   RFC1918
    };

    /// <summary>
    /// Routable "Internet": the complement of the private/loopback carve-outs
    /// over public-unicast IPv4 (1.0.0.0–223.255.255.255, so 0/8, multicast
    /// 224/4 and reserved 240/4 are excluded), plus global-unicast IPv6
    /// (2000::/3). Generated from <see cref="ExcludedV4"/> so there are no gaps
    /// and the set exactly matches <see cref="IsLan"/>; firewall rules can't
    /// negate, so the block set must enumerate every routable range.
    /// </summary>
    public static readonly string Internet = BuildInternetV4() + ",2000::/3";

    /// <summary>The COM remote-address set for a scope (empty for Inbound — it's direction-only).</summary>
    public static string RemoteAddresses(NetworkScope scope) => scope switch
    {
        NetworkScope.Localhost => Localhost,
        NetworkScope.Lan => Lan,
        NetworkScope.Internet => Internet,
        _ => "Any",
    };

    /// <summary>Parse a scope token ("internet"/"lan"/"localhost"/"inbound").</summary>
    public static bool TryParse(string? token, out NetworkScope scope)
    {
        scope = NetworkScope.Internet;
        switch ((token ?? string.Empty).Trim().ToLowerInvariant())
        {
            case "internet": scope = NetworkScope.Internet; return true;
            case "lan": scope = NetworkScope.Lan; return true;
            case "localhost" or "local": scope = NetworkScope.Localhost; return true;
            case "inbound" or "in": scope = NetworkScope.Inbound; return true;
            default: return false;
        }
    }

    /// <summary>True when an address is loopback.</summary>
    public static bool IsLocalhost(IPAddress ip) => IPAddress.IsLoopback(ip);

    /// <summary>True when an address is in a private LAN range.</summary>
    public static bool IsLan(IPAddress ip)
    {
        ArgumentNullException.ThrowIfNull(ip);
        if (ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal)
        {
            return true;
        }

        if (ip.AddressFamily == AddressFamily.InterNetworkV6)
        {
            var b0 = ip.GetAddressBytes()[0];
            return (b0 & 0xFE) == 0xFC; // fc00::/7 ULA
        }

        if (ip.AddressFamily != AddressFamily.InterNetwork)
        {
            return false;
        }

        // Loopback (127/8) is classified by IsLocalhost; here LAN means the
        // private/link-local/CGNAT carve-outs — derived from the same source
        // the firewall Internet set is built from.
        var v = ToUInt(ip);
        foreach (var (start, end) in ExcludedV4)
        {
            if (start == LoopbackStart)
            {
                continue; // 127/8 belongs to IsLocalhost, not IsLan
            }

            if (v >= start && v <= end)
            {
                return true;
            }
        }

        return false;
    }

    private const uint LoopbackStart = 127u << 24;

    // ─── IPv4 complement generation (single source of truth) ──────────────────

    private static (uint Start, uint End) Range(byte a, byte b, byte c, byte d, int prefix)
    {
        var addr = ((uint)a << 24) | ((uint)b << 16) | ((uint)c << 8) | d;
        var size = prefix == 0 ? 0u : (prefix >= 32 ? 1u : 1u << (32 - prefix));
        var mask = prefix == 0 ? 0u : uint.MaxValue << (32 - prefix);
        var start = addr & mask;
        return (start, prefix >= 32 ? start : start + size - 1);
    }

    private static uint ToUInt(IPAddress ip)
    {
        var b = ip.GetAddressBytes();
        return ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
    }

    /// <summary>
    /// Build the comma-joined IPv4 Internet CIDR set: public-unicast space
    /// (1.0.0.0–223.255.255.255) minus <see cref="ExcludedV4"/>, decomposed into
    /// aligned CIDR blocks with no gaps.
    /// </summary>
    private static string BuildInternetV4()
    {
        const uint baseStart = 1u << 24;              // 1.0.0.0
        const uint baseEnd = (223u << 24) | 0x00FFFFFF; // 223.255.255.255

        var excluded = ExcludedV4
            .Select(r => (Start: Math.Max(r.Start, baseStart), End: Math.Min(r.End, baseEnd)))
            .Where(r => r.Start <= r.End)
            .OrderBy(r => r.Start)
            .ToList();

        var cidrs = new List<string>();
        var cursor = baseStart;
        foreach (var (start, end) in excluded)
        {
            if (start > cursor)
            {
                EmitRange(cursor, start - 1, cidrs);
            }

            if (end >= cursor)
            {
                cursor = end == uint.MaxValue ? uint.MaxValue : end + 1;
                if (end == uint.MaxValue)
                {
                    return string.Join(',', cidrs);
                }
            }
        }

        if (cursor <= baseEnd)
        {
            EmitRange(cursor, baseEnd, cidrs);
        }

        return string.Join(',', cidrs);
    }

    /// <summary>Decompose an inclusive [lo, hi] range into aligned CIDR blocks.</summary>
    private static void EmitRange(uint lo, uint hi, List<string> into)
    {
        var start = lo;
        while (start <= hi)
        {
            // Largest block that both aligns to `start` and fits within [start, hi].
            var maxByAlign = start == 0 ? 32 : BitOperations.TrailingZeroCount(start);
            var span = (ulong)hi - start + 1;
            var maxBySpan = 63 - BitOperations.LeadingZeroCount(span); // floor(log2(span))
            var size = Math.Min(maxByAlign, maxBySpan);
            into.Add($"{ToDotted(start)}/{32 - size}");

            var next = (ulong)start + (1UL << size);
            if (next > uint.MaxValue)
            {
                break;
            }

            start = (uint)next;
        }
    }

    private static string ToDotted(uint v) =>
        $"{(v >> 24) & 0xFF}.{(v >> 16) & 0xFF}.{(v >> 8) & 0xFF}.{v & 0xFF}";

    /// <summary>True when an address is public/routable (not localhost, not LAN).</summary>
    public static bool IsInternet(IPAddress ip) => !IsLocalhost(ip) && !IsLan(ip);

    /// <summary>Classify an address string; null when unparseable.</summary>
    public static NetworkScope? Classify(string? address)
    {
        if (!IPAddress.TryParse(address, out var ip))
        {
            return null;
        }

        if (IsLocalhost(ip))
        {
            return NetworkScope.Localhost;
        }

        return IsLan(ip) ? NetworkScope.Lan : NetworkScope.Internet;
    }
}
