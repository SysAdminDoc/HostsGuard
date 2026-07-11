using System.Net;
using System.Net.Sockets;

namespace HostsGuard.Core;

/// <summary>One IP-list scan's outcome: normalized entries + line diagnostics.</summary>
public sealed record IpListScan(
    IReadOnlyList<string> Entries,
    long Invalid,
    long Duplicates,
    long Unsafe);

/// <summary>
/// Parser for IP-format blocklists (HaGeZi ips/*, FireHOL-style): one IPv4/IPv6
/// address or CIDR per line, #/!/; comments. Entries are normalized to their
/// canonical text form and de-duplicated. Non-routable targets (loopback,
/// private, link-local, multicast, unspecified) and over-wide CIDRs are
/// rejected as unsafe — a hostile or broken list must never yield a firewall
/// rule that blocks the LAN or all traffic.
/// </summary>
public static class IpBlocklistParser
{
    /// <summary>Widest accepted IPv4 prefix (a /8 is 16M addresses; /0 would block everything).</summary>
    public const int MinIpv4Prefix = 8;

    /// <summary>Widest accepted IPv6 prefix.</summary>
    public const int MinIpv6Prefix = 16;

    public static IpListScan Scan(string text)
    {
        var entries = new List<string>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        long invalid = 0, duplicates = 0, unsafeCount = 0;

        foreach (var raw in (text ?? string.Empty).Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line[0] is '#' or '!' or ';')
            {
                continue;
            }

            var hash = line.IndexOf('#', StringComparison.Ordinal);
            if (hash >= 0)
            {
                line = line[..hash].Trim();
            }

            if (line.Length == 0)
            {
                continue;
            }

            var token = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries)[0];
            switch (Normalize(token))
            {
                case (null, false):
                    invalid++;
                    break;
                case (null, true):
                    unsafeCount++;
                    break;
                case ({ } entry, _):
                    if (seen.Add(entry))
                    {
                        entries.Add(entry);
                    }
                    else
                    {
                        duplicates++;
                    }

                    break;
            }
        }

        return new IpListScan(entries, invalid, duplicates, unsafeCount);
    }

    /// <summary>
    /// Normalize a single token to a canonical IP or CIDR entry. Returns
    /// (entry, _) when valid, (null, true) when parseable but unsafe to block,
    /// and (null, false) when unparseable.
    /// </summary>
    public static (string? Entry, bool Unsafe) Normalize(string token)
    {
        token = (token ?? string.Empty).Trim();
        if (token.Length == 0)
        {
            return (null, false);
        }

        var slash = token.IndexOf('/', StringComparison.Ordinal);
        if (slash < 0)
        {
            if (!IPAddress.TryParse(token, out var ip) || HasPort(token, ip))
            {
                return (null, false);
            }

            return IsBlockable(ip) ? (ip.ToString(), false) : (null, true);
        }

        var prefixText = token[(slash + 1)..];
        if (!IPAddress.TryParse(token[..slash], out var baseIp) ||
            !int.TryParse(prefixText, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var prefix))
        {
            return (null, false);
        }

        var maxPrefix = baseIp.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
        if (prefix > maxPrefix)
        {
            return (null, false);
        }

        var minPrefix = baseIp.AddressFamily == AddressFamily.InterNetwork ? MinIpv4Prefix : MinIpv6Prefix;
        if (prefix < minPrefix || !IsBlockable(baseIp))
        {
            return (null, true);
        }

        return prefix == maxPrefix ? (baseIp.ToString(), false) : ($"{baseIp}/{prefix}", false);
    }

    /// <summary>An IPv4 "1.2.3.4:443" parses as an address on some runtimes — reject explicitly.</summary>
    private static bool HasPort(string token, IPAddress parsed) =>
        parsed.AddressFamily == AddressFamily.InterNetwork && token.Contains(':', StringComparison.Ordinal);

    private static bool IsBlockable(IPAddress ip)
    {
        if (IPAddress.IsLoopback(ip) || ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any) ||
            ip.Equals(IPAddress.Broadcast))
        {
            return false;
        }

        var bytes = ip.GetAddressBytes();
        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            return bytes[0] switch
            {
                10 => false,                                  // RFC1918
                127 => false,                                 // loopback
                169 when bytes[1] == 254 => false,            // link-local
                172 when bytes[1] >= 16 && bytes[1] <= 31 => false, // RFC1918
                192 when bytes[1] == 168 => false,            // RFC1918
                >= 224 => false,                              // multicast + reserved
                _ => true,
            };
        }

        return !ip.IsIPv6LinkLocal && !ip.IsIPv6Multicast && !ip.IsIPv6SiteLocal &&
               (bytes[0] & 0xFE) != 0xFC; // fc00::/7 unique-local
    }
}
