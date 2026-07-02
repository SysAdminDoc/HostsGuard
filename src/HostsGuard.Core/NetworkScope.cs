using System.Net;
using System.Net.Sockets;

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

    /// <summary>
    /// Routable "Internet": the complement of localhost+LAN as an explicit set of
    /// public ranges (firewall rules can't negate). IPv4 public space split
    /// around the private carve-outs, plus global-unicast IPv6.
    /// </summary>
    public const string Internet =
        "1.0.0.0/8,2.0.0.0/7,4.0.0.0/6,8.0.0.0/7,11.0.0.0/8,12.0.0.0/6,16.0.0.0/4," +
        "32.0.0.0/3,64.0.0.0/3,96.0.0.0/4,112.0.0.0/5,120.0.0.0/6,124.0.0.0/7,126.0.0.0/8," +
        "128.0.0.0/3,160.0.0.0/5,168.0.0.0/6,173.0.0.0/8,174.0.0.0/7,176.0.0.0/4," +
        "192.0.0.0/9,192.128.0.0/11,192.160.0.0/13,192.169.0.0/16,192.170.0.0/15," +
        "192.172.0.0/14,192.176.0.0/12,192.192.0.0/10,193.0.0.0/8,194.0.0.0/7,196.0.0.0/6," +
        "200.0.0.0/5,208.0.0.0/4,2000::/3";

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
        if (ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal)
        {
            return true;
        }

        if (ip.AddressFamily == AddressFamily.InterNetworkV6)
        {
            var b0 = ip.GetAddressBytes()[0];
            return (b0 & 0xFE) == 0xFC; // fc00::/7 ULA
        }

        var b = ip.GetAddressBytes();
        return b[0] switch
        {
            10 => true,
            127 => true,
            169 when b[1] == 254 => true,        // link-local
            172 when b[1] is >= 16 and <= 31 => true,
            192 when b[1] == 168 => true,
            100 when b[1] is >= 64 and <= 127 => true, // CGNAT
            _ => false,
        };
    }

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
