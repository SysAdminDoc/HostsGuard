using System.Net;

namespace HostsGuard.Core;

/// <summary>Validation and canonicalization for intentional hosts-file domain-to-IP pins.</summary>
public static class HostRedirect
{
    public static bool TryNormalize(
        string? domain,
        string? address,
        out string canonicalDomain,
        out string canonicalAddress,
        out string error)
    {
        canonicalDomain = Domains.ToAscii(domain);
        canonicalAddress = string.Empty;
        if (!Domains.LooksLikeDomain(canonicalDomain))
        {
            error = $"'{domain}' is not a valid domain";
            return false;
        }

        if (!IPAddress.TryParse(address?.Trim(), out var ip))
        {
            error = $"'{address}' is not a valid IP address";
            return false;
        }

        if (ip.IsIPv4MappedToIPv6)
        {
            ip = ip.MapToIPv4();
        }

        if (ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any) ||
            ip.Equals(IPAddress.Broadcast) || ip.IsIPv6Multicast || IsIpv4Multicast(ip))
        {
            error = $"'{address}' is not a unicast IP address";
            return false;
        }

        canonicalAddress = ip.ToString();
        error = string.Empty;
        return true;
    }

    private static bool IsIpv4Multicast(IPAddress ip)
    {
        if (ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
        {
            return false;
        }

        var first = ip.GetAddressBytes()[0];
        return first is >= 224 and <= 239;
    }
}
