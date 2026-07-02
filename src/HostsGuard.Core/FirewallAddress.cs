using System.Net;

namespace HostsGuard.Core;

/// <summary>
/// Validates the address forms a Windows Firewall rule accepts: a single IP,
/// a CIDR subnet (host bits allowed, matching Python <c>ipaddress(strict=False)</c>),
/// or a dash range. Port of the Python <c>valid_fw_addr</c>.
/// </summary>
public static class FirewallAddress
{
    public static bool IsValid(string? value)
    {
        var v = (value ?? string.Empty).Trim();
        if (v.Length == 0)
        {
            return false;
        }

        if (v.Contains('/', StringComparison.Ordinal))
        {
            return IsCidr(v);
        }

        if (v.Contains('-', StringComparison.Ordinal))
        {
            var idx = v.IndexOf('-', StringComparison.Ordinal);
            var a = v[..idx].Trim();
            var b = v[(idx + 1)..].Trim();
            return IPAddress.TryParse(a, out _) && IPAddress.TryParse(b, out _);
        }

        return IPAddress.TryParse(v, out _);
    }

    private static bool IsCidr(string v)
    {
        var idx = v.IndexOf('/', StringComparison.Ordinal);
        var addrPart = v[..idx];
        var prefixPart = v[(idx + 1)..];
        if (!IPAddress.TryParse(addrPart, out var addr))
        {
            return false;
        }

        // Non-strict: allow host bits set (Python strict=False). Only validate prefix range.
        if (!int.TryParse(prefixPart, out var prefix))
        {
            return false;
        }

        var max = addr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? 128 : 32;
        return prefix >= 0 && prefix <= max;
    }
}
