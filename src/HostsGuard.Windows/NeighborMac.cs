using System.Net;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace HostsGuard.Windows;

/// <summary>
/// Resolves an IPv4 address to its MAC via the ARP table (<c>SendARP</c>) —
/// used to fingerprint the default gateway for network-profile switching
/// (NET-083). Best-effort: returns null when the address can't be resolved.
/// </summary>
[SupportedOSPlatform("windows")]
public static class NeighborMac
{
    public static string? ForAddress(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);
        if (address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
        {
            return null;
        }

        var dest = BitConverter.ToUInt32(address.GetAddressBytes(), 0);
        var mac = new byte[6];
        var len = mac.Length;
        try
        {
            if (SendARP(dest, 0, mac, ref len) != 0 || len == 0)
            {
                return null;
            }
        }
        catch (DllNotFoundException)
        {
            return null;
        }

        return string.Join(':', mac.Take(len).Select(b => b.ToString("X2")));
    }

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern int SendARP(uint destIp, uint srcIp, byte[] macAddr, ref int macAddrLen);
}
