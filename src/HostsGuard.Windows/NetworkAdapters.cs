using System.Net.NetworkInformation;
using System.Runtime.Versioning;

namespace HostsGuard.Windows;

/// <summary>A network interface as the kill-switch UI sees it (NET-119).</summary>
public sealed record AdapterInfo(string Name, string Description, bool IsUp, bool IsVpnLikely);

/// <summary>
/// Enumerates network interfaces for the VPN-presence kill-switch (NET-119): lists
/// adapters for the picker and answers "is an adapter matching this name up?".
/// A match is a case-insensitive substring test against either the adapter's
/// friendly name or its description, so the user can key on "WireGuard", "Mullvad",
/// "ProtonVPN", "TAP", etc. No elevation required.
/// </summary>
[SupportedOSPlatform("windows")]
public static class NetworkAdapters
{
    /// <summary>All non-loopback interfaces, VPN-likely ones flagged, for the picker.</summary>
    public static IReadOnlyList<AdapterInfo> List()
    {
        var list = new List<AdapterInfo>();
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.NetworkInterfaceType == NetworkInterfaceType.Loopback)
            {
                continue;
            }

            list.Add(new AdapterInfo(
                nic.Name,
                nic.Description,
                nic.OperationalStatus == OperationalStatus.Up,
                LooksLikeVpn(nic.Name, nic.Description, nic.NetworkInterfaceType)));
        }

        // VPN-likely first, then up before down, then by name — the useful ordering.
        return list
            .OrderByDescending(a => a.IsVpnLikely)
            .ThenByDescending(a => a.IsUp)
            .ThenBy(a => a.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    /// <summary>True when an interface whose name/description matches <paramref name="match"/> is up.</summary>
    public static bool IsUp(string match)
    {
        if (string.IsNullOrWhiteSpace(match))
        {
            return false;
        }

        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.OperationalStatus == OperationalStatus.Up
                && Matches(nic.Name, nic.Description, match))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>Pure name/description substring match (case-insensitive), unit-testable.</summary>
    public static bool Matches(string name, string description, string match)
    {
        if (string.IsNullOrWhiteSpace(match))
        {
            return false;
        }

        return (name ?? string.Empty).Contains(match, StringComparison.OrdinalIgnoreCase)
            || (description ?? string.Empty).Contains(match, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Heuristic: does this look like a VPN/tunnel adapter (for the picker hint)?</summary>
    public static bool LooksLikeVpn(string name, string description, NetworkInterfaceType type)
    {
        if (type == NetworkInterfaceType.Tunnel || type == NetworkInterfaceType.Ppp)
        {
            return true;
        }

        var hay = ((name ?? string.Empty) + " " + (description ?? string.Empty));
        foreach (var needle in VpnHints)
        {
            if (hay.Contains(needle, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static readonly string[] VpnHints =
    {
        "vpn", "wireguard", "wintun", "openvpn", "tap-windows", "tap-",
        "mullvad", "proton", "wg", "nordlynx", "tailscale", "zerotier",
        "expressvpn", "surfshark", "windscribe",
    };
}
