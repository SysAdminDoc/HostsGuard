using System.Net.NetworkInformation;
using System.Runtime.Versioning;

namespace HostsGuard.Windows;

/// <summary>The currently-joined network's legacy fingerprint and match signals.</summary>
public sealed record NetworkFingerprint(string Fingerprint, string Label)
{
    public string GatewayMac { get; init; } = string.Empty;

    public string Ssid { get; init; } = string.Empty;

    public string InterfaceName { get; init; } = string.Empty;

    public string DnsSuffix { get; init; } = string.Empty;

    public bool VpnPresent { get; init; }
}

/// <summary>Current-network identity source, fakeable for tests.</summary>
public interface INetworkIdentity
{
    /// <summary>The active network's fingerprint + label, or null when offline.</summary>
    NetworkFingerprint? Current();
}

/// <summary>
/// Fingerprints the joined network (NET-083) from the active interface's default
/// gateway MAC — stable per physical network, independent of DHCP lease and not
/// spoofable by a renamed SSID. Falls back to the interface's own MAC when no
/// gateway is visible. No elevation required.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class NetworkIdentity : INetworkIdentity
{
    public NetworkFingerprint? Current()
    {
        try
        {
            return Resolve();
        }
        catch (NetworkInformationException)
        {
            return null;
        }
    }

    private static NetworkFingerprint? Resolve()
    {
        var interfaces = NetworkInterface.GetAllNetworkInterfaces();
        var vpnPresent = interfaces.Any(IsActiveVpn);
        foreach (var nic in interfaces
                     .Where(n => n.OperationalStatus == OperationalStatus.Up
                                 && n.NetworkInterfaceType != NetworkInterfaceType.Loopback
                                 && n.NetworkInterfaceType != NetworkInterfaceType.Tunnel)
                     .OrderBy(n => n.Id, StringComparer.Ordinal))
        {
            var props = nic.GetIPProperties();
            var gateway = props.GatewayAddresses.FirstOrDefault(g =>
                g.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);
            if (gateway is null)
            {
                continue;
            }

            // Prefer the gateway MAC (from the ARP/neighbor table) — stable per LAN.
            var gatewayMac = NeighborMac.ForAddress(gateway.Address);
            var fingerprint = gatewayMac
                ?? nic.GetPhysicalAddress().ToString() + "@" + gateway.Address;
            if (string.IsNullOrWhiteSpace(fingerprint))
            {
                continue;
            }

            return new NetworkFingerprint(fingerprint, nic.Name)
            {
                GatewayMac = gatewayMac ?? string.Empty,
                Ssid = WlanSsid.ForInterface(nic.Id) ?? string.Empty,
                InterfaceName = nic.Name,
                DnsSuffix = props.DnsSuffix ?? string.Empty,
                VpnPresent = vpnPresent,
            };
        }

        return null;
    }

    internal static bool IsActiveVpn(NetworkInterface nic)
    {
        if (nic.OperationalStatus != OperationalStatus.Up)
        {
            return false;
        }

        if (nic.NetworkInterfaceType is NetworkInterfaceType.Tunnel or NetworkInterfaceType.Ppp)
        {
            return true;
        }

        var identity = $"{nic.Name} {nic.Description}";
        return identity.Contains("VPN", StringComparison.OrdinalIgnoreCase)
            || identity.Contains("WIREGUARD", StringComparison.OrdinalIgnoreCase)
            || identity.Contains("OPENVPN", StringComparison.OrdinalIgnoreCase)
            || identity.Contains("TAP-WINDOWS", StringComparison.OrdinalIgnoreCase)
            || identity.Contains("TUNNEL", StringComparison.OrdinalIgnoreCase);
    }
}
