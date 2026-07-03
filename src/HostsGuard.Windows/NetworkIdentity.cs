using System.Net.NetworkInformation;
using System.Runtime.Versioning;

namespace HostsGuard.Windows;

/// <summary>The currently-joined network's fingerprint and a human label.</summary>
public sealed record NetworkFingerprint(string Fingerprint, string Label);

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
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces()
                     .Where(n => n.OperationalStatus == OperationalStatus.Up
                                 && n.NetworkInterfaceType != NetworkInterfaceType.Loopback
                                 && n.NetworkInterfaceType != NetworkInterfaceType.Tunnel))
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

            return new NetworkFingerprint(fingerprint, nic.Name);
        }

        return null;
    }
}
