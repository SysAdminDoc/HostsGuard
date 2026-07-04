using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32;

namespace HostsGuard.Windows;

/// <summary>DNS cache flush + resolver switching, interface-first for testability.</summary>
public interface IDnsConfig
{
    /// <summary>Flush the Windows DNS client cache. Returns false if the API refused.</summary>
    bool FlushCache();

    /// <summary>
    /// Set static DNS servers on all connected physical adapters (registry
    /// NameServer, the documented pre-SetInterfaceDnsSettings mechanism).
    /// Empty list resets to DHCP. Returns the adapters changed.
    /// </summary>
    IReadOnlyList<string> SetResolvers(IReadOnlyList<string> servers);
}

/// <summary>
/// Native DNS control: <c>dnsapi!DnsFlushResolverCache</c> for the cache and
/// per-interface registry NameServer values for resolver switching — replaces
/// the Python <c>ipconfig /flushdns</c> + <c>Set-DnsClientServerAddress</c> shelling.
/// Mutation requires elevation (the service has it).
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class DnsConfig : IDnsConfig
{
    private const string InterfacesKey = @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces";

    [DllImport("dnsapi.dll", SetLastError = false)]
    private static extern uint DnsFlushResolverCache();

    public bool FlushCache() => DnsFlushResolverCache() != 0;

    public IReadOnlyList<string> SetResolvers(IReadOnlyList<string> servers)
    {
        ArgumentNullException.ThrowIfNull(servers);
        var value = string.Join(",", servers);
        var changed = new List<string>();
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.OperationalStatus != OperationalStatus.Up ||
                nic.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel)
            {
                continue;
            }

            var hasIpv4 = nic.GetIPProperties().UnicastAddresses
                .Any(a => a.Address.AddressFamily == AddressFamily.InterNetwork);
            if (!hasIpv4)
            {
                continue;
            }

            using var key = Registry.LocalMachine.OpenSubKey($@"{InterfacesKey}\{nic.Id}", writable: true);
            if (key is null)
            {
                continue;
            }

            key.SetValue("NameServer", value, RegistryValueKind.String);
            changed.Add(nic.Name);
        }

        FlushCache();
        return changed;
    }

    /// <summary>The machine's currently configured resolver IPs (all adapters).</summary>
    public static IReadOnlyList<IPAddress> CurrentResolvers()
        => NetworkInterface.GetAllNetworkInterfaces()
            .Where(n => n.OperationalStatus == OperationalStatus.Up)
            .SelectMany(n => n.GetIPProperties().DnsAddresses)
            .Distinct()
            .ToList();

    // ─── Encrypted-DNS (DoH) posture (NET-112) ───────────────────────────────

    private const string DohInterfacesKey =
        @"SYSTEM\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters";

    /// <summary>
    /// True when a configured DoH server requires encryption with no plaintext
    /// fallback (the "encrypted DNS only" posture). Windows stores this per DoH
    /// server as <c>DohFlags</c>: 2 (and the 3 variant) mean require-no-fallback;
    /// 1 is opportunistic (fallback allowed). Best-effort — see
    /// <see cref="RequiresEncryption"/>.
    /// </summary>
    public static bool RequiresEncryption(int dohFlags) => dohFlags is 2 or 3;

    /// <summary>
    /// Best-effort probe of whether the machine is in an encrypted-DNS-only posture
    /// (any active interface has a DoH server flagged require-no-fallback). Blocking
    /// encrypted DNS on such a machine can sever name resolution unless the resolver
    /// is exempted — the caller should warn. Never throws.
    /// </summary>
    public static bool IsEncryptedDnsOnly()
    {
        try
        {
            using var root = Registry.LocalMachine.OpenSubKey(DohInterfacesKey);
            if (root is null)
            {
                return false;
            }

            foreach (var ifaceName in root.GetSubKeyNames())
            {
                // …\{iface}\DohInterfaceSettings\Doh(6)?\{serverIp} → DohFlags DWORD.
                using var doh = root.OpenSubKey($@"{ifaceName}\DohInterfaceSettings");
                if (doh is null)
                {
                    continue;
                }

                foreach (var family in doh.GetSubKeyNames()) // "Doh", "Doh6"
                {
                    using var servers = doh.OpenSubKey(family);
                    if (servers is null)
                    {
                        continue;
                    }

                    foreach (var server in servers.GetSubKeyNames())
                    {
                        using var s = servers.OpenSubKey(server);
                        if (s?.GetValue("DohFlags") is int flags && RequiresEncryption(flags))
                        {
                            return true;
                        }
                    }
                }
            }
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException)
        {
            // Best-effort: an unreadable registry means we simply don't warn.
        }

        return false;
    }
}
