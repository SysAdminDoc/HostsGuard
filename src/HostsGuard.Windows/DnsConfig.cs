using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32;

namespace HostsGuard.Windows;

/// <summary>One row from the Windows DNS client resolver cache.</summary>
public sealed record DnsCacheRecord(string Name, string Type, int DataLength, uint Flags);

/// <summary>DNS cache flush + resolver switching, interface-first for testability.</summary>
public interface IDnsConfig
{
    /// <summary>Flush the Windows DNS client cache. Returns false if the API refused.</summary>
    bool FlushCache();

    /// <summary>Flush one Windows DNS client cache entry by name.</summary>
    bool FlushCacheEntry(string name);

    /// <summary>Snapshot the Windows DNS client resolver cache.</summary>
    IReadOnlyList<DnsCacheRecord> GetCacheEntries(int limit, string? search);

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

    [DllImport("dnsapi.dll", EntryPoint = "DnsFlushResolverCacheEntry_W", CharSet = CharSet.Unicode, SetLastError = false)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DnsFlushResolverCacheEntry(string name);

    [DllImport("dnsapi.dll", EntryPoint = "DnsGetCacheDataTable", SetLastError = false)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DnsGetCacheDataTable(out IntPtr cacheTable);

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct DnsCacheEntryNative
    {
        public readonly IntPtr Next;
        public readonly IntPtr Name;
        public readonly ushort Type;
        public readonly ushort DataLength;
        public readonly uint Flags;
    }

    public bool FlushCache() => DnsFlushResolverCache() != 0;

    public bool FlushCacheEntry(string name)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        return DnsFlushResolverCacheEntry(name);
    }

    public IReadOnlyList<DnsCacheRecord> GetCacheEntries(int limit, string? search)
    {
        var max = limit <= 0 ? 500 : Math.Clamp(limit, 1, 5_000);
        var needle = (search ?? string.Empty).Trim();
        if (!DnsGetCacheDataTable(out var table) || table == IntPtr.Zero)
        {
            return Array.Empty<DnsCacheRecord>();
        }

        var entries = new List<DnsCacheRecord>();
        var current = table;
        var walked = 0;
        while (current != IntPtr.Zero && entries.Count < max && walked++ < 20_000)
        {
            var native = Marshal.PtrToStructure<DnsCacheEntryNative>(current);
            var name = Marshal.PtrToStringUni(native.Name)?.TrimEnd('.') ?? string.Empty;
            var type = FormatDnsType(native.Type);
            if (name.Length != 0 &&
                (needle.Length == 0 ||
                 name.Contains(needle, StringComparison.OrdinalIgnoreCase) ||
                 type.Contains(needle, StringComparison.OrdinalIgnoreCase)))
            {
                entries.Add(new DnsCacheRecord(name, type, native.DataLength, native.Flags));
            }

            current = native.Next;
        }

        return entries;
    }

    private static string FormatDnsType(ushort type) => type switch
    {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        43 => "DS",
        48 => "DNSKEY",
        52 => "TLSA",
        64 => "SVCB",
        65 => "HTTPS",
        _ => type.ToString(System.Globalization.CultureInfo.InvariantCulture),
    };

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
