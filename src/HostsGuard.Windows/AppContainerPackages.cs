using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using HostsGuard.Core;

namespace HostsGuard.Windows;

/// <summary>Enumerates installed app-container/MSIX packages for package-scoped firewall rules.</summary>
[SupportedOSPlatform("windows")]
internal static class AppContainerPackages
{
    private const uint ForceComputeBinaries = 0x1;

    public static IReadOnlyList<FwAppPackage> List()
    {
        var error = NetworkIsolationEnumAppContainers(ForceComputeBinaries, out var count, out var containers);
        if (error != 0)
        {
            throw new Win32Exception((int)error, "NetworkIsolationEnumAppContainers failed");
        }

        if (containers == IntPtr.Zero || count == 0)
        {
            return Array.Empty<FwAppPackage>();
        }

        try
        {
            var size = Marshal.SizeOf<AppContainerNative>();
            var rows = new List<FwAppPackage>((int)count);
            for (var i = 0; i < count; i++)
            {
                var native = Marshal.PtrToStructure<AppContainerNative>(IntPtr.Add(containers, i * size));
                var family = PtrToString(native.AppContainerName);
                var sid = SidToString(native.AppContainerSid);
                if (family.Length == 0 || sid.Length == 0)
                {
                    continue;
                }

                rows.Add(new FwAppPackage(
                    family,
                    sid,
                    PtrToString(native.DisplayName),
                    PtrToString(native.PackageFullName),
                    ReadStringArray(native.Binaries.Binaries, native.Binaries.Count)));
            }

            return rows
                .GroupBy(p => p.PackageSid, StringComparer.OrdinalIgnoreCase)
                .Select(g => g.First())
                .OrderBy(p => p.DisplayName.Length == 0 ? p.PackageFamilyName : p.DisplayName, StringComparer.OrdinalIgnoreCase)
                .ToList();
        }
        finally
        {
            _ = NetworkIsolationFreeAppContainers(containers);
        }
    }

    private static string ReadStringArray(IntPtr values, uint count)
    {
        if (values == IntPtr.Zero || count == 0)
        {
            return string.Empty;
        }

        var paths = new List<string>((int)count);
        for (var i = 0; i < count; i++)
        {
            var ptr = Marshal.ReadIntPtr(values, i * IntPtr.Size);
            var value = PtrToString(ptr);
            if (value.Length != 0)
            {
                paths.Add(value);
            }
        }

        return string.Join(';', paths.Distinct(StringComparer.OrdinalIgnoreCase));
    }

    private static string SidToString(IntPtr sid)
    {
        if (sid == IntPtr.Zero || !ConvertSidToStringSid(sid, out var text))
        {
            return string.Empty;
        }

        try
        {
            return PtrToString(text);
        }
        finally
        {
            _ = LocalFree(text);
        }
    }

    private static string PtrToString(IntPtr value)
        => value == IntPtr.Zero ? string.Empty : Marshal.PtrToStringUni(value)?.Trim() ?? string.Empty;

    [StructLayout(LayoutKind.Sequential)]
    private struct AppContainerNative
    {
        public IntPtr AppContainerSid;
        public IntPtr UserSid;
        public IntPtr AppContainerName;
        public IntPtr DisplayName;
        public IntPtr Description;
        public AppContainerCapabilities Capabilities;
        public AppContainerBinaries Binaries;
        public IntPtr WorkingDirectory;
        public IntPtr PackageFullName;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct AppContainerCapabilities
    {
        public uint Count;
        public IntPtr Capabilities;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct AppContainerBinaries
    {
        public uint Count;
        public IntPtr Binaries;
    }

    [DllImport("FirewallAPI.dll")]
    private static extern uint NetworkIsolationEnumAppContainers(
        uint flags,
        out uint count,
        out IntPtr appContainers);

    [DllImport("FirewallAPI.dll")]
    private static extern uint NetworkIsolationFreeAppContainers(IntPtr appContainers);

    [DllImport("advapi32.dll", EntryPoint = "ConvertSidToStringSidW", SetLastError = true)]
    private static extern bool ConvertSidToStringSid(IntPtr sid, out IntPtr stringSid);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr LocalFree(IntPtr memory);
}
