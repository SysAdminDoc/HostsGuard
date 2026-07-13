using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;

namespace HostsGuard.Windows;

/// <summary>Best-effort native WLAN lookup for the SSID joined by an interface.</summary>
[SupportedOSPlatform("windows")]
internal static class WlanSsid
{
    private const int CurrentConnectionOpcode = 7;
    private const int ConnectionAttributesSsidLengthOffset = 520;
    private const int ConnectionAttributesSsidOffset = 524;
    private const int MaximumSsidBytes = 32;

    public static string? ForInterface(string interfaceId)
    {
        if (!Guid.TryParse(interfaceId, out var wanted))
        {
            return null;
        }

        IntPtr client = IntPtr.Zero;
        IntPtr list = IntPtr.Zero;
        try
        {
            if (WlanOpenHandle(2, IntPtr.Zero, out _, out client) != 0
                || WlanEnumInterfaces(client, IntPtr.Zero, out list) != 0
                || list == IntPtr.Zero)
            {
                return null;
            }

            var count = Marshal.ReadInt32(list);
            var itemSize = Marshal.SizeOf<WlanInterfaceInfo>();
            var item = IntPtr.Add(list, sizeof(int) * 2);
            for (var index = 0; index < count; index++, item = IntPtr.Add(item, itemSize))
            {
                var info = Marshal.PtrToStructure<WlanInterfaceInfo>(item);
                if (info.InterfaceGuid != wanted)
                {
                    continue;
                }

                return QueryCurrentSsid(client, info.InterfaceGuid);
            }
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException or MarshalDirectiveException)
        {
            return null;
        }
        finally
        {
            if (list != IntPtr.Zero)
            {
                WlanFreeMemory(list);
            }

            if (client != IntPtr.Zero)
            {
                _ = WlanCloseHandle(client, IntPtr.Zero);
            }
        }

        return null;
    }

    private static string? QueryCurrentSsid(IntPtr client, Guid interfaceGuid)
    {
        IntPtr data = IntPtr.Zero;
        try
        {
            if (WlanQueryInterface(
                    client,
                    ref interfaceGuid,
                    CurrentConnectionOpcode,
                    IntPtr.Zero,
                    out var dataSize,
                    out data,
                    out _) != 0
                || data == IntPtr.Zero
                || dataSize < ConnectionAttributesSsidOffset)
            {
                return null;
            }

            var length = Marshal.ReadInt32(data, ConnectionAttributesSsidLengthOffset);
            if (length is <= 0 or > MaximumSsidBytes
                || dataSize < ConnectionAttributesSsidOffset + length)
            {
                return null;
            }

            var bytes = new byte[length];
            Marshal.Copy(IntPtr.Add(data, ConnectionAttributesSsidOffset), bytes, 0, length);
            return Encoding.UTF8.GetString(bytes);
        }
        finally
        {
            if (data != IntPtr.Zero)
            {
                WlanFreeMemory(data);
            }
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WlanInterfaceInfo
    {
        public Guid InterfaceGuid;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string Description;

        public int State;
    }

    [DllImport("wlanapi.dll")]
    private static extern int WlanOpenHandle(
        int clientVersion,
        IntPtr reserved,
        out int negotiatedVersion,
        out IntPtr clientHandle);

    [DllImport("wlanapi.dll")]
    private static extern int WlanCloseHandle(IntPtr clientHandle, IntPtr reserved);

    [DllImport("wlanapi.dll")]
    private static extern int WlanEnumInterfaces(IntPtr clientHandle, IntPtr reserved, out IntPtr interfaceList);

    [DllImport("wlanapi.dll")]
    private static extern int WlanQueryInterface(
        IntPtr clientHandle,
        ref Guid interfaceGuid,
        int opcode,
        IntPtr reserved,
        out int dataSize,
        out IntPtr data,
        out int opcodeValueType);

    [DllImport("wlanapi.dll")]
    private static extern void WlanFreeMemory(IntPtr memory);
}
