using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace HostsGuard.Windows;

/// <summary>A live network connection with owning-process attribution.</summary>
public sealed record ConnectionInfo(
    string Protocol,
    string LocalAddress,
    int LocalPort,
    string RemoteAddress,
    int RemotePort,
    string State,
    int Pid,
    string Process,
    string Direction = "outbound",
    string ProcessPath = "",
    string PackageFamilyName = "");

/// <summary>Best-effort process identity attached to an IPHLPAPI owner PID.</summary>
public sealed record ConnectionOwnerInfo(string Process, string ProcessPath = "", string PackageFamilyName = "");

/// <summary>
/// PID-attributed connection snapshots via IPHLPAPI <c>GetExtendedTcpTable</c>
/// (IPv4 + IPv6) — replaces the Python psutil dependency. Reading the table needs
/// no elevation. Process names are resolved from PID and cached.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class ConnectionMonitor
{
    private const int AfInet = 2;
    private const int AfInet6 = 23;
    private const int TcpTableOwnerPidAll = 5;
    private const int UdpTableOwnerPid = 1;

    private static readonly string[] TcpStates =
    {
        "", "CLOSED", "LISTEN", "SYN_SENT", "SYN_RCVD", "ESTABLISHED",
        "FIN_WAIT1", "FIN_WAIT2", "CLOSE_WAIT", "CLOSING", "LAST_ACK", "TIME_WAIT", "DELETE_TCB",
    };

    private readonly ConcurrentDictionary<int, ConnectionOwnerInfo> _procCache = new();
    private readonly Func<int, ConnectionOwnerInfo> _ownerLookup;
    private int _snapshots;

    public ConnectionMonitor(Func<int, ConnectionOwnerInfo>? ownerLookup = null)
        => _ownerLookup = ownerLookup ?? LookupOwner;

    /// <summary>Snapshot all TCP connections and UDP endpoints (IPv4 + IPv6) with owning process.</summary>
    public IReadOnlyList<ConnectionInfo> Snapshot()
    {
        if (++_snapshots % 30 == 0)
        {
            _procCache.Clear();
        }

        var list = new List<ConnectionInfo>();
        list.AddRange(SnapshotTcp4());
        list.AddRange(SnapshotTcp6());
        list.AddRange(SnapshotUdp4());
        list.AddRange(SnapshotUdp6());
        return list;
    }

    private IEnumerable<ConnectionInfo> SnapshotTcp4()
    {
        foreach (var row in ReadTable<MIB_TCPROW_OWNER_PID>(AfInet))
        {
            var owner = Owner((int)row.dwOwningPid);
            yield return new ConnectionInfo(
                "TCP",
                new IPAddress(BitConverter.GetBytes(row.dwLocalAddr)).ToString(),
                Port(row.dwLocalPort),
                new IPAddress(BitConverter.GetBytes(row.dwRemoteAddr)).ToString(),
                Port(row.dwRemotePort),
                StateName(row.dwState),
                (int)row.dwOwningPid,
                owner.Process,
                ProcessPath: owner.ProcessPath,
                PackageFamilyName: owner.PackageFamilyName);
        }
    }

    private IEnumerable<ConnectionInfo> SnapshotTcp6()
    {
        foreach (var row in ReadTable<MIB_TCP6ROW_OWNER_PID>(AfInet6))
        {
            var owner = Owner((int)row.dwOwningPid);
            yield return new ConnectionInfo(
                "TCP",
                new IPAddress(row.ucLocalAddr).ToString(),
                Port(row.dwLocalPort),
                new IPAddress(row.ucRemoteAddr).ToString(),
                Port(row.dwRemotePort),
                StateName(row.dwState),
                (int)row.dwOwningPid,
                owner.Process,
                ProcessPath: owner.ProcessPath,
                PackageFamilyName: owner.PackageFamilyName);
        }
    }

    private IEnumerable<ConnectionInfo> SnapshotUdp4()
    {
        foreach (var row in ReadUdpTable<MIB_UDPROW_OWNER_PID>(AfInet))
        {
            var owner = Owner((int)row.dwOwningPid);
            yield return new ConnectionInfo(
                "UDP",
                new IPAddress(BitConverter.GetBytes(row.dwLocalAddr)).ToString(),
                Port(row.dwLocalPort),
                string.Empty,
                0,
                "LISTEN",
                (int)row.dwOwningPid,
                owner.Process,
                "inbound",
                owner.ProcessPath,
                owner.PackageFamilyName);
        }
    }

    private IEnumerable<ConnectionInfo> SnapshotUdp6()
    {
        foreach (var row in ReadUdpTable<MIB_UDP6ROW_OWNER_PID>(AfInet6))
        {
            var owner = Owner((int)row.dwOwningPid);
            yield return new ConnectionInfo(
                "UDP",
                new IPAddress(row.ucLocalAddr, row.dwLocalScopeId).ToString(),
                Port(row.dwLocalPort),
                string.Empty,
                0,
                "LISTEN",
                (int)row.dwOwningPid,
                owner.Process,
                "inbound",
                owner.ProcessPath,
                owner.PackageFamilyName);
        }
    }

    private static IEnumerable<T> ReadTable<T>(int af) where T : struct
    {
        var size = 0;
        _ = GetExtendedTcpTable(IntPtr.Zero, ref size, true, af, TcpTableOwnerPidAll, 0);
        if (size == 0)
        {
            yield break;
        }

        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            if (GetExtendedTcpTable(buffer, ref size, true, af, TcpTableOwnerPidAll, 0) != 0)
            {
                yield break;
            }

            var count = Marshal.ReadInt32(buffer); // dwNumEntries
            var rowSize = Marshal.SizeOf<T>();
            var ptr = IntPtr.Add(buffer, 4);
            for (var i = 0; i < count; i++)
            {
                yield return Marshal.PtrToStructure<T>(ptr);
                ptr = IntPtr.Add(ptr, rowSize);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static IEnumerable<T> ReadUdpTable<T>(int af) where T : struct
    {
        var size = 0;
        _ = GetExtendedUdpTable(IntPtr.Zero, ref size, true, af, UdpTableOwnerPid, 0);
        if (size == 0)
        {
            yield break;
        }

        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            if (GetExtendedUdpTable(buffer, ref size, true, af, UdpTableOwnerPid, 0) != 0)
            {
                yield break;
            }

            var count = Marshal.ReadInt32(buffer);
            var rowSize = Marshal.SizeOf<T>();
            var ptr = IntPtr.Add(buffer, 4);
            for (var i = 0; i < count; i++)
            {
                yield return Marshal.PtrToStructure<T>(ptr);
                ptr = IntPtr.Add(ptr, rowSize);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static string StateName(uint state) => state < TcpStates.Length ? TcpStates[state] : state.ToString();

    // Ports are stored as a DWORD with the 16-bit port in network byte order in the low word.
    private static int Port(uint dwPort) => ((int)(dwPort & 0xFF) << 8) | (int)((dwPort >> 8) & 0xFF);

    private ConnectionOwnerInfo Owner(int pid)
    {
        if (pid <= 0)
        {
            return new ConnectionOwnerInfo(pid == 0 ? "System Idle" : "?");
        }

        return _procCache.GetOrAdd(pid, _ownerLookup);
    }

    private static ConnectionOwnerInfo LookupOwner(int pid)
    {
        try
        {
            using var proc = System.Diagnostics.Process.GetProcessById(pid);
            string path;
            try
            {
                path = proc.MainModule?.FileName ?? string.Empty;
            }
            catch (System.ComponentModel.Win32Exception)
            {
                path = string.Empty;
            }
            catch (InvalidOperationException)
            {
                path = string.Empty;
            }

            return new ConnectionOwnerInfo(proc.ProcessName, path, PackageFamilyName(pid));
        }
        catch (ArgumentException)
        {
            return new ConnectionOwnerInfo("?");
        }
        catch (InvalidOperationException)
        {
            return new ConnectionOwnerInfo("?");
        }
    }

    private static string PackageFamilyName(int pid)
    {
        const uint processQueryLimitedInformation = 0x1000;
        var handle = OpenProcess(processQueryLimitedInformation, false, (uint)pid);
        if (handle == IntPtr.Zero)
        {
            return string.Empty;
        }

        try
        {
            uint length = 0;
            var first = GetPackageFamilyName(handle, ref length, null);
            if (first != 122 || length == 0) // ERROR_INSUFFICIENT_BUFFER; unpackaged returns APPMODEL_ERROR_NO_PACKAGE.
            {
                return string.Empty;
            }

            var buffer = new char[length];
            return GetPackageFamilyName(handle, ref length, buffer) == 0
                ? new string(buffer, 0, Math.Max(0, (int)length - 1))
                : string.Empty;
        }
        finally
        {
            _ = CloseHandle(handle);
        }
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        IntPtr pTcpTable, ref int pdwSize, bool bOrder, int ulAf, int tableClass, uint reserved);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedUdpTable(
        IntPtr pUdpTable, ref int pdwSize, bool bOrder, int ulAf, int tableClass, uint reserved);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint desiredAccess, bool inheritHandle, uint processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern int GetPackageFamilyName(IntPtr process, ref uint packageFamilyNameLength, [Out] char[]? packageFamilyName);

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCPROW_OWNER_PID
    {
        public uint dwState;
        public uint dwLocalAddr;
        public uint dwLocalPort;
        public uint dwRemoteAddr;
        public uint dwRemotePort;
        public uint dwOwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCP6ROW_OWNER_PID
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] ucLocalAddr;
        public uint dwLocalScopeId;
        public uint dwLocalPort;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] ucRemoteAddr;
        public uint dwRemoteScopeId;
        public uint dwRemotePort;
        public uint dwState;
        public uint dwOwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_UDPROW_OWNER_PID
    {
        public uint dwLocalAddr;
        public uint dwLocalPort;
        public uint dwOwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_UDP6ROW_OWNER_PID
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] ucLocalAddr;
        public uint dwLocalScopeId;
        public uint dwLocalPort;
        public uint dwOwningPid;
    }
}
