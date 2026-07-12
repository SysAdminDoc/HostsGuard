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
    string Direction = "outbound");

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

    private static readonly string[] TcpStates =
    {
        "", "CLOSED", "LISTEN", "SYN_SENT", "SYN_RCVD", "ESTABLISHED",
        "FIN_WAIT1", "FIN_WAIT2", "CLOSE_WAIT", "CLOSING", "LAST_ACK", "TIME_WAIT", "DELETE_TCB",
    };

    private readonly ConcurrentDictionary<int, string> _procCache = new();
    private int _snapshots;

    /// <summary>Snapshot all TCP connections (IPv4 + IPv6) with owning process.</summary>
    public IReadOnlyList<ConnectionInfo> Snapshot()
    {
        if (++_snapshots % 30 == 0)
        {
            _procCache.Clear();
        }

        var list = new List<ConnectionInfo>();
        list.AddRange(SnapshotTcp4());
        list.AddRange(SnapshotTcp6());
        return list;
    }

    private IEnumerable<ConnectionInfo> SnapshotTcp4()
    {
        foreach (var row in ReadTable<MIB_TCPROW_OWNER_PID>(AfInet))
        {
            yield return new ConnectionInfo(
                "TCP",
                new IPAddress(BitConverter.GetBytes(row.dwLocalAddr)).ToString(),
                Port(row.dwLocalPort),
                new IPAddress(BitConverter.GetBytes(row.dwRemoteAddr)).ToString(),
                Port(row.dwRemotePort),
                StateName(row.dwState),
                (int)row.dwOwningPid,
                ProcessName((int)row.dwOwningPid));
        }
    }

    private IEnumerable<ConnectionInfo> SnapshotTcp6()
    {
        foreach (var row in ReadTable<MIB_TCP6ROW_OWNER_PID>(AfInet6))
        {
            yield return new ConnectionInfo(
                "TCP",
                new IPAddress(row.ucLocalAddr).ToString(),
                Port(row.dwLocalPort),
                new IPAddress(row.ucRemoteAddr).ToString(),
                Port(row.dwRemotePort),
                StateName(row.dwState),
                (int)row.dwOwningPid,
                ProcessName((int)row.dwOwningPid));
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

    private static string StateName(uint state) => state < TcpStates.Length ? TcpStates[state] : state.ToString();

    // Ports are stored as a DWORD with the 16-bit port in network byte order in the low word.
    private static int Port(uint dwPort) => ((int)(dwPort & 0xFF) << 8) | (int)((dwPort >> 8) & 0xFF);

    private string ProcessName(int pid)
    {
        if (pid <= 0)
        {
            return pid == 0 ? "System Idle" : "?";
        }

        return _procCache.GetOrAdd(pid, static p =>
        {
            try
            {
                using var proc = System.Diagnostics.Process.GetProcessById(p);
                return proc.ProcessName;
            }
            catch (ArgumentException)
            {
                return "?";
            }
            catch (InvalidOperationException)
            {
                return "?";
            }
        });
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        IntPtr pTcpTable, ref int pdwSize, bool bOrder, int ulAf, int tableClass, uint reserved);

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
}
