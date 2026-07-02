using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace HostsGuard.Windows;

/// <summary>PID→service mapping surface, fakeable for tests.</summary>
public interface IServiceAttribution
{
    /// <summary>Display text for a PID ("DNS Client", or comma-joined when shared); "" when not a service.</summary>
    string DisplayFor(int pid);

    /// <summary>
    /// The one service owning a PID — (SCM short name, display name) — or null
    /// when the process hosts none or several (a per-service rule would be
    /// ambiguous in the shared case).
    /// </summary>
    (string Key, string Display)? SoleOwner(int pid);
}

/// <summary>
/// PID→service attribution via SCM enumeration (<c>EnumServicesStatusExW</c> with
/// SC_ENUM_PROCESS_INFO) — the defining svchost problem (NET-073). Since
/// Win10 1703 services split into one svchost each on machines with &gt;3.5 GB
/// RAM, so a PID usually maps to exactly one service. Enumeration needs no
/// elevation; the snapshot is cached briefly because the feed asks per tick.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class ServiceAttribution : IServiceAttribution
{
    private static readonly TimeSpan SnapshotTtl = TimeSpan.FromSeconds(5);

    private readonly object _gate = new();
    private Dictionary<int, List<(string Key, string Display)>> _byPid = new();
    private DateTime _snapshotAt = DateTime.MinValue;

    public string DisplayFor(int pid)
    {
        var owners = Owners(pid);
        return owners.Count switch
        {
            0 => string.Empty,
            1 => owners[0].Display,
            _ => string.Join(", ", owners.Select(o => o.Display)),
        };
    }

    public (string Key, string Display)? SoleOwner(int pid)
    {
        var owners = Owners(pid);
        return owners.Count == 1 ? owners[0] : null;
    }

    private IReadOnlyList<(string Key, string Display)> Owners(int pid)
    {
        if (pid <= 4)
        {
            return [];
        }

        lock (_gate)
        {
            if (DateTime.UtcNow - _snapshotAt > SnapshotTtl)
            {
                try
                {
                    _byPid = Snapshot();
                }
                catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException)
                {
                    // SCM hiccup — keep serving the stale snapshot.
                }

                _snapshotAt = DateTime.UtcNow;
            }

            return _byPid.TryGetValue(pid, out var owners) ? owners : [];
        }
    }

    /// <summary>Enumerate active Win32 services and group them by owning PID.</summary>
    public static Dictionary<int, List<(string Key, string Display)>> Snapshot()
    {
        const int ScManagerEnumerateService = 0x0004;
        const int ScEnumProcessInfo = 0;
        const int ServiceWin32 = 0x30;
        const int ServiceActive = 0x01;
        const int ErrorMoreData = 234;

        var scm = OpenSCManagerW(null, null, ScManagerEnumerateService);
        if (scm == IntPtr.Zero)
        {
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "OpenSCManager failed");
        }

        try
        {
            // Size probe, then the real call.
            _ = EnumServicesStatusExW(scm, ScEnumProcessInfo, ServiceWin32, ServiceActive,
                IntPtr.Zero, 0, out var needed, out _, IntPtr.Zero, null);
            if (Marshal.GetLastWin32Error() != ErrorMoreData || needed == 0)
            {
                return new Dictionary<int, List<(string, string)>>();
            }

            var buffer = Marshal.AllocHGlobal(needed);
            try
            {
                if (!EnumServicesStatusExW(scm, ScEnumProcessInfo, ServiceWin32, ServiceActive,
                        buffer, needed, out _, out var returned, IntPtr.Zero, null))
                {
                    throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "EnumServicesStatusEx failed");
                }

                var map = new Dictionary<int, List<(string, string)>>();
                var entrySize = Marshal.SizeOf<ENUM_SERVICE_STATUS_PROCESSW>();
                for (var i = 0; i < returned; i++)
                {
                    var entry = Marshal.PtrToStructure<ENUM_SERVICE_STATUS_PROCESSW>(buffer + (i * entrySize));
                    var pid = (int)entry.ServiceStatusProcess.dwProcessId;
                    if (pid <= 0)
                    {
                        continue;
                    }

                    var key = Marshal.PtrToStringUni(entry.lpServiceName) ?? string.Empty;
                    var display = Marshal.PtrToStringUni(entry.lpDisplayName) ?? key;
                    if (key.Length == 0)
                    {
                        continue;
                    }

                    if (!map.TryGetValue(pid, out var list))
                    {
                        map[pid] = list = [];
                    }

                    list.Add((key, display.Length != 0 ? display : key));
                }

                return map;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
        finally
        {
            CloseServiceHandle(scm);
        }
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenSCManagerW(string? machineName, string? databaseName, int desiredAccess);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EnumServicesStatusExW(
        IntPtr scManager, int infoLevel, int serviceType, int serviceState,
        IntPtr services, int bufSize, out int bytesNeeded, out int servicesReturned,
        IntPtr resumeHandle, string? groupName);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseServiceHandle(IntPtr handle);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct ENUM_SERVICE_STATUS_PROCESSW
    {
        public IntPtr lpServiceName;
        public IntPtr lpDisplayName;
        public SERVICE_STATUS_PROCESS ServiceStatusProcess;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SERVICE_STATUS_PROCESS
    {
        public uint dwServiceType;
        public uint dwCurrentState;
        public uint dwControlsAccepted;
        public uint dwWin32ExitCode;
        public uint dwServiceSpecificExitCode;
        public uint dwCheckPoint;
        public uint dwWaitHint;
        public uint dwProcessId;
        public uint dwServiceFlags;
    }
}
