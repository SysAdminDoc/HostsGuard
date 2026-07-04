using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;

namespace HostsGuard.Windows;

/// <summary>
/// Best-effort process-parentage lookup (NET-093 child-process auto-allow):
/// resolves a PID's parent PID (via <c>NtQueryInformationProcess</c>
/// ProcessBasicInformation) and the parent's image path. Everything is
/// best-effort — a dead or higher-integrity parent simply yields null, and the
/// consent path falls back to prompting (deny-by-default preserved).
/// </summary>
[SupportedOSPlatform("windows")]
public static class ProcessTree
{
    /// <summary>The parent PID and image path for <paramref name="pid"/>, or null.</summary>
    public static (int ParentPid, string ParentPath)? GetParent(int pid)
    {
        if (pid <= 0)
        {
            return null;
        }

        var handle = OpenProcess(ProcessQueryLimitedInformation, false, pid);
        if (handle == IntPtr.Zero)
        {
            return null;
        }

        try
        {
            var info = default(ProcessBasicInformation);
            var status = NtQueryInformationProcess(handle, 0, ref info, Marshal.SizeOf<ProcessBasicInformation>(), out _);
            if (status != 0)
            {
                return null;
            }

            var parentPid = (int)info.InheritedFromUniqueProcessId.ToInt64();
            if (parentPid <= 0)
            {
                return null;
            }

            return (parentPid, GetImagePath(parentPid) ?? string.Empty);
        }
        finally
        {
            CloseHandle(handle);
        }
    }

    /// <summary>Full image path of a live PID (QueryFullProcessImageName), or null.</summary>
    public static string? GetImagePath(int pid)
    {
        if (pid <= 0)
        {
            return null;
        }

        var handle = OpenProcess(ProcessQueryLimitedInformation, false, pid);
        if (handle == IntPtr.Zero)
        {
            return null;
        }

        try
        {
            var capacity = 1024;
            var buffer = new StringBuilder(capacity);
            return QueryFullProcessImageName(handle, 0, buffer, ref capacity) ? buffer.ToString() : null;
        }
        finally
        {
            CloseHandle(handle);
        }
    }

    private const int ProcessQueryLimitedInformation = 0x1000;

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessBasicInformation
    {
        public IntPtr ExitStatus;
        public IntPtr PebBaseAddress;
        public IntPtr AffinityMask;
        public IntPtr BasePriority;
        public IntPtr UniqueProcessId;
        public IntPtr InheritedFromUniqueProcessId;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(int access, bool inheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageName(IntPtr process, int flags, StringBuilder exeName, ref int size);

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(
        IntPtr process, int infoClass, ref ProcessBasicInformation info, int infoLength, out int returnLength);
}
