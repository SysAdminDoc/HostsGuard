using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace HostsGuard.Windows;

/// <summary>Best-effort process command-line reader via the PEB.</summary>
[SupportedOSPlatform("windows")]
public static class ProcessCommandLine
{
    private const int ProcessBasicInformationClass = 0;
    private const int ProcessQueryLimitedInformation = 0x1000;
    private const int ProcessVmRead = 0x0010;
    private const int PebProcessParametersOffset64 = 0x20;
    private const int RtlCommandLineOffset64 = 0x70;
    private const int MaxCommandLineBytes = (64 * 1024) - 2;

    public static string? Read(int processId)
    {
        if (processId <= 0)
        {
            return null;
        }

        using var handle = OpenProcess(ProcessQueryLimitedInformation | ProcessVmRead, false, processId);
        if (handle.IsInvalid)
        {
            return null;
        }

        var info = new ProcessBasicInformation();
        var status = NtQueryInformationProcess(
            handle,
            ProcessBasicInformationClass,
            ref info,
            Marshal.SizeOf<ProcessBasicInformation>(),
            out _);
        if (status != 0 || info.PebBaseAddress == IntPtr.Zero)
        {
            return null;
        }

        try
        {
            var processParameters = ReadPointer(handle, info.PebBaseAddress + PebProcessParametersOffset64);
            if (processParameters == IntPtr.Zero)
            {
                return null;
            }

            var commandLine = ReadUnicodeString(handle, processParameters + RtlCommandLineOffset64);
            return string.IsNullOrWhiteSpace(commandLine) ? null : commandLine;
        }
        catch (InvalidOperationException)
        {
            return null;
        }
    }

    private static IntPtr ReadPointer(SafeProcessHandle handle, IntPtr address)
    {
        var buffer = new byte[IntPtr.Size];
        ReadExact(handle, address, buffer);
        return IntPtr.Size == 8
            ? new IntPtr(BitConverter.ToInt64(buffer, 0))
            : new IntPtr(BitConverter.ToInt32(buffer, 0));
    }

    private static string? ReadUnicodeString(SafeProcessHandle handle, IntPtr address)
    {
        var header = new byte[IntPtr.Size == 8 ? 16 : 8];
        ReadExact(handle, address, header);
        var length = BitConverter.ToUInt16(header, 0);
        if (length == 0 || length > MaxCommandLineBytes || length % 2 != 0)
        {
            return null;
        }

        var bufferOffset = IntPtr.Size == 8 ? 8 : 4;
        var bufferAddress = IntPtr.Size == 8
            ? new IntPtr(BitConverter.ToInt64(header, bufferOffset))
            : new IntPtr(BitConverter.ToInt32(header, bufferOffset));
        if (bufferAddress == IntPtr.Zero)
        {
            return null;
        }

        var text = new byte[length];
        ReadExact(handle, bufferAddress, text);
        return Encoding.Unicode.GetString(text).TrimEnd('\0');
    }

    private static void ReadExact(SafeProcessHandle handle, IntPtr address, byte[] buffer)
    {
        if (!ReadProcessMemory(handle, address, buffer, buffer.Length, out var read) || read.ToInt64() != buffer.Length)
        {
            throw new InvalidOperationException("process memory read failed");
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern SafeProcessHandle OpenProcess(int desiredAccess, bool inheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(SafeProcessHandle process, IntPtr baseAddress, byte[] buffer, int size, out IntPtr bytesRead);

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(
        SafeProcessHandle process,
        int processInformationClass,
        ref ProcessBasicInformation processInformation,
        int processInformationLength,
        out int returnLength);

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessBasicInformation
    {
        public IntPtr Reserved1;
        public IntPtr PebBaseAddress;
        public IntPtr Reserved2;
        public IntPtr Reserved3;
        public IntPtr UniqueProcessId;
        public IntPtr InheritedFromUniqueProcessId;
    }
}
