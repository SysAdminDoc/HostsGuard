using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace HostsGuard.Windows;

/// <summary>The SCM fields that must survive an in-place update rollback.</summary>
public sealed record WindowsServiceConfiguration(
    string BinaryPath,
    uint ServiceType,
    uint StartType,
    uint ErrorControl,
    string Account,
    string DisplayName,
    string[] Dependencies,
    string Description,
    uint FailureResetPeriod,
    string FailureRebootMessage,
    string FailureCommand,
    WindowsServiceFailureAction[] FailureActions);

public sealed record WindowsServiceFailureAction(int Type, uint DelayMilliseconds);

/// <summary>Fakeable service-control boundary used by update recovery.</summary>
public interface IWindowsServiceUpdateControl
{
    WindowsServiceConfiguration Capture();

    void StopAndWait(TimeSpan timeout);

    void Restore(WindowsServiceConfiguration configuration);

    void StartAndWait(TimeSpan timeout);
}

/// <summary>
/// Direct SCM update operations. The updater uses this instead of parsing
/// <c>sc.exe</c> output, so stop/start timeouts and configuration restoration
/// have typed failure semantics.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsServiceUpdateControl(string serviceName = "HostsGuardSvc") : IWindowsServiceUpdateControl
{
    private const uint ScManagerConnect = 0x0001;
    private const uint ScManagerCreateService = 0x0002;
    private const uint ServiceQueryConfig = 0x0001;
    private const uint ServiceChangeConfig = 0x0002;
    private const uint ServiceQueryStatus = 0x0004;
    private const uint ServiceStart = 0x0010;
    private const uint ServiceStop = 0x0020;
    private const uint ServiceAllRequired = ServiceQueryConfig | ServiceChangeConfig | ServiceQueryStatus | ServiceStart | ServiceStop;
    private const uint ServiceControlStop = 0x00000001;
    private const uint ServiceStopped = 0x00000001;
    private const uint ServiceRunning = 0x00000004;
    private const int ScStatusProcessInfo = 0;
    private const int ServiceConfigDescription = 1;
    private const int ServiceConfigFailureActions = 2;
    private const int ErrorInsufficientBuffer = 122;
    private const int ErrorServiceAlreadyRunning = 1056;
    private const int ErrorServiceNotActive = 1062;
    private const int ErrorServiceDoesNotExist = 1060;

    public WindowsServiceConfiguration Capture()
    {
        using var handles = Open(ServiceQueryConfig);
        _ = QueryServiceConfigW(handles.Service, IntPtr.Zero, 0, out var needed);
        if (needed == 0 || Marshal.GetLastWin32Error() != ErrorInsufficientBuffer)
        {
            throw LastError("QueryServiceConfig size probe failed");
        }

        var buffer = Marshal.AllocHGlobal(needed);
        try
        {
            if (!QueryServiceConfigW(handles.Service, buffer, needed, out _))
            {
                throw LastError("QueryServiceConfig failed");
            }

            var value = Marshal.PtrToStructure<QUERY_SERVICE_CONFIGW>(buffer);
            var failure = ReadFailureActions(handles.Service);
            return new WindowsServiceConfiguration(
                Ptr(value.lpBinaryPathName),
                value.dwServiceType,
                value.dwStartType,
                value.dwErrorControl,
                Ptr(value.lpServiceStartName),
                Ptr(value.lpDisplayName),
                ReadMultiString(value.lpDependencies),
                ReadDescription(handles.Service),
                failure.ResetPeriod,
                failure.RebootMessage,
                failure.Command,
                failure.Actions);
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    public void StopAndWait(TimeSpan timeout)
    {
        ServiceHandles handles;
        try
        {
            handles = Open(ServiceStop | ServiceQueryStatus);
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == ErrorServiceDoesNotExist)
        {
            return;
        }

        using (handles)
        {
            var status = QueryStatus(handles.Service);
            if (status.dwCurrentState == ServiceStopped)
            {
                return;
            }

            if (!ControlService(handles.Service, ServiceControlStop, out _) &&
                Marshal.GetLastWin32Error() != ErrorServiceNotActive)
            {
                throw LastError("service stop request failed");
            }

            WaitForState(handles.Service, ServiceStopped, timeout, "stop");
        }
    }

    public void Restore(WindowsServiceConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        var dependencies = configuration.Dependencies.Length == 0
            ? "\0"
            : string.Join('\0', configuration.Dependencies) + "\0\0";
        using var handles = OpenForRestore(configuration, dependencies);
        if (!ChangeServiceConfigW(
                handles.Service,
                configuration.ServiceType,
                configuration.StartType,
                configuration.ErrorControl,
                configuration.BinaryPath,
                null,
                IntPtr.Zero,
                dependencies,
                configuration.Account,
                null,
                configuration.DisplayName))
        {
            throw LastError("service configuration restore failed");
        }

        var descriptionPointer = Marshal.StringToHGlobalUni(configuration.Description);
        var description = new SERVICE_DESCRIPTIONW { lpDescription = descriptionPointer };
        var descriptionBuffer = Marshal.AllocHGlobal(Marshal.SizeOf<SERVICE_DESCRIPTIONW>());
        try
        {
            Marshal.StructureToPtr(description, descriptionBuffer, false);
            if (!ChangeServiceConfig2W(handles.Service, ServiceConfigDescription, descriptionBuffer))
            {
                throw LastError("service description restore failed");
            }
        }
        finally
        {
            Marshal.FreeHGlobal(descriptionBuffer);
            Marshal.FreeHGlobal(descriptionPointer);
        }

        RestoreFailureActions(handles.Service, configuration);
    }

    public void StartAndWait(TimeSpan timeout)
    {
        using var handles = Open(ServiceStart | ServiceQueryStatus);
        var status = QueryStatus(handles.Service);
        if (status.dwCurrentState == ServiceRunning)
        {
            return;
        }

        if (!StartServiceW(handles.Service, 0, IntPtr.Zero) &&
            Marshal.GetLastWin32Error() != ErrorServiceAlreadyRunning)
        {
            throw LastError("service start request failed");
        }

        WaitForState(handles.Service, ServiceRunning, timeout, "start");
    }

    private ServiceHandles Open(uint serviceAccess)
    {
        var manager = OpenSCManagerW(null, null, ScManagerConnect | ScManagerCreateService);
        if (manager == IntPtr.Zero)
        {
            throw LastError("OpenSCManager failed");
        }

        var service = OpenServiceW(manager, serviceName, serviceAccess);
        if (service == IntPtr.Zero)
        {
            var error = LastError($"OpenService({serviceName}) failed");
            CloseServiceHandle(manager);
            throw error;
        }

        return new ServiceHandles(manager, service);
    }

    private ServiceHandles OpenForRestore(WindowsServiceConfiguration configuration, string dependencies)
    {
        var manager = OpenSCManagerW(null, null, ScManagerConnect | ScManagerCreateService);
        if (manager == IntPtr.Zero)
        {
            throw LastError("OpenSCManager failed");
        }

        var service = OpenServiceW(manager, serviceName, ServiceAllRequired);
        if (service == IntPtr.Zero && Marshal.GetLastWin32Error() == ErrorServiceDoesNotExist)
        {
            service = CreateServiceW(
                manager,
                serviceName,
                configuration.DisplayName,
                ServiceAllRequired,
                configuration.ServiceType,
                configuration.StartType,
                configuration.ErrorControl,
                configuration.BinaryPath,
                null,
                IntPtr.Zero,
                dependencies,
                configuration.Account,
                null);
        }

        if (service == IntPtr.Zero)
        {
            var error = LastError($"restore/open service {serviceName} failed");
            CloseServiceHandle(manager);
            throw error;
        }

        return new ServiceHandles(manager, service);
    }

    private static SERVICE_STATUS_PROCESS QueryStatus(IntPtr service)
    {
        var size = Marshal.SizeOf<SERVICE_STATUS_PROCESS>();
        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            if (!QueryServiceStatusEx(service, ScStatusProcessInfo, buffer, size, out _))
            {
                throw LastError("QueryServiceStatusEx failed");
            }

            return Marshal.PtrToStructure<SERVICE_STATUS_PROCESS>(buffer);
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static void WaitForState(IntPtr service, uint expected, TimeSpan timeout, string action)
    {
        var deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline)
        {
            if (QueryStatus(service).dwCurrentState == expected)
            {
                return;
            }

            Thread.Sleep(100);
        }

        throw new TimeoutException($"service did not {action} within {timeout.TotalSeconds:N0} seconds");
    }

    private static string ReadDescription(IntPtr service)
    {
        _ = QueryServiceConfig2W(service, ServiceConfigDescription, IntPtr.Zero, 0, out var needed);
        if (needed == 0)
        {
            return string.Empty;
        }

        var buffer = Marshal.AllocHGlobal(needed);
        try
        {
            if (!QueryServiceConfig2W(service, ServiceConfigDescription, buffer, needed, out _))
            {
                throw LastError("QueryServiceConfig2 description failed");
            }

            return Ptr(Marshal.PtrToStructure<SERVICE_DESCRIPTIONW>(buffer).lpDescription);
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static (uint ResetPeriod, string RebootMessage, string Command, WindowsServiceFailureAction[] Actions)
        ReadFailureActions(IntPtr service)
    {
        _ = QueryServiceConfig2W(service, ServiceConfigFailureActions, IntPtr.Zero, 0, out var needed);
        if (needed == 0)
        {
            return (0, string.Empty, string.Empty, []);
        }

        var buffer = Marshal.AllocHGlobal(needed);
        try
        {
            if (!QueryServiceConfig2W(service, ServiceConfigFailureActions, buffer, needed, out _))
            {
                throw LastError("QueryServiceConfig2 failure actions failed");
            }

            var value = Marshal.PtrToStructure<SERVICE_FAILURE_ACTIONSW>(buffer);
            var actions = new WindowsServiceFailureAction[value.cActions];
            var actionSize = Marshal.SizeOf<SC_ACTION>();
            for (var i = 0; i < actions.Length; i++)
            {
                var action = Marshal.PtrToStructure<SC_ACTION>(value.lpsaActions + (i * actionSize));
                actions[i] = new WindowsServiceFailureAction(action.Type, action.Delay);
            }

            return (value.dwResetPeriod, Ptr(value.lpRebootMsg), Ptr(value.lpCommand), actions);
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static void RestoreFailureActions(IntPtr service, WindowsServiceConfiguration configuration)
    {
        var actionSize = Marshal.SizeOf<SC_ACTION>();
        var actionsBuffer = configuration.FailureActions.Length == 0
            ? IntPtr.Zero
            : Marshal.AllocHGlobal(actionSize * configuration.FailureActions.Length);
        var rebootMessage = configuration.FailureRebootMessage.Length == 0
            ? IntPtr.Zero
            : Marshal.StringToHGlobalUni(configuration.FailureRebootMessage);
        var command = configuration.FailureCommand.Length == 0
            ? IntPtr.Zero
            : Marshal.StringToHGlobalUni(configuration.FailureCommand);
        var configBuffer = Marshal.AllocHGlobal(Marshal.SizeOf<SERVICE_FAILURE_ACTIONSW>());
        try
        {
            for (var i = 0; i < configuration.FailureActions.Length; i++)
            {
                var action = configuration.FailureActions[i];
                Marshal.StructureToPtr(
                    new SC_ACTION { Type = action.Type, Delay = action.DelayMilliseconds },
                    actionsBuffer + (i * actionSize),
                    false);
            }

            Marshal.StructureToPtr(new SERVICE_FAILURE_ACTIONSW
            {
                dwResetPeriod = configuration.FailureResetPeriod,
                lpRebootMsg = rebootMessage,
                lpCommand = command,
                cActions = (uint)configuration.FailureActions.Length,
                lpsaActions = actionsBuffer,
            }, configBuffer, false);
            if (!ChangeServiceConfig2W(service, ServiceConfigFailureActions, configBuffer))
            {
                throw LastError("service failure actions restore failed");
            }
        }
        finally
        {
            Marshal.FreeHGlobal(configBuffer);
            if (actionsBuffer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(actionsBuffer);
            }

            if (rebootMessage != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(rebootMessage);
            }

            if (command != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(command);
            }
        }
    }

    private static string[] ReadMultiString(IntPtr pointer)
    {
        if (pointer == IntPtr.Zero)
        {
            return [];
        }

        var values = new List<string>();
        var offset = 0;
        while (true)
        {
            var value = Marshal.PtrToStringUni(pointer + offset * sizeof(char));
            if (string.IsNullOrEmpty(value))
            {
                break;
            }

            values.Add(value);
            offset += value.Length + 1;
        }

        return [.. values];
    }

    private static string Ptr(IntPtr value) => Marshal.PtrToStringUni(value) ?? string.Empty;

    private static Win32Exception LastError(string message) =>
        new(Marshal.GetLastWin32Error(), message);

    private sealed class ServiceHandles(IntPtr manager, IntPtr service) : IDisposable
    {
        public IntPtr Service { get; } = service;

        public void Dispose()
        {
            CloseServiceHandle(Service);
            CloseServiceHandle(manager);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct QUERY_SERVICE_CONFIGW
    {
        public uint dwServiceType;
        public uint dwStartType;
        public uint dwErrorControl;
        public IntPtr lpBinaryPathName;
        public IntPtr lpLoadOrderGroup;
        public uint dwTagId;
        public IntPtr lpDependencies;
        public IntPtr lpServiceStartName;
        public IntPtr lpDisplayName;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SERVICE_DESCRIPTIONW
    {
        public IntPtr lpDescription;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SERVICE_FAILURE_ACTIONSW
    {
        public uint dwResetPeriod;
        public IntPtr lpRebootMsg;
        public IntPtr lpCommand;
        public uint cActions;
        public IntPtr lpsaActions;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SC_ACTION
    {
        public int Type;
        public uint Delay;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SERVICE_STATUS
    {
        public uint dwServiceType;
        public uint dwCurrentState;
        public uint dwControlsAccepted;
        public uint dwWin32ExitCode;
        public uint dwServiceSpecificExitCode;
        public uint dwCheckPoint;
        public uint dwWaitHint;
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

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenSCManagerW(string? machineName, string? databaseName, uint desiredAccess);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenServiceW(IntPtr manager, string serviceName, uint desiredAccess);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateServiceW(
        IntPtr manager,
        string serviceName,
        string displayName,
        uint desiredAccess,
        uint serviceType,
        uint startType,
        uint errorControl,
        string binaryPath,
        string? loadOrderGroup,
        IntPtr tagId,
        string dependencies,
        string account,
        string? password);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryServiceConfigW(IntPtr service, IntPtr serviceConfig, int bufferSize, out int bytesNeeded);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryServiceConfig2W(IntPtr service, int infoLevel, IntPtr buffer, int bufferSize, out int bytesNeeded);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ChangeServiceConfigW(
        IntPtr service,
        uint serviceType,
        uint startType,
        uint errorControl,
        string binaryPath,
        string? loadOrderGroup,
        IntPtr tagId,
        string dependencies,
        string account,
        string? password,
        string displayName);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ChangeServiceConfig2W(IntPtr service, int infoLevel, IntPtr info);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryServiceStatusEx(
        IntPtr service, int infoLevel, IntPtr buffer, int bufferSize, out int bytesNeeded);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ControlService(IntPtr service, uint control, out SERVICE_STATUS status);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool StartServiceW(IntPtr service, int argc, IntPtr argv);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseServiceHandle(IntPtr handle);
}
