using System.Diagnostics.Eventing.Reader;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Xml.Linq;
using HostsGuard.Core;

namespace HostsGuard.Windows;

/// <summary>A connection the Windows Filtering Platform blocked (Security 5157/5152).</summary>
public sealed record BlockedConnection(
    DateTime TsUtc,
    string Application,    // DOS path (device path resolved via DevicePathMapper)
    string Direction,      // "In" | "Out"
    string RemoteAddress,
    int RemotePort,
    string Protocol,       // "TCP" | "UDP" | raw number for anything else
    int ProcessId,
    int EventId,           // 5157 (connection) | 5152 (packet drop)
    string FilterRuntimeId = "",
    string FilterOrigin = "",
    string LayerName = "",
    string LayerRuntimeId = "",
    int InterfaceIndex = 0,
    string InterfaceName = "",
    string LocalAddress = "",
    int LocalPort = 0)
{
    public WfpAuditProvenance Provenance => new(
        FilterRuntimeId,
        FilterOrigin,
        LayerName,
        LayerRuntimeId,
        InterfaceIndex,
        InterfaceName);
}

/// <summary>
/// WFCP-003: the WFC-parity blocked-connection source. The TCP-table poller can
/// only see connections that succeeded; the filtering platform's Security-log
/// events are the only user-mode signal for connections that were *blocked*.
/// Subscribes to Security events 5157/5152 via EventLogWatcher (requires the
/// LocalSystem service context) and surfaces typed <see cref="BlockedConnection"/>
/// records with the app's device path resolved to a DOS path.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class BlockedConnectionWatch : IDisposable
{
    public const int ConnectionBlockedEventId = 5157;
    public const int PacketDropEventId = 5152;

    // Audit subcategory GUIDs (stable across locales, unlike names).
    public static readonly Guid FilteringPlatformConnection = new("0CCE9226-69AE-11D9-BED3-505054503030");
    public static readonly Guid FilteringPlatformPacketDrop = new("0CCE9225-69AE-11D9-BED3-505054503030");

    private const string Query = "*[System[(EventID=5157 or EventID=5152)]]";

    private readonly DevicePathMapper _mapper;
    private readonly Action<BlockedConnection> _onBlocked;
    private readonly Action<string>? _log;
    private EventLogWatcher? _watcher;

    public BlockedConnectionWatch(DevicePathMapper mapper, Action<BlockedConnection> onBlocked, Action<string>? log = null)
    {
        _mapper = mapper ?? throw new ArgumentNullException(nameof(mapper));
        _onBlocked = onBlocked ?? throw new ArgumentNullException(nameof(onBlocked));
        _log = log;
    }

    /// <summary>True while the Security-log subscription is live.</summary>
    public bool IsActive => _watcher?.Enabled == true;

    /// <summary>
    /// Start watching. Returns false (logged, no throw) when the Security log
    /// is not readable — i.e. outside the elevated service context.
    /// </summary>
    public bool Start()
    {
        if (_watcher is not null)
        {
            return true;
        }

        try
        {
            var watcher = new EventLogWatcher(new EventLogQuery("Security", PathType.LogName, Query));
            watcher.EventRecordWritten += OnEvent;
            watcher.Enabled = true;
            _watcher = watcher;
            return true;
        }
        catch (Exception ex) when (ex is EventLogException or UnauthorizedAccessException or InvalidOperationException)
        {
            _log?.Invoke($"blocked-connection watch unavailable: {ex.Message}");
            return false;
        }
    }

    public void Stop()
    {
        if (_watcher is { } watcher)
        {
            _watcher = null;
            watcher.Enabled = false;
            watcher.Dispose();
        }
    }

    private void OnEvent(object? sender, EventRecordWrittenEventArgs e)
    {
        using var record = e.EventRecord;
        if (record is null)
        {
            // Subscription error notification (e.g. log cleared) — the watcher
            // itself stays subscribed, nothing to parse.
            return;
        }

        try
        {
            var fields = ParseEventXml(record.ToXml());
            var ts = (record.TimeCreated ?? DateTime.UtcNow).ToUniversalTime();
            var blocked = FromFields(fields, record.Id, ts, _mapper);
            if (blocked is not null)
            {
                _onBlocked(blocked);
            }
        }
        catch (Exception ex) when (ex is EventLogException or System.Xml.XmlException)
        {
            _log?.Invoke($"blocked-connection parse failed: {ex.Message}");
        }
    }

    /// <summary>Extract EventData name/value pairs from an event's XML rendering.</summary>
    public static Dictionary<string, string> ParseEventXml(string xml)
    {
        XNamespace ns = "http://schemas.microsoft.com/win/2004/08/events/event";
        return XDocument.Parse(xml)
            .Descendants(ns + "Data")
            .Where(d => d.Attribute("Name") is not null)
            .ToDictionary(d => d.Attribute("Name")!.Value, d => d.Value, StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Map 5157/5152 EventData into a typed record. Returns null for events
    /// with no application path (nothing to decide on).
    /// </summary>
    public static BlockedConnection? FromFields(
        IReadOnlyDictionary<string, string> fields,
        int eventId,
        DateTime tsUtc,
        DevicePathMapper mapper,
        Func<int, string?>? interfaceNameResolver = null)
    {
        ArgumentNullException.ThrowIfNull(mapper);
        if (!fields.TryGetValue("Application", out var application) || application.Length == 0)
        {
            return null;
        }

        // %%14592 = inbound, %%14593 = outbound (message-table constants).
        var direction = fields.GetValueOrDefault("Direction") == "%%14592" ? "In" : "Out";
        var protocol = fields.GetValueOrDefault("Protocol") switch
        {
            "6" => "TCP",
            "17" => "UDP",
            var other => other ?? string.Empty,
        };
        var sourceAddress = fields.GetValueOrDefault("SourceAddress") ?? string.Empty;
        var destinationAddress = fields.GetValueOrDefault("DestAddress") ?? string.Empty;
        _ = int.TryParse(fields.GetValueOrDefault("SourcePort"), out var sourcePort);
        _ = int.TryParse(fields.GetValueOrDefault("DestPort"), out var destinationPort);
        var remoteAddress = direction == "In" ? sourceAddress : destinationAddress;
        var remotePort = direction == "In" ? sourcePort : destinationPort;
        var localAddress = direction == "In" ? destinationAddress : sourceAddress;
        var localPort = direction == "In" ? destinationPort : sourcePort;
        _ = int.TryParse(fields.GetValueOrDefault("ProcessID") ?? fields.GetValueOrDefault("ProcessId"), out var pid);
        _ = int.TryParse(First(fields, "InterfaceIndex", "InterfaceIdx", "Interface"), out var interfaceIndex);
        var interfaceName = First(fields, "InterfaceName", "InterfaceAlias", "InterfaceDescription");
        if (interfaceName.Length == 0 && interfaceIndex > 0)
        {
            interfaceName = SafeResolveInterfaceName(interfaceIndex, interfaceNameResolver);
        }

        return new BlockedConnection(
            tsUtc,
            mapper.ToDosPath(application),
            direction,
            remoteAddress,
            remotePort,
            protocol,
            pid,
            eventId,
            First(fields, "FilterRTID", "FilterRuntimeId", "FilterRunTimeId"),
            First(fields, "FilterOrigin", "Filter Origin"),
            First(fields, "LayerName"),
            First(fields, "LayerRTID", "LayerRuntimeId", "LayerRunTimeId"),
            interfaceIndex,
            interfaceName,
            localAddress,
            localPort);
    }

    private static string First(IReadOnlyDictionary<string, string> fields, params string[] names)
    {
        foreach (var name in names)
        {
            if (fields.TryGetValue(name, out var value) && !string.IsNullOrWhiteSpace(value))
            {
                return value.Trim();
            }
        }

        return string.Empty;
    }

    private static string SafeResolveInterfaceName(int interfaceIndex, Func<int, string?>? resolver)
    {
        try
        {
            return (resolver?.Invoke(interfaceIndex) ?? ResolveInterfaceName(interfaceIndex) ?? string.Empty).Trim();
        }
        catch (Exception ex) when (ex is NetworkInformationException or InvalidOperationException)
        {
            return string.Empty;
        }
    }

    private static string? ResolveInterfaceName(int interfaceIndex)
    {
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            var properties = nic.GetIPProperties();
            if (properties.GetIPv4Properties()?.Index == interfaceIndex ||
                properties.GetIPv6Properties()?.Index == interfaceIndex)
            {
                return nic.Name.Length != 0 ? nic.Name : nic.Description;
            }
        }

        return null;
    }

    public void Dispose() => Stop();

    // ─── Audit policy (the events only exist when auditing is on) ────────────

    /// <summary>
    /// Enable "Filtering Platform Connection" (success+failure) and
    /// "Filtering Platform Packet Drop" (failure) auditing. Tries the
    /// AuditSetSystemPolicy API under SeSecurityPrivilege first, then falls
    /// back to auditpol with locale-stable GUIDs. Elevation required.
    /// </summary>
    public static bool EnableAuditPolicy(Action<string>? log = null)
    {
        try
        {
            EnablePrivilege("SeSecurityPrivilege");
            var policies = new[]
            {
                new AUDIT_POLICY_INFORMATION
                {
                    AuditSubCategoryGuid = FilteringPlatformConnection,
                    AuditingInformation = AuditSuccess | AuditFailure,
                },
                new AUDIT_POLICY_INFORMATION
                {
                    AuditSubCategoryGuid = FilteringPlatformPacketDrop,
                    AuditingInformation = AuditFailure,
                },
            };
            if (AuditSetSystemPolicy(policies, (uint)policies.Length))
            {
                return true;
            }

            log?.Invoke($"AuditSetSystemPolicy failed (win32 {Marshal.GetLastWin32Error()}); falling back to auditpol");
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException or InvalidOperationException)
        {
            log?.Invoke($"AuditSetSystemPolicy unavailable: {ex.Message}; falling back to auditpol");
        }

        return RunAuditPol($"/set /subcategory:\"{{{FilteringPlatformConnection}}}\" /success:enable /failure:enable", log)
            && RunAuditPol($"/set /subcategory:\"{{{FilteringPlatformPacketDrop}}}\" /failure:enable", log);
    }

    private static bool RunAuditPol(string arguments, Action<string>? log)
    {
        try
        {
            using var process = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName = "auditpol.exe",
                Arguments = arguments,
                UseShellExecute = false,
                CreateNoWindow = true,
            });
            process!.WaitForExit(10_000);
            if (process.ExitCode == 0)
            {
                return true;
            }

            log?.Invoke($"auditpol exited {process.ExitCode} for {arguments}");
            return false;
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            log?.Invoke($"auditpol failed: {ex.Message}");
            return false;
        }
    }

    private const uint AuditSuccess = 0x1; // POLICY_AUDIT_EVENT_SUCCESS
    private const uint AuditFailure = 0x2; // POLICY_AUDIT_EVENT_FAILURE

    [StructLayout(LayoutKind.Sequential)]
    private struct AUDIT_POLICY_INFORMATION
    {
        public Guid AuditSubCategoryGuid;
        public uint AuditingInformation;
        public Guid AuditCategoryGuid; // ignored by AuditSetSystemPolicy
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool AuditSetSystemPolicy(
        [In] AUDIT_POLICY_INFORMATION[] pAuditPolicy, uint policyCount);

    private static void EnablePrivilege(string privilege)
    {
        if (!OpenProcessToken(System.Diagnostics.Process.GetCurrentProcess().Handle,
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out var token))
        {
            throw new InvalidOperationException($"OpenProcessToken failed ({Marshal.GetLastWin32Error()})");
        }

        try
        {
            if (!LookupPrivilegeValueW(null, privilege, out var luid))
            {
                throw new InvalidOperationException($"LookupPrivilegeValue failed ({Marshal.GetLastWin32Error()})");
            }

            var tp = new TOKEN_PRIVILEGES
            {
                PrivilegeCount = 1,
                Luid = luid,
                Attributes = SE_PRIVILEGE_ENABLED,
            };
            if (!AdjustTokenPrivileges(token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero) ||
                Marshal.GetLastWin32Error() != 0)
            {
                throw new InvalidOperationException($"AdjustTokenPrivileges failed ({Marshal.GetLastWin32Error()})");
            }
        }
        finally
        {
            CloseHandle(token);
        }
    }

    private const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
    private const uint TOKEN_QUERY = 0x0008;
    private const uint SE_PRIVILEGE_ENABLED = 0x0002;

    [StructLayout(LayoutKind.Sequential)]
    private struct LUID
    {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TOKEN_PRIVILEGES
    {
        public uint PrivilegeCount;
        public LUID Luid;
        public uint Attributes;
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool LookupPrivilegeValueW(string? systemName, string name, out LUID luid);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool AdjustTokenPrivileges(
        IntPtr tokenHandle, bool disableAllPrivileges, ref TOKEN_PRIVILEGES newState,
        uint bufferLength, IntPtr previousState, IntPtr returnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);
}
