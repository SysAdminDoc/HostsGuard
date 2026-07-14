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
    private readonly object _gate = new();
    private readonly ObservationIntegrityTracker _health = new("security_log");
    private EventLogWatcher? _watcher;
    private long? _lastOldestRecordNumber;
    private bool _auditPolicyHealthy;
    private int _recoveryQueued;
    private int _recoveryGeneration;
    private bool _recoveryEnabled;
    private bool _disposed;

    public BlockedConnectionWatch(DevicePathMapper mapper, Action<BlockedConnection> onBlocked, Action<string>? log = null)
    {
        _mapper = mapper ?? throw new ArgumentNullException(nameof(mapper));
        _onBlocked = onBlocked ?? throw new ArgumentNullException(nameof(onBlocked));
        _log = log;
    }

    /// <summary>True while the Security-log subscription is live.</summary>
    public bool IsActive
    {
        get
        {
            lock (_gate)
            {
                return _watcher?.Enabled == true;
            }
        }
    }

    /// <summary>Current Security-log liveness and cumulative loss/restart counters.</summary>
    public ObservationIntegritySnapshot Health => _health.Snapshot();

    /// <summary>
    /// Start watching. Returns false (logged, no throw) when the Security log
    /// is not readable — i.e. outside the elevated service context.
    /// </summary>
    public bool Start()
    {
        EventLogWatcher? stale = null;
        lock (_gate)
        {
            if (_disposed)
            {
                _health.Unavailable("monitor disposed", countGap: false);
                return false;
            }

            if (_watcher?.Enabled == true)
            {
                return true;
            }

            stale = _watcher;
            _watcher = null;
        }

        DisposeWatcher(stale);

        try
        {
            var watcher = new EventLogWatcher(new EventLogQuery("Security", PathType.LogName, Query));
            watcher.EventRecordWritten += OnEvent;
            watcher.Enabled = true;
            lock (_gate)
            {
                if (_disposed)
                {
                    watcher.Dispose();
                    return false;
                }

                _watcher = watcher;
                _recoveryEnabled = true;
                _health.Started();
                if (!_auditPolicyHealthy)
                {
                    _health.Degraded("Windows Filtering Platform audit policy is disabled or unverified");
                }
            }

            return true;
        }
        catch (Exception ex) when (ex is EventLogException or UnauthorizedAccessException or InvalidOperationException)
        {
            _log?.Invoke($"blocked-connection watch unavailable: {ex.Message}");
            _health.Unavailable($"Security-log watch unavailable: {ex.Message}");
            return false;
        }
    }

    /// <summary>Restart a failed Event Log subscription without restarting the service.</summary>
    public bool EnsureStarted() => Start();

    public void Stop()
    {
        lock (_gate)
        {
            _recoveryEnabled = false;
        }

        Interlocked.Increment(ref _recoveryGeneration);
        StopWatcher();
    }

    private void StopWatcher()
    {
        EventLogWatcher? watcher;
        lock (_gate)
        {
            watcher = _watcher;
            _watcher = null;
        }

        DisposeWatcher(watcher);
    }

    private static void DisposeWatcher(EventLogWatcher? watcher)
    {
        if (watcher is null)
        {
            return;
        }

        try
        {
            watcher.Enabled = false;
        }
        catch (Exception ex) when (ex is EventLogException or InvalidOperationException)
        {
            // A failed subscription may already be detached.
        }

        watcher.Dispose();
    }

    private void OnEvent(object? sender, EventRecordWrittenEventArgs e)
    {
        if (e.EventException is { } subscriptionError)
        {
            _health.RecordLoss(1, $"Security-log subscription failed: {subscriptionError.Message}");
            _log?.Invoke($"blocked-connection watch interrupted: {subscriptionError.Message}");
            QueueRecovery();
            return;
        }

        using var record = e.EventRecord;
        if (record is null)
        {
            _health.RecordLoss(1, "Security-log subscription returned no record");
            QueueRecovery();
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

            if (_auditPolicyHealthy)
            {
                _health.Healthy();
            }
        }
        catch (Exception ex) when (ex is EventLogException or System.Xml.XmlException)
        {
            _log?.Invoke($"blocked-connection parse failed: {ex.Message}");
        }
    }

    private void QueueRecovery()
    {
        lock (_gate)
        {
            if (!_recoveryEnabled || _disposed)
            {
                return;
            }
        }

        if (Interlocked.Exchange(ref _recoveryQueued, 1) != 0)
        {
            return;
        }

        var generation = Volatile.Read(ref _recoveryGeneration);
        ThreadPool.QueueUserWorkItem(_ =>
        {
            try
            {
                if (generation != Volatile.Read(ref _recoveryGeneration))
                {
                    return;
                }

                StopWatcher();
                bool canRecover;
                lock (_gate)
                {
                    canRecover = !_disposed && _recoveryEnabled;
                }

                if (canRecover && generation == Volatile.Read(ref _recoveryGeneration))
                {
                    Start();
                }
            }
            finally
            {
                Interlocked.Exchange(ref _recoveryQueued, 0);
            }
        });
    }

    /// <summary>
    /// Track the readable Security-log window. An advancing oldest record is a
    /// rollover: historical evidence before that record is no longer available.
    /// Returns the number of records that left the readable window.
    /// </summary>
    public long ProbeLogWindow()
    {
        try
        {
            var info = EventLogSession.GlobalSession.GetLogInformation("Security", PathType.LogName);
            return ObserveLogWindow(info.OldestRecordNumber);
        }
        catch (Exception ex) when (ex is EventLogException or UnauthorizedAccessException or InvalidOperationException)
        {
            _health.Unavailable($"Security-log metadata unavailable: {ex.Message}");
            _log?.Invoke($"Security-log integrity probe failed: {ex.Message}");
            return 0;
        }
    }

    internal long ObserveLogWindow(long? oldestRecordNumber)
    {
        if (oldestRecordNumber is null or <= 0)
        {
            return 0;
        }

        long delta = 0;
        lock (_gate)
        {
            if (_lastOldestRecordNumber is { } previous)
            {
                if (oldestRecordNumber.Value > previous)
                {
                    delta = oldestRecordNumber.Value - previous;
                }
                else if (oldestRecordNumber.Value < previous)
                {
                    // A clear/reset can restart record numbering rather than
                    // monotonically advancing the oldest record.
                    delta = 1;
                }
            }

            _lastOldestRecordNumber = oldestRecordNumber.Value;
        }

        if (delta > 0)
        {
            _health.RecordGap(delta, $"Security log rolled over; {delta} record(s) left the readable window");
        }
        else if (IsActive && _auditPolicyHealthy)
        {
            _health.Healthy();
        }

        return delta;
    }

    /// <summary>Apply an independently queried audit-policy state to health.</summary>
    public void ReportAuditPolicy(bool enabled)
    {
        bool changed;
        lock (_gate)
        {
            changed = _auditPolicyHealthy != enabled;
            _auditPolicyHealthy = enabled;
        }

        if (!enabled)
        {
            if (changed)
            {
                _health.RecordGap(1, "Windows Filtering Platform audit policy was disabled");
            }
            else
            {
                _health.Degraded("Windows Filtering Platform audit policy is disabled");
            }
        }
        else if (IsActive)
        {
            _health.Healthy(changed ? "audit policy restored; observing" : "observing");
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

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
        }

        Stop();
    }

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

    /// <summary>Query the two locale-stable WFP audit subcategories.</summary>
    public static bool IsAuditPolicyEnabled(Action<string>? log = null)
    {
        IntPtr policies = IntPtr.Zero;
        try
        {
            var categories = new[] { FilteringPlatformConnection, FilteringPlatformPacketDrop };
            if (!AuditQuerySystemPolicy(categories, (uint)categories.Length, out policies) || policies == IntPtr.Zero)
            {
                log?.Invoke($"AuditQuerySystemPolicy failed (win32 {Marshal.GetLastWin32Error()})");
                return false;
            }

            var size = Marshal.SizeOf<AUDIT_POLICY_INFORMATION>();
            var connection = Marshal.PtrToStructure<AUDIT_POLICY_INFORMATION>(policies);
            var packetDrop = Marshal.PtrToStructure<AUDIT_POLICY_INFORMATION>(IntPtr.Add(policies, size));
            return (connection.AuditingInformation & (AuditSuccess | AuditFailure)) == (AuditSuccess | AuditFailure)
                && (packetDrop.AuditingInformation & AuditFailure) == AuditFailure;
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException or InvalidOperationException)
        {
            log?.Invoke($"AuditQuerySystemPolicy unavailable: {ex.Message}");
            return false;
        }
        finally
        {
            if (policies != IntPtr.Zero)
            {
                AuditFree(policies);
            }
        }
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

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool AuditQuerySystemPolicy(
        [In] Guid[] pSubCategoryGuids, uint policyCount, out IntPtr ppAuditPolicy);

    [DllImport("advapi32.dll")]
    private static extern void AuditFree(IntPtr buffer);

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
