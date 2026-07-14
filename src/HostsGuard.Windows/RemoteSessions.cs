using System.Globalization;
using System.Net;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;

namespace HostsGuard.Windows;

public sealed record RemoteDesktopSession(
    int SessionId,
    string State,
    bool Active,
    string ClientName,
    string SourceAddress,
    DateTime? ConnectedAtUtc,
    DateTime? DisconnectedAtUtc);

public sealed record RemoteSessionSnapshot(
    bool Available,
    string ErrorCode,
    DateTime CheckedAtUtc,
    IReadOnlyList<RemoteDesktopSession> Sessions);

public interface IRemoteSessionSource
{
    RemoteSessionSnapshot Snapshot();
}

public sealed class UnavailableRemoteSessionSource(string errorCode) : IRemoteSessionSource
{
    public RemoteSessionSnapshot Snapshot() => new(
        false,
        RemoteSessionText.Clean(errorCode, 64, "not_configured"),
        DateTime.UtcNow,
        []);
}

/// <summary>
/// Read-only Terminal Services inventory. It exposes active RDP sessions and
/// disconnected sessions retained by Windows within a bounded recent window;
/// it never changes logon, session, firewall, or audit policy.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsRemoteSessionSource : IRemoteSessionSource
{
    private static readonly IntPtr CurrentServer = IntPtr.Zero;
    private readonly TimeSpan _recentWindow;
    private readonly Func<DateTime> _utcNow;

    public WindowsRemoteSessionSource(
        TimeSpan? recentWindow = null,
        Func<DateTime>? utcNow = null)
    {
        _recentWindow = recentWindow ?? TimeSpan.FromHours(24);
        _utcNow = utcNow ?? (() => DateTime.UtcNow);
    }

    public RemoteSessionSnapshot Snapshot()
    {
        var now = _utcNow();
        try
        {
            if (!WTSEnumerateSessions(CurrentServer, 0, 1, out var buffer, out var count))
            {
                return Unavailable(now, "wts_enumeration_failed");
            }

            try
            {
                var sessions = new List<RemoteDesktopSession>();
                var size = Marshal.SizeOf<WtsSessionInfo>();
                for (var index = 0; index < count; index++)
                {
                    var native = Marshal.PtrToStructure<WtsSessionInfo>(IntPtr.Add(buffer, index * size));
                    var station = RemoteSessionText.Clean(
                        Marshal.PtrToStringUni(native.WinStationName), 64, string.Empty);
                    var protocol = QueryUInt16(native.SessionId, WtsInfoClass.ClientProtocolType);
                    if (protocol != 2 && !station.StartsWith("RDP-", StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    var state = StateName(native.State);
                    var active = native.State == WtsConnectState.Active;
                    var (connectedAt, disconnectedAt) = QueryTimes(native.SessionId);
                    var recent = disconnectedAt.HasValue && now - disconnectedAt.Value <= _recentWindow;
                    if (!active && !recent)
                    {
                        continue;
                    }

                    sessions.Add(new RemoteDesktopSession(
                        native.SessionId,
                        state,
                        active,
                        QueryString(native.SessionId, WtsInfoClass.ClientName),
                        QueryAddress(native.SessionId),
                        connectedAt,
                        disconnectedAt));
                }

                return new RemoteSessionSnapshot(
                    true,
                    string.Empty,
                    now,
                    sessions.OrderByDescending(session => session.Active)
                        .ThenBy(session => session.SessionId)
                        .ToArray());
            }
            finally
            {
                WTSFreeMemory(buffer);
            }
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException or
                                   SEHException or TypeLoadException)
        {
            return Unavailable(now, "wts_api_unavailable");
        }
    }

    private static string QueryString(int sessionId, WtsInfoClass infoClass)
    {
        if (!WTSQuerySessionInformation(CurrentServer, sessionId, infoClass, out var buffer, out _))
        {
            return string.Empty;
        }

        try
        {
            return RemoteSessionText.Clean(Marshal.PtrToStringUni(buffer), 64, string.Empty);
        }
        finally
        {
            WTSFreeMemory(buffer);
        }
    }

    private static ushort QueryUInt16(int sessionId, WtsInfoClass infoClass)
    {
        if (!WTSQuerySessionInformation(CurrentServer, sessionId, infoClass, out var buffer, out var bytes))
        {
            return 0;
        }

        try
        {
            if (bytes < sizeof(ushort))
            {
                return 0;
            }

            return unchecked((ushort)Marshal.ReadInt16(buffer));
        }
        finally
        {
            WTSFreeMemory(buffer);
        }
    }

    private static string QueryAddress(int sessionId)
    {
        if (!WTSQuerySessionInformation(CurrentServer, sessionId, WtsInfoClass.ClientAddress,
                out var buffer, out var bytes))
        {
            return string.Empty;
        }

        try
        {
            if (bytes < Marshal.SizeOf<WtsClientAddress>())
            {
                return string.Empty;
            }

            var address = Marshal.PtrToStructure<WtsClientAddress>(buffer);
            if (address.Address is null)
            {
                return string.Empty;
            }

            return address.AddressFamily switch
            {
                2 when address.Address.Length >= 6 => new IPAddress(address.Address[2..6]).ToString(),
                23 when address.Address.Length >= 18 => new IPAddress(address.Address[2..18]).ToString(),
                _ => string.Empty,
            };
        }
        catch (ArgumentException)
        {
            return string.Empty;
        }
        finally
        {
            WTSFreeMemory(buffer);
        }
    }

    private static (DateTime? ConnectedAtUtc, DateTime? DisconnectedAtUtc) QueryTimes(int sessionId)
    {
        if (!WTSQuerySessionInformation(CurrentServer, sessionId, WtsInfoClass.SessionInfo,
                out var buffer, out var bytes))
        {
            return default;
        }

        try
        {
            if (bytes < Marshal.SizeOf<WtsInfo>())
            {
                return default;
            }

            var info = Marshal.PtrToStructure<WtsInfo>(buffer);
            return (FromFileTime(info.ConnectTime), FromFileTime(info.DisconnectTime));
        }
        finally
        {
            WTSFreeMemory(buffer);
        }
    }

    private static DateTime? FromFileTime(long value)
    {
        if (value <= 0)
        {
            return null;
        }

        try
        {
            return DateTime.FromFileTimeUtc(value);
        }
        catch (ArgumentOutOfRangeException)
        {
            return null;
        }
    }

    private static RemoteSessionSnapshot Unavailable(DateTime now, string code)
        => new(false, code, now, []);

    internal static string StateName(WtsConnectState state) => state switch
    {
        WtsConnectState.Active => "active",
        WtsConnectState.Connected => "connected",
        WtsConnectState.ConnectQuery => "connect-query",
        WtsConnectState.Shadow => "shadow",
        WtsConnectState.Disconnected => "disconnected",
        WtsConnectState.Idle => "idle",
        WtsConnectState.Listen => "listen",
        WtsConnectState.Reset => "reset",
        WtsConnectState.Down => "down",
        WtsConnectState.Init => "initializing",
        _ => "unknown",
    };

    [DllImport("wtsapi32.dll", EntryPoint = "WTSEnumerateSessionsW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WTSEnumerateSessions(
        IntPtr server,
        int reserved,
        int version,
        out IntPtr sessionInfo,
        out int count);

    [DllImport("wtsapi32.dll", EntryPoint = "WTSQuerySessionInformationW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WTSQuerySessionInformation(
        IntPtr server,
        int sessionId,
        WtsInfoClass infoClass,
        out IntPtr buffer,
        out int bytesReturned);

    [DllImport("wtsapi32.dll")]
    private static extern void WTSFreeMemory(IntPtr memory);

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct WtsSessionInfo
    {
        public readonly int SessionId;
        public readonly IntPtr WinStationName;
        public readonly WtsConnectState State;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WtsClientAddress
    {
        public int AddressFamily;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 20)]
        public byte[]? Address;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WtsInfo
    {
        public WtsConnectState State;
        public int SessionId;
        public int IncomingBytes;
        public int OutgoingBytes;
        public int IncomingFrames;
        public int OutgoingFrames;
        public int IncomingCompressedBytes;
        public int OutgoingCompressedBytes;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
        public string? WinStationName;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 17)]
        public string? Domain;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 21)]
        public string? UserName;

        public long ConnectTime;
        public long DisconnectTime;
        public long LastInputTime;
        public long LogonTime;
        public long CurrentTime;
    }

    internal enum WtsConnectState
    {
        Active,
        Connected,
        ConnectQuery,
        Shadow,
        Disconnected,
        Idle,
        Listen,
        Reset,
        Down,
        Init,
    }

    private enum WtsInfoClass
    {
        ClientName = 10,
        ClientAddress = 14,
        ClientProtocolType = 16,
        SessionInfo = 24,
    }
}

internal static class RemoteSessionText
{
    internal static string Clean(string? value, int maxLength, string fallback)
    {
        var builder = new StringBuilder(Math.Min(value?.Length ?? 0, maxLength));
        foreach (var ch in (value ?? string.Empty).Normalize(NormalizationForm.FormKC))
        {
            var category = char.GetUnicodeCategory(ch);
            if (char.IsControl(ch) || char.IsSurrogate(ch) || category == UnicodeCategory.Format)
            {
                continue;
            }

            builder.Append(ch);
            if (builder.Length == maxLength)
            {
                break;
            }
        }

        var result = builder.ToString().Trim();
        return result.Length == 0 ? fallback : result;
    }
}
