using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace HostsGuard.Windows;

/// <summary>The bounded outcome of reading a DHCPv4/v6 DNR option.</summary>
public enum DnrOptionOutcome
{
    Success,
    NoOption,
    Busy,
    Timeout,
    ApiUnavailable,
    Failed,
}

/// <summary>Raw option payload retained for strict parsing in Core.</summary>
public sealed record DnrOptionResult(DnrOptionOutcome Outcome, byte[] Data, int NativeStatus, string Error);

public interface IDnrOptionSource
{
    Task<DnrOptionResult> ReadV4Async(
        string adapterId,
        TimeSpan timeout,
        CancellationToken cancellationToken);

    Task<DnrOptionResult> ReadV6Async(
        string adapterId,
        TimeSpan timeout,
        CancellationToken cancellationToken);
}

internal interface IDhcpDnrNative
{
    DnrOptionResult ReadV4(string adapterId);
    DnrOptionResult ReadV6(string adapterId);
}

/// <summary>
/// Bounded facade over the synchronous DHCP Client API. Microsoft documents a
/// worst-case two-minute DHCP-INFORM wait, so at most one native call may run
/// after a caller timeout; later probes report busy instead of accumulating
/// blocked worker threads.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class DhcpDnrOptionSource : IDnrOptionSource
{
    private readonly IDhcpDnrNative _native;
    private readonly SemaphoreSlim _nativeGate = new(1, 1);

    public DhcpDnrOptionSource()
        : this(new SystemDhcpDnrNative())
    {
    }

    internal DhcpDnrOptionSource(IDhcpDnrNative native)
    {
        _native = native;
    }

    public Task<DnrOptionResult> ReadV4Async(
        string adapterId,
        TimeSpan timeout,
        CancellationToken cancellationToken)
        => ReadAsync(adapterId, timeout, cancellationToken, _native.ReadV4);

    public Task<DnrOptionResult> ReadV6Async(
        string adapterId,
        TimeSpan timeout,
        CancellationToken cancellationToken)
        => ReadAsync(adapterId, timeout, cancellationToken, _native.ReadV6);

    private async Task<DnrOptionResult> ReadAsync(
        string adapterId,
        TimeSpan timeout,
        CancellationToken cancellationToken,
        Func<string, DnrOptionResult> readNative)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(adapterId);
        if (timeout <= TimeSpan.Zero || timeout > TimeSpan.FromSeconds(30))
        {
            throw new ArgumentOutOfRangeException(nameof(timeout));
        }

        cancellationToken.ThrowIfCancellationRequested();
        if (!await _nativeGate.WaitAsync(0, cancellationToken).ConfigureAwait(false))
        {
            return new(DnrOptionOutcome.Busy, [], 0, "prior_dhcp_request_still_running");
        }

        var read = Task.Run(() => readNative(adapterId), CancellationToken.None);
        _ = read.ContinueWith(
            static (_, state) => ((SemaphoreSlim)state!).Release(),
            _nativeGate,
            CancellationToken.None,
            TaskContinuationOptions.ExecuteSynchronously,
            TaskScheduler.Default);
        try
        {
            return await read.WaitAsync(timeout, cancellationToken).ConfigureAwait(false);
        }
        catch (TimeoutException)
        {
            return new(DnrOptionOutcome.Timeout, [], 1460, "dhcp_request_timeout");
        }
    }
}

[SupportedOSPlatform("windows")]
internal sealed class SystemDhcpDnrNative : IDhcpDnrNative
{
    private const uint RequestSynchronous = 0x2;
    private const uint OptionV4Dnr = 162;
    private const uint OptionV6Dnr = 144;
    private const int ErrorSuccess = 0;
    private const int ErrorMoreData = 234;
    private const int ErrorFileNotFound = 2;
    private const int ErrorNotFound = 1168;
    private const int InitialBufferBytes = 1024;
    private const int MaxBufferBytes = 65_535;

    public DnrOptionResult ReadV4(string adapterId)
    {
        try
        {
            var status = DhcpCApiInitialize(out _);
            if (status != ErrorSuccess)
            {
                return new(DnrOptionOutcome.Failed, [], checked((int)status), $"dhcp_initialize_{status}");
            }

            try
            {
                return Request(adapterId);
            }
            finally
            {
                DhcpCApiCleanup();
            }
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException or BadImageFormatException)
        {
            return new(DnrOptionOutcome.ApiUnavailable, [], 0, ex.GetType().Name);
        }
    }

    public DnrOptionResult ReadV6(string adapterId)
    {
        try
        {
            Dhcpv6CApiInitialize(out _);
            try
            {
                return RequestV6(adapterId);
            }
            finally
            {
                Dhcpv6CApiCleanup();
            }
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException or BadImageFormatException)
        {
            return new(DnrOptionOutcome.ApiUnavailable, [], 0, ex.GetType().Name);
        }
    }

    private static DnrOptionResult Request(string adapterId)
    {
        var parameterPointer = Marshal.AllocHGlobal(Marshal.SizeOf<DhcpApiParameterNative>());
        try
        {
            for (var capacity = InitialBufferBytes; capacity <= MaxBufferBytes; capacity = NextCapacity(capacity))
            {
                Marshal.StructureToPtr(
                    new DhcpApiParameterNative { OptionId = OptionV4Dnr },
                    parameterPointer,
                    false);
                var buffer = Marshal.AllocHGlobal(capacity);
                try
                {
                    var size = checked((uint)capacity);
                    var status = DhcpRequestParams(
                        RequestSynchronous,
                        IntPtr.Zero,
                        adapterId,
                        IntPtr.Zero,
                        new DhcpApiParameterArrayNative(),
                        new DhcpApiParameterArrayNative { Count = 1, Parameters = parameterPointer },
                        buffer,
                        ref size,
                        null);
                    if (status == ErrorMoreData && size > capacity && size <= MaxBufferBytes)
                    {
                        capacity = checked((int)size) - 1;
                        continue;
                    }

                    if (status is ErrorFileNotFound or ErrorNotFound)
                    {
                        return new(DnrOptionOutcome.NoOption, [], checked((int)status), "option_not_present");
                    }

                    if (status != ErrorSuccess)
                    {
                        return new(DnrOptionOutcome.Failed, [], checked((int)status), $"dhcp_status_{status}");
                    }

                    var returned = Marshal.PtrToStructure<DhcpApiParameterNative>(parameterPointer);
                    if (returned.Data == IntPtr.Zero || returned.DataLength == 0)
                    {
                        return new(DnrOptionOutcome.NoOption, [], checked((int)status), "option_not_present");
                    }

                    if (returned.DataLength > MaxBufferBytes)
                    {
                        return new(DnrOptionOutcome.Failed, [], checked((int)status), "option_too_large");
                    }

                    var data = new byte[checked((int)returned.DataLength)];
                    Marshal.Copy(returned.Data, data, 0, data.Length);
                    return new(DnrOptionOutcome.Success, data, checked((int)status), string.Empty);
                }
                finally
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }

            return new(DnrOptionOutcome.Failed, [], ErrorMoreData, "option_too_large");
        }
        finally
        {
            Marshal.FreeHGlobal(parameterPointer);
        }
    }

    private static DnrOptionResult RequestV6(string adapterId)
    {
        var parameterPointer = Marshal.AllocHGlobal(Marshal.SizeOf<DhcpApiParameterNative>());
        try
        {
            for (var capacity = InitialBufferBytes; capacity <= MaxBufferBytes; capacity = NextCapacity(capacity))
            {
                Marshal.StructureToPtr(
                    new DhcpApiParameterNative { OptionId = OptionV6Dnr },
                    parameterPointer,
                    false);
                var buffer = Marshal.AllocHGlobal(capacity);
                try
                {
                    var size = checked((uint)capacity);
                    var status = Dhcpv6RequestParams(
                        false,
                        IntPtr.Zero,
                        NormalizeAdapterGuid(adapterId),
                        IntPtr.Zero,
                        new DhcpApiParameterArrayNative { Count = 1, Parameters = parameterPointer },
                        buffer,
                        ref size);
                    if (status == ErrorMoreData && size > capacity && size <= MaxBufferBytes)
                    {
                        capacity = checked((int)size) - 1;
                        continue;
                    }

                    if (status is ErrorFileNotFound or ErrorNotFound)
                    {
                        return new(DnrOptionOutcome.NoOption, [], checked((int)status), "option_not_present");
                    }

                    if (status != ErrorSuccess)
                    {
                        return new(DnrOptionOutcome.Failed, [], checked((int)status), $"dhcpv6_status_{status}");
                    }

                    var returned = Marshal.PtrToStructure<DhcpApiParameterNative>(parameterPointer);
                    if (returned.Data == IntPtr.Zero || returned.DataLength == 0)
                    {
                        return new(DnrOptionOutcome.NoOption, [], 0, "option_not_present");
                    }

                    if (returned.DataLength > MaxBufferBytes)
                    {
                        return new(DnrOptionOutcome.Failed, [], 0, "option_too_large");
                    }

                    var data = new byte[checked((int)returned.DataLength)];
                    Marshal.Copy(returned.Data, data, 0, data.Length);
                    return new(DnrOptionOutcome.Success, data, 0, string.Empty);
                }
                finally
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }

            return new(DnrOptionOutcome.Failed, [], ErrorMoreData, "option_too_large");
        }
        finally
        {
            Marshal.FreeHGlobal(parameterPointer);
        }
    }

    private static string NormalizeAdapterGuid(string adapterId)
        => Guid.TryParse(adapterId, out var parsed) ? parsed.ToString("B") : adapterId;

    private static int NextCapacity(int capacity) => Math.Min(capacity * 2, MaxBufferBytes);

    [DllImport("dhcpcsvc.dll", ExactSpelling = true)]
    private static extern uint DhcpCApiInitialize(out uint version);

    [DllImport("dhcpcsvc.dll", ExactSpelling = true)]
    private static extern void DhcpCApiCleanup();

    [DllImport("dhcpcsvc.dll", ExactSpelling = true, CharSet = CharSet.Unicode)]
    private static extern uint DhcpRequestParams(
        uint flags,
        IntPtr reserved,
        string adapterName,
        IntPtr classId,
        DhcpApiParameterArrayNative sendParameters,
        DhcpApiParameterArrayNative receivedParameters,
        IntPtr buffer,
        ref uint size,
        string? requestId);

    [DllImport("dhcpcsvc6.dll", ExactSpelling = true)]
    private static extern void Dhcpv6CApiInitialize(out uint version);

    [DllImport("dhcpcsvc6.dll", ExactSpelling = true)]
    private static extern void Dhcpv6CApiCleanup();

    [DllImport("dhcpcsvc6.dll", ExactSpelling = true, CharSet = CharSet.Unicode)]
    private static extern uint Dhcpv6RequestParams(
        [MarshalAs(UnmanagedType.Bool)] bool forceNewInform,
        IntPtr reserved,
        string adapterName,
        IntPtr classId,
        DhcpApiParameterArrayNative receivedParameters,
        IntPtr buffer,
        ref uint size);
}

[StructLayout(LayoutKind.Sequential)]
internal struct DhcpApiParameterNative
{
    public uint Flags;
    public uint OptionId;
    public int IsVendor;
    public IntPtr Data;
    public uint DataLength;
}

[StructLayout(LayoutKind.Sequential)]
internal struct DhcpApiParameterArrayNative
{
    public uint Count;
    public IntPtr Parameters;
}
