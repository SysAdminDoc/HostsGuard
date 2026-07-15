using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace HostsGuard.Windows;

public sealed record WfpPersistentFilter(
    ulong FilterId,
    Guid FilterKey,
    string Name,
    string Lifetime,
    Guid LayerKey,
    string LayerName,
    Guid SubLayerKey,
    string SubLayerName,
    string Action,
    Guid? CalloutKey,
    bool Disabled);

public sealed record WfpFilterSnapshot(
    bool Available,
    string ErrorCode,
    DateTime CheckedAtUtc,
    IReadOnlyList<WfpPersistentFilter> Filters);

public interface IWfpFilterInventory
{
    WfpFilterSnapshot Snapshot();
}

/// <summary>
/// Read-only enumeration of persistent and boot-time Windows Filtering
/// Platform filters. This class opens an observation-only engine session and
/// exposes no add, delete, transaction, or policy-mutation entry point.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsWfpFilterInventory : IWfpFilterInventory
{
    private const uint RpcCAuthnWinnt = 10;
    private const uint PersistentFlag = 0x00000001;
    private const uint BootTimeFlag = 0x00000002;
    private const uint DisabledFlag = 0x00000020;
    private const uint IncludeBootTime = 0x00000008;
    private const uint IncludeDisabled = 0x00000010;
    private const uint AllActions = 0xFFFFFFFF;
    private const uint ActionCalloutFlag = 0x00004000;
    private const uint PageSize = 256;
    private const int MaxFilters = 20_000;

    private readonly Func<DateTime> _utcNow;

    public WindowsWfpFilterInventory()
        : this(() => DateTime.UtcNow)
    {
    }

    internal WindowsWfpFilterInventory(Func<DateTime> utcNow) =>
        _utcNow = utcNow ?? throw new ArgumentNullException(nameof(utcNow));

    public WfpFilterSnapshot Snapshot()
    {
        var checkedAt = DateTime.SpecifyKind(_utcNow(), DateTimeKind.Utc);
        IntPtr engine = IntPtr.Zero;
        IntPtr enumHandle = IntPtr.Zero;
        try
        {
            ThrowIfError(FwpmEngineOpen0(
                null,
                RpcCAuthnWinnt,
                IntPtr.Zero,
                IntPtr.Zero,
                out engine));

            var template = new FwpmFilterEnumTemplate0
            {
                LayerKey = Guid.Empty,
                EnumType = 0,
                Flags = IncludeBootTime | IncludeDisabled,
                ActionMask = AllActions,
            };
            ThrowIfError(FwpmFilterCreateEnumHandle0(engine, ref template, out enumHandle));

            var layerNames = new Dictionary<Guid, string>();
            var subLayerNames = new Dictionary<Guid, string>();
            var filters = new List<WfpPersistentFilter>();
            while (true)
            {
                IntPtr entries = IntPtr.Zero;
                uint returned = 0;
                try
                {
                    ThrowIfError(FwpmFilterEnum0(engine, enumHandle, PageSize, out entries, out returned));
                    for (var index = 0; index < returned; index++)
                    {
                        var entry = Marshal.ReadIntPtr(entries, checked((int)(index * IntPtr.Size)));
                        if (entry == IntPtr.Zero)
                        {
                            continue;
                        }

                        var filter = Marshal.PtrToStructure<FwpmFilter0>(entry);
                        if ((filter.Flags & (PersistentFlag | BootTimeFlag)) == 0)
                        {
                            continue;
                        }

                        if (filters.Count >= MaxFilters)
                        {
                            return Unavailable(checkedAt, "filter_limit_exceeded");
                        }

                        var layerName = LookupLayerName(engine, filter.LayerKey, layerNames);
                        var subLayerName = LookupSubLayerName(engine, filter.SubLayerKey, subLayerNames);
                        var action = ActionName(filter.Action.Type);
                        filters.Add(new WfpPersistentFilter(
                            filter.FilterId,
                            filter.FilterKey,
                            Clean(Marshal.PtrToStringUni(filter.DisplayData.Name), 160, filter.FilterKey.ToString("D")),
                            LifetimeName(filter.Flags),
                            filter.LayerKey,
                            layerName,
                            filter.SubLayerKey,
                            subLayerName,
                            action,
                            (filter.Action.Type & ActionCalloutFlag) != 0 ? filter.Action.ActionKey : null,
                            (filter.Flags & DisabledFlag) != 0));
                    }
                }
                finally
                {
                    if (entries != IntPtr.Zero)
                    {
                        FwpmFreeMemory0(ref entries);
                    }
                }

                if (returned < PageSize)
                {
                    break;
                }
            }

            return new WfpFilterSnapshot(
                true,
                string.Empty,
                checkedAt,
                filters.OrderBy(filter => filter.FilterKey).ToArray());
        }
        catch (WfpInteropException ex)
        {
            return Unavailable(checkedAt, $"wfp_error_0x{ex.Code:x8}");
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException or
                                   TypeLoadException or Win32Exception)
        {
            return Unavailable(checkedAt, "wfp_api_unavailable");
        }
        finally
        {
            if (enumHandle != IntPtr.Zero && engine != IntPtr.Zero)
            {
                _ = FwpmFilterDestroyEnumHandle0(engine, enumHandle);
            }

            if (engine != IntPtr.Zero)
            {
                _ = FwpmEngineClose0(engine);
            }
        }
    }

    internal static string LifetimeName(uint flags) => (flags & (PersistentFlag | BootTimeFlag)) switch
    {
        BootTimeFlag => "boot-time",
        PersistentFlag => "persistent",
        PersistentFlag | BootTimeFlag => "persistent+boot-time",
        _ => "dynamic",
    };

    internal static string ActionName(uint action) => action switch
    {
        0x00001001 => "block",
        0x00001002 => "permit",
        0x00005003 => "callout-terminating",
        0x00006004 => "callout-inspection",
        0x00004005 => "callout-unknown",
        0x00002006 => "continue",
        0x00000007 => "none",
        0x00000008 => "none-no-match",
        _ => $"unknown-0x{action:x8}",
    };

    private static string LookupLayerName(
        IntPtr engine,
        Guid key,
        IDictionary<Guid, string> cache)
    {
        if (cache.TryGetValue(key, out var name))
        {
            return name;
        }

        IntPtr layerPointer = IntPtr.Zero;
        try
        {
            var lookupKey = key;
            var error = FwpmLayerGetByKey0(engine, ref lookupKey, out layerPointer);
            if (error == 0 && layerPointer != IntPtr.Zero)
            {
                var layer = Marshal.PtrToStructure<FwpmLayerPrefix>(layerPointer);
                name = Clean(Marshal.PtrToStringUni(layer.DisplayData.Name), 128, key.ToString("D"));
            }
            else
            {
                name = key.ToString("D");
            }
        }
        finally
        {
            if (layerPointer != IntPtr.Zero)
            {
                FwpmFreeMemory0(ref layerPointer);
            }
        }

        cache[key] = name;
        return name;
    }

    private static string LookupSubLayerName(
        IntPtr engine,
        Guid key,
        IDictionary<Guid, string> cache)
    {
        if (cache.TryGetValue(key, out var name))
        {
            return name;
        }

        IntPtr subLayerPointer = IntPtr.Zero;
        try
        {
            var lookupKey = key;
            var error = FwpmSubLayerGetByKey0(engine, ref lookupKey, out subLayerPointer);
            if (error == 0 && subLayerPointer != IntPtr.Zero)
            {
                var subLayer = Marshal.PtrToStructure<FwpmSubLayerPrefix>(subLayerPointer);
                name = Clean(Marshal.PtrToStringUni(subLayer.DisplayData.Name), 128, key.ToString("D"));
            }
            else
            {
                name = key.ToString("D");
            }
        }
        finally
        {
            if (subLayerPointer != IntPtr.Zero)
            {
                FwpmFreeMemory0(ref subLayerPointer);
            }
        }

        cache[key] = name;
        return name;
    }

    private static string Clean(string? value, int maxLength, string fallback) =>
        RemoteSessionText.Clean(value, maxLength, fallback);

    private static WfpFilterSnapshot Unavailable(DateTime checkedAt, string errorCode) => new(
        false,
        Clean(errorCode, 64, "wfp_inventory_unavailable"),
        checkedAt,
        []);

    private static void ThrowIfError(uint error)
    {
        if (error != 0)
        {
            throw new WfpInteropException(error);
        }
    }

    [DllImport("fwpuclnt.dll", EntryPoint = "FwpmEngineOpen0", CharSet = CharSet.Unicode)]
    private static extern uint FwpmEngineOpen0(
        string? serverName,
        uint authnService,
        IntPtr authIdentity,
        IntPtr session,
        out IntPtr engineHandle);

    [DllImport("fwpuclnt.dll", EntryPoint = "FwpmEngineClose0")]
    private static extern uint FwpmEngineClose0(IntPtr engineHandle);

    [DllImport("fwpuclnt.dll", EntryPoint = "FwpmFilterCreateEnumHandle0")]
    private static extern uint FwpmFilterCreateEnumHandle0(
        IntPtr engineHandle,
        ref FwpmFilterEnumTemplate0 enumTemplate,
        out IntPtr enumHandle);

    [DllImport("fwpuclnt.dll", EntryPoint = "FwpmFilterEnum0")]
    private static extern uint FwpmFilterEnum0(
        IntPtr engineHandle,
        IntPtr enumHandle,
        uint numEntriesRequested,
        out IntPtr entries,
        out uint numEntriesReturned);

    [DllImport("fwpuclnt.dll", EntryPoint = "FwpmFilterDestroyEnumHandle0")]
    private static extern uint FwpmFilterDestroyEnumHandle0(IntPtr engineHandle, IntPtr enumHandle);

    [DllImport("fwpuclnt.dll", EntryPoint = "FwpmLayerGetByKey0")]
    private static extern uint FwpmLayerGetByKey0(IntPtr engineHandle, ref Guid key, out IntPtr layer);

    [DllImport("fwpuclnt.dll", EntryPoint = "FwpmSubLayerGetByKey0")]
    private static extern uint FwpmSubLayerGetByKey0(IntPtr engineHandle, ref Guid key, out IntPtr subLayer);

    [DllImport("fwpuclnt.dll", EntryPoint = "FwpmFreeMemory0")]
    private static extern void FwpmFreeMemory0(ref IntPtr pointer);

    [StructLayout(LayoutKind.Sequential)]
    private struct FwpmDisplayData0
    {
        public IntPtr Name;
        public IntPtr Description;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FwpByteBlob
    {
        public uint Size;
        public IntPtr Data;
    }

    [StructLayout(LayoutKind.Explicit, Size = 16)]
    private struct FwpValueUnion
    {
        [FieldOffset(0)] public ulong UInt64;
        [FieldOffset(0)] public IntPtr Pointer;
        [FieldOffset(0)] public Guid Guid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FwpValue0
    {
        public uint Type;
        public FwpValueUnion Value;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FwpmAction0
    {
        public uint Type;
        public Guid ActionKey;
    }

    [StructLayout(LayoutKind.Explicit, Size = 16)]
    private struct FwpContextUnion
    {
        [FieldOffset(0)] public ulong RawContext;
        [FieldOffset(0)] public Guid ProviderContextKey;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FwpmFilter0
    {
        public Guid FilterKey;
        public FwpmDisplayData0 DisplayData;
        public uint Flags;
        public IntPtr ProviderKey;
        public FwpByteBlob ProviderData;
        public Guid LayerKey;
        public Guid SubLayerKey;
        public FwpValue0 Weight;
        public uint NumFilterConditions;
        public IntPtr FilterCondition;
        public FwpmAction0 Action;
        public FwpContextUnion Context;
        public IntPtr Reserved;
        public ulong FilterId;
        public FwpValue0 EffectiveWeight;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FwpmFilterEnumTemplate0
    {
        public IntPtr ProviderKey;
        public Guid LayerKey;
        public uint EnumType;
        public uint Flags;
        public IntPtr ProviderContextTemplate;
        public uint NumFilterConditions;
        public IntPtr FilterCondition;
        public uint ActionMask;
        public IntPtr CalloutKey;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FwpmLayerPrefix
    {
        public Guid LayerKey;
        public FwpmDisplayData0 DisplayData;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FwpmSubLayerPrefix
    {
        public Guid SubLayerKey;
        public FwpmDisplayData0 DisplayData;
    }

    private sealed class WfpInteropException(uint code) : Exception
    {
        public uint Code { get; } = code;
    }
}
