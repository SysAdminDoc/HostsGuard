using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace HostsGuard.Windows;

/// <summary>The observable outcome of one direct Windows DNS resource-record query.</summary>
public enum DnsRawQueryOutcome
{
    Success,
    NoRecords,
    NameNotFound,
    Timeout,
    ApiUnavailable,
    Failed,
}

/// <summary>A DNS resource record whose RDATA remains in bounded wire format for Core parsing.</summary>
public sealed record DnsRawResourceRecord(
    string Name,
    ushort Type,
    uint TtlSeconds,
    byte[] Rdata);

/// <summary>Result of one HTTPS (65) or SVCB (64) query through the Windows resolver.</summary>
public sealed record DnsRawQueryResult(
    DnsRawQueryOutcome Outcome,
    IReadOnlyList<DnsRawResourceRecord> Records,
    int NativeStatus,
    string Error);

/// <summary>Cancellable direct-query seam for HTTPS/SVCB records.</summary>
public interface IDnsServiceBindingQuery
{
    Task<DnsRawQueryResult> QueryResourceRecordsAsync(
        string name,
        ushort recordType,
        TimeSpan timeout,
        CancellationToken cancellationToken);
}

/// <summary>
/// Windows <c>DnsQueryEx</c> wrapper. Queries remain asynchronous so
/// <c>DnsCancelQuery</c> can stop an in-flight resolver operation. SVCB/HTTPS are
/// intentionally requested without <c>DNS_QUERY_PARSE_ALL_RECORDS</c>, making
/// dnsapi return the exact flat RDATA consumed by the bounded Core parser.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class DnsQueryExServiceBindingQuery : IDnsServiceBindingQuery
{
    internal const ushort DnsTypeSvcb = 64;
    internal const ushort DnsTypeHttps = 65;

    private readonly IDnsQueryExNative _native;

    public DnsQueryExServiceBindingQuery()
        : this(new SystemDnsQueryExNative())
    {
    }

    internal DnsQueryExServiceBindingQuery(IDnsQueryExNative native)
    {
        _native = native;
    }

    public async Task<DnsRawQueryResult> QueryResourceRecordsAsync(
        string name,
        ushort recordType,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        if (recordType is not DnsTypeSvcb and not DnsTypeHttps)
        {
            throw new ArgumentOutOfRangeException(
                nameof(recordType),
                recordType,
                "Only SVCB (64) and HTTPS (65) resource records are supported.");
        }

        if (timeout <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(timeout));
        }

        cancellationToken.ThrowIfCancellationRequested();
        var normalizedName = name.Trim().TrimEnd('.');
        if (normalizedName.Length == 0)
        {
            throw new ArgumentException("A DNS name is required.", nameof(name));
        }

        using var operation = new QueryOperation(_native, normalizedName, recordType);
        return await operation.RunAsync(timeout, cancellationToken).ConfigureAwait(false);
    }

    private sealed class QueryOperation : IDisposable
    {
        private const int ErrorSuccess = 0;
        private const int ErrorCancelled = 1223;
        private const int ErrorTimeout = 1460;
        private const int DnsErrorRcodeNameError = 9003;
        private const int DnsInfoNoRecords = 9501;
        private const int DnsRequestPending = 9506;
        private const int DnsFreeRecordList = 1;
        private const int MaxRecords = 128;
        private const int MaxRdataBytes = 65_535;

        private static readonly DnsQueryCompletion CompletionCallback = OnQueryComplete;

        private readonly IDnsQueryExNative _native;
        private readonly IntPtr _queryName;
        private readonly IntPtr _request;
        private readonly IntPtr _result;
        private readonly IntPtr _cancel;
        private readonly GCHandle _selfHandle;
        private readonly TaskCompletionSource<DnsRawQueryResult> _completion =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        private CancellationToken _callerToken;
        private CancellationToken _timeoutToken;
        private CancellationTokenRegistration _cancellationRegistration;
        private int _cancelRequested;
        private bool _disposed;

        public QueryOperation(IDnsQueryExNative native, string name, ushort recordType)
        {
            _native = native;
            _queryName = Marshal.StringToHGlobalUni(name);
            _request = Marshal.AllocHGlobal(Marshal.SizeOf<DnsQueryRequestNative>());
            _result = Marshal.AllocHGlobal(Marshal.SizeOf<DnsQueryResultNative>());
            _cancel = Marshal.AllocHGlobal(32);
            Clear(_request, Marshal.SizeOf<DnsQueryRequestNative>());
            Clear(_result, Marshal.SizeOf<DnsQueryResultNative>());
            Clear(_cancel, 32);

            _selfHandle = GCHandle.Alloc(this);
            Marshal.StructureToPtr(
                new DnsQueryRequestNative
                {
                    Version = 1,
                    QueryName = _queryName,
                    QueryType = recordType,
                    QueryOptions = 0, // Flat/unknown data preserves the exact wire RDATA.
                    CompletionCallback = Marshal.GetFunctionPointerForDelegate(CompletionCallback),
                    QueryContext = GCHandle.ToIntPtr(_selfHandle),
                },
                _request,
                false);
            Marshal.StructureToPtr(new DnsQueryResultNative { Version = 1 }, _result, false);
        }

        public async Task<DnsRawQueryResult> RunAsync(
            TimeSpan timeout,
            CancellationToken cancellationToken)
        {
            _callerToken = cancellationToken;
            using var timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutSource.CancelAfter(timeout);
            _timeoutToken = timeoutSource.Token;

            int status;
            try
            {
                status = _native.Query(_request, _result, _cancel);
            }
            catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException or BadImageFormatException)
            {
                return Unavailable(ex.GetType().Name);
            }

            if (status == DnsRequestPending)
            {
                _cancellationRegistration = timeoutSource.Token.Register(static state =>
                {
                    var operation = (QueryOperation)state!;
                    Interlocked.Exchange(ref operation._cancelRequested, 1);
                    try
                    {
                        _ = operation._native.Cancel(operation._cancel);
                    }
                    catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException or BadImageFormatException)
                    {
                        // The original query remains pending when cancellation is
                        // unavailable. Keep its buffers alive until dnsapi invokes
                        // the completion callback; completing here would permit a
                        // callback into freed request/result/context memory.
                    }
                }, this);

                return await _completion.Task.ConfigureAwait(false);
            }

            return Complete(status);
        }

        private static void OnQueryComplete(IntPtr context, IntPtr result)
        {
            try
            {
                var handle = GCHandle.FromIntPtr(context);
                if (handle.Target is QueryOperation operation)
                {
                    var nativeResult = Marshal.PtrToStructure<DnsQueryResultNative>(result);
                    if (nativeResult.QueryStatus == ErrorCancelled &&
                        Volatile.Read(ref operation._cancelRequested) != 0 &&
                        operation._callerToken.IsCancellationRequested)
                    {
                        operation.FreeRecords(nativeResult.QueryRecords);
                        operation._completion.TrySetCanceled(operation._callerToken);
                    }
                    else
                    {
                        operation._completion.TrySetResult(operation.Complete(nativeResult.QueryStatus));
                    }
                }
            }
            catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
            {
                // A malformed callback cannot be surfaced safely without a valid operation.
            }
        }

        private DnsRawQueryResult Complete(int immediateStatus)
        {
            var nativeResult = Marshal.PtrToStructure<DnsQueryResultNative>(_result);
            var status = immediateStatus == DnsRequestPending ? nativeResult.QueryStatus : immediateStatus;

            if (status == ErrorCancelled && Volatile.Read(ref _cancelRequested) != 0)
            {
                if (_timeoutToken.IsCancellationRequested)
                {
                    FreeRecords(nativeResult.QueryRecords);
                    return new(DnsRawQueryOutcome.Timeout, [], status, "timeout");
                }
            }

            if (status == ErrorTimeout)
            {
                FreeRecords(nativeResult.QueryRecords);
                return new(DnsRawQueryOutcome.Timeout, [], status, "timeout");
            }

            if (status == DnsInfoNoRecords)
            {
                FreeRecords(nativeResult.QueryRecords);
                return new(DnsRawQueryOutcome.NoRecords, [], status, "no_records");
            }

            if (status == DnsErrorRcodeNameError)
            {
                FreeRecords(nativeResult.QueryRecords);
                return new(DnsRawQueryOutcome.NameNotFound, [], status, "name_not_found");
            }

            if (status != ErrorSuccess)
            {
                FreeRecords(nativeResult.QueryRecords);
                return new(DnsRawQueryOutcome.Failed, [], status, $"dns_status_{status}");
            }

            try
            {
                var records = CopyRecords(nativeResult.QueryRecords);
                return records.Count == 0
                    ? new(DnsRawQueryOutcome.NoRecords, [], DnsInfoNoRecords, "no_records")
                    : new(DnsRawQueryOutcome.Success, records, ErrorSuccess, string.Empty);
            }
            finally
            {
                FreeRecords(nativeResult.QueryRecords);
            }
        }

        private static IReadOnlyList<DnsRawResourceRecord> CopyRecords(IntPtr head)
        {
            var records = new List<DnsRawResourceRecord>();
            var current = head;
            while (current != IntPtr.Zero && records.Count < MaxRecords)
            {
                var header = Marshal.PtrToStructure<DnsRecordHeaderNative>(current);
                if (header.Type is DnsTypeSvcb or DnsTypeHttps)
                {
                    var data = IntPtr.Add(current, Marshal.SizeOf<DnsRecordHeaderNative>());
                    var byteCount = Marshal.ReadInt32(data);
                    if (byteCount >= 0 && byteCount <= MaxRdataBytes)
                    {
                        var rdata = new byte[byteCount];
                        if (byteCount != 0)
                        {
                            Marshal.Copy(IntPtr.Add(data, sizeof(uint)), rdata, 0, byteCount);
                        }

                        records.Add(new(
                            Marshal.PtrToStringUni(header.Name)?.TrimEnd('.') ?? string.Empty,
                            header.Type,
                            header.Ttl,
                            rdata));
                    }
                }

                current = header.Next;
            }

            return records;
        }

        private void FreeRecords(IntPtr records)
        {
            if (records != IntPtr.Zero)
            {
                _native.FreeRecordList(records, DnsFreeRecordList);
            }
        }

        private static DnsRawQueryResult Unavailable(string reason)
            => new(DnsRawQueryOutcome.ApiUnavailable, [], 0, reason);

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            _cancellationRegistration.Dispose();
            if (_selfHandle.IsAllocated)
            {
                _selfHandle.Free();
            }

            Marshal.FreeHGlobal(_cancel);
            Marshal.FreeHGlobal(_result);
            Marshal.FreeHGlobal(_request);
            Marshal.FreeHGlobal(_queryName);
        }

        private static void Clear(IntPtr memory, int length)
        {
            for (var offset = 0; offset < length; offset++)
            {
                Marshal.WriteByte(memory, offset, 0);
            }
        }
    }
}

[StructLayout(LayoutKind.Sequential)]
internal struct DnsQueryRequestNative
{
    public uint Version;
    public IntPtr QueryName;
    public ushort QueryType;
    public ulong QueryOptions;
    public IntPtr DnsServerList;
    public uint InterfaceIndex;
    public IntPtr CompletionCallback;
    public IntPtr QueryContext;
}

[StructLayout(LayoutKind.Sequential)]
internal struct DnsQueryResultNative
{
    public uint Version;
    public int QueryStatus;
    public ulong QueryOptions;
    public IntPtr QueryRecords;
    public IntPtr Reserved;
}

[StructLayout(LayoutKind.Sequential)]
internal struct DnsRecordHeaderNative
{
    public IntPtr Next;
    public IntPtr Name;
    public ushort Type;
    public ushort DataLength;
    public uint Flags;
    public uint Ttl;
    public uint Reserved;
}

[UnmanagedFunctionPointer(CallingConvention.Winapi)]
internal delegate void DnsQueryCompletion(IntPtr queryContext, IntPtr queryResults);

internal interface IDnsQueryExNative
{
    int Query(IntPtr request, IntPtr result, IntPtr cancel);
    int Cancel(IntPtr cancel);
    void FreeRecordList(IntPtr records, int freeType);
}

[SupportedOSPlatform("windows")]
internal sealed class SystemDnsQueryExNative : IDnsQueryExNative
{
    public int Query(IntPtr request, IntPtr result, IntPtr cancel)
        => DnsQueryEx(request, result, cancel);

    public int Cancel(IntPtr cancel) => DnsCancelQuery(cancel);

    public void FreeRecordList(IntPtr records, int freeType)
        => DnsRecordListFree(records, freeType);

    [DllImport("dnsapi.dll", ExactSpelling = true)]
    private static extern int DnsQueryEx(IntPtr request, IntPtr result, IntPtr cancel);

    [DllImport("dnsapi.dll", ExactSpelling = true)]
    private static extern int DnsCancelQuery(IntPtr cancel);

    [DllImport("dnsapi.dll", ExactSpelling = true)]
    private static extern void DnsRecordListFree(IntPtr recordList, int freeType);
}
