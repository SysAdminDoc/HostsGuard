using System.Runtime.InteropServices;
using FluentAssertions;
using HostsGuard.Windows;

namespace HostsGuard.Windows.Tests;

public sealed class DnsServiceBindingQueryTests
{
    [Fact]
    public async Task Live_windows_query_returns_a_bounded_explicit_outcome()
    {
        var query = new DnsQueryExServiceBindingQuery();

        var result = await query.QueryResourceRecordsAsync(
            "cloudflare.com",
            65,
            TimeSpan.FromSeconds(3),
            CancellationToken.None);

        result.Outcome.Should().BeOneOf(Enum.GetValues<DnsRawQueryOutcome>());
        result.Records.Should().HaveCountLessThanOrEqualTo(128);
        result.Records.Should().OnlyContain(record => record.Type == 65 && record.Rdata.Length <= 65_535);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(63)]
    [InlineData(66)]
    public async Task RejectsUnsupportedRecordTypes(ushort recordType)
    {
        var native = new FakeDnsQueryExNative();
        var query = new DnsQueryExServiceBindingQuery(native);

        var act = () => query.QueryResourceRecordsAsync(
            "example.com",
            recordType,
            TimeSpan.FromSeconds(1),
            CancellationToken.None);

        await act.Should().ThrowAsync<ArgumentOutOfRangeException>();
        native.QueryCount.Should().Be(0);
    }

    [Fact]
    public async Task ReportsUnavailableApiWithoutThrowing()
    {
        var native = new FakeDnsQueryExNative { QueryException = new EntryPointNotFoundException() };
        var query = new DnsQueryExServiceBindingQuery(native);

        var result = await query.QueryResourceRecordsAsync(
            "example.com",
            65,
            TimeSpan.FromSeconds(1),
            CancellationToken.None);

        result.Outcome.Should().Be(DnsRawQueryOutcome.ApiUnavailable);
        result.Records.Should().BeEmpty();
        result.Error.Should().Be(nameof(EntryPointNotFoundException));
    }

    [Theory]
    [InlineData(9501, DnsRawQueryOutcome.NoRecords, "no_records")]
    [InlineData(9003, DnsRawQueryOutcome.NameNotFound, "name_not_found")]
    [InlineData(1460, DnsRawQueryOutcome.Timeout, "timeout")]
    [InlineData(9002, DnsRawQueryOutcome.Failed, "dns_status_9002")]
    public async Task MapsNativeVisibilityStatuses(
        int nativeStatus,
        DnsRawQueryOutcome outcome,
        string error)
    {
        var native = new FakeDnsQueryExNative { QueryStatus = nativeStatus };
        var query = new DnsQueryExServiceBindingQuery(native);

        var result = await query.QueryResourceRecordsAsync(
            "missing.example",
            64,
            TimeSpan.FromSeconds(1),
            CancellationToken.None);

        result.Outcome.Should().Be(outcome);
        result.NativeStatus.Should().Be(nativeStatus);
        result.Error.Should().Be(error);
        result.Records.Should().BeEmpty();
    }

    [Fact]
    public async Task CopiesFlatRdataAndFreesNativeRecordList()
    {
        var expected = new byte[] { 0, 1, 0, 1, 0, 3, 2, (byte)'h', (byte)'2' };
        using var record = NativeRecord.Create("svc.example.com.", 65, 300, expected);
        var native = new FakeDnsQueryExNative
        {
            QueryStatus = 0,
            QueryRecords = record.Pointer,
        };
        var query = new DnsQueryExServiceBindingQuery(native);

        var result = await query.QueryResourceRecordsAsync(
            "svc.example.com.",
            65,
            TimeSpan.FromSeconds(1),
            CancellationToken.None);

        result.Outcome.Should().Be(DnsRawQueryOutcome.Success);
        result.Records.Should().ContainSingle().Which.Should().BeEquivalentTo(
            new DnsRawResourceRecord("svc.example.com", 65, 300, expected));
        native.FreedRecords.Should().Equal(record.Pointer);
    }

    [Fact]
    public async Task CallerCancellationCancelsNativeQueryAndPropagates()
    {
        var native = new FakeDnsQueryExNative { QueryStatus = 9506 };
        var query = new DnsQueryExServiceBindingQuery(native);
        using var cancellation = new CancellationTokenSource();

        var pending = query.QueryResourceRecordsAsync(
            "example.com",
            65,
            TimeSpan.FromSeconds(5),
            cancellation.Token);
        cancellation.Cancel();

        await FluentActions.Awaiting(() => pending).Should().ThrowAsync<OperationCanceledException>();
        native.CancelCount.Should().Be(1);
    }

    [Fact]
    public async Task TimeoutCancelsNativeQueryAndReturnsExplicitOutcome()
    {
        var native = new FakeDnsQueryExNative { QueryStatus = 9506 };
        var query = new DnsQueryExServiceBindingQuery(native);

        var result = await query.QueryResourceRecordsAsync(
            "example.com",
            64,
            TimeSpan.FromMilliseconds(20),
            CancellationToken.None);

        result.Outcome.Should().Be(DnsRawQueryOutcome.Timeout);
        result.NativeStatus.Should().Be(1223);
        native.CancelCount.Should().Be(1);
    }

    [Fact]
    public async Task AlreadyCancelledRequestNeverStartsNativeQuery()
    {
        var native = new FakeDnsQueryExNative();
        var query = new DnsQueryExServiceBindingQuery(native);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        var act = () => query.QueryResourceRecordsAsync(
            "example.com",
            65,
            TimeSpan.FromSeconds(1),
            cancellation.Token);

        await act.Should().ThrowAsync<OperationCanceledException>();
        native.QueryCount.Should().Be(0);
    }

    private sealed class FakeDnsQueryExNative : IDnsQueryExNative
    {
        private IntPtr _request;
        private IntPtr _result;

        public int QueryStatus { get; init; }
        public IntPtr QueryRecords { get; init; }
        public Exception? QueryException { get; init; }
        public int QueryCount { get; private set; }
        public int CancelCount { get; private set; }
        public List<IntPtr> FreedRecords { get; } = [];

        public int Query(IntPtr request, IntPtr result, IntPtr cancel)
        {
            QueryCount++;
            if (QueryException is not null)
            {
                throw QueryException;
            }

            _request = request;
            _result = result;
            if (QueryStatus != 9506)
            {
                WriteResult(QueryStatus, QueryRecords);
            }

            return QueryStatus;
        }

        public int Cancel(IntPtr cancel)
        {
            CancelCount++;
            WriteResult(1223, IntPtr.Zero);
            var request = Marshal.PtrToStructure<DnsQueryRequestNative>(_request);
            var callback = Marshal.GetDelegateForFunctionPointer<DnsQueryCompletion>(request.CompletionCallback);
            callback(request.QueryContext, _result);
            return 0;
        }

        public void FreeRecordList(IntPtr records, int freeType)
        {
            freeType.Should().Be(1);
            FreedRecords.Add(records);
        }

        private void WriteResult(int status, IntPtr records)
        {
            Marshal.StructureToPtr(
                new DnsQueryResultNative
                {
                    Version = 1,
                    QueryStatus = status,
                    QueryRecords = records,
                },
                _result,
                false);
        }
    }

    private sealed class NativeRecord : IDisposable
    {
        private readonly IntPtr _name;

        private NativeRecord(IntPtr pointer, IntPtr name)
        {
            Pointer = pointer;
            _name = name;
        }

        public IntPtr Pointer { get; }

        public static NativeRecord Create(string name, ushort type, uint ttl, byte[] rdata)
        {
            var namePointer = Marshal.StringToHGlobalUni(name);
            var headerSize = Marshal.SizeOf<DnsRecordHeaderNative>();
            var pointer = Marshal.AllocHGlobal(headerSize + sizeof(uint) + rdata.Length);
            Marshal.StructureToPtr(
                new DnsRecordHeaderNative
                {
                    Name = namePointer,
                    Type = type,
                    DataLength = checked((ushort)(sizeof(uint) + rdata.Length)),
                    Ttl = ttl,
                },
                pointer,
                false);
            Marshal.WriteInt32(IntPtr.Add(pointer, headerSize), rdata.Length);
            Marshal.Copy(rdata, 0, IntPtr.Add(pointer, headerSize + sizeof(uint)), rdata.Length);
            return new NativeRecord(pointer, namePointer);
        }

        public void Dispose()
        {
            Marshal.FreeHGlobal(Pointer);
            Marshal.FreeHGlobal(_name);
        }
    }
}
