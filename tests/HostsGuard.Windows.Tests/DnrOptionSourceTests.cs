using FluentAssertions;
using HostsGuard.Windows;

namespace HostsGuard.Windows.Tests;

public sealed class DnrOptionSourceTests
{
    [Fact]
    public async Task Returns_native_option_payload_without_mutation()
    {
        var native = new FakeDhcpDnrNative(new(
            DnrOptionOutcome.Success,
            [0, 4, 0, 1, 1, 0],
            0,
            string.Empty));
        var source = new DhcpDnrOptionSource(native);

        var result = await source.ReadV4Async(
            "adapter-guid",
            TimeSpan.FromSeconds(1),
            CancellationToken.None);

        result.Outcome.Should().Be(DnrOptionOutcome.Success);
        result.Data.Should().Equal(0, 4, 0, 1, 1, 0);
        native.AdapterIds.Should().Equal("adapter-guid");
    }

    [Fact]
    public async Task Times_out_without_accumulating_native_workers()
    {
        using var release = new ManualResetEventSlim();
        var native = new FakeDhcpDnrNative(
            new(DnrOptionOutcome.NoOption, [], 2, "option_not_present"),
            release);
        var source = new DhcpDnrOptionSource(native);

        var first = await source.ReadV4Async(
            "one",
            TimeSpan.FromMilliseconds(20),
            CancellationToken.None);
        var second = await source.ReadV4Async(
            "two",
            TimeSpan.FromMilliseconds(20),
            CancellationToken.None);
        release.Set();

        first.Outcome.Should().Be(DnrOptionOutcome.Timeout);
        second.Outcome.Should().Be(DnrOptionOutcome.Busy);
        native.AdapterIds.Should().Equal("one");
    }

    private sealed class FakeDhcpDnrNative(
        DnrOptionResult result,
        ManualResetEventSlim? release = null) : IDhcpDnrNative
    {
        public List<string> AdapterIds { get; } = [];

        public DnrOptionResult ReadV4(string adapterId)
        {
            AdapterIds.Add(adapterId);
            release?.Wait();
            return result;
        }

        public DnrOptionResult ReadV6(string adapterId) => ReadV4(adapterId);
    }
}
