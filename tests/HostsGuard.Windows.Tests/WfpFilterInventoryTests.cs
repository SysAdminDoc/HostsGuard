using FluentAssertions;

namespace HostsGuard.Windows.Tests;

public sealed class WfpFilterInventoryTests
{
    [Theory]
    [InlineData(0x00000001u, "persistent")]
    [InlineData(0x00000002u, "boot-time")]
    [InlineData(0x00000003u, "persistent+boot-time")]
    [InlineData(0u, "dynamic")]
    public void Lifetime_flags_have_stable_contract_names(uint flags, string expected) =>
        WindowsWfpFilterInventory.LifetimeName(flags).Should().Be(expected);

    [Theory]
    [InlineData(0x00001001u, "block")]
    [InlineData(0x00001002u, "permit")]
    [InlineData(0x00005003u, "callout-terminating")]
    [InlineData(0x00006004u, "callout-inspection")]
    [InlineData(0x00004005u, "callout-unknown")]
    [InlineData(0x00002006u, "continue")]
    [InlineData(0x00000007u, "none")]
    [InlineData(0x00000008u, "none-no-match")]
    public void Action_constants_have_stable_contract_names(uint action, string expected) =>
        WindowsWfpFilterInventory.ActionName(action).Should().Be(expected);

    [Fact]
    public void Live_probe_returns_typed_read_only_availability()
    {
        var snapshot = new WindowsWfpFilterInventory().Snapshot();

        snapshot.CheckedAtUtc.Kind.Should().Be(DateTimeKind.Utc);
        if (snapshot.Available)
        {
            snapshot.ErrorCode.Should().BeEmpty();
            snapshot.Filters.Should().OnlyContain(filter =>
                filter.FilterKey != Guid.Empty &&
                filter.LayerKey != Guid.Empty &&
                filter.SubLayerKey != Guid.Empty &&
                (filter.Lifetime == "persistent" || filter.Lifetime == "boot-time" ||
                 filter.Lifetime == "persistent+boot-time") &&
                filter.Action.Length != 0);
        }
        else
        {
            snapshot.ErrorCode.Should().MatchRegex("^(wfp_error_0x[0-9a-f]{8}|wfp_api_unavailable|filter_limit_exceeded)$");
            snapshot.Filters.Should().BeEmpty();
        }
    }
}
