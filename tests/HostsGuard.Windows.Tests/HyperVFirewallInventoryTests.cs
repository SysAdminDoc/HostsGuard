using FluentAssertions;

namespace HostsGuard.Windows.Tests;

public sealed class HyperVFirewallInventoryTests
{
    private static readonly DateTime CheckedAt = new(2026, 7, 14, 16, 30, 0, DateTimeKind.Utc);

    [Fact]
    public void Parser_preserves_creator_policy_and_profile_merge_evidence()
    {
        const string output = """
            unrelated diagnostic line
            HG_HYPERV_JSON:{"available":true,"errorCode":"","workloads":[{"creatorId":"{40E0AC32-46A5-438A-A0B2-2B479E8F2E90}","displayName":"WSL\u202e","settingPresent":true,"enabled":true,"defaultInboundAction":"Block","defaultOutboundAction":"Allow","allowHostPolicyMerge":true,"loopbackEnabled":false,"profiles":[{"name":"Public","enabled":true,"defaultInboundAction":"Block","defaultOutboundAction":"Allow","allowLocalFirewallRules":false},{"name":"Domain","enabled":true,"defaultInboundAction":"Block","defaultOutboundAction":"Allow","allowLocalFirewallRules":true}]}]}
            """;

        var snapshot = PowerShellHyperVFirewallInventory.ParseOutput(output, CheckedAt);

        snapshot.Available.Should().BeTrue();
        snapshot.ErrorCode.Should().BeEmpty();
        snapshot.CheckedAtUtc.Should().Be(CheckedAt);
        var workload = snapshot.Workloads.Should().ContainSingle().Subject;
        workload.CreatorId.Should().Be("{40E0AC32-46A5-438A-A0B2-2B479E8F2E90}");
        workload.DisplayName.Should().Be("WSL", "bidi format characters must not reach diagnostics UI");
        workload.SettingPresent.Should().BeTrue();
        workload.Enabled.Should().BeTrue();
        workload.DefaultInboundAction.Should().Be("Block");
        workload.DefaultOutboundAction.Should().Be("Allow");
        workload.AllowHostPolicyMerge.Should().BeTrue();
        workload.LoopbackEnabled.Should().BeFalse();
        workload.Profiles.Select(profile => profile.Name).Should().Equal("Domain", "Public");
        workload.Profiles[0].AllowLocalFirewallRules.Should().BeTrue();
    }

    [Theory]
    [InlineData("noise", "invalid_query_output")]
    [InlineData("HG_HYPERV_JSON:{not-json}", "invalid_query_output")]
    [InlineData("HG_HYPERV_JSON:{\"available\":false,\"errorCode\":\"cmdlet_unavailable\",\"workloads\":[]}", "cmdlet_unavailable")]
    public void Parser_returns_bounded_unavailable_state_for_unsupported_or_invalid_output(
        string output,
        string errorCode)
    {
        var snapshot = PowerShellHyperVFirewallInventory.ParseOutput(output, CheckedAt);

        snapshot.Available.Should().BeFalse();
        snapshot.ErrorCode.Should().Be(errorCode);
        snapshot.Workloads.Should().BeEmpty();
    }

    [Fact]
    public async Task Timeout_is_reported_without_throwing()
    {
        var inventory = new PowerShellHyperVFirewallInventory(
            _ => Task.FromResult(new HyperVCommandResult(-1, string.Empty, string.Empty, true)),
            () => CheckedAt);

        var snapshot = await inventory.SnapshotAsync();

        snapshot.Available.Should().BeFalse();
        snapshot.ErrorCode.Should().Be("powershell_query_timeout");
    }

    [Fact]
    public async Task Live_query_is_read_only_and_returns_a_typed_snapshot()
    {
        var snapshot = await new PowerShellHyperVFirewallInventory().SnapshotAsync();

        snapshot.CheckedAtUtc.Kind.Should().Be(DateTimeKind.Utc);
        if (snapshot.Available)
        {
            snapshot.ErrorCode.Should().BeEmpty();
            snapshot.Workloads.Should().OnlyContain(workload =>
                workload.CreatorId.Length > 0 && workload.CreatorId.Length <= 128 &&
                workload.Profiles.All(profile => profile.Name.Length > 0 && profile.Name.Length <= 32));
        }
        else
        {
            snapshot.ErrorCode.Should().BeOneOf(
                "cmdlet_unavailable",
                "powershell_unavailable",
                "powershell_query_failed",
                "powershell_query_timeout",
                "invalid_query_output");
            snapshot.Workloads.Should().BeEmpty();
        }
    }
}
