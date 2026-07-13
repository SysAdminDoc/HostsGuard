using FluentAssertions;
using HostsGuard.App.Services;
using HostsGuard.App.ViewModels;
using HostsGuard.Contracts;
using HostsGuard.Ipc;
using Xunit;

namespace HostsGuard.App.Tests;

public sealed class NetworkProfileSurfaceTests
{
    private static ToolsViewModel CreateVm() => new(
        new HostsServiceClient(NamedPipeChannel.Create(SessionToken.Generate(), "hg-profile-surface-none")),
        new FakeConfirm(true));

    [Fact]
    public void Match_rule_preserves_each_additive_criterion_and_optional_vpn_state()
    {
        var source = new NetworkProfileEntry
        {
            Profile = "Work",
            Label = "Office",
            GatewayMac = "AA:BB:CC:DD:EE:FF",
            Ssid = "Office Wi-Fi",
            InterfaceName = "Wi-Fi",
            DnsSuffix = "corp.example",
            VpnPresent = true,
        };

        var row = NetworkProfileRuleViewModel.From(source);
        var roundTrip = row.ToEntry("Work");

        roundTrip.Should().BeEquivalentTo(source);
        row.CriteriaText.Should().Contain("AA:BB:CC:DD:EE:FF")
            .And.Contain("Office Wi-Fi")
            .And.Contain("corp.example")
            .And.Contain("VPN");
    }

    [Fact]
    public void Match_rule_commands_require_a_profile_criterion_or_selected_rule()
    {
        var vm = CreateVm();

        vm.SaveNetworkProfileRuleCommand.CanExecute(null).Should().BeFalse();
        vm.DeleteNetworkProfileRuleCommand.CanExecute(null).Should().BeFalse();

        vm.SelectedProfile = "Work";
        vm.NetworkRuleSsid = "Office Wi-Fi";

        vm.SaveNetworkProfileRuleCommand.CanExecute(null).Should().BeTrue();

        vm.SelectedNetworkProfileRule = NetworkProfileRuleViewModel.From(new NetworkProfileEntry
        {
            Profile = "Work",
            Label = "Office",
            Ssid = "Office Wi-Fi",
        });

        vm.DeleteNetworkProfileRuleCommand.CanExecute(null).Should().BeTrue();
    }

    [Fact]
    public void Captive_portal_recovery_starts_read_only_and_unavailable_until_a_suspected_probe()
    {
        var vm = CreateVm();

        vm.CaptivePortalStatusText.Should().Contain("not checked");
        vm.CaptivePortalPauseAvailable.Should().BeFalse();
        vm.PauseForCaptivePortalCommand.CanExecute("5").Should().BeFalse();
    }
}
