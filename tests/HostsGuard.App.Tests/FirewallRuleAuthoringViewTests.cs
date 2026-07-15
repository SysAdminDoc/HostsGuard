using FluentAssertions;
using HostsGuard.App.Services;
using HostsGuard.App.ViewModels;
using HostsGuard.Core;
using HostsGuard.Ipc;
using Xunit;

namespace HostsGuard.App.Tests;

public sealed class FirewallRuleAuthoringViewTests
{
    private static FwRulesViewModel CreateVm() => new(
        new HostsServiceClient(NamedPipeChannel.Create(SessionToken.Generate(), "hg-rule-authoring-none")),
        new FakeConfirm(true));

    [Theory]
    [InlineData("", "TCP", true, "Any")]
    [InlineData("*", "UDP", true, "Any")]
    [InlineData("443,80,80-82", "TCP", true, "80-82,443")]
    [InlineData("8000 - 8010", "UDP", true, "8000-8010")]
    [InlineData("0", "TCP", false, "")]
    [InlineData("9000-8000", "TCP", false, "")]
    [InlineData("443", "Any", false, "")]
    [InlineData("53", "ICMPv4", false, "")]
    public void Port_validation_matches_shared_authoring_normalization(
        string input, string protocol, bool expected, string normalized)
    {
        FwRulesViewModel.TryNormalizePorts(input, protocol, out var actual, out _)
            .Should().Be(expected);
        actual.Should().Be(normalized);
    }

    [Fact]
    public void Ports_summary_keeps_local_and_remote_constraints()
    {
        var row = new FwRuleViewModel
        {
            LocalPorts = "8000-8010",
            RemotePortsForDisplay = "443",
        };

        row.Ports.Should().Be("local 8000-8010 | remote 443");
    }

    [Fact]
    public void Managed_rule_loads_full_scope_into_edit_form()
    {
        var vm = CreateVm();
        vm.EditRule(new FwRuleViewModel
        {
            Name = "HG_Web_service",
            Source = "hostsguard",
            Direction = "In",
            Action = "Allow",
            Protocol = "TCP",
            RemoteAddr = "Any",
            LocalPorts = "8080-8082",
            RemotePortsForDisplay = "443",
            Interfaces = "Ethernet,Wi-Fi",
            Program = @"C:\apps\web.exe",
            Description = "Allow the local dashboard",
            Enabled = false,
        });

        vm.IsEditingRule.Should().BeTrue();
        vm.NewRuleName.Should().Be("Web_service");
        vm.NewRuleLocalPorts.Should().Be("8080-8082");
        vm.NewRuleRemotePorts.Should().Be("443");
        vm.NewRuleInterfaces.Should().Be("Ethernet, Wi-Fi");
        vm.NewRuleEnabled.Should().BeFalse();
        vm.NewRuleDescription.Should().Be("Allow the local dashboard");
        vm.CreateRulePreview.Should().Contain("local ports 8080-8082")
            .And.Contain("remote ports 443")
            .And.Contain("interfaces Ethernet,Wi-Fi")
            .And.Contain(@"program C:\apps\web.exe")
            .And.Contain("description Allow the local dashboard");
    }

    [Fact]
    public void Invalid_port_scope_disables_create_with_clear_feedback()
    {
        var vm = CreateVm();
        vm.NewRuleName = "Web";
        vm.NewRuleProtocol = "Any";
        vm.NewRuleLocalPorts = "443";

        vm.CreateRuleCommand.CanExecute(null).Should().BeFalse();
        vm.CreateRuleHelpText.Should().Contain("select TCP or UDP");
    }

    [Fact]
    public void Foreign_rule_remains_read_only()
    {
        var vm = CreateVm();

        vm.EditRule(new FwRuleViewModel { Name = "Windows rule", Source = "system" });

        vm.IsEditingRule.Should().BeFalse();
        vm.StatusText.Should().Contain("Only HostsGuard-managed");
    }

    [Fact]
    public void Description_visibility_and_length_validation_are_explicit()
    {
        new FwRuleViewModel { Description = "Windows-authored intent" }.HasDescription.Should().BeTrue();
        new FwRuleViewModel().HasDescription.Should().BeFalse();

        var vm = CreateVm();
        vm.NewRuleName = "Documented";
        vm.NewRuleDescription = new string('x', FirewallRuleAuthoring.MaxDescriptionLength + 1);

        vm.CreateRuleCommand.CanExecute(null).Should().BeFalse();
        vm.CreateRuleHelpText.Should().Contain(FirewallRuleAuthoring.MaxDescriptionLength.ToString());
    }
}
