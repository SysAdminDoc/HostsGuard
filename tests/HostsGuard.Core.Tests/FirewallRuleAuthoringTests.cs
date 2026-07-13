using FluentAssertions;
using HostsGuard.Core;
using Xunit;

namespace HostsGuard.Core.Tests;

public sealed class FirewallRuleAuthoringTests
{
    [Fact]
    public void Tcp_ports_and_selected_interfaces_normalize_deterministically()
    {
        var ok = FirewallRuleAuthoring.TryNormalize(
            Rule(localPorts: "8000-8010", remotePorts: "443", interfaces: "Wi-Fi,Ethernet,wi-fi"),
            out var normalized,
            out var error,
            ["Ethernet", "Wi-Fi"]);

        ok.Should().BeTrue(error);
        normalized.Protocol.Should().Be("TCP");
        normalized.LocalPorts.Should().Be("8000-8010");
        normalized.RemotePorts.Should().Be("443");
        normalized.Interfaces.Should().Be("Ethernet,Wi-Fi");
    }

    [Theory]
    [InlineData("0")]
    [InlineData("65536")]
    [InlineData("9000-8000")]
    [InlineData("80-")]
    [InlineData("80,,443")]
    [InlineData("abc")]
    public void Invalid_port_specs_fail(string ports)
    {
        FirewallRuleAuthoring.TryNormalize(Rule(localPorts: ports), out _, out var error).Should().BeFalse();
        error.Should().NotBeNullOrWhiteSpace();
    }

    [Theory]
    [InlineData("Any")]
    [InlineData("ICMPv4")]
    [InlineData("ICMPv6")]
    public void Ports_fail_for_incompatible_protocols(string protocol)
    {
        FirewallRuleAuthoring.TryNormalize(Rule(protocol: protocol, remotePorts: "443"), out _, out var error)
            .Should().BeFalse();
        error.Should().Contain("cannot specify ports");
    }

    [Fact]
    public void Port_ranges_are_sorted_merged_and_deduplicated()
    {
        FirewallRuleAuthoring.TryNormalizePorts("443,8001-8010,8000-8002,443", out var normalized, out var error)
            .Should().BeTrue(error);

        normalized.Should().Be("443,8000-8010");
    }

    [Theory]
    [InlineData("Ethernet,,Wi-Fi")]
    [InlineData("Ethernet,Any")]
    [InlineData("Ethernet,*")]
    public void Invalid_interface_lists_fail(string interfaces)
    {
        FirewallRuleAuthoring.TryNormalize(Rule(interfaces: interfaces), out _, out var error).Should().BeFalse();
        error.Should().NotBeNullOrWhiteSpace();
    }

    [Fact]
    public void Unknown_interface_fails_against_live_aliases_and_matching_case_is_canonicalized()
    {
        FirewallRuleAuthoring.TryNormalizeInterfaces("ethernet,Missing", out _, out var error, ["Ethernet", "Wi-Fi"])
            .Should().BeFalse();
        error.Should().Be("interface 'Missing' is not available");

        FirewallRuleAuthoring.TryNormalizeInterfaces("wi-fi,ETHERNET", out var normalized, out error, ["Ethernet", "Wi-Fi"])
            .Should().BeTrue(error);
        normalized.Should().Be("Ethernet,Wi-Fi");
    }

    [Fact]
    public void Ports_and_interfaces_survive_portable_policy_json_round_trip()
    {
        FirewallRuleAuthoring.TryNormalize(
            Rule(localPorts: "8000-8010", remotePorts: "443", interfaces: "Ethernet,Wi-Fi"),
            out var validated,
            out var error).Should().BeTrue(error);
        var policy = new PortablePolicy
        {
            FirewallRules =
            [
                new PolicyFirewallRule
                {
                    Name = validated.Name,
                    Direction = validated.Direction,
                    Action = validated.Action,
                    RemoteAddr = validated.RemoteAddr,
                    Protocol = validated.Protocol,
                    Program = validated.Program,
                    Enabled = validated.Enabled,
                    RemotePorts = validated.RemotePorts,
                    ServiceName = validated.ServiceName,
                    LocalPorts = validated.LocalPorts,
                    Interfaces = validated.Interfaces,
                },
            ],
        };

        var restored = PortablePolicy.FromJson(policy.ToJson()).FirewallRules.Should().ContainSingle().Subject;
        restored.Protocol.Should().Be("TCP");
        restored.LocalPorts.Should().Be("8000-8010");
        restored.RemotePorts.Should().Be("443");
        restored.Interfaces.Should().Be("Ethernet,Wi-Fi");
    }

    private static FwRule Rule(
        string protocol = "TCP",
        string localPorts = "Any",
        string remotePorts = "Any",
        string interfaces = "Any") =>
        new("HG_Custom", "Out", "Allow", true, "Any", protocol, string.Empty, "hostsguard",
            RemotePorts: remotePorts, LocalPorts: localPorts, Interfaces: interfaces);
}
