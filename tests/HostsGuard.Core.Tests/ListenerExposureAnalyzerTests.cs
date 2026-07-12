using FluentAssertions;
using HostsGuard.Core;
using Xunit;

namespace HostsGuard.Core.Tests;

public sealed class ListenerExposureAnalyzerTests
{
    private static readonly InboundFirewallProfile PublicBlock = new("Public", true, true);
    private static readonly InboundFirewallProfile PublicAllow = new("Public", true, false);

    [Fact]
    public void Includes_tcp_udp_ipv4_ipv6_and_sorts_deterministically()
    {
        var input = new[]
        {
            Endpoint("UDP", "::", 5353, 3),
            Endpoint("TCP", "::1", 443, 2),
            Endpoint("UDP", "0.0.0.0", 53, 1),
            Endpoint("TCP", "0.0.0.0", 80, 4),
            Endpoint("ICMP", "0.0.0.0", 1, 5),
            Endpoint("TCP", "0.0.0.0", 0, 6),
        };

        var rows = Analyze(input);

        rows.Select(row => (row.Endpoint.Protocol, row.Endpoint.LocalAddress, row.Endpoint.LocalPort))
            .Should().Equal(
                ("TCP", "0.0.0.0", 80),
                ("TCP", "::1", 443),
                ("UDP", "0.0.0.0", 53),
                ("UDP", "::", 5353));
    }

    [Fact]
    public void Deduplicates_identical_normalized_tuples_but_preserves_distinct_pids()
    {
        var rows = Analyze([
            Endpoint("tcp", "0.0.0.0", 80, 1),
            Endpoint("TCP", "0.0.0.0", 80, 1),
            Endpoint("TCP", "0.0.0.0", 80, 2),
        ]);

        rows.Should().HaveCount(2);
        rows.Select(row => row.Endpoint.Pid).Should().Equal(1, 2);
    }

    [Theory]
    [InlineData("0.0.0.0", ListenerBindScope.Any, true)]
    [InlineData("::", ListenerBindScope.Any, true)]
    [InlineData("127.0.0.1", ListenerBindScope.Loopback, false)]
    [InlineData("::1", ListenerBindScope.Loopback, false)]
    [InlineData("169.254.1.2", ListenerBindScope.LinkLocal, false)]
    [InlineData("fe80::1%12", ListenerBindScope.LinkLocal, false)]
    [InlineData("10.0.0.5", ListenerBindScope.Private, false)]
    [InlineData("fc00::1", ListenerBindScope.Private, false)]
    [InlineData("203.0.113.5", ListenerBindScope.Private, false)]
    [InlineData("2001:db8::1", ListenerBindScope.Private, false)]
    [InlineData("::ffff:10.0.0.1", ListenerBindScope.Private, false)]
    [InlineData("8.8.8.8", ListenerBindScope.Public, true)]
    [InlineData("2606:4700:4700::1111", ListenerBindScope.Public, true)]
    public void Classifies_bind_scope_without_claiming_reachability(
        string address, ListenerBindScope expected, bool publicBound)
    {
        var row = Analyze([Endpoint("TCP", address, 443, 1)]).Single();

        row.BindScope.Should().Be(expected);
        row.PublicBound.Should().Be(publicBound);
        row.Finding.Should().NotContain("reachable");
    }

    [Fact]
    public void Public_bound_unruled_is_flagged_even_when_default_inbound_blocks()
    {
        var row = Analyze([Endpoint("TCP", "0.0.0.0", 8080, 42)]).Single();

        row.NeedsAttention.Should().BeTrue();
        row.Finding.Should().Be("public_bound_unruled");
        row.Profiles.Single().Action.Should().Be(ListenerInboundAction.DefaultBlock);
    }

    [Fact]
    public void Loopback_unruled_is_not_flagged()
    {
        var row = Analyze([Endpoint("TCP", "127.0.0.1", 8080, 42)]).Single();

        row.NeedsAttention.Should().BeFalse();
        row.Finding.Should().Be("local_bind");
    }

    [Fact]
    public void Matches_program_service_and_package_identity_case_insensitively()
    {
        var owner = new ListenerOwnerAttribution(42, @"c:\apps\server.exe", "WebSvc", "Web Service", "Contoso.Web_123", "S-1-15-2-42");
        var rules = new[]
        {
            Rule("program", program: @"C:\Apps\SERVER.exe"),
            Rule("service", service: "websvc"),
            Rule("family", family: "contoso.web_123"),
            Rule("sid", sid: "s-1-15-2-42"),
            Rule("other", program: @"C:\Apps\other.exe"),
        };

        var row = Analyze([Endpoint("TCP", "0.0.0.0", 8080, 42)], [owner], rules).Single();

        row.Owner.Should().Be(owner);
        row.Profiles.Single().RuleNames.Should().BeEquivalentTo("program", "service", "family", "sid");
        row.Profiles.Single().Action.Should().Be(ListenerInboundAction.AllowRule);
    }

    [Fact]
    public void Protocol_and_local_port_range_limit_coverage()
    {
        var rules = new[]
        {
            Rule("udp-range", protocol: "UDP", localPorts: "8000-8100"),
            Rule("wrong-port", localPorts: "443"),
            Rule("wrong-protocol", protocol: "TCP", localPorts: "53"),
        };

        var udp = Analyze([Endpoint("UDP", "::", 8080, 1)], rules: rules).Single();

        udp.Profiles.Single().RuleNames.Should().Equal("udp-range");
    }

    [Fact]
    public void Blanket_block_wins_blanket_allow()
    {
        var row = Analyze([Endpoint("TCP", "0.0.0.0", 443, 1)], rules:
            [Rule("allow"), Rule("block", action: "Block")]).Single();

        row.Profiles.Single().Action.Should().Be(ListenerInboundAction.BlockRule);
        row.Profiles.Single().RuleNames.Should().Equal("block");
        row.NeedsAttention.Should().BeFalse();
    }

    [Fact]
    public void Rule_for_inactive_profile_is_reported_as_profile_mismatch()
    {
        var row = Analyze([Endpoint("TCP", "0.0.0.0", 443, 1)], rules:
            [Rule("private-only", profiles: "Private")]).Single();

        row.Profiles.Single().Action.Should().Be(ListenerInboundAction.ProfileMismatch);
        row.Finding.Should().Be("public_bound_profile_mismatch");
        row.NeedsAttention.Should().BeTrue();
    }

    [Fact]
    public void Profile_mismatch_preserves_default_allow_for_risk_classification()
    {
        var row = Analyze([Endpoint("TCP", "0.0.0.0", 443, 1)], profiles: [PublicAllow], rules:
            [Rule("private-only", profiles: "Private")]).Single();

        row.Profiles.Single().Action.Should().Be(ListenerInboundAction.ProfileMismatch);
        row.Profiles.Single().DefaultInboundBlock.Should().BeFalse();
    }

    [Fact]
    public void Exact_package_family_is_sufficient_when_owner_sid_is_unavailable()
    {
        var owner = new ListenerOwnerAttribution(42, PackageFamilyName: "Contoso.Web_123");
        var rule = Rule("package", family: "Contoso.Web_123", sid: "S-1-15-2-42");

        var row = Analyze([Endpoint("TCP", "0.0.0.0", 443, 42)], [owner], [rule]).Single();

        row.Profiles.Single().Action.Should().Be(ListenerInboundAction.AllowRule);
    }

    [Fact]
    public void Restricted_allow_under_default_block_is_not_blanket_allow()
    {
        var row = Analyze([Endpoint("TCP", "0.0.0.0", 443, 1)], rules:
            [Rule("lan-only", remote: "LocalSubnet")]).Single();

        row.Profiles.Single().Action.Should().Be(ListenerInboundAction.RestrictedAllow);
        row.Profiles.Single().RuleNames.Should().Equal("lan-only");
        row.Finding.Should().NotBe("public_bound_profile_mismatch");
        row.NeedsAttention.Should().BeTrue("some remote sources are locally allowed");
    }

    [Fact]
    public void Restricted_block_under_default_allow_is_not_blanket_block()
    {
        var row = Analyze([Endpoint("TCP", "0.0.0.0", 443, 1)], profiles: [PublicAllow], rules:
            [Rule("one-source", action: "Block", remote: "203.0.113.7")]).Single();

        row.Profiles.Single().Action.Should().Be(ListenerInboundAction.RestrictedBlock);
        row.NeedsAttention.Should().BeTrue("other remote sources follow the allow default");
    }

    [Fact]
    public void Interface_scoped_rule_is_never_treated_as_blanket_coverage()
    {
        var row = Analyze([Endpoint("TCP", "192.168.1.5", 443, 1)], rules:
            [Rule("wifi", interfaces: "Wi-Fi")]).Single();

        row.Profiles.Single().Action.Should().Be(ListenerInboundAction.RestrictedAllow);
    }

    [Fact]
    public void Rule_bound_to_different_local_address_does_not_cover_listener()
    {
        var row = Analyze([Endpoint("TCP", "8.8.8.8", 443, 1)], rules:
            [Rule("other-address", localAddresses: "8.8.4.4")]).Single();

        row.Profiles.Single().Action.Should().Be(ListenerInboundAction.DefaultBlock);
        row.Finding.Should().Be("public_bound_unruled");
    }

    [Fact]
    public void Matching_local_cidr_covers_specific_bind_but_scopes_wildcard_bind()
    {
        var rule = Rule("local-cidr", localAddresses: "8.8.8.0/24");

        Analyze([Endpoint("TCP", "8.8.8.8", 443, 1)], rules: [rule]).Single()
            .Profiles.Single().Action.Should().Be(ListenerInboundAction.AllowRule);
        Analyze([Endpoint("TCP", "0.0.0.0", 443, 1)], rules: [rule]).Single()
            .Profiles.Single().Action.Should().Be(ListenerInboundAction.RestrictedAllow);
    }

    [Fact]
    public void Firewall_disabled_is_explicit_for_each_current_profile()
    {
        var profiles = new[]
        {
            new InboundFirewallProfile("Private", false, true),
            new InboundFirewallProfile("Public", true, true),
        };

        var row = Analyze([Endpoint("UDP", "::", 5353, 1)], profiles: profiles).Single();

        row.Profiles.Select(profile => profile.Profile).Should().Equal("Private", "Public");
        row.Profiles[0].Action.Should().Be(ListenerInboundAction.FirewallDisabled);
        row.NeedsAttention.Should().BeTrue();
    }

    private static ListenerEndpoint Endpoint(string protocol, string address, int port, int pid) =>
        new(protocol, address, port, pid, $"p{pid}");

    private static FwRule Rule(
        string name,
        string action = "Allow",
        string protocol = "TCP",
        string remote = "Any",
        string program = "",
        string service = "",
        string localPorts = "Any",
        string interfaces = "Any",
        string family = "",
        string sid = "",
        string profiles = "Public",
        string localAddresses = "Any") =>
        new(name, "In", action, true, remote, protocol, program, "system",
            ServiceName: service, LocalPorts: localPorts, Interfaces: interfaces,
            PackageFamilyName: family, PackageSid: sid, Profiles: profiles,
            LocalAddresses: localAddresses);

    private static IReadOnlyList<ListenerExposureAssessment> Analyze(
        IEnumerable<ListenerEndpoint> endpoints,
        IEnumerable<ListenerOwnerAttribution>? owners = null,
        IEnumerable<FwRule>? rules = null,
        IEnumerable<InboundFirewallProfile>? profiles = null) =>
        ListenerExposureAnalyzer.Analyze(endpoints, owners ?? [], rules ?? [], profiles ?? [PublicBlock]);
}
