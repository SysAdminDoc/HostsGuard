using FluentAssertions;
using HostsGuard.Core;
using Xunit;

namespace HostsGuard.Core.Tests;

public sealed class NetworkProfileMatcherTests
{
    private static readonly NetworkProfileIdentity Identity = new(
        "legacy-fingerprint",
        "AA:BB:CC:DD:EE:FF",
        "Office Wi-Fi",
        "Wi-Fi",
        "corp.example",
        VpnPresent: true);

    [Fact]
    public void Every_populated_predicate_must_match()
    {
        var exact = new NetworkProfileMatchRule(
            "Work", "Office", GatewayMac: "aa-bb-cc-dd-ee-ff", Ssid: "office wi-fi",
            InterfaceName: "wi-fi", DnsSuffix: "CORP.EXAMPLE.", VpnPresent: true);
        var wrongSuffix = exact with { Profile = "Wrong", DnsSuffix = "guest.example" };

        NetworkProfileMatcher.Matches(Identity, exact).Should().BeTrue();
        NetworkProfileMatcher.Matches(Identity, wrongSuffix).Should().BeFalse();
    }

    [Fact]
    public void More_specific_rule_wins_before_signal_precedence()
    {
        var result = NetworkProfileMatcher.Match(Identity, new[]
        {
            new NetworkProfileMatchRule("Gateway", "", GatewayMac: "AA:BB:CC:DD:EE:FF"),
            new NetworkProfileMatchRule("Specific", "", Ssid: "Office Wi-Fi", VpnPresent: true),
        });

        result.Should().NotBeNull();
        result!.Profile.Should().Be("Specific");
    }

    [Fact]
    public void Equal_specificity_uses_documented_signal_precedence()
    {
        var result = NetworkProfileMatcher.Match(Identity, new[]
        {
            new NetworkProfileMatchRule("Vpn", "", VpnPresent: true),
            new NetworkProfileMatchRule("Interface", "", InterfaceName: "Wi-Fi"),
            new NetworkProfileMatchRule("Dns", "", DnsSuffix: "corp.example"),
            new NetworkProfileMatchRule("Ssid", "", Ssid: "Office Wi-Fi"),
            new NetworkProfileMatchRule("Gateway", "", GatewayMac: "AABBCCDDEEFF"),
        });

        result.Should().NotBeNull();
        result!.Profile.Should().Be("Gateway");
    }

    [Fact]
    public void Final_tie_break_is_stable_regardless_of_input_order()
    {
        var first = new NetworkProfileMatchRule("Alpha", "Z", Ssid: "Office Wi-Fi");
        var second = new NetworkProfileMatchRule("Beta", "A", Ssid: "Office Wi-Fi");

        NetworkProfileMatcher.Match(Identity, new[] { second, first })!.Profile.Should().Be("Alpha");
        NetworkProfileMatcher.Match(Identity, new[] { first, second })!.Profile.Should().Be("Alpha");
    }

    [Fact]
    public void Same_ssid_with_a_new_gateway_is_detected_deterministically()
    {
        var first = new NetworkProfileMatchRule(
            "Work", "Primary", GatewayMac: "11:22:33:44:55:66", Ssid: "Office Wi-Fi");
        var second = new NetworkProfileMatchRule(
            "Guest", "Fallback", GatewayMac: "22:33:44:55:66:77", Ssid: "Office Wi-Fi");

        NetworkProfileMatcher.FindSameSsidGatewayDrift(Identity, new[] { second, first })
            .Should().Be(second);
        NetworkProfileMatcher.FindSameSsidGatewayDrift(Identity, new[] { first, second })
            .Should().Be(second);
    }

    [Fact]
    public void Any_known_gateway_for_the_same_ssid_suppresses_drift()
    {
        var rules = new[]
        {
            new NetworkProfileMatchRule("Old", "", GatewayMac: "11:22:33:44:55:66", Ssid: "Office Wi-Fi"),
            new NetworkProfileMatchRule("Current", "", GatewayMac: "AA-BB-CC-DD-EE-FF", Ssid: "Office Wi-Fi"),
        };

        NetworkProfileMatcher.FindSameSsidGatewayDrift(Identity, rules).Should().BeNull();
    }

    [Fact]
    public void Same_gateway_with_other_predicate_mismatch_is_not_gateway_drift()
    {
        var rule = new NetworkProfileMatchRule(
            "Work", "", GatewayMac: "AA:BB:CC:DD:EE:FF", Ssid: "Office Wi-Fi",
            DnsSuffix: "different.example");

        NetworkProfileMatcher.Match(Identity, new[] { rule }).Should().BeNull();
        NetworkProfileMatcher.FindSameSsidGatewayDrift(Identity, new[] { rule }).Should().BeNull();
    }

    [Fact]
    public void Drift_requires_ssid_and_a_comparable_gateway_signal()
    {
        var ssidOnly = new NetworkProfileMatchRule("Work", "", Ssid: "Office Wi-Fi");
        var noSsid = Identity with { Ssid = string.Empty };

        NetworkProfileMatcher.FindSameSsidGatewayDrift(Identity, new[] { ssidOnly }).Should().BeNull();
        NetworkProfileMatcher.FindSameSsidGatewayDrift(noSsid, new[] { ssidOnly }).Should().BeNull();
    }

    [Fact]
    public void Codec_preserves_additive_selectors_and_legacy_fingerprints()
    {
        var rule = new NetworkProfileMatchRule(
            "Work", "Office", GatewayMac: "AA:BB:CC:DD:EE:FF", Ssid: "Office Wi-Fi",
            InterfaceName: "Wi-Fi", DnsSuffix: "corp.example", VpnPresent: false);

        var stored = NetworkProfileSelectorCodec.Encode(rule);
        stored.Should().StartWith("match:v1:");
        NetworkProfileSelectorCodec.Decode(stored, rule.Profile, rule.Label).Should().Be(rule);

        NetworkProfileSelectorCodec.Encode(new("Home", "", Fingerprint: "legacy-gateway"))
            .Should().Be("legacy-gateway");
        NetworkProfileSelectorCodec.Decode("legacy-gateway", "Home", "")
            .Should().Be(new NetworkProfileMatchRule("Home", "", Fingerprint: "legacy-gateway"));
    }

    [Fact]
    public void Portable_policy_accepts_legacy_shape_and_round_trips_new_selectors()
    {
        var legacy = PortablePolicy.FromJson("""
            { "Version": 1, "NetworkProfiles": [
              { "Fingerprint": "old-gateway", "Profile": "Home", "Label": "Home" }
            ] }
            """);
        legacy.NetworkProfiles.Should().ContainSingle(n =>
            n.Fingerprint == "old-gateway" && n.VpnPresent == null && n.Ssid == string.Empty);

        legacy.NetworkProfiles.Add(new PolicyNetworkProfile
        {
            Profile = "Work",
            Label = "Corporate",
            Ssid = "Office Wi-Fi",
            DnsSuffix = "corp.example",
            VpnPresent = true,
        });
        var parsed = PortablePolicy.FromJson(legacy.ToJson());
        parsed.NetworkProfiles.Should().ContainSingle(n =>
            n.Profile == "Work" && n.Ssid == "Office Wi-Fi" && n.DnsSuffix == "corp.example" && n.VpnPresent == true);
    }
}
