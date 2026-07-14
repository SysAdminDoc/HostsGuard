using System.Text.Json;
using FluentAssertions;
using HostsGuard.Core;
using Xunit;

namespace HostsGuard.Core.Tests;

public sealed class PortablePolicyValidationTests
{
    public static TheoryData<string> AmbiguousDocuments => new()
    {
        """{ "Version": 1, "Version": 1 }""",
        """{ "Version": 1, "version": 1 }""",
        """{ "Version": 1, "Unexpected": true }""",
        """{ "Version": 1, "Lock": { "Enabled": false, "Unexpected": true } }""",
        """{ "Version": 1, "Domains": [ { "Domain": "Example.com" }, { "Domain": "example.com" } ] }""",
        """{ "Version": 1, "FirewallRules": [ { "Name": "HG_Test" }, { "Name": "hg_test" } ] }""",
        """{ "Version": 1, "Profiles": [ { "Name": "Home" }, { "Name": "home" } ] }""",
        """{ "Version": 1, "Profiles": [ { "Name": "Home", "Rules": [ { "Domain": "Example.com" }, { "Domain": "example.com" } ] } ] }""",
        """{ "Version": 1, "BlocklistSubs": [ { "Name": "Primary" }, { "Name": "primary" } ] }""",
    };

    [Theory]
    [MemberData(nameof(AmbiguousDocuments))]
    public void Ambiguous_or_unknown_json_is_rejected(string json)
    {
        var act = () => PortablePolicy.FromJson(json);

        act.Should().Throw<JsonException>();
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(0)]
    [InlineData(2)]
    public void Unsupported_or_nonpositive_versions_are_rejected(int version)
    {
        var act = () => PortablePolicy.FromJson($"{{ \"Version\": {version} }}");

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*version*unsupported*");
    }

    [Fact]
    public void Existing_v1_shape_remains_deterministic()
    {
        var parsed = PortablePolicy.FromJson("""
            {
              "Version": 1,
              "Domains": [ { "Domain": "ads.example", "Status": "blocked" } ],
              "Lock": { "Enabled": true }
            }
            """);

        var reparsed = PortablePolicy.FromJson(parsed.ToJson());
        reparsed.Version.Should().Be(1);
        reparsed.Domains.Should().ContainSingle(row => row.Domain == "ads.example");
        reparsed.Lock.Enabled.Should().BeTrue();
    }
}
