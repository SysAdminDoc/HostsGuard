using FluentAssertions;
using HostsGuard.Core;
using HostsGuard.Diagnostics;
using Xunit;

namespace HostsGuard.Diagnostics.Tests;

/// <summary>
/// The portable-policy JSON Schema is generated from the model (drift-proof) and
/// gates hand-authored automation before it is applied. Every exported v1 policy
/// must validate; type errors must report precise JSON Pointer paths.
/// </summary>
public class PortablePolicySchemaTests
{
    [Fact]
    public void A_default_exported_policy_validates()
    {
        var json = new PortablePolicy().ToJson();
        PortablePolicySchema.Validate(json).Should().BeEmpty();
    }

    [Fact]
    public void A_populated_exported_policy_validates()
    {
        var policy = new PortablePolicy
        {
            Domains =
            {
                new PolicyDomain { Domain = "ads.example.com", Status = "blocked", Source = "list:test" },
            },
            AllowlistSubs = { "https://good.example/allow.txt" },
            Settings = { ["theme"] = "dark" },
        };
        policy.Consent = new PolicyConsent();

        PortablePolicySchema.Validate(policy.ToJson()).Should().BeEmpty();
    }

    [Fact]
    public void Invalid_json_reports_a_root_error()
    {
        var errors = PortablePolicySchema.Validate("{ not json");
        errors.Should().ContainSingle().Which.Pointer.Should().Be("");
    }

    [Fact]
    public void A_wrong_scalar_type_reports_a_json_pointer()
    {
        // Version must be an integer; a string value must fail with a located error.
        var errors = PortablePolicySchema.Validate("""{ "Version": "one" }""");
        errors.Should().NotBeEmpty();
        errors.Should().Contain(e => e.Pointer.Contains("Version", System.StringComparison.Ordinal));
    }

    [Fact]
    public void A_wrong_array_element_type_reports_a_located_error()
    {
        // Domains must be objects; a bare string element must fail with a path
        // pointing into the array.
        var errors = PortablePolicySchema.Validate("""{ "Version": 1, "Domains": [ "not-an-object" ] }""");
        errors.Should().NotBeEmpty();
        errors.Should().Contain(e => e.Pointer.Contains("Domains", System.StringComparison.Ordinal));
    }

    [Fact]
    public void The_published_schema_is_non_empty_json()
    {
        var schema = PortablePolicySchema.SchemaJson();
        schema.Should().Contain("\"type\"");
        schema.Should().NotContain("\"required\""); // presence is intentionally lenient
    }
}
