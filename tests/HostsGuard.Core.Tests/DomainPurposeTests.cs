using FluentAssertions;
using HostsGuard.Core;
using Xunit;

namespace HostsGuard.Core.Tests;

/// <summary>NET-078: curated domain-purpose annotations, longest-suffix match.</summary>
public sealed class DomainPurposeTests
{
    [Theory]
    [InlineData("telemetry.microsoft.com", "Microsoft telemetry")]
    [InlineData("www.google-analytics.com", "Google Analytics")]
    [InlineData("stats.g.doubleclick.net", "Google Ads")]
    [InlineData("e12345.dscx.akamaiedge.net", "Akamai CDN")]
    [InlineData("d111.cloudfront.net", "Amazon CloudFront CDN")]
    [InlineData("r1---sn-abc.googlevideo.com", "YouTube video")]
    public void Known_domains_get_a_purpose(string domain, string expected)
        => DomainPurpose.Lookup(domain).Should().Be(expected);

    [Theory]
    [InlineData("example.com")]
    [InlineData("")]
    [InlineData(null)]
    [InlineData("microsoft.com")]  // bare — not a specific telemetry/update suffix
    public void Unknown_domains_return_blank(string? domain)
        => DomainPurpose.Lookup(domain).Should().BeEmpty();

    [Fact]
    public void Longest_suffix_wins()
    {
        // "watson.telemetry.microsoft.com" is more specific than "telemetry.microsoft.com".
        DomainPurpose.Lookup("watson.telemetry.microsoft.com").Should().Be("Microsoft error reporting");
    }
}
