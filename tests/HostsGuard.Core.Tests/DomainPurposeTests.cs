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

    [Theory]
    [InlineData("9.113.0.203.in-addr.arpa", "Reverse DNS lookup (PTR)")]
    [InlineData("stun.l.google.com", "STUN server (VoIP/WebRTC NAT traversal)")]
    [InlineData("stun.sipgate.net", "STUN server (VoIP/WebRTC NAT traversal)")]
    [InlineData("avatars.fastly.steamstatic.com", "Steam static content CDN")]
    [InlineData("fa723fc1b171.use14.playlist.live-video.net", "Amazon IVS / Twitch live video")]
    [InlineData("v20.events.data.microsoft.com", "Windows telemetry events")]
    [InlineData("api.anthropic.com", "Anthropic / Claude API")]
    [InlineData("x1.c.lencr.org", "Let's Encrypt certificate infrastructure")]
    [InlineData("hit.api.useinsider.com", "Insider marketing analytics")]
    [InlineData("edgedl.me.gvt1.com", "Google software downloads")]
    [InlineData("urlhaus.abuse.ch", "abuse.ch threat intelligence")]
    public void Promoted_field_knowledge_resolves(string domain, string expected)
        => DomainPurpose.Lookup(domain).Should().Be(expected);

    [Fact]
    public void Specific_wp_entries_beat_the_generic_wp_suffix()
        => DomainPurpose.Lookup("stats.wp.com").Should().Be("WordPress.com analytics");
}
