using FluentAssertions;
using HostsGuard.Core;
using Xunit;

namespace HostsGuard.Core.Tests;

public class DnsEventNormalizerTests
{
    [Theory]
    [InlineData("Ads.Example.COM.", true, "ads.example.com")]
    [InlineData("tracker.net", true, "tracker.net")]
    [InlineData("  cdn.site.org  ", true, "cdn.site.org")]
    public void Accepts_and_cleans(string raw, bool ok, string expected)
    {
        DnsEventNormalizer.TryNormalize(raw, out var domain).Should().Be(ok);
        domain.Should().Be(expected);
    }

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    [InlineData("localhost")]   // no dot + ignored
    [InlineData("wpad")]        // ignored
    [InlineData("singlelabel")] // no dot
    public void Rejects(string? raw)
    {
        DnsEventNormalizer.TryNormalize(raw, out var domain).Should().BeFalse();
        domain.Should().BeEmpty();
    }
}
