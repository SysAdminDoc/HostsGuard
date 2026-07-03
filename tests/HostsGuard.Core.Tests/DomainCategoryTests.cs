using FluentAssertions;
using HostsGuard.Core;
using Xunit;

namespace HostsGuard.Core.Tests;

public sealed class DomainCategoryTests
{
    [Theory]
    [InlineData("ad.doubleclick.net", "Google Ads")]
    [InlineData("pagead2.googlesyndication.com", "Google Ads")]
    [InlineData("www.googletagmanager.com", "Google Tracking")]
    [InlineData("pixel.facebook.com", "Facebook/Meta Tracking")]
    [InlineData("connect.facebook.net", "Facebook/Meta Tracking")]
    [InlineData("settings-win.data.microsoft.com", "Microsoft Telemetry")]
    [InlineData("v20.events.data.microsoft.com", "Microsoft Telemetry")]
    [InlineData("bat.bing.com", "Microsoft Telemetry")]
    [InlineData("c.amazon-adsystem.com", "Amazon Ads")]
    [InlineData("secure.adnxs.com", "Major Ad Networks")]
    [InlineData("id.rlcdn.com", "Major Ad Networks")]
    [InlineData("b.scorecardresearch.com", "Analytics")]
    [InlineData("o33249.ingest.us.sentry.io", "Analytics")]
    [InlineData("mc.yandex.ru", "Yandex Analytics")]
    [InlineData("unknown.example.com", "")]
    [InlineData("", "")]
    public void Lookup_suffix_matches_curated_categories(string domain, string expected)
        => DomainCategories.Lookup(domain).Should().Be(expected);
}
