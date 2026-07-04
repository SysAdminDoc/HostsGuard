using FluentAssertions;
using HostsGuard.Core;
using Xunit;

namespace HostsGuard.Core.Tests;

public sealed class DomainCategoryTests
{
    [Theory]
    [InlineData("ad.doubleclick.net", "Advertising")]
    [InlineData("pagead2.googlesyndication.com", "Advertising")]
    [InlineData("www.googletagmanager.com", "Tracking & Analytics")]
    [InlineData("pixel.facebook.com", "Tracking & Analytics")]
    [InlineData("connect.facebook.net", "Tracking & Analytics")]
    [InlineData("settings-win.data.microsoft.com", "Telemetry")]
    [InlineData("v20.events.data.microsoft.com", "Telemetry")]
    [InlineData("bat.bing.com", "Telemetry")]
    [InlineData("c.amazon-adsystem.com", "Advertising")]
    [InlineData("secure.adnxs.com", "Advertising")]
    [InlineData("id.rlcdn.com", "Advertising")]
    [InlineData("b.scorecardresearch.com", "Tracking & Analytics")]
    [InlineData("o33249.ingest.us.sentry.io", "Tracking & Analytics")]
    [InlineData("mc.yandex.ru", "Tracking & Analytics")]
    [InlineData("unknown.example.com", "")]
    [InlineData("", "")]
    public void Lookup_suffix_matches_curated_categories(string domain, string expected)
        => DomainCategories.Lookup(domain).Should().Be(expected);

    [Theory]
    [InlineData("Snapchat Tracking", "Tracking & Analytics")]
    [InlineData("LinkedIn CDN", "CDN")]
    [InlineData("Oracle Maxymiser", "Other")]
    [InlineData("Google Ads", "Advertising")]
    [InlineData("Adobe Telemetry", "Telemetry")]
    [InlineData("Mail.ru Ads", "Advertising")]
    [InlineData("Advertising", "Advertising")]
    [InlineData("", "")]
    public void Canonicalize_folds_granular_labels_into_the_taxonomy(string input, string expected)
        => DomainCategories.Canonicalize(input).Should().Be(expected);
}
