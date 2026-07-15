using FluentAssertions;
using HostsGuard.Core;
using Xunit;

namespace HostsGuard.Core.Tests;

public sealed class AllowlistRecommendationScorerTests
{
    [Theory]
    [InlineData(4, true, true)]
    [InlineData(100, false, true)]
    [InlineData(100, true, false)]
    public void Every_safety_signal_is_required(long hits, bool cdn, bool trustedParent)
    {
        AllowlistRecommendationScorer.Score(hits, cdn, trustedParent).Should().Be(0);
    }

    [Theory]
    [InlineData(5, 75)]
    [InlineData(10, 80)]
    [InlineData(25, 85)]
    [InlineData(100, 90)]
    [InlineData(250, 95)]
    [InlineData(1000, 100)]
    public void Frequency_bands_are_stable_and_bounded(long hits, int expected)
    {
        AllowlistRecommendationScorer.Score(hits, resolvesToCdn: true, parentTrusted: true)
            .Should().Be(expected);
    }
}
