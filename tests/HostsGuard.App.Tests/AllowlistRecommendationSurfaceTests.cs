using FluentAssertions;
using HostsGuard.App.ViewModels;
using HostsGuard.Contracts;
using Xunit;

namespace HostsGuard.App.Tests;

public sealed class AllowlistRecommendationSurfaceTests
{
    [Fact]
    public void Recommendation_row_preserves_rank_and_explainable_evidence()
    {
        var row = AllowlistRecommendationViewModel.From(new AllowlistRecommendationEntry
        {
            Domain = "assets.example.test",
            Hits = 250,
            Score = 95,
            Process = "child.exe",
            ParentApp = "launcher.exe",
            CdnEvidence = "edge.cloudfront.net (Amazon CloudFront CDN)",
            TrustEvidence = "trusted publisher: Contoso",
        });

        row.Score.Should().Be(95);
        row.Domain.Should().Be("assets.example.test");
        row.CdnEvidence.Should().Contain("cloudfront.net");
        row.TrustEvidence.Should().Contain("Contoso");
    }
}
