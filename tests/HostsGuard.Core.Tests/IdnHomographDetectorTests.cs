using FluentAssertions;
using HostsGuard.Core;
using Xunit;

namespace HostsGuard.Core.Tests;

public sealed class IdnHomographDetectorTests
{
    private readonly IdnHomographDetector _detector = new();

    [Fact]
    public void Cyrillic_paypal_homograph_collides_with_trusted_ascii_domain()
    {
        var result = _detector.Analyze("раураl.com", trustedDomains: ["paypal.com"]);

        result.IsIdn.Should().BeTrue();
        result.IsSuspicious.Should().BeTrue();
        result.Matches.Should().ContainSingle().Which.Should().Be(
            new IdnHomographMatch("paypal.com", IdnDomainSource.Trusted, result.Skeleton));
        result.Scripts.Should().BeEquivalentTo("Cyrillic", "Latin");
        result.Evidence.Should().Contain(evidence => evidence.StartsWith("mixed_script:", StringComparison.Ordinal));
        result.Evidence.Should().Contain("skeleton_collision");
        IdnHomographAssessment.RecommendedAction.Should().Be("alert_only");
    }

    [Fact]
    public void Greek_omicron_google_homograph_collides_with_allowlist()
    {
        var result = _detector.Analyze("gοοgle.com", allowlistedDomains: ["google.com"]);

        result.IsSuspicious.Should().BeTrue();
        result.Matches.Single().Source.Should().Be(IdnDomainSource.Allowlisted);
        result.Scripts.Should().BeEquivalentTo("Greek", "Latin");
        result.RestrictionLevel.Should().Be(IdnRestrictionLevel.MinimallyRestrictive);
    }

    [Theory]
    [InlineData("пример.рф")]
    [InlineData("παράδειγμα.δοκιμή")]
    [InlineData("例え.テスト")]
    [InlineData("münchen.de")]
    public void Legitimate_multilingual_idn_without_reference_collision_is_not_flagged(string domain)
    {
        var result = _detector.Analyze(domain, trustedDomains: ["example.com", "paypal.com"]);

        result.IsIdn.Should().BeTrue();
        result.IsSuspicious.Should().BeFalse();
        result.Matches.Should().BeEmpty();
    }

    [Fact]
    public void Exact_idna_equivalent_allowlist_entry_is_not_a_homograph()
    {
        var result = _detector.Analyze("MÜNCHEN.de.", allowlistedDomains: ["xn--mnchen-3ya.de", "münchen.de"]);

        result.AsciiDomain.Should().Be("xn--mnchen-3ya.de");
        result.UnicodeDomain.Should().Be("münchen.de");
        result.IsSuspicious.Should().BeFalse();
    }

    [Fact]
    public void Ascii_only_skeleton_collision_is_not_an_idn_homograph_alert()
    {
        var result = _detector.Analyze("paypa1.com", trustedDomains: ["paypal.com"]);

        result.IsIdn.Should().BeFalse();
        result.Matches.Should().ContainSingle("Unicode data maps ASCII digit one to a Latin-l skeleton");
        result.IsSuspicious.Should().BeFalse();
    }

    [Fact]
    public void Collision_sources_are_preserved_and_deduplicated_deterministically()
    {
        var result = _detector.Analyze(
            "раураl.com",
            allowlistedDomains: ["paypal.com", "PAYPAL.COM"],
            trustedDomains: ["paypal.com"],
            recentDomains: ["paypal.com"]);

        result.Matches.Select(match => match.Source).Should().Equal(
            IdnDomainSource.Allowlisted, IdnDomainSource.Trusted, IdnDomainSource.Recent);
    }

    [Fact]
    public void Mixed_japanese_scripts_receive_highly_restrictive_evidence_not_an_alert()
    {
        var result = _detector.Analyze("日本ご.jp");

        result.Scripts.Should().Contain("Han").And.Contain("Hiragana").And.Contain("Latin");
        result.RestrictionLevel.Should().Be(IdnRestrictionLevel.HighlyRestrictive);
        result.Evidence.Should().Contain("restriction_level:highly_restrictive");
        result.IsSuspicious.Should().BeFalse();
    }

    [Fact]
    public void Invalid_idna_input_is_rejected_without_fallback_comparison()
    {
        var act = () => _detector.Analyze("bad domain.example", trustedDomains: ["example.com"]);

        act.Should().Throw<ArgumentException>().WithMessage("Domain is not valid IDNA input.*");
    }

    [Fact]
    public void Cache_is_bounded_under_high_cardinality_recent_domains()
    {
        var detector = new IdnHomographDetector(16);
        for (var i = 0; i < 100; i++)
        {
            detector.Analyze($"domain-{i}.example");
        }

        detector.CacheEntryCount.Should().BeLessThanOrEqualTo(16);
    }

    [Fact]
    public void Unicode_data_version_is_pinned()
    {
        IdnHomographDetector.UnicodeVersion.Should().Be("17.0.0");
        IdnHomographDetector.Default.Should().NotBeNull();
    }
}
