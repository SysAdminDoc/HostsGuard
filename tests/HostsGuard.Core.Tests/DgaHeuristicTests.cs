using FluentAssertions;
using HostsGuard.Core;
using System.Text.Json;
using Xunit;

namespace HostsGuard.Core.Tests;

/// <summary>
/// NET-201: the DGA heuristic must flag random-looking registered names while
/// leaving real brands — including long multi-word ones and CDN roots with
/// random subdomains — alone. Detector, so it favours false-negatives.
/// </summary>
public class DgaHeuristicTests
{
    [Theory]
    [InlineData("kq3v9xzptlw.com")]
    [InlineData("xjqzwbvhkpm.net")]
    [InlineData("7g4k9v2xq8zn.info")]
    [InlineData("bcdfghjklmnp.com")]     // long consonant run
    public void Flags_algorithmic_registered_names(string domain)
        => DgaHeuristic.LooksAlgorithmic(domain).Should().BeTrue();

    [Theory]
    [InlineData("google.com")]
    [InlineData("microsoft.com")]
    [InlineData("cloudflare.net")]
    [InlineData("googletagmanager.com")] // long but pronounceable multi-word
    [InlineData("amazonaws.com")]
    [InlineData("wikipedia.org")]
    [InlineData("stackoverflow.com")]
    [InlineData("github.com")]
    public void Leaves_real_brands_alone(string domain)
        => DgaHeuristic.LooksAlgorithmic(domain).Should().BeFalse();

    [Theory]
    [InlineData("d1a2b3c4e5f6.cloudfront.net")] // random SUBDOMAIN, normal root
    [InlineData("abc123def456.s3.amazonaws.com")]
    public void Ignores_random_subdomains_under_normal_roots(string domain)
        => DgaHeuristic.LooksAlgorithmic(domain).Should().BeFalse();

    [Theory]
    [InlineData("short.io")]   // registrable label too short to classify
    [InlineData("abc.com")]
    [InlineData("")]
    [InlineData("not a domain")]
    public void Short_or_invalid_names_are_not_flagged(string domain)
        => DgaHeuristic.LooksAlgorithmic(domain).Should().BeFalse();

    [Fact]
    public void Score_breakdown_exposes_every_threshold_weight_and_contribution()
    {
        var score = DgaHeuristic.Analyze("kq3v9xzptlw.com");

        score.Version.Should().Be(DgaHeuristic.ScoreVersion);
        score.RegistrableLabel.Should().Be("kq3v9xzptlw");
        score.MinimumLabelLength.Should().Be(DgaHeuristic.MinimumLabelLength);
        score.EntropyThreshold.Should().Be(DgaHeuristic.EntropyThreshold);
        score.EntropyWeight.Should().Be(DgaHeuristic.EntropyWeight);
        score.EntropyContribution.Should().Be(score.Entropy >= score.EntropyThreshold ? score.EntropyWeight : 0);
        score.VowelRatioThreshold.Should().Be(DgaHeuristic.VowelRatioThreshold);
        score.LowVowelWeight.Should().Be(DgaHeuristic.LowVowelWeight);
        score.DigitRatioThreshold.Should().Be(DgaHeuristic.DigitRatioThreshold);
        score.HighDigitWeight.Should().Be(DgaHeuristic.HighDigitWeight);
        score.ConsonantRunThreshold.Should().Be(DgaHeuristic.ConsonantRunThreshold);
        score.ConsonantRunWeight.Should().Be(DgaHeuristic.ConsonantRunWeight);
        score.NumericOnlyWeight.Should().Be(DgaHeuristic.NumericOnlyWeight);
        score.DecisionThreshold.Should().Be(DgaHeuristic.DecisionThreshold);
        score.Score.Should().Be(score.EntropyContribution + score.LowVowelContribution +
            score.HighDigitContribution + score.ConsonantRunContribution + score.NumericOnlyContribution);
        score.IsAlgorithmic.Should().BeTrue();
        score.Reason.Should().Be("entropy_and_structure");
    }

    [Theory]
    [InlineData("münchen.de")]
    [InlineData("пример.рф")]
    [InlineData("παράδειγμα.δοκιμή")]
    [InlineData("例え.テスト")]
    public void Idn_encoding_is_explicitly_excluded_from_alerting(string domain)
    {
        var score = DgaHeuristic.Analyze(domain);

        score.IsIdnEncoded.Should().BeTrue();
        score.IsAlgorithmic.Should().BeFalse();
        score.Reason.Should().Be("idn_encoding_excluded");
    }

    [Fact]
    public void Versioned_corpus_meets_measured_precision_and_recall_ratchets()
    {
        var corpus = LoadCorpus();
        corpus.Version.Should().Be("dga-corpus-v1");
        corpus.Cases.Select(c => c.Group).Should().Contain([
            "random-dga", "wordlist-dga", "cdn-subdomain", "idn", "short", "mutation"]);

        var measured = corpus.Cases.Select(c => (Case: c, Actual: DgaHeuristic.LooksAlgorithmic(c.Domain))).ToArray();
        var truePositive = measured.Count(row => row.Case.Expected && row.Actual);
        var falsePositive = measured.Count(row => !row.Case.Expected && row.Actual);
        var falseNegative = measured.Count(row => row.Case.Expected && !row.Actual);
        var precision = truePositive / (double)Math.Max(1, truePositive + falsePositive);
        var recall = truePositive / (double)Math.Max(1, truePositive + falseNegative);

        precision.Should().BeGreaterThanOrEqualTo(0.95, DescribeFailures(measured));
        recall.Should().BeGreaterThanOrEqualTo(0.75, DescribeFailures(measured));
    }

    [Fact]
    public void Corpus_and_scores_are_deterministic_across_repeated_runs()
    {
        foreach (var item in LoadCorpus().Cases)
        {
            DgaHeuristic.Analyze(item.Domain).Should().Be(DgaHeuristic.Analyze(item.Domain));
        }
    }

    private static DgaCorpus LoadCorpus()
    {
        var assembly = typeof(DgaHeuristic).Assembly;
        var name = assembly.GetManifestResourceNames().Single(n => n.EndsWith("dga-corpus-v1.json", StringComparison.Ordinal));
        using var stream = assembly.GetManifestResourceStream(name)!;
        return JsonSerializer.Deserialize<DgaCorpus>(stream, new JsonSerializerOptions { PropertyNameCaseInsensitive = true })!;
    }

    private static string DescribeFailures(IEnumerable<(DgaCase Case, bool Actual)> measured) =>
        "Corpus mismatches: " + string.Join(", ", measured.Where(row => row.Case.Expected != row.Actual)
            .Select(row => $"{row.Case.Domain} expected={row.Case.Expected} actual={row.Actual}"));

    private sealed record DgaCorpus(string Version, IReadOnlyList<DgaCase> Cases);
    private sealed record DgaCase(string Domain, bool Expected, string Group);
}
