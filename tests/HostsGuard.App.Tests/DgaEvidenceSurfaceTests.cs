using System.Globalization;
using System.IO;
using FluentAssertions;
using HostsGuard.App.Services;
using HostsGuard.App.ViewModels;
using HostsGuard.Contracts;
using Xunit;

namespace HostsGuard.App.Tests;

public sealed class DgaEvidenceSurfaceTests
{
    [Fact]
    public void Suspicious_domain_maps_exact_service_score_evidence_without_reclassification()
    {
        var original = CultureInfo.CurrentUICulture;
        CultureInfo.CurrentUICulture = CultureInfo.GetCultureInfo("en");
        try
        {
            var source = new AlertEntry
            {
                Type = "suspicious_domain",
                Subject = "kq3v9xzptlw.com",
                DgaEvidence = new DgaEvidence
                {
                    Version = "dga-score-v1",
                    RegistrableLabel = "kq3v9xzptlw",
                    LabelLength = 11,
                    Entropy = 3.46,
                    EntropyThreshold = 3.2,
                    VowelRatio = 0,
                    VowelRatioThreshold = 0.25,
                    DigitRatio = 2d / 11d,
                    DigitRatioThreshold = 0.35,
                    MaxConsonantRun = 5,
                    ConsonantRunThreshold = 5,
                    Score = 3,
                    DecisionThreshold = 2,
                    IsAlgorithmic = true,
                    Reason = "entropy_and_structure",
                },
            };

            var row = AlertRowViewModel.From(source);

            row.HasDgaEvidence.Should().BeTrue();
            row.DgaEvidence.Should().BeSameAs(source.DgaEvidence);
            row.DgaRegistrableLabel.Should().Be("kq3v9xzptlw (11 characters; dga-score-v1)");
            row.DgaScoreText.Should().Be("3.00 (decision threshold 2.00)");
            row.DgaEntropyText.Should().Be("3.46 (threshold 3.20)");
            row.DgaVowelRatioText.Should().Be("0% (threshold 25%)");
            row.DgaDigitRatioText.Should().Be("18% (threshold 35%)");
            row.DgaConsonantRunText.Should().Be("5 (threshold 5)");
            row.DgaReason.Should().Be("entropy_and_structure; algorithmic=True");
        }
        finally
        {
            CultureInfo.CurrentUICulture = original;
        }
    }

    [Fact]
    public void Non_dga_alert_does_not_show_dga_diagnostics()
    {
        var row = AlertRowViewModel.From(new AlertEntry { Type = "threat_hit" });

        row.HasDgaEvidence.Should().BeFalse();
        row.DgaScoreText.Should().BeEmpty();
    }

    [Theory]
    [InlineData("es", "Evidencia de dominio algorítmico")]
    [InlineData("de", "Nachweis für algorithmische Domäne")]
    [InlineData("fr", "Preuve de domaine algorithmique")]
    public void Dga_explainer_title_is_translated(string culture, string expected)
    {
        var original = CultureInfo.CurrentUICulture;
        CultureInfo.CurrentUICulture = CultureInfo.GetCultureInfo(culture);
        try
        {
            I18n.T("Dga_AlertExplainerTitle", "fallback").Should().Be(expected);
        }
        finally
        {
            CultureInfo.CurrentUICulture = original;
        }
    }

    [Fact]
    public void Alerts_xaml_preserves_default_off_alert_only_and_accessible_evidence_bindings()
    {
        var path = Path.Combine(
            RepoRoot(), "src", "HostsGuard.App", "Views", "AlertsPage.xaml");
        var xaml = File.ReadAllText(path);

        xaml.Should().Contain("SelectedAlert.HasDgaEvidence");
        xaml.Should().Contain("Key=Dga_DefaultOffAlertOnly");
        xaml.Should().Contain("Key=Dga_AlertExplainerName");
        xaml.Should().Contain("SelectedAlert.DgaScoreText");
        xaml.Should().Contain("SelectedAlert.DgaReason");
    }

    private static string RepoRoot()
    {
        var directory = AppContext.BaseDirectory;
        while (directory is not null && !File.Exists(Path.Combine(directory, "HostsGuard.sln")))
        {
            directory = Path.GetDirectoryName(directory);
        }
        return directory ?? throw new DirectoryNotFoundException("HostsGuard repo root was not found.");
    }
}
