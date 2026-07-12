using FluentAssertions;
using HostsGuard.Core;
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
}
