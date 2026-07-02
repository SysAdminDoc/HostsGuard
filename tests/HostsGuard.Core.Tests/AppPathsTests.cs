using FluentAssertions;
using HostsGuard.Core;
using Xunit;

namespace HostsGuard.Core.Tests;

/// <summary>NET-069: versioned-path normalization so an updated app stays recognizable.</summary>
public sealed class AppPathsTests
{
    [Theory]
    [InlineData(@"C:\Program Files\App\1.2.3\app.exe", @"C:\Program Files\App\*\app.exe")]
    [InlineData(@"C:\Users\x\AppData\Local\Discord\1.0.9012\Discord.exe", @"C:\Users\x\AppData\Local\Discord\*\Discord.exe")]
    [InlineData(@"C:\Program Files\Google\Chrome\Application\120.0.6099.130\chrome.exe", @"C:\Program Files\Google\Chrome\Application\*\chrome.exe")]
    [InlineData(@"C:\Users\x\AppData\Local\slack\app-4.35.126\slack.exe", @"C:\Users\x\AppData\Local\slack\*\slack.exe")]
    [InlineData(@"C:\Program Files\Steady\steady.exe", @"C:\Program Files\Steady\steady.exe")] // no version segment
    public void Normalizes_version_directory_segments(string path, string expected)
        => AppPaths.NormalizeVersionedPath(path).Should().Be(expected);

    [Fact]
    public void Never_wildcards_the_file_name_even_if_versionlike()
        => AppPaths.NormalizeVersionedPath(@"C:\tools\1.2.3").Should().Be(@"C:\tools\1.2.3");

    [Fact]
    public void SameVersionedApp_matches_across_version_bumps_only()
    {
        AppPaths.SameVersionedApp(
            @"C:\App\1.2.3\app.exe", @"C:\App\1.3.0\app.exe").Should().BeTrue();
        AppPaths.SameVersionedApp(
            @"C:\App\1.2.3\app.exe", @"C:\Other\1.3.0\app.exe").Should().BeFalse();
        // No version segment on either side → not a versioned-app match.
        AppPaths.SameVersionedApp(@"C:\App\app.exe", @"C:\App\app.exe").Should().BeFalse();
    }
}
