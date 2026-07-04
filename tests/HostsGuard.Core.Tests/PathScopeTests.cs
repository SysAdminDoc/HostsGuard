using FluentAssertions;
using HostsGuard.Core;
using Xunit;

namespace HostsGuard.Core.Tests;

/// <summary>NET-117: folder-scope path matching for "trust this whole folder".</summary>
public class PathScopeTests
{
    [Theory]
    [InlineData(@"C:\Apps\Portable\v2\app.exe", @"C:\Apps\Portable", true)]
    [InlineData(@"C:\Apps\Portable\app.exe", @"C:\Apps\Portable\", true)]   // trailing slash
    [InlineData(@"C:/Apps/Portable/app.exe", @"C:\Apps\Portable", true)]    // forward slashes
    [InlineData(@"c:\apps\portable\app.exe", @"C:\Apps\Portable", true)]    // case-insensitive
    [InlineData(@"C:\AppsPortable\app.exe", @"C:\Apps", false)]             // sibling prefix, not under
    [InlineData(@"C:\Other\app.exe", @"C:\Apps\Portable", false)]
    [InlineData(@"", @"C:\Apps", false)]
    [InlineData(@"C:\Apps\app.exe", @"", false)]
    public void IsUnder_matches_folder_prefix(string appPath, string folder, bool expected)
        => PathScope.IsUnder(appPath, folder).Should().Be(expected);

    [Theory]
    [InlineData(@"C:\Apps\Portable\v2\app.exe", @"C:\Apps\Portable\v2")]
    [InlineData(@"C:/Apps/app.exe", @"C:\Apps")]
    [InlineData(@"app.exe", "")]
    [InlineData(@"", "")]
    public void ParentFolder_returns_the_directory(string appPath, string expected)
        => PathScope.ParentFolder(appPath).Should().Be(expected);
}
