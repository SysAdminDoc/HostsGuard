using FluentAssertions;
using HostsGuard.Core;
using Xunit;

namespace HostsGuard.Core.Tests;

/// <summary>NET-068: baseline matches Windows system binaries, rejects impostors + svchost.</summary>
public sealed class KnownSafeBaselineTests
{
    [Theory]
    [InlineData(@"C:\Windows\System32\MoUsoCoreWorker.exe", true)]
    [InlineData(@"c:\windows\system32\msmpeng.exe", true)]   // case-insensitive
    [InlineData("System", true)]                              // pathless kernel
    [InlineData(@"C:\Windows\System32\svchost.exe", false)]   // deliberately excluded
    [InlineData(@"C:\Temp\MsMpEng.exe", false)]               // impostor outside Windows
    [InlineData(@"C:\Users\x\game.exe", false)]
    [InlineData("", false)]
    public void IsBaseline_classifies_correctly(string path, bool expected)
        => KnownSafeBaseline.IsBaseline(path).Should().Be(expected);

    [Fact]
    public void Baseline_excludes_svchost_by_design()
        => KnownSafeBaseline.Entries.Should().NotContain(e => e.FileName.Equals("svchost.exe", StringComparison.OrdinalIgnoreCase));
}
