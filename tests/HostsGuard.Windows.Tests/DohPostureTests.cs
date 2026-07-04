using FluentAssertions;
using HostsGuard.Windows;
using Xunit;

namespace HostsGuard.Windows.Tests;

/// <summary>
/// NET-112: the DoH-flags interpretation used to detect an encrypted-DNS-only
/// (no-plaintext-fallback) posture, so HostsGuard can warn before a DoH block
/// that could sever name resolution.
/// </summary>
public class DohPostureTests
{
    [Theory]
    [InlineData(2, true)]   // require encryption, no fallback
    [InlineData(3, true)]   // require + auto-template variant
    [InlineData(1, false)]  // opportunistic — plaintext fallback allowed
    [InlineData(0, false)]  // disabled
    [InlineData(5, false)]  // auto/template, fallback allowed
    public void RequiresEncryption_flags_no_fallback(int dohFlags, bool expected)
        => DnsConfig.RequiresEncryption(dohFlags).Should().Be(expected);

    [Fact]
    public void IsEncryptedDnsOnly_never_throws()
    {
        // Best-effort registry probe: whatever this machine's posture, it must
        // return a bool without throwing.
        var act = () => DnsConfig.IsEncryptedDnsOnly();
        act.Should().NotThrow();
    }
}
