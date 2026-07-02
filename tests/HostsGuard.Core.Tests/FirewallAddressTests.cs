using FluentAssertions;
using HostsGuard.Core;
using Xunit;

namespace HostsGuard.Core.Tests;

public class FirewallAddressTests
{
    [Theory]
    [InlineData("8.8.8.8", true)]
    [InlineData("2606:4700:4700::1111", true)]
    [InlineData("10.0.0.0/8", true)]
    [InlineData("10.0.0.5/8", true)] // non-strict: host bits allowed
    [InlineData("192.168.1.1-192.168.1.50", true)]
    [InlineData("", false)]
    [InlineData(null, false)]
    [InlineData("not-an-ip", false)]
    [InlineData("999.999.999.999", false)]
    [InlineData("8.8.8.8; Remove-Item", false)]
    [InlineData("10.0.0.0/99", false)]
    public void IsValid_matches_python(string? input, bool expected) =>
        FirewallAddress.IsValid(input).Should().Be(expected);
}
