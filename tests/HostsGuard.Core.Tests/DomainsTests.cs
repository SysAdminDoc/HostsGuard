using FluentAssertions;
using HostsGuard.Core;
using Xunit;

namespace HostsGuard.Core.Tests;

public class DomainsTests
{
    [Theory]
    [InlineData("example.com", true)]
    [InlineData("sub.example.com", true)]
    [InlineData("my-domain.example.com", true)]
    [InlineData("localhost", false)]
    [InlineData("192.168.1.1", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    [InlineData("ip6-localhost", false)]
    [InlineData("-invalid.com", false)]
    public void LooksLikeDomain_matches_python(string? input, bool expected) =>
        Domains.LooksLikeDomain(input).Should().Be(expected);

    [Theory]
    [InlineData("example.com", "example.com")]
    [InlineData("www.example.com", "example.com")]
    [InlineData("a.b.c.example.com", "example.com")]
    [InlineData("www.example.co.uk", "example.co.uk")]
    [InlineData("mail.example.com.au", "example.com.au")]
    [InlineData("sub.example.co.jp", "example.co.jp")]
    [InlineData("google.com", "google.com")]
    public void GetRoot_matches_python(string input, string expected) =>
        Domains.GetRoot(input).Should().Be(expected);
}
