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

    [Theory]
    [InlineData("example.com", "example.com")]           // ASCII unchanged
    [InlineData("Example.COM", "example.com")]           // lowercased
    [InlineData("example.com.", "example.com")]          // trailing dot stripped (NET-177)
    [InlineData(" example.com ", "example.com")]         // trimmed
    [InlineData("münchen.de", "xn--mnchen-3ya.de")]      // IDN → punycode (NET-170)
    [InlineData("例え.jp", "xn--r8jz45g.jp")]             // IDN → punycode
    [InlineData("xn--mnchen-3ya.de", "xn--mnchen-3ya.de")] // idempotent on punycode
    public void ToAscii_normalizes_and_punycodes(string input, string expected) =>
        Domains.ToAscii(input).Should().Be(expected);

    [Theory]
    [InlineData("münchen.de", true)]   // Unicode IDN is now a valid blockable domain
    [InlineData("例え.jp", true)]
    [InlineData("bücher.example", true)]
    public void LooksLikeDomain_accepts_unicode_idns(string input, bool expected) =>
        Domains.LooksLikeDomain(input).Should().Be(expected);
}
