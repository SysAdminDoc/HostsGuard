using FluentAssertions;
using Xunit;

namespace HostsGuard.Service.Tests;

/// <summary>
/// NET-199: a public registrable domain answering with a private-LAN address is
/// the DNS-rebinding signature — but hosts-file sinks, loopback, local names,
/// and normal public answers must never be flagged.
/// </summary>
public sealed class DnsRebindDetectorTests
{
    [Theory]
    [InlineData("192.168.1.10")]
    [InlineData("10.0.0.5")]
    [InlineData("172.16.4.4")]
    [InlineData("169.254.1.1")]
    [InlineData("100.64.0.1")]
    public void Public_domain_resolving_to_a_private_lan_address_is_flagged(string ip)
    {
        DnsRebindDetector.PrivateAnswersForPublicDomain("attacker.example.com", new[] { "93.184.216.34", ip })
            .Should().ContainSingle().Which.Should().Be(ip);
    }

    [Theory]
    [InlineData("0.0.0.0")]      // hosts-file sink
    [InlineData("127.0.0.1")]    // loopback / hosts sink
    [InlineData("::")]           // unspecified
    [InlineData("93.184.216.34")] // ordinary public answer
    public void Sink_loopback_and_public_answers_are_not_flagged(string ip)
    {
        DnsRebindDetector.PrivateAnswersForPublicDomain("cdn.example.com", new[] { ip })
            .Should().BeEmpty();
    }

    [Theory]
    [InlineData("printer.local")]
    [InlineData("nas.lan")]
    [InlineData("myhost")]              // single-label
    [InlineData("1.0.168.192.in-addr.arpa")]
    [InlineData("router.home.arpa")]
    public void Local_and_non_registrable_names_are_never_flagged(string name)
    {
        DnsRebindDetector.PrivateAnswersForPublicDomain(name, new[] { "192.168.1.1" })
            .Should().BeEmpty();
    }

    [Fact]
    public void Multiple_private_answers_are_de_duplicated()
    {
        DnsRebindDetector.PrivateAnswersForPublicDomain("x.example.org",
            new[] { "10.0.0.1", "10.0.0.1", "10.0.0.2" })
            .Should().BeEquivalentTo(new[] { "10.0.0.1", "10.0.0.2" });
    }

    [Fact]
    public void No_addresses_or_empty_domain_returns_empty()
    {
        DnsRebindDetector.PrivateAnswersForPublicDomain("example.com", null).Should().BeEmpty();
        DnsRebindDetector.PrivateAnswersForPublicDomain("", new[] { "10.0.0.1" }).Should().BeEmpty();
    }
}
