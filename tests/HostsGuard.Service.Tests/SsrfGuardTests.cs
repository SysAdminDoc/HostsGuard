using System.Net;
using FluentAssertions;
using HostsGuard.Service;
using Xunit;

namespace HostsGuard.Service.Tests;

/// <summary>
/// NET-062 P1: the client-URL SSRF guard rejects loopback, private, link-local,
/// CGNAT, ULA, multicast, and metadata targets and non-https schemes, while
/// letting genuine public https through.
/// </summary>
public sealed class SsrfGuardTests
{
    [Theory]
    [InlineData("127.0.0.1", false)]
    [InlineData("10.1.2.3", false)]
    [InlineData("172.16.5.5", false)]
    [InlineData("172.31.255.1", false)]
    [InlineData("172.32.0.1", true)]     // just outside the /12
    [InlineData("192.168.0.1", false)]
    [InlineData("169.254.169.254", false)] // cloud metadata / link-local
    [InlineData("100.64.0.1", false)]    // CGNAT
    [InlineData("100.128.0.1", true)]    // just outside CGNAT /10
    [InlineData("0.0.0.0", false)]
    [InlineData("224.0.0.1", false)]     // multicast
    [InlineData("8.8.8.8", true)]
    [InlineData("1.1.1.1", true)]
    public void Ipv4_public_classification(string ip, bool expectedPublic)
        => SsrfGuard.IsPublic(IPAddress.Parse(ip)).Should().Be(expectedPublic);

    [Theory]
    [InlineData("::1", false)]
    [InlineData("fe80::1", false)]       // link-local
    [InlineData("fc00::1", false)]       // unique local
    [InlineData("fd12:3456::1", false)]  // unique local
    [InlineData("ff02::1", false)]       // multicast
    [InlineData("2606:4700:4700::1111", true)] // Cloudflare public v6
    public void Ipv6_public_classification(string ip, bool expectedPublic)
        => SsrfGuard.IsPublic(IPAddress.Parse(ip)).Should().Be(expectedPublic);

    [Fact]
    public async Task Non_https_and_private_literals_are_blocked()
    {
        await FluentActions.Awaiting(() => SsrfGuard.EnsurePublicHttpsAsync("http://example.com/list.txt", default))
            .Should().ThrowAsync<SsrfBlockedException>();
        await FluentActions.Awaiting(() => SsrfGuard.EnsurePublicHttpsAsync("https://127.0.0.1/x", default))
            .Should().ThrowAsync<SsrfBlockedException>();
        await FluentActions.Awaiting(() => SsrfGuard.EnsurePublicHttpsAsync("https://169.254.169.254/latest/meta-data/", default))
            .Should().ThrowAsync<SsrfBlockedException>();
        await FluentActions.Awaiting(() => SsrfGuard.EnsurePublicHttpsAsync("not a url", default))
            .Should().ThrowAsync<SsrfBlockedException>();
    }

    [Fact]
    public async Task Public_https_literal_passes()
        => await SsrfGuard.EnsurePublicHttpsAsync("https://1.1.1.1/hosts.txt", default);
}
