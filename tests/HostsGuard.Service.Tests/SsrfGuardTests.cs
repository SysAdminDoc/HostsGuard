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
    [InlineData("255.255.255.255", false)] // broadcast
    [InlineData("192.0.0.171", false)]   // 192.0.0.0/24 IETF protocol assignments (NAT64 discovery)
    [InlineData("192.0.2.5", false)]     // TEST-NET-1
    [InlineData("198.51.100.5", false)]  // TEST-NET-2
    [InlineData("203.0.113.5", false)]   // TEST-NET-3
    [InlineData("198.18.0.1", false)]    // benchmarking /15
    [InlineData("198.19.255.1", false)]  // benchmarking /15
    [InlineData("198.20.0.1", true)]     // just outside the /15
    [InlineData("8.8.8.8", true)]
    [InlineData("1.1.1.1", true)]
    public void Ipv4_public_classification(string ip, bool expectedPublic)
        => SsrfGuard.IsPublic(IPAddress.Parse(ip)).Should().Be(expectedPublic);

    [Theory]
    [InlineData("::1", false)]
    [InlineData("::", false)]            // unspecified
    [InlineData("fe80::1", false)]       // link-local
    [InlineData("fc00::1", false)]       // unique local
    [InlineData("fd12:3456::1", false)]  // unique local
    [InlineData("ff02::1", false)]       // multicast
    [InlineData("64:ff9b::a00:1", false)]        // NAT64 well-known embedding 10.0.0.1 (private)
    [InlineData("64:ff9b::c0a8:105", false)]     // NAT64 well-known embedding 192.168.1.5 (private)
    [InlineData("64:ff9b::808:808", true)]       // NAT64 well-known embedding 8.8.8.8 (public)
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

    [Theory]
    [InlineData("https://api.deepseek.com", true)]     // public hostname (rebind caught at connect)
    [InlineData("https://8.8.8.8/v1", true)]           // public IP literal
    [InlineData("http://api.deepseek.com", false)]     // not https
    [InlineData("https://127.0.0.1:11434", false)]     // loopback literal
    [InlineData("https://169.254.169.254/latest", false)] // metadata literal
    [InlineData("https://192.168.1.10", false)]        // private literal
    [InlineData("ftp://example.com", false)]
    [InlineData("", false)]
    public void IsSafeHttpsEndpoint_gates_scheme_and_ip_literals(string url, bool expected)
        => SsrfGuard.IsSafeHttpsEndpoint(url).Should().Be(expected);

    // DNS-rebinding defense: the connect-time filter drops private addresses even
    // when the pre-check saw a public one, and throws if nothing public survives.
    [Fact]
    public void Connect_time_filter_keeps_only_public_addresses()
    {
        var mixed = new[]
        {
            IPAddress.Parse("192.168.1.5"),   // private — must be dropped
            IPAddress.Parse("8.8.8.8"),       // public — must survive
            IPAddress.Parse("127.0.0.1"),     // loopback — must be dropped
        };

        HttpListFetcher.PublicAddressesOrThrow("evil.example", mixed)
            .Should().ContainSingle().Which.Should().Be(IPAddress.Parse("8.8.8.8"));
    }

    [Fact]
    public void Connect_time_filter_throws_when_all_private()
    {
        var rebind = new[] { IPAddress.Parse("169.254.169.254"), IPAddress.Parse("10.0.0.1") };

        FluentActions.Invoking(() => HttpListFetcher.PublicAddressesOrThrow("rebind.example", rebind))
            .Should().Throw<SsrfBlockedException>();
    }
}
