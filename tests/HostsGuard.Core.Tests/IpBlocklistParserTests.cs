using FluentAssertions;
using HostsGuard.Core;
using Xunit;

namespace HostsGuard.Core.Tests;

/// <summary>NET-171: IP-format blocklist parsing, safety filtering, and dedup.</summary>
public class IpBlocklistParserTests
{
    [Fact]
    public void Parses_ipv4_ipv6_and_cidr_entries()
    {
        var scan = IpBlocklistParser.Scan("""
            # HaGeZi-style header
            1.2.3.4
            2606:4700:4700::1111
            203.0.113.0/24
            2001:db8::/32
            """);

        scan.Entries.Should().BeEquivalentTo(new[]
        {
            "1.2.3.4",
            "2606:4700:4700::1111",
            "203.0.113.0/24",
            "2001:db8::/32",
        });
        scan.Invalid.Should().Be(0);
        scan.Duplicates.Should().Be(0);
        scan.Unsafe.Should().Be(0);
    }

    [Fact]
    public void Skips_comments_and_inline_comments()
    {
        var scan = IpBlocklistParser.Scan("# comment\n! adblock comment\n; ini comment\n1.2.3.4 # trailing\n   \n");
        scan.Entries.Should().BeEquivalentTo(new[] { "1.2.3.4" });
        scan.Invalid.Should().Be(0);
    }

    [Fact]
    public void Counts_invalid_lines()
    {
        var scan = IpBlocklistParser.Scan("not-an-ip\n999.1.1.1\n1.2.3.4/33\n2001:db8::/129\n1.2.3.4:443\n1.2.3.4/abc\n");
        scan.Entries.Should().BeEmpty();
        scan.Invalid.Should().Be(6);
    }

    [Fact]
    public void Counts_duplicates_once()
    {
        var scan = IpBlocklistParser.Scan("1.2.3.4\n1.2.3.4\n1.2.3.4\n");
        scan.Entries.Should().BeEquivalentTo(new[] { "1.2.3.4" });
        scan.Duplicates.Should().Be(2);
    }

    [Theory]
    [InlineData("127.0.0.1")]     // loopback
    [InlineData("0.0.0.0")]       // unspecified
    [InlineData("10.1.2.3")]      // RFC1918
    [InlineData("172.16.0.1")]    // RFC1918
    [InlineData("192.168.1.1")]   // RFC1918
    [InlineData("169.254.1.1")]   // link-local
    [InlineData("224.0.0.1")]     // multicast
    [InlineData("255.255.255.255")]
    [InlineData("fe80::1")]       // v6 link-local
    [InlineData("ff02::1")]       // v6 multicast
    [InlineData("fd00::1")]       // v6 unique-local
    [InlineData("::")]            // v6 unspecified
    [InlineData("::1")]           // v6 loopback
    public void Refuses_non_routable_targets_as_unsafe(string entry)
    {
        var scan = IpBlocklistParser.Scan(entry + "\n");
        scan.Entries.Should().BeEmpty();
        scan.Unsafe.Should().Be(1);
    }

    [Theory]
    [InlineData("8.0.0.0/7")]     // wider than /8 could block huge swaths
    [InlineData("1.2.3.4/0")]     // block-all
    [InlineData("2001:db8::/8")]  // wider than /16
    public void Refuses_over_wide_cidrs_as_unsafe(string entry)
    {
        var scan = IpBlocklistParser.Scan(entry + "\n");
        scan.Entries.Should().BeEmpty();
        scan.Unsafe.Should().Be(1);
    }

    [Theory]
    [InlineData("::ffff:192.168.1.1")]  // IPv4-mapped RFC1918 — must not slip past v4 checks
    [InlineData("::ffff:10.0.0.1")]
    [InlineData("::ffff:127.0.0.1")]     // IPv4-mapped loopback
    [InlineData("100.64.0.1")]           // CGNAT 100.64/10 (the user's ISP path)
    [InlineData("100.127.255.1")]        // CGNAT upper bound
    [InlineData("0.5.4.3")]              // 0.0.0.0/8
    public void Refuses_mapped_and_extra_nonroutable_targets_as_unsafe(string entry)
    {
        var scan = IpBlocklistParser.Scan(entry + "\n");
        scan.Entries.Should().BeEmpty();
        scan.Unsafe.Should().Be(1);
    }

    [Fact]
    public void Cidr_host_bits_are_masked_to_the_network()
    {
        var scan = IpBlocklistParser.Scan("203.0.113.55/24\n2001:db8:abcd:1234::99/32\n");
        scan.Entries.Should().BeEquivalentTo(new[] { "203.0.113.0/24", "2001:db8::/32" });
    }

    [Fact]
    public void Cidr_entries_denoting_the_same_network_dedupe()
    {
        var scan = IpBlocklistParser.Scan("203.0.113.5/24\n203.0.113.200/24\n");
        scan.Entries.Should().BeEquivalentTo(new[] { "203.0.113.0/24" });
        scan.Duplicates.Should().Be(1);
    }

    [Fact]
    public void Full_prefix_cidr_collapses_to_the_bare_address()
    {
        var scan = IpBlocklistParser.Scan("1.2.3.4/32\n2001:db8::5/128\n");
        scan.Entries.Should().BeEquivalentTo(new[] { "1.2.3.4", "2001:db8::5" });
    }

    [Fact]
    public void Ipv6_text_is_canonicalized_for_dedup()
    {
        var scan = IpBlocklistParser.Scan("2001:DB8:0:0:0:0:0:1\n2001:db8::1\n");
        scan.Entries.Should().BeEquivalentTo(new[] { "2001:db8::1" });
        scan.Duplicates.Should().Be(1);
    }

    [Theory]
    [InlineData("1.2.3.4:443")]      // IPv4 with a port
    [InlineData("1.2.3.4:443/32")]   // IPv4:port carrying a CIDR suffix
    public void Ipv4_addresses_carrying_a_port_are_rejected_not_blocked(string token)
    {
        // A bracketless IPv6 literal legitimately contains colons, so only IPv4
        // host:port can be disambiguated — and it must never yield a block entry.
        var scan = IpBlocklistParser.Scan(token + "\n");
        scan.Entries.Should().BeEmpty();
        scan.Invalid.Should().Be(1);
    }
}
