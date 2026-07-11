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
}
