using FluentAssertions;
using HostsGuard.Core;
using Xunit;

namespace HostsGuard.Core.Tests;

/// <summary>NET-077: the blocklist merge health scan (dupes, invalid, hijack).</summary>
public class BlocklistScanTests
{
    [Fact]
    public void Scan_counts_duplicates_invalid_and_clean_domains()
    {
        var text = string.Join('\n',
            "# comment",
            "0.0.0.0 ads.example.com",
            "0.0.0.0 ads.example.com",   // duplicate
            "tracker.example.net",       // bare domain
            "not a domain !!!",          // invalid
            "");

        var scan = BlocklistCatalog.Scan(text);

        scan.Domains.Should().BeEquivalentTo(["ads.example.com", "tracker.example.net"]);
        scan.Duplicates.Should().Be(1);
        scan.Invalid.Should().Be(1);
        scan.HijackFlagged.Should().Be(0);
    }

    [Fact]
    public void Scan_flags_and_excludes_hosts_hijack_entries()
    {
        var text = string.Join('\n',
            "0.0.0.0 blocked.example.com",       // legit sink
            "127.0.0.1 also-blocked.example",    // legit sink
            "93.184.216.34 victim-bank.com",     // hijack: routable IP
            "8.8.8.8 redirected.example.org");   // hijack: routable IP

        var scan = BlocklistCatalog.Scan(text);

        scan.HijackFlagged.Should().Be(2);
        scan.Domains.Should().BeEquivalentTo(["blocked.example.com", "also-blocked.example"]);
        scan.Domains.Should().NotContain("victim-bank.com");
    }

    [Fact]
    public void Sink_ipv6_and_ipv4_are_not_hijacks()
    {
        var scan = BlocklistCatalog.Scan(":: blocked.example\n::1 other.example");
        scan.HijackFlagged.Should().Be(0);
        scan.Domains.Should().HaveCount(2);
    }

    [Fact]
    public void ParseDomains_still_returns_the_clean_set() =>
        BlocklistCatalog.ParseDomains("0.0.0.0 a.com\n0.0.0.0 a.com\nb.com")
            .Should().BeEquivalentTo(["a.com", "b.com"]);
}
