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
    public void Scan_accepts_comment_and_null_route_hosts_fixture()
    {
        var text = string.Join('\n',
            "# hosts-style comment",
            "! adblock-style comment",
            "0.0.0.0 ads.example.com # inline hosts comment",
            "127.0.0.1 TRACKER.Example.NET",
            ":: ipv6.example.org",
            "::1 loopback.example.org",
            "0:0:0:0:0:0:0:0 zero.example.org",
            "0:0:0:0:0:0:0:1 long-loopback.example.org",
            "");

        var scan = BlocklistCatalog.Scan(text);

        scan.Total.Should().Be(6);
        scan.Domains.Should().Equal([
            "ads.example.com",
            "tracker.example.net",
            "ipv6.example.org",
            "loopback.example.org",
            "zero.example.org",
            "long-loopback.example.org",
        ]);
        scan.Duplicates.Should().Be(0);
        scan.Invalid.Should().Be(0);
        scan.HijackFlagged.Should().Be(0);
    }

    [Fact]
    public void Scan_counts_adblock_exclusions_wildcards_and_cosmetic_filters_as_invalid()
    {
        var text = string.Join('\n',
            "@@||allow.example^",
            "||ads.example^",              // NET-174: lossless -> imports as a domain
            "*.wild.example",
            "/tracker\\d+\\.example/",
            "[Adblock Plus 2.0]",
            "example.com##.ad",
            "0.0.0.0 filter.example##.ad",
            "0.0.0.0 valid.example # inline hosts comment");

        var scan = BlocklistCatalog.Scan(text);

        scan.Total.Should().Be(8);
        scan.Domains.Should().Equal(["ads.example", "valid.example"]);
        scan.Duplicates.Should().Be(0);
        scan.Invalid.Should().Be(6);
        scan.HijackFlagged.Should().Be(0);
        scan.ModifiersStripped.Should().Be(0);
    }

    // ─── NET-174 import transforms ───────────────────────────────────────────

    [Fact]
    public void Plain_adblock_domain_rules_convert_to_domains()
    {
        var scan = BlocklistCatalog.Scan(string.Join('\n',
            "||ads.example^",
            "||Tracker.Example.NET",     // no anchor, mixed case
            "||dup.example^",
            "0.0.0.0 dup.example"));     // hosts line duplicates the converted rule

        scan.Domains.Should().Equal(["ads.example", "tracker.example.net", "dup.example"]);
        scan.Duplicates.Should().Be(1);
        scan.Invalid.Should().Be(0);
        scan.ModifiersStripped.Should().Be(0);
    }

    [Fact]
    public void Adblock_modifier_rules_are_stripped_never_imported_as_bare_domains()
    {
        var scan = BlocklistCatalog.Scan(string.Join('\n',
            "||conditional.example^$third-party",
            "||scripty.example^$script,domain=~safe.example",
            "||plain.example^"));

        scan.ModifiersStripped.Should().Be(2);
        scan.Domains.Should().Equal(["plain.example"]);
        scan.Domains.Should().NotContain("conditional.example");
        scan.Invalid.Should().Be(0);
    }

    [Theory]
    [InlineData("||ads.example^path")]        // trailing path after anchor
    [InlineData("||ads.example/banner^")]     // path component
    [InlineData("||*.wild.example^")]         // wildcard
    [InlineData("||ads.example^|")]           // end anchor
    [InlineData("||ads.example:8080^")]       // port
    public void Non_lossless_adblock_rules_stay_invalid(string rule)
    {
        var scan = BlocklistCatalog.Scan(rule + "\n");
        scan.Domains.Should().BeEmpty();
        scan.Invalid.Should().Be(1);
        scan.ModifiersStripped.Should().Be(0);
    }

    [Fact]
    public void Catalog_entries_carry_gallery_metadata()
    {
        foreach (var source in BlocklistCatalog.Sources)
        {
            source.Tags.Should().NotBeEmpty($"{source.Name} needs gallery tags");
            source.Homepage.Should().StartWith("https://", $"{source.Name} needs a homepage");
            source.Description.Should().NotBeEmpty($"{source.Name} needs a description");
        }
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
        var scan = BlocklistCatalog.Scan(string.Join('\n',
            ":: blocked.example",
            "::1 other.example",
            "0:0:0:0:0:0:0:0 zero.example",
            "0:0:0:0:0:0:0:1 long-loopback.example"));
        scan.HijackFlagged.Should().Be(0);
        scan.Domains.Should().Equal(["blocked.example", "other.example", "zero.example", "long-loopback.example"]);
    }

    [Fact]
    public void Scan_deduplicates_case_and_trailing_dot_before_hijack_diagnostics()
    {
        var text = string.Join('\n',
            "0.0.0.0 Ads.Example.COM.",
            "ads.example.com",
            "255.255.255.255 broadcast.example",
            "fe80::1 linklocal.example",
            "2001:4860:4860::8888 redirected.example",
            "0:0:0:0:0:0:0:0 zero.example");

        var scan = BlocklistCatalog.Scan(text);

        scan.Total.Should().Be(6);
        scan.Domains.Should().Equal(["ads.example.com", "zero.example"]);
        scan.Duplicates.Should().Be(1);
        scan.Invalid.Should().Be(0);
        scan.HijackFlagged.Should().Be(3);
    }

    [Fact]
    public void ParseDomains_still_returns_the_clean_set() =>
        BlocklistCatalog.ParseDomains("0.0.0.0 a.com\n0.0.0.0 a.com\nb.com")
            .Should().BeEquivalentTo(["a.com", "b.com"]);

    [Fact]
    public async Task Streaming_scan_matches_buffered_scan()
    {
        const string text = "# comment\n0.0.0.0 Ads.Example\n||tracker.example^\n0.0.0.0 ads.example\n8.8.8.8 hijack.example\n";
        using var reader = new StringReader(text);

        var streamed = await BlocklistCatalog.ScanAsync(reader, CancellationToken.None);

        streamed.Should().BeEquivalentTo(BlocklistCatalog.Scan(text));
    }
}
