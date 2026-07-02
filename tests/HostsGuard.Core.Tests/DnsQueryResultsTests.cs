using FluentAssertions;
using HostsGuard.Core;
using Xunit;

namespace HostsGuard.Core.Tests;

/// <summary>NET-075: CNAME extraction from the ETW DNS completion QueryResults field.</summary>
public sealed class DnsQueryResultsTests
{
    [Fact]
    public void Extracts_cname_targets_and_ignores_address_records()
    {
        var results = "type: 5 cdn.tracker.example.;type: 1 93.184.216.34;type: 28 ::1";

        var cnames = DnsQueryResults.ExtractCnames(results);

        cnames.Should().ContainSingle().Which.Should().Be("cdn.tracker.example");
    }

    [Fact]
    public void Handles_a_multi_hop_cname_chain_deduped()
    {
        var results = "type: 5 a.alias.net;type: 5 b.alias.net;type: 5 a.alias.net;type: 1 1.2.3.4";

        DnsQueryResults.ExtractCnames(results).Should().Equal("a.alias.net", "b.alias.net");
    }

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    [InlineData("type: 1 1.2.3.4")]      // no CNAME
    [InlineData("garbage;;type: x y")]   // malformed
    public void Returns_empty_for_no_cname(string? results)
        => DnsQueryResults.ExtractCnames(results).Should().BeEmpty();
}
