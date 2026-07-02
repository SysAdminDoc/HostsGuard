using FluentAssertions;
using HostsGuard.Core;
using Xunit;

namespace HostsGuard.Core.Tests;

public class HostsFileTests
{
    [Theory]
    [InlineData("0.0.0.0 ads.example.com", "0.0.0.0 ads.example.com")]
    [InlineData("127.0.0.1 ads.example.com", "0.0.0.0 ads.example.com")]
    [InlineData("0.0.0.0 ads.example.com # block ads", "0.0.0.0 ads.example.com")]
    [InlineData("0.0.0.0 ADS.Example.COM", "0.0.0.0 ads.example.com")]
    [InlineData("0.0.0.0 example.com.", "0.0.0.0 example.com")]
    [InlineData(":: ads.example.com", "0.0.0.0 ads.example.com")]
    [InlineData("0.0.0.0 192.168.1.1", "0.0.0.0 192.168.1.1")]
    [InlineData("0.0.0.0\tads.example.com", "0.0.0.0 ads.example.com")]
    public void NormLine_normalizes(string input, string expected) =>
        HostsFile.NormLine(input).Should().Be(expected);

    [Theory]
    [InlineData("")]
    [InlineData("# this is a comment")]
    [InlineData("127.0.0.1 localhost")]
    [InlineData("0.0.0.0 -invalid")]
    public void NormLine_rejects(string input) =>
        HostsFile.NormLine(input).Should().BeNull();

    [Fact]
    public void NormLine_domain_only_no_normalize() =>
        HostsFile.NormLine("ads.example.com", normalize: false).Should().Be("ads.example.com");

    [Fact]
    public void Clean_deduplicates_and_counts()
    {
        var lines = new[] { "0.0.0.0 a.com", "0.0.0.0 a.com", "0.0.0.0 b.com" };
        var result = HostsFile.Clean(lines);
        var domains = result.Lines
            .Where(l => l.Length != 0 && !l.StartsWith('#'))
            .Select(l => l.Split(' ')[^1]).ToList();
        domains.Count(d => d == "a.com").Should().Be(1);
        result.Stats.Dupes.Should().Be(1);
    }

    [Fact]
    public void Clean_honors_whitelist()
    {
        var lines = new[] { "0.0.0.0 blocked.com", "0.0.0.0 allowed.com" };
        var result = HostsFile.Clean(lines, new HashSet<string> { "allowed.com" });
        result.Lines.Should().NotContain(l => l.EndsWith("allowed.com"));
        result.Stats.Whitelist.Should().Be(1);
    }

    [Fact]
    public void Clean_preserves_custom_comments()
    {
        var result = HostsFile.Clean(new[] { "# my custom comment", "0.0.0.0 a.com" });
        result.Lines.Should().Contain(l => l.Contains("# my custom comment"));
    }

    [Fact]
    public void Clean_is_idempotent()
    {
        var first = HostsFile.Clean(new[] { "0.0.0.0 a.com", "0.0.0.0 b.com" }).Lines;
        var second = HostsFile.Clean(first).Lines;
        second.Should().Equal(first);
        second.Count(l => l.StartsWith("# Copyright (c) 1993-2009")).Should().Be(1);
        second.Count(l => l.Contains("entries managed by")).Should().Be(1);
    }

    [Fact]
    public void Clean_empty_input()
    {
        var result = HostsFile.Clean(Array.Empty<string>());
        result.Stats.Total.Should().Be(0);
    }
}
