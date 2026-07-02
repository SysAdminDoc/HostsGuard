using FluentAssertions;
using HostsGuard.Core;
using Xunit;

namespace HostsGuard.Core.Tests;

public class SearchQueryTests
{
    private static Dictionary<string, object?> Record(string domain, string proc, string status, string[]? tags = null) =>
        new(StringComparer.Ordinal)
        {
            ["domain"] = domain,
            ["process"] = proc,
            ["status"] = status,
            ["tags"] = tags ?? Array.Empty<string>(),
        };

    [Fact]
    public void Empty_query_matches_everything() =>
        SearchQuery.Matches(Record("a.com", "chrome", "blocked"), "").Should().BeTrue();

    [Fact]
    public void Bare_term_is_substring_over_all_fields()
    {
        var r = Record("ads.example.com", "chrome.exe", "blocked");
        SearchQuery.Matches(r, "example").Should().BeTrue();
        SearchQuery.Matches(r, "firefox").Should().BeFalse();
    }

    [Fact]
    public void Field_scoped_contains()
    {
        var r = Record("ads.example.com", "chrome.exe", "blocked");
        SearchQuery.Matches(r, "process:chrome").Should().BeTrue();
        SearchQuery.Matches(r, "process:firefox").Should().BeFalse();
        // 'chrome' only in process, so a domain-scoped search misses it.
        SearchQuery.Matches(r, "domain:chrome").Should().BeFalse();
    }

    [Fact]
    public void Negation_excludes()
    {
        var r = Record("ads.example.com", "chrome.exe", "blocked");
        SearchQuery.Matches(r, "!chrome").Should().BeFalse();
        SearchQuery.Matches(r, "!firefox").Should().BeTrue();
    }

    [Fact]
    public void NotEqual_on_field()
    {
        var r = Record("a.com", "chrome", "blocked");
        SearchQuery.Matches(r, "status!=allowed").Should().BeTrue();
        SearchQuery.Matches(r, "status!=blocked").Should().BeFalse();
    }

    [Fact]
    public void Aliases_resolve_field()
    {
        var r = Record("ads.example.com", "chrome", "blocked");
        var aliases = new Dictionary<string, string> { ["proc"] = "process" };
        SearchQuery.Matches(r, "proc:chrome", aliases).Should().BeTrue();
    }

    [Fact]
    public void List_valued_fields_are_searchable()
    {
        var r = Record("a.com", "chrome", "blocked", new[] { "ads", "tracking" });
        SearchQuery.Matches(r, "tags:tracking").Should().BeTrue();
        SearchQuery.Matches(r, "tags:malware").Should().BeFalse();
    }

    [Fact]
    public void Quoted_multiword_term()
    {
        var r = Record("my ads domain.com", "chrome", "blocked");
        SearchQuery.Matches(r, "\"ads domain\"").Should().BeTrue();
        var terms = SearchQuery.Parse("\"ads domain\"");
        terms.Should().ContainSingle();
        terms[0].Value.Should().Be("ads domain");
    }

    [Fact]
    public void Multiple_terms_are_anded()
    {
        var r = Record("ads.example.com", "chrome", "blocked");
        SearchQuery.Matches(r, "example process:chrome").Should().BeTrue();
        SearchQuery.Matches(r, "example process:firefox").Should().BeFalse();
    }

    [Fact]
    public void Unbalanced_quote_falls_back_to_whitespace_split()
    {
        var terms = SearchQuery.Parse("\"unclosed value");
        // Fallback split yields two bare tokens rather than throwing.
        terms.Should().HaveCount(2);
    }
}
