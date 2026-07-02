using FluentAssertions;
using HostsGuard.Core;
using Xunit;

namespace HostsGuard.Core.Tests;

/// <summary>NET-065: the curated catalog ships an Encrypted-DNS bootstrap source.</summary>
public sealed class BlocklistCatalogTests
{
    [Fact]
    public void Catalog_includes_a_doh_resolver_bootstrap_source()
    {
        var doh = BlocklistCatalog.Sources.Where(s => s.Category == "Encrypted DNS").ToList();

        doh.Should().NotBeEmpty("DoH-bypass is the primary threat to hosts blocking");
        doh.Should().Contain(s => s.Name.Contains("DoH", StringComparison.OrdinalIgnoreCase));
        doh.Should().OnlyContain(s => s.Url.StartsWith("https://", StringComparison.Ordinal));
    }

    [Fact]
    public void All_catalog_sources_are_https_and_uniquely_named()
    {
        BlocklistCatalog.Sources.Should().OnlyContain(s => s.Url.StartsWith("https://", StringComparison.Ordinal));
        BlocklistCatalog.Sources.Select(s => s.Name).Should().OnlyHaveUniqueItems();
    }
}
