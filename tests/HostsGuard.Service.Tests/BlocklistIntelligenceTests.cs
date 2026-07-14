using System.Runtime.Versioning;
using FluentAssertions;
using HostsGuard.Core;
using HostsGuard.Data;
using Microsoft.Data.Sqlite;
using Xunit;

namespace HostsGuard.Service.Tests;

internal sealed class FakeIntelFetcher : IListFetcher
{
    public Dictionary<string, string> Responses { get; } = new(StringComparer.Ordinal);

    public Task<string> FetchAsync(string url, int maxBytes, CancellationToken ct)
        => Responses.TryGetValue(url, out var text)
            ? Task.FromResult(text)
            : throw new InvalidOperationException($"no response for {url}");

    public Task<byte[]> FetchBytesAsync(string url, int maxBytes, CancellationToken ct)
        => throw new InvalidOperationException("not used by the intelligence index");
}

[SupportedOSPlatform("windows")]
public sealed class BlocklistIntelligenceTests : IDisposable
{
    private readonly string _dir;
    private readonly HostsDatabase _db;
    private readonly FakeIntelFetcher _fetcher = new();

    public BlocklistIntelligenceTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "hg_intel_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        _db = new HostsDatabase(Path.Combine(_dir, "db.sqlite"));
    }

    public void Dispose()
    {
        _db.Dispose();
        try { Directory.Delete(_dir, true); } catch (IOException) { /* best effort */ }
    }

    [Fact]
    public async Task Refresh_indexes_reachable_lists_and_skips_failures()
    {
        // Serve two catalog sources; every other source fails and is skipped.
        var first = BlocklistCatalog.Sources[0];
        var second = BlocklistCatalog.Sources[1];
        _fetcher.Responses[first.Url] = "0.0.0.0 ads.example.com\n0.0.0.0 tracker.example.net\n";
        _fetcher.Responses[second.Url] = "0.0.0.0 ads.example.com\n";

        using var intel = new BlocklistIntelligence(_db, _fetcher);
        var (indexed, failed) = await intel.RefreshAsync(CancellationToken.None);

        indexed.Should().Be(2);
        failed.Should().Be(BlocklistCatalog.Sources.Count - 2);
        _db.GetBlocklistsFor("ads.example.com").Should().BeEquivalentTo(new[] { first.Name, second.Name });
        _db.GetBlocklistsFor("tracker.example.net").Should().BeEquivalentTo(new[] { first.Name });
        _db.GetBlocklistsFor("clean.example.org").Should().BeEmpty();
        intel.LastRefreshed.Should().NotBeEmpty();

        var membership = _db.GetListMembership(new[] { "ads.example.com", "clean.example.org" });
        membership.Should().ContainKey("ads.example.com").WhoseValue.Should().HaveCount(2);
        membership.Should().NotContainKey("clean.example.org");
    }

    [Fact]
    public async Task Refresh_replaces_a_lists_previous_rows()
    {
        var first = BlocklistCatalog.Sources[0];
        _fetcher.Responses[first.Url] = "0.0.0.0 old.example.com\n";
        using var intel = new BlocklistIntelligence(_db, _fetcher);
        await intel.RefreshAsync(CancellationToken.None);

        _fetcher.Responses[first.Url] = "0.0.0.0 new.example.com\n";
        await intel.RefreshAsync(CancellationToken.None);

        _db.GetBlocklistsFor("old.example.com").Should().BeEmpty();
        _db.GetBlocklistsFor("new.example.com").Should().ContainSingle();
    }
}
