using System.Runtime.Versioning;
using FluentAssertions;
using HostsGuard.Core;
using HostsGuard.Data;
using HostsGuard.Windows;
using Microsoft.Data.Sqlite;
using Xunit;

namespace HostsGuard.Service.Tests;

/// <summary>NET-077: mirror fallback, the health report, and allowlist-override counting.</summary>
[SupportedOSPlatform("windows")]
public sealed class BlocklistHealthTests : IDisposable
{
    private readonly string _dir;
    private readonly HostsEngine _hosts;
    private readonly HostsDatabase _db;
    private readonly FakeListFetcher _fetcher = new();
    private readonly ListImporter _importer;

    public BlocklistHealthTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "hg_health_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        var hostsPath = Path.Combine(_dir, "hosts");
        File.WriteAllText(hostsPath, "# hosts\n");
        _hosts = new HostsEngine(hostsPath);
        _db = new HostsDatabase(Path.Combine(_dir, "hostsguard.db"));
        _importer = new ListImporter(_hosts, _db, _fetcher, TimeSpan.FromHours(24));
    }

    public void Dispose()
    {
        _importer.Dispose();
        _db.Dispose();
        try
        {
            Directory.Delete(_dir, true);
        }
        catch (IOException)
        {
            // best effort
        }
    }

    [Fact]
    public async Task Import_reports_scan_health()
    {
        _fetcher.Responses["https://x/list.txt"] =
            "0.0.0.0 a.com\n0.0.0.0 a.com\ngarbage !!\n93.184.216.34 hijack.com\nb.com";

        var outcome = await _importer.ImportBlocklistAsync("Test", "https://x/list.txt", CancellationToken.None);

        outcome.Total.Should().Be(2);           // a.com, b.com
        outcome.Duplicates.Should().Be(1);
        outcome.Invalid.Should().Be(1);
        outcome.HijackFlagged.Should().Be(1);
        outcome.MirrorUsed.Should().BeFalse();
    }

    [Fact]
    public async Task Import_falls_back_to_the_catalog_mirror_when_the_primary_fails()
    {
        // Use a real catalog source that has a mirror; primary throws, mirror serves.
        var src = BlocklistCatalog.Sources.First(s => s.Mirror.Length != 0);
        _fetcher.Responses[src.Mirror] = "0.0.0.0 mirror-served.com";
        // src.Url has no fake response → FetchAsync throws → mirror fallback.

        var outcome = await _importer.ImportBlocklistAsync(src.Name, src.Url, CancellationToken.None);

        outcome.MirrorUsed.Should().BeTrue();
        outcome.Total.Should().Be(1);
        _fetcher.Fetched.Should().Contain(src.Url).And.Contain(src.Mirror);
    }

    [Fact]
    public async Task Import_without_a_mirror_propagates_the_failure()
    {
        // "Custom" URL not in the catalog → no mirror → the fetch error surfaces.
        var act = async () => await _importer.ImportBlocklistAsync("Custom", "https://nope/none.txt", CancellationToken.None);
        await act.Should().ThrowAsync<InvalidOperationException>();
    }

    [Fact]
    public async Task Import_counts_allowlist_overrides()
    {
        _db.AddDomainsBulk([("keep.com", "whitelisted", "allowlist")]);
        _fetcher.Responses["https://x/list.txt"] = "0.0.0.0 keep.com\n0.0.0.0 block.com";

        var outcome = await _importer.ImportBlocklistAsync("Test", "https://x/list.txt", CancellationToken.None);

        outcome.AllowlistOverrides.Should().Be(1);
        _hosts.GetBlocked().Should().Contain("block.com").And.NotContain("keep.com");
    }
}
