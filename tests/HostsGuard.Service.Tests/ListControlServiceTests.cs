using System.Runtime.Versioning;
using System.Text;
using FluentAssertions;
using HostsGuard.Contracts;
using HostsGuard.Data;
using HostsGuard.Ipc;
using HostsGuard.Windows;
using Microsoft.AspNetCore.Builder;
using Microsoft.Data.Sqlite;
using Xunit;

namespace HostsGuard.Service.Tests;

internal sealed class FakeListFetcher : IListFetcher
{
    public Dictionary<string, string> Responses { get; } = new(StringComparer.Ordinal);

    public Dictionary<string, byte[]> BinaryResponses { get; } = new(StringComparer.Ordinal);

    public List<string> Fetched { get; } = new();

    public Task<string> FetchAsync(string url, int maxBytes, CancellationToken ct)
    {
        Fetched.Add(url);
        if (!Responses.TryGetValue(url, out var text))
        {
            throw new InvalidOperationException($"no fake response for {url}");
        }

        var bytes = Encoding.UTF8.GetByteCount(text);
        if (bytes > maxBytes)
        {
            throw new InvalidOperationException($"list at {url} exceeds {maxBytes} bytes");
        }

        return Task.FromResult(text);
    }

    public Task<byte[]> FetchBytesAsync(string url, int maxBytes, CancellationToken ct)
    {
        Fetched.Add(url);
        if (!BinaryResponses.TryGetValue(url, out var data))
        {
            throw new InvalidOperationException($"no fake binary response for {url}");
        }

        if (data.Length > maxBytes)
        {
            throw new InvalidOperationException($"list at {url} exceeds {maxBytes} bytes");
        }

        return Task.FromResult(data);
    }
}

/// <summary>
/// NET-030/031: blocklist import (parse, dedupe, bulk upsert, subscription,
/// diff counts, oversized warning) and allowlist subscriptions that always win.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class ListControlServiceTests : IAsyncLifetime
{
    private string _dir = null!;
    private WebApplication _app = null!;
    private ServiceState _state = null!;
    private FakeListFetcher _fetcher = null!;
    private string _pipe = null!;
    private string _token = null!;

    public async Task InitializeAsync()
    {
        _dir = Path.Combine(Path.GetTempPath(), "hg_lists_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        var hostsPath = Path.Combine(_dir, "hosts");
        File.WriteAllText(hostsPath, "# hosts\n");

        _fetcher = new FakeListFetcher();
        _state = new ServiceState(
            new HostsEngine(hostsPath),
            new HostsDatabase(Path.Combine(_dir, "hostsguard.db")),
            dataDir: _dir,
            listFetcher: _fetcher);
        _token = SessionToken.Generate();
        _pipe = "HostsGuard.ListsTest." + Guid.NewGuid().ToString("N");
        _app = ServiceHost.Build(_state, _token, _pipe);
        await _app.StartAsync();
    }

    public async Task DisposeAsync()
    {
        await _app.DisposeAsync();
        _state.Dispose();
        SqliteConnection.ClearAllPools();
        try { Directory.Delete(_dir, true); } catch (IOException) { /* best effort */ }
    }

    private ListControl.ListControlClient Client(Grpc.Net.Client.GrpcChannel ch) => new(ch);

    [Fact]
    public async Task Import_parses_blocks_records_subscription_and_reports_diff()
    {
        _fetcher.Responses["https://lists.test/ads.txt"] = """
            # comment header
            0.0.0.0 ads.example.com
            127.0.0.1 track.example.net # trailing comment
            plain.example.org
            0.0.0.0 ads.example.com
            not a valid line !!!
            localhost
            """;

        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var result = await Client(channel).ImportBlocklistAsync(
            new BlocklistRequest { Name = "Test Ads", Url = "https://lists.test/ads.txt" });

        result.Ok.Should().BeTrue();
        result.Total.Should().Be(3); // deduped, comments/invalid/localhost dropped
        result.Added.Should().Be(3);
        _state.Hosts.GetBlocked().Should().BeEquivalentTo("ads.example.com", "track.example.net", "plain.example.org");
        _state.Db.GetDomainSource("ads.example.com").Should().Be("list:Test Ads");
        _state.Db.RecordDnsSightings(new[]
        {
            new DnsSightingWrite("ads.example.com", "browser", null, DateTime.Now),
            new DnsSightingWrite("track.example.net", "browser", null, DateTime.Now),
        });

        var sources = await Client(channel).ListBlocklistSourcesAsync(new Empty());
        sources.Sources.Should().Contain(s =>
            s.Name == "Test Ads" &&
            s.Subscribed &&
            s.DomainCount == 3 &&
            s.Category == "Custom" &&
            s.Hits30D == 2);
    }

    [Fact]
    public async Task Curated_catalog_lists_25_plus_sources_with_large_flags()
    {
        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var sources = await Client(channel).ListBlocklistSourcesAsync(new Empty());

        sources.Sources.Count.Should().BeGreaterThanOrEqualTo(25);
        sources.Sources.Should().Contain(s => s.Name == "StevenBlack Unified" && s.LargeListWarning);
        sources.Sources.Should().Contain(s => s.Name == "AdAway" && !s.LargeListWarning);
    }

    [Fact]
    public async Task Import_rejects_non_https_sources()
    {
        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var result = await Client(channel).ImportBlocklistAsync(
            new BlocklistRequest { Name = "Evil", Url = "http://lists.test/x.txt" });

        result.Ok.Should().BeFalse();
        result.ErrorCode.Should().Be("hostsguard.error.v1/invalid_source");
    }

    [Fact]
    public async Task Whitelisted_domain_survives_a_blocklist_import()
    {
        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var hosts = new HostsControl.HostsControlClient(channel);
        await hosts.AllowAsync(new DomainRequest { Domain = "keep.example.com", Source = "manual" });

        _fetcher.Responses["https://lists.test/all.txt"] = "0.0.0.0 keep.example.com\n0.0.0.0 bad.example.com\n";
        var result = await Client(channel).ImportBlocklistAsync(
            new BlocklistRequest { Name = "All", Url = "https://lists.test/all.txt" });

        result.Ok.Should().BeTrue();
        _state.Db.GetDomainStatus("keep.example.com").Should().Be("whitelisted"); // upsert never downgraded
        _state.Hosts.GetBlocked().Should().NotContain("keep.example.com");        // re-applied after import
        _state.Hosts.GetBlocked().Should().Contain("bad.example.com");
    }

    [Fact]
    public async Task Refresh_all_reimports_every_subscription()
    {
        _fetcher.Responses["https://lists.test/a.txt"] = "0.0.0.0 a1.example.com\n";
        _fetcher.Responses["https://lists.test/b.txt"] = "0.0.0.0 b1.example.com\n";
        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var client = Client(channel);
        await client.ImportBlocklistAsync(new BlocklistRequest { Name = "A", Url = "https://lists.test/a.txt" });
        await client.ImportBlocklistAsync(new BlocklistRequest { Name = "B", Url = "https://lists.test/b.txt" });

        _fetcher.Responses["https://lists.test/a.txt"] = "0.0.0.0 a1.example.com\n0.0.0.0 a2.example.com\n";
        var result = await client.RefreshBlocklistsAsync(new Empty());

        result.Ok.Should().BeTrue();
        _state.Hosts.GetBlocked().Should().Contain(new[] { "a1.example.com", "a2.example.com", "b1.example.com" });
    }

    [Fact]
    public async Task Disable_stops_refresh_but_keeps_domains()
    {
        _fetcher.Responses["https://lists.test/c.txt"] = "0.0.0.0 c1.example.com\n";
        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var client = Client(channel);
        await client.ImportBlocklistAsync(new BlocklistRequest { Name = "C", Url = "https://lists.test/c.txt" });

        (await client.SetBlocklistEnabledAsync(new BlocklistToggleRequest { Name = "C", Enabled = false })).Ok.Should().BeTrue();

        _fetcher.Fetched.Clear();
        await client.RefreshBlocklistsAsync(new Empty());
        _fetcher.Fetched.Should().BeEmpty();
        _state.Hosts.GetBlocked().Should().Contain("c1.example.com");
    }

    [Fact]
    public async Task Preview_does_not_mutate_and_remove_rolls_back_only_source_owned_domains()
    {
        _fetcher.Responses["https://lists.test/a.txt"] = """
            0.0.0.0 only-a.example.com
            0.0.0.0 shared.example.com
            0.0.0.0 manual.example.com
            bad line !!!
            """;
        _fetcher.Responses["https://lists.test/b.txt"] = """
            0.0.0.0 shared.example.com
            0.0.0.0 only-b.example.com
            """;
        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var client = Client(channel);
        var hosts = new HostsControl.HostsControlClient(channel);
        await hosts.BlockAsync(new DomainRequest { Domain = "manual.example.com", Source = "manual" });

        var preview = await client.PreviewBlocklistAsync(new BlocklistRequest { Name = "A", Url = "https://lists.test/a.txt" });
        preview.Ok.Should().BeTrue();
        preview.Preview.Should().BeTrue();
        preview.Total.Should().Be(3);
        preview.Added.Should().Be(2);
        preview.Invalid.Should().Be(1);
        _state.Hosts.GetBlocked().Should().NotContain("only-a.example.com");

        await client.ImportBlocklistAsync(new BlocklistRequest { Name = "A", Url = "https://lists.test/a.txt" });
        await client.ImportBlocklistAsync(new BlocklistRequest { Name = "B", Url = "https://lists.test/b.txt" });

        var ack = await client.RemoveBlocklistSubscriptionAsync(new BlocklistRequest { Name = "A" });

        ack.Ok.Should().BeTrue();
        ack.Message.Should().Contain("deleted 1").And.Contain("preserved 2");
        _state.Hosts.GetBlocked().Should().NotContain("only-a.example.com");
        _state.Hosts.GetBlocked().Should().Contain(new[] { "shared.example.com", "only-b.example.com", "manual.example.com" });
        _state.Db.GetDomainSource("manual.example.com").Should().Be("manual");
        _state.Db.GetBlocklistSubs().Should().NotContain(s => s.Name == "A");
    }

    [Fact]
    public async Task Allowlist_subscriptions_whitelist_and_unblock()
    {
        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var client = Client(channel);
        _fetcher.Responses["https://lists.test/block.txt"] = "0.0.0.0 cdn.example.com\n0.0.0.0 junk.example.com\n";
        await client.ImportBlocklistAsync(new BlocklistRequest { Name = "Block", Url = "https://lists.test/block.txt" });

        _fetcher.Responses["https://lists.test/allow.txt"] = "cdn.example.com\n";
        var urls = new AllowlistUrls();
        urls.Urls.Add("https://lists.test/allow.txt");
        (await client.SetAllowlistsAsync(urls)).Ok.Should().BeTrue();
        (await client.RefreshAllowlistsAsync(new Empty())).Ok.Should().BeTrue();

        _state.Db.GetDomainStatus("cdn.example.com").Should().Be("whitelisted");
        _state.Hosts.GetBlocked().Should().NotContain("cdn.example.com");

        // A later blocklist import cannot re-block it.
        await client.ImportBlocklistAsync(new BlocklistRequest { Name = "Block", Url = "https://lists.test/block.txt" });
        _state.Db.GetDomainStatus("cdn.example.com").Should().Be("whitelisted");
        _state.Hosts.GetBlocked().Should().NotContain("cdn.example.com");
    }

    [Fact]
    public async Task Allowlist_urls_must_be_https()
    {
        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var urls = new AllowlistUrls();
        urls.Urls.Add("ftp://lists.test/allow.txt");

        var ack = await Client(channel).SetAllowlistsAsync(urls);

        ack.Ok.Should().BeFalse();
        ack.ErrorCode.Should().Be("hostsguard.error.v1/invalid_source");
    }

    [Fact]
    public async Task Oversized_import_surfaces_the_dns_client_warning()
    {
        var sb = new StringBuilder();
        for (var i = 0; i < 100_100; i++)
        {
            sb.Append("0.0.0.0 d").Append(i).Append(".bulk.example.com\n");
        }

        _fetcher.Responses["https://lists.test/huge.txt"] = sb.ToString();
        using var channel = NamedPipeChannel.Create(_token, _pipe);

        var result = await Client(channel).ImportBlocklistAsync(
            new BlocklistRequest { Name = "Huge", Url = "https://lists.test/huge.txt" });

        result.Ok.Should().BeTrue();
        result.HostsEntries.Should().BeGreaterThan(100_000);
        result.Warning.Should().Contain("DNS Client");
    }
}
