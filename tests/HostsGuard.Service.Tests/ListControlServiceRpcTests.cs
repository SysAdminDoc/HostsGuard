using System.Runtime.Versioning;
using FluentAssertions;
using Grpc.Core;
using HostsGuard.Contracts;
using HostsGuard.Core;
using HostsGuard.Data;
using HostsGuard.Windows;
using Microsoft.Data.Sqlite;
using Xunit;

namespace HostsGuard.Service.Tests;

/// <summary>
/// Direct in-proc RPC tests for <see cref="ListControlServiceImpl"/> — request
/// validation and error-code mapping for the blocklist/allowlist/IP-blocklist
/// handler layer, which the coordinator-level tests do not exercise. A fake list
/// fetcher wires the coordinators so the not-found/no-checkpoint paths run.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class ListControlServiceRpcTests : IDisposable
{
    private readonly string _dir;
    private readonly ServiceState _state;
    private readonly ListControlServiceImpl _lists;

    public ListControlServiceRpcTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "hg_listrpc_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        File.WriteAllText(Path.Combine(_dir, "hosts"), "# hosts\n");
        _state = new ServiceState(
            new HostsEngine(Path.Combine(_dir, "hosts")),
            new HostsDatabase(Path.Combine(_dir, "hostsguard.db")),
            firewall: new FakeFirewallEngine(),
            dataDir: _dir,
            listFetcher: new FakeListFetcher());
        _lists = new ListControlServiceImpl(_state);
    }

    // The content-import handlers read context.CancellationToken, so a real (if
    // minimal) context is needed rather than the null! the other handlers accept.
    private static readonly ServerCallContext Ctx = new FakeServerCallContext();

    private sealed class FakeServerCallContext : ServerCallContext
    {
        protected override string MethodCore => string.Empty;
        protected override string HostCore => string.Empty;
        protected override string PeerCore => string.Empty;
        protected override DateTime DeadlineCore => DateTime.MaxValue;
        protected override Metadata RequestHeadersCore => new();
        protected override CancellationToken CancellationTokenCore => CancellationToken.None;
        protected override Metadata ResponseTrailersCore => new();
        protected override Status StatusCore { get; set; }
        protected override WriteOptions? WriteOptionsCore { get; set; }
        protected override AuthContext AuthContextCore => new(null, new Dictionary<string, List<AuthProperty>>());
        protected override ContextPropagationToken CreatePropagationTokenCore(ContextPropagationOptions? options) => null!;
        protected override Task WriteResponseHeadersAsyncCore(Metadata responseHeaders) => Task.CompletedTask;
    }

    [Fact]
    public async Task Blocklist_name_is_required()
    {
        (await _lists.SetBlocklistEnabled(new BlocklistToggleRequest { Name = "  ", Enabled = true }, Ctx))
            .ErrorCode.Should().Be("hostsguard.error.v1/invalid_source");
        (await _lists.RemoveBlocklistSubscription(new BlocklistRequest { Name = "" }, Ctx))
            .ErrorCode.Should().Be("hostsguard.error.v1/invalid_source");
        (await _lists.RestoreBlocklistCheckpoint(new BlocklistRequest { Name = "" }, Ctx))
            .ErrorCode.Should().Be("hostsguard.error.v1/invalid_source");
    }

    [Fact]
    public async Task Restore_without_a_checkpoint_reports_no_checkpoint()
    {
        (await _lists.RestoreBlocklistCheckpoint(new BlocklistRequest { Name = "never-subscribed" }, Ctx))
            .ErrorCode.Should().Be("hostsguard.error.v1/no_checkpoint");
    }

    [Fact]
    public async Task Allowlists_reject_non_https_and_round_trip_https()
    {
        (await _lists.SetAllowlists(new AllowlistUrls { Urls = { "http://insecure.example/allow.txt" } }, Ctx))
            .ErrorCode.Should().Be("hostsguard.error.v1/invalid_source");

        (await _lists.SetAllowlists(new AllowlistUrls { Urls = { "https://good.example/allow.txt" } }, Ctx))
            .Ok.Should().BeTrue();
        (await _lists.GetAllowlists(new Empty(), Ctx)).Urls.Should().Contain("https://good.example/allow.txt");
    }

    [Fact]
    public async Task Ip_blocklist_name_is_required_and_unknown_reports_not_found()
    {
        (await _lists.SetIpBlocklistEnabled(new BlocklistToggleRequest { Name = "", Enabled = true }, Ctx))
            .ErrorCode.Should().Be("hostsguard.error.v1/invalid_source");
        (await _lists.RemoveIpBlocklist(new BlocklistRequest { Name = "" }, Ctx))
            .ErrorCode.Should().Be("hostsguard.error.v1/invalid_source");
        (await _lists.RollbackIpBlocklist(new BlocklistRequest { Name = "" }, Ctx))
            .ErrorCode.Should().Be("hostsguard.error.v1/invalid_source");

        // A well-formed name for a source that was never subscribed → not_found.
        (await _lists.SetIpBlocklistEnabled(new BlocklistToggleRequest { Name = "ghost-ips", Enabled = false }, Ctx))
            .ErrorCode.Should().Be("hostsguard.error.v1/not_found");
    }

    [Fact]
    public async Task ListIpBlocklists_starts_empty()
        => (await _lists.ListIpBlocklists(new Empty(), Ctx)).Sources.Should().BeEmpty();

    private static BlocklistContentRequest Content(string name, string text)
        => new() { Name = name, Content = Google.Protobuf.ByteString.CopyFromUtf8(text) };

    [Fact]
    public async Task Import_from_local_content_blocks_domains_offline()
    {
        const string hosts = "0.0.0.0 ads.example.com\n0.0.0.0 track.example.net\n# comment\n";

        var preview = await _lists.PreviewBlocklistContent(Content("my-local", hosts), Ctx);
        preview.Ok.Should().BeTrue();
        preview.Added.Should().Be(2);
        _state.Hosts.GetBlocked().Should().NotContain("ads.example.com"); // preview does not mutate

        var import = await _lists.ImportBlocklistContent(Content("my-local", hosts), Ctx);
        import.Ok.Should().BeTrue();
        import.Added.Should().Be(2);
        _state.Hosts.GetBlocked().Should().Contain(new[] { "ads.example.com", "track.example.net" });

        // The local source is listed as a custom subscription and removes cleanly.
        (await _lists.ListBlocklistSources(new Empty(), Ctx)).Sources
            .Should().Contain(s => s.Name == "my-local");
        (await _lists.RemoveBlocklistSubscription(new BlocklistRequest { Name = "my-local" }, Ctx)).Ok.Should().BeTrue();
        _state.Hosts.GetBlocked().Should().NotContain("ads.example.com");
    }

    [Fact]
    public async Task Local_content_import_validates_name_content_and_size()
    {
        (await _lists.ImportBlocklistContent(Content("  ", "0.0.0.0 x.example\n"), Ctx))
            .ErrorCode.Should().Be("hostsguard.error.v1/invalid_source");
        (await _lists.ImportBlocklistContent(Content("empty", ""), Ctx))
            .ErrorCode.Should().Be("hostsguard.error.v1/invalid_source");

        var huge = new BlocklistContentRequest
        {
            Name = "huge",
            Content = Google.Protobuf.ByteString.CopyFrom(new byte[BlocklistCatalog.MaxBlocklistBytes + 1]),
        };
        (await _lists.ImportBlocklistContent(huge, Ctx)).ErrorCode.Should().Be("hostsguard.error.v1/content_too_large");
    }

    [Fact]
    public async Task A_refresh_skips_locally_imported_sources()
    {
        await _lists.ImportBlocklistContent(Content("local-only", "0.0.0.0 keep.example\n"), Ctx);

        // No refreshable subscriptions exist, so refresh is a clean no-op and the
        // local source (local: URL) is never fetched or dropped.
        var refresh = await _lists.RefreshBlocklists(new Empty(), Ctx);
        refresh.Ok.Should().BeTrue();
        _state.Hosts.GetBlocked().Should().Contain("keep.example");
    }

    public void Dispose()
    {
        _state.Dispose();
        SqliteConnection.ClearAllPools();
        try { Directory.Delete(_dir, true); } catch (IOException) { /* best effort */ }
    }
}
