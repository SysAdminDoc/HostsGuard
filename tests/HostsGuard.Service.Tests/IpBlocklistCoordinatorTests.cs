using System.Runtime.Versioning;
using FluentAssertions;
using HostsGuard.Data;
using Microsoft.Data.Sqlite;
using Xunit;

namespace HostsGuard.Service.Tests;

/// <summary>
/// NET-171: IP-format blocklists become chunked HG_IPBlock_* firewall block
/// rules with churn-guarded refresh, rollback, and safe-target filtering.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class IpBlocklistCoordinatorTests : IDisposable
{
    private const string Url = "https://lists.example.com/doh-ips.txt";

    private readonly string _dir;
    private readonly HostsDatabase _db;
    private readonly FakeFirewallEngine _firewall = new();
    private readonly FakeListFetcher _fetcher = new();
    private readonly IpBlocklistCoordinator _coordinator;

    public IpBlocklistCoordinatorTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "hg_iplists_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        _db = new HostsDatabase(Path.Combine(_dir, "hostsguard.db"));
        _coordinator = new IpBlocklistCoordinator(_db, _firewall, _fetcher);
    }

    private static string Addresses(int count) =>
        string.Join('\n', Enumerable.Range(0, count).Select(i => $"5.0.{i / 250}.{i % 250 + 1}"));

    private IReadOnlyList<string> IpBlockRules() =>
        _firewall.Rules.Keys.Where(k => k.StartsWith("HG_IPBlock_", StringComparison.Ordinal)).ToList();

    [Fact]
    public async Task Import_creates_chunked_block_rules()
    {
        _fetcher.Responses[Url] = Addresses(300);

        var outcome = await _coordinator.ImportAsync("doh-ips", Url, CancellationToken.None);

        outcome.Total.Should().Be(300);
        outcome.Rules.Should().Be(3); // 128 + 128 + 44
        outcome.Truncated.Should().BeFalse();
        IpBlockRules().Should().HaveCount(3);
        foreach (var rule in IpBlockRules().Select(r => _firewall.Rules[r]))
        {
            rule.Direction.Should().Be("Out");
            rule.Action.Should().Be("Block");
            rule.Enabled.Should().BeTrue();
            rule.RemoteAddr.Split(',').Length.Should().BeLessThanOrEqualTo(128);
        }

        var row = _db.GetIpBlocklistSource("doh-ips");
        row.Should().NotBeNull();
        row!.AddressCount.Should().Be(300);
        row.RuleCount.Should().Be(3);
        row.HealthStatus.Should().Be("ok");
    }

    [Fact]
    public async Task Reimport_deletes_stale_rules_when_the_list_shrinks()
    {
        _fetcher.Responses[Url] = Addresses(300);
        await _coordinator.ImportAsync("shrink", Url, CancellationToken.None);

        _fetcher.Responses[Url] = Addresses(100);
        var outcome = await _coordinator.ImportAsync("shrink", Url, CancellationToken.None);

        outcome.Rules.Should().Be(1);
        IpBlockRules().Should().HaveCount(1);
        _db.GetIpBlocklistSource("shrink")!.RuleCount.Should().Be(1);
    }

    [Fact]
    public async Task Scheduled_refresh_guards_suspicious_churn()
    {
        _fetcher.Responses[Url] = Addresses(200);
        await _coordinator.ImportAsync("guarded", Url, CancellationToken.None);

        _fetcher.Responses[Url] = Addresses(10); // 95% drop
        var outcome = await _coordinator.RefreshAllAsync(CancellationToken.None);

        outcome.Guarded.Should().Be(1);
        IpBlockRules().Should().HaveCount(2); // prior 200-address payload untouched
        var row = _db.GetIpBlocklistSource("guarded")!;
        row.AddressCount.Should().Be(200);
        row.HealthStatus.Should().Be("guarded");
        row.LastError.Should().Contain("fell");
    }

    [Fact]
    public async Task Scheduled_refresh_guards_an_empty_payload()
    {
        _fetcher.Responses[Url] = Addresses(10);
        await _coordinator.ImportAsync("emptied", Url, CancellationToken.None);

        _fetcher.Responses[Url] = "# nothing left\n";
        var outcome = await _coordinator.RefreshAllAsync(CancellationToken.None);

        outcome.Guarded.Should().Be(1);
        _db.GetIpBlocklistSource("emptied")!.AddressCount.Should().Be(10);
    }

    [Fact]
    public async Task Scheduled_refresh_records_fetch_failures()
    {
        _fetcher.Responses[Url] = Addresses(5);
        await _coordinator.ImportAsync("failing", Url, CancellationToken.None);

        _fetcher.Responses.Remove(Url); // FakeListFetcher throws on unknown URL
        var outcome = await _coordinator.RefreshAllAsync(CancellationToken.None);

        outcome.Failed.Should().Be(1);
        var row = _db.GetIpBlocklistSource("failing")!;
        row.HealthStatus.Should().Be("error");
        row.LastError.Should().NotBeEmpty();
    }

    [Fact]
    public async Task Rollback_restores_the_previous_payload()
    {
        _fetcher.Responses[Url] = "1.2.3.4\n5.6.7.8\n";
        await _coordinator.ImportAsync("rollme", Url, CancellationToken.None);

        _fetcher.Responses[Url] = "9.9.9.9\n";
        await _coordinator.ImportAsync("rollme", Url, CancellationToken.None);
        _firewall.Rules[IpBlockRules().Single()].RemoteAddr.Should().Be("9.9.9.9");

        var outcome = _coordinator.Rollback("rollme");

        outcome.Total.Should().Be(2);
        _firewall.Rules[IpBlockRules().Single()].RemoteAddr.Should().Be("1.2.3.4,5.6.7.8");
        var row = _db.GetIpBlocklistSource("rollme")!;
        row.AddressCount.Should().Be(2);
        row.HealthStatus.Should().Be("restored");
    }

    [Fact]
    public void Rollback_without_a_previous_payload_throws()
    {
        var act = () => _coordinator.Rollback("never-imported");
        act.Should().Throw<InvalidOperationException>();
    }

    [Fact]
    public async Task Remove_deletes_every_rule_and_the_subscription()
    {
        _fetcher.Responses[Url] = Addresses(300);
        await _coordinator.ImportAsync("removeme", Url, CancellationToken.None);

        var ack = _coordinator.Remove("removeme");

        ack.Ok.Should().BeTrue();
        IpBlockRules().Should().BeEmpty();
        _db.GetIpBlocklistSource("removeme").Should().BeNull();
    }

    [Fact]
    public async Task Disable_and_enable_toggle_the_live_rules()
    {
        _fetcher.Responses[Url] = Addresses(300);
        await _coordinator.ImportAsync("toggleme", Url, CancellationToken.None);

        _coordinator.SetEnabled("toggleme", false).Ok.Should().BeTrue();
        IpBlockRules().Select(r => _firewall.Rules[r].Enabled).Should().AllBeEquivalentTo(false);
        _db.GetIpBlocklistSource("toggleme")!.Enabled.Should().BeFalse();

        _coordinator.SetEnabled("toggleme", true).Ok.Should().BeTrue();
        IpBlockRules().Select(r => _firewall.Rules[r].Enabled).Should().AllBeEquivalentTo(true);
    }

    [Fact]
    public async Task Oversized_lists_are_capped_with_an_explicit_warning()
    {
        using var small = new IpBlocklistCoordinator(_db, _firewall, _fetcher, maxAddressesPerRule: 4, maxRules: 2);
        _fetcher.Responses[Url] = Addresses(10);

        var outcome = await small.ImportAsync("capped", Url, CancellationToken.None);

        outcome.Truncated.Should().BeTrue();
        outcome.Warning.Should().Contain("cap");
        outcome.Rules.Should().Be(2);
        var row = _db.GetIpBlocklistSource("capped")!;
        row.AddressCount.Should().Be(8);
        row.Truncated.Should().BeTrue();
    }

    [Fact]
    public async Task Unsafe_and_invalid_entries_never_become_rules()
    {
        _fetcher.Responses[Url] = "127.0.0.1\n10.0.0.0/8\n0.0.0.0/0\nnot-an-ip\n1.2.3.4\n";

        var outcome = await _coordinator.ImportAsync("mixed", Url, CancellationToken.None);

        outcome.Total.Should().Be(1);
        outcome.Unsafe.Should().Be(3);
        outcome.Invalid.Should().Be(1);
        _firewall.Rules[IpBlockRules().Single()].RemoteAddr.Should().Be("1.2.3.4");
    }

    private sealed class BlockingFetcher : IListFetcher
    {
        public readonly ManualResetEventSlim Started = new(false);
        public readonly ManualResetEventSlim Release = new(false);

        public async Task<string> FetchAsync(string url, int maxBytes, CancellationToken ct)
        {
            Started.Set();
            await Task.Run(() => Release.Wait(ct), ct);
            return "9.9.9.9";
        }

        public Task<byte[]> FetchBytesAsync(string url, int maxBytes, CancellationToken ct)
            => Task.FromResult(System.Text.Encoding.UTF8.GetBytes("9.9.9.9"));
    }

    [Fact]
    public async Task Dispose_drains_an_in_flight_scheduled_refresh()
    {
        // The timer callback fire-and-forgets an async refresh; Dispose must wait
        // for it so it can never touch the DB/firewall after Db.Dispose.
        var fetcher = new BlockingFetcher();
        var coordinator = new IpBlocklistCoordinator(_db, _firewall, fetcher);
        _db.UpsertIpBlocklistSource("drain", "https://lists.example.com/x.txt",
            new[] { "9.9.9.9" }, "seed-hash", string.Empty, 0, Array.Empty<string>(), 1, truncated: false);

        coordinator.KickScheduledRefresh(); // simulate the timer tick
        fetcher.Started.Wait(TimeSpan.FromSeconds(5)).Should().BeTrue("the scheduled refresh should reach the fetcher");

        var dispose = Task.Run(() => coordinator.Dispose());
        (await Task.WhenAny(dispose, Task.Delay(300))).Should().NotBe(dispose,
            "Dispose must block while a refresh is in flight");

        fetcher.Release.Set();
        (await Task.WhenAny(dispose, Task.Delay(TimeSpan.FromSeconds(6)))).Should().Be(dispose,
            "Dispose returns once the in-flight refresh drains");
        await dispose;
    }

    public void Dispose()
    {
        _coordinator.Dispose();
        _db.Dispose();
        SqliteConnection.ClearAllPools();
        try
        {
            Directory.Delete(_dir, recursive: true);
        }
        catch (IOException)
        {
        }
    }
}
