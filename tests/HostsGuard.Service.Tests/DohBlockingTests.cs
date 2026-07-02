using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using FluentAssertions;
using HostsGuard.Contracts;
using HostsGuard.Core;
using HostsGuard.Data;
using HostsGuard.Ipc;
using HostsGuard.Windows;
using Microsoft.AspNetCore.Builder;
using Microsoft.Data.Sqlite;
using Xunit;

namespace HostsGuard.Service.Tests;

/// <summary>
/// NET-033: encrypted-DNS blocking (resolver-IP + port 853 rules, own-resolver
/// exemption) and the SHA-256-gated DoH intelligence refresh that preserves
/// prior state on failure.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class DohBlockingTests : IAsyncLifetime
{
    private string _dir = null!;
    private WebApplication _app = null!;
    private ServiceState _state = null!;
    private FakeFirewallEngine _fw = null!;
    private FakeListFetcher _fetcher = null!;
    private string _pipe = null!;
    private string _token = null!;

    public async Task InitializeAsync()
    {
        _dir = Path.Combine(Path.GetTempPath(), "hg_doh_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        var hostsPath = Path.Combine(_dir, "hosts");
        File.WriteAllText(hostsPath, "# hosts\n");

        _fw = new FakeFirewallEngine();
        _fetcher = new FakeListFetcher();
        _state = new ServiceState(
            new HostsEngine(hostsPath),
            new HostsDatabase(Path.Combine(_dir, "hostsguard.db")),
            _fw,
            dataDir: _dir,
            listFetcher: _fetcher);
        _token = SessionToken.Generate();
        _pipe = "HostsGuard.DohTest." + Guid.NewGuid().ToString("N");
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

    [Fact]
    public async Task Block_creates_resolver_and_port_853_rules_with_exemptions()
    {
        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var fw = new FirewallControl.FirewallControlClient(channel);

        var request = new DohBlockRequest();
        request.Exempt.Add("1.1.1.1"); // the user's own resolver
        var ack = await fw.BlockEncryptedDnsAsync(request);

        ack.Ok.Should().BeTrue();
        _fw.Rules.Should().ContainKey("HG_DoH_IPs");
        _fw.Rules["HG_DoH_IPs"].RemoteAddr.Should().Contain("185.228.168.168").And.NotContain("1.1.1.1,");
        _fw.Rules["HG_DoH_IPs"].RemoteAddr.Split(',').Should().NotContain("1.1.1.1");
        _fw.Rules["HG_DoT_TCP"].RemotePorts.Should().Be("853");
        _fw.Rules["HG_DoT_TCP"].Protocol.Should().Be("TCP");
        _fw.Rules["HG_DoT_UDP"].Protocol.Should().Be("UDP");
        _state.Db.GetFwStateNames().Should().Contain(new[] { "HG_DoH_IPs", "HG_DoT_TCP", "HG_DoT_UDP" });
    }

    [Fact]
    public async Task Unblock_removes_all_doh_rules()
    {
        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var fw = new FirewallControl.FirewallControlClient(channel);
        await fw.BlockEncryptedDnsAsync(new DohBlockRequest());

        var ack = await fw.UnblockEncryptedDnsAsync(new Empty());

        ack.Ok.Should().BeTrue();
        _fw.Rules.Keys.Should().NotContain(k => k.StartsWith("HG_Do"));
        _state.Db.GetFwStateNames().Should().NotContain("HG_DoH_IPs");
    }

    [Fact]
    public async Task Quic_block_creates_udp443_rule_and_status_reflects_it()
    {
        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var fw = new FirewallControl.FirewallControlClient(channel);
        var dns = new DnsControl.DnsControlClient(channel);

        (await dns.GetDohStatusAsync(new Empty())).QuicBlocked.Should().BeFalse();

        var ack = await fw.BlockQuicAsync(new Empty());
        ack.Ok.Should().BeTrue();
        _fw.Rules.Should().ContainKey("HG_QUIC_UDP443");
        _fw.Rules["HG_QUIC_UDP443"].Protocol.Should().Be("UDP");
        _fw.Rules["HG_QUIC_UDP443"].RemotePorts.Should().Be("443");
        _fw.Rules["HG_QUIC_UDP443"].Direction.Should().Be("Out");
        _state.Db.GetFwStateNames().Should().Contain("HG_QUIC_UDP443");
        (await dns.GetDohStatusAsync(new Empty())).QuicBlocked.Should().BeTrue();

        // Idempotent re-block.
        (await fw.BlockQuicAsync(new Empty())).Ok.Should().BeTrue();

        var un = await fw.UnblockQuicAsync(new Empty());
        un.Ok.Should().BeTrue();
        _fw.Rules.Should().NotContainKey("HG_QUIC_UDP443");
        _state.Db.GetFwStateNames().Should().NotContain("HG_QUIC_UDP443");
        (await dns.GetDohStatusAsync(new Empty())).QuicBlocked.Should().BeFalse();
    }

    [Fact]
    public async Task Doh_status_reflects_blocking_state()
    {
        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var dns = new DnsControl.DnsControlClient(channel);
        var fw = new FirewallControl.FirewallControlClient(channel);

        (await dns.GetDohStatusAsync(new Empty())).BlockingActive.Should().BeFalse();
        (await dns.GetDohStatusAsync(new Empty())).ResolverIps.Should().Be(DohResolvers.BuiltIn.Count);

        await fw.BlockEncryptedDnsAsync(new DohBlockRequest());

        (await dns.GetDohStatusAsync(new Empty())).BlockingActive.Should().BeTrue();
    }

    [Fact]
    public async Task Remote_refresh_requires_a_matching_sha256()
    {
        const string payload = """{"ips": ["203.0.113.53", "203.0.113.54"]}""";
        _fetcher.Responses["https://lists.test/doh.json"] = payload;
        var goodHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(payload))).ToLowerInvariant();

        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var dns = new DnsControl.DnsControlClient(channel);

        // No hash → rejected, state untouched.
        var noHash = await dns.RefreshDohIntelligenceAsync(new DohRefreshRequest { Url = "https://lists.test/doh.json" });
        noHash.Ok.Should().BeFalse();
        File.Exists(_state.Doh.FilePath).Should().BeFalse();

        // Wrong hash → rejected, state untouched.
        var badHash = await dns.RefreshDohIntelligenceAsync(new DohRefreshRequest
        {
            Url = "https://lists.test/doh.json",
            Sha256 = new string('0', 64),
        });
        badHash.Ok.Should().BeFalse();
        badHash.ErrorCode.Should().Be("hostsguard.error.v1/refresh_failed");
        File.Exists(_state.Doh.FilePath).Should().BeFalse();

        // Correct hash → learned IPs join the blocking set.
        var good = await dns.RefreshDohIntelligenceAsync(new DohRefreshRequest
        {
            Url = "https://lists.test/doh.json",
            Sha256 = goodHash,
        });
        good.Ok.Should().BeTrue();
        _state.Doh.CurrentIps().Should().Contain("203.0.113.53");

        var status = await dns.GetDohStatusAsync(new Empty());
        status.ExtraIps.Should().BeGreaterThanOrEqualTo(2);
        status.Sha256.Should().Be(goodHash);
    }

    [Fact]
    public async Task Failed_refresh_preserves_previous_state()
    {
        const string payload = """["203.0.113.99"]""";
        _fetcher.Responses["https://lists.test/doh1.json"] = payload;
        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(payload))).ToLowerInvariant();

        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var dns = new DnsControl.DnsControlClient(channel);
        (await dns.RefreshDohIntelligenceAsync(new DohRefreshRequest { Url = "https://lists.test/doh1.json", Sha256 = hash }))
            .Ok.Should().BeTrue();

        // Second refresh fails (fetcher has no response for the new URL).
        var failed = await dns.RefreshDohIntelligenceAsync(new DohRefreshRequest
        {
            Url = "https://lists.test/missing.json",
            Sha256 = new string('a', 64),
        });

        failed.Ok.Should().BeFalse();
        _state.Doh.CurrentIps().Should().Contain("203.0.113.99"); // prior state intact
    }

    [Fact]
    public void Connection_to_a_doh_resolver_is_categorized()
    {
        using var sub = _state.Bus.Subscribe<ConnectionEvent>();

        _state.PublishConnection(new ConnectionInfo("TCP", "10.0.0.5", 51000, "8.8.8.8", 443, "ESTABLISHED", 1, "browser.exe"));
        _state.PublishConnection(new ConnectionInfo("TCP", "10.0.0.5", 51001, "93.184.216.34", 443, "ESTABLISHED", 1, "browser.exe"));

        sub.Reader.TryRead(out var doh).Should().BeTrue();
        doh!.Category.Should().Be("DoH/DoT");
        sub.Reader.TryRead(out var plain).Should().BeTrue();
        plain!.Category.Should().BeEmpty();
    }
}
