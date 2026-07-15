using System.IO.Compression;
using System.Runtime.Versioning;
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
/// NET-035: threat-intel overlay (Feodo refresh, persisted set, THREAT flag on
/// live connections), GeoIP refresh guards (gzip cap + corrupt-database
/// rejection), and the Core gzip-expansion cap.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class ThreatGeoIpTests : IAsyncLifetime
{
    private string _dir = null!;
    private WebApplication _app = null!;
    private ServiceState _state = null!;
    private FakeListFetcher _fetcher = null!;
    private FakeDnsConfig _dns = null!;
    private string _pipe = null!;
    private string _token = null!;

    public async Task InitializeAsync()
    {
        _dir = Path.Combine(Path.GetTempPath(), "hg_threat_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        var hostsPath = Path.Combine(_dir, "hosts");
        File.WriteAllText(hostsPath, "# hosts\n");

        _fetcher = new FakeListFetcher();
        _dns = new FakeDnsConfig();
        _state = new ServiceState(
            new HostsEngine(hostsPath),
            new HostsDatabase(Path.Combine(_dir, "hostsguard.db")),
            dataDir: _dir,
            listFetcher: _fetcher,
            dns: _dns);
        _token = SessionToken.Generate();
        _pipe = "HostsGuard.ThreatTest." + Guid.NewGuid().ToString("N");
        _app = ServiceHost.Build(_state, _token, _pipe);
        await _app.StartAsync();
    }

    public async Task DisposeAsync()
    {
        await _app.DisposeAsync();
        _state.Dispose();
        try { Directory.Delete(_dir, true); } catch (IOException) { /* best effort */ }
    }

    [Fact]
    public async Task Threat_refresh_parses_persists_and_flags_connections()
    {
        _fetcher.Responses[ThreatIntel.FeodoUrl] = """
            # Feodo Tracker botnet C2 IP blocklist
            198.51.100.66
            203.0.113.99
            not-an-ip
            """;

        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var ack = await new ListControl.ListControlClient(channel).RefreshThreatIntelAsync(new Empty());

        ack.Ok.Should().BeTrue();
        ack.Message.Should().Contain("2 IPs");
        _state.Threats.Contains("198.51.100.66").Should().BeTrue();

        // The set survives a service restart via the persisted file.
        var reloaded = new ThreatIntel(_dir);
        reloaded.Contains("203.0.113.99").Should().BeTrue();

        // Live connections to a listed IP surface as THREAT.
        using var sub = _state.Bus.Subscribe<ConnectionEvent>();
        _state.PublishConnection(new ConnectionInfo("TCP", "10.0.0.5", 51000, "198.51.100.66", 443, "ESTABLISHED", 1, "evil.exe"));
        sub.Reader.TryRead(out var ev).Should().BeTrue();
        ev!.FwStatus.Should().Be("THREAT");
        _state.Db.GetAlerts(new AlertFilter(Type: "threat_hit")).Rows
            .Should().ContainSingle(a => a.Subject == "198.51.100.66" && a.Process == "evil.exe");
    }

    [Fact]
    public async Task Empty_threat_list_is_rejected_and_prior_set_kept()
    {
        _fetcher.Responses[ThreatIntel.FeodoUrl] = "198.51.100.66\n";
        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var lists = new ListControl.ListControlClient(channel);
        (await lists.RefreshThreatIntelAsync(new Empty())).Ok.Should().BeTrue();

        _fetcher.Responses[ThreatIntel.FeodoUrl] = "# nothing but comments\n";
        var ack = await lists.RefreshThreatIntelAsync(new Empty());

        ack.Ok.Should().BeFalse();
        _state.Threats.Contains("198.51.100.66").Should().BeTrue();
    }

    [Fact]
    public async Task Threat_refresh_rescans_only_bounded_privacy_eligible_history_and_dedupes_forever()
    {
        var now = DateTime.Now;
        _state.Db.HistoryRetentionDays = 365;
        _state.Db.UpsertHistoryPrivacyExclusion("domain", "private.example");
        _state.Db.RecordConnection(new ConnHistoryRow(now.AddMinutes(-5).ToString("o"), "one.exe", 1, "TCP",
            "198.51.100.66", 443, "US", string.Empty, "public.example"));
        _state.Db.RecordConnection(new ConnHistoryRow(now.AddMinutes(-4).ToString("o"), "one.exe", 1, "TCP",
            "198.51.100.66", 8443, "US", string.Empty, "public.example"));
        _state.Db.RecordConnection(new ConnHistoryRow(now.AddMinutes(-3).ToString("o"), "two.exe", 2, "UDP",
            "203.0.113.99", 53, "US", string.Empty));
        _state.Db.RecordConnection(new ConnHistoryRow(now.AddMinutes(-2).ToString("o"), "private.exe", 3, "TCP",
            "192.0.2.10", 443, "US", string.Empty, "api.private.example"));
        _state.Db.RecordConnection(new ConnHistoryRow(now.AddDays(-31).ToString("o"), "expired.exe", 4, "TCP",
            "192.0.2.11", 443, "US", string.Empty));
        _state.Db.RecordConnection(new ConnHistoryRow(now.AddMinutes(-1).ToString("o"), "benign.exe", 5, "TCP",
            "192.0.2.12", 443, "US", string.Empty));
        _fetcher.Responses[ThreatIntel.FeodoUrl] = "198.51.100.66\n203.0.113.99\n192.0.2.10\n192.0.2.11\n";

        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var client = new ListControl.ListControlClient(channel);
        var first = await client.RefreshThreatIntelAsync(new Empty());

        first.Ok.Should().BeTrue();
        first.Message.Should().Contain("scanned 4 retained connections").And.Contain("2 new alerts");
        var alerts = _state.Db.GetAlerts(new AlertFilter(Type: "threat_hit", SurfaceOnly: false)).Rows;
        alerts.Should().HaveCount(2).And.OnlyContain(alert =>
            alert.Action == "threat_connection" &&
            alert.Details.Contains("alert-only", StringComparison.Ordinal) &&
            !alert.Details.Contains("private.example", StringComparison.Ordinal));
        _state.Db.GetFwState().Should().BeEmpty("retrospective matching is alert-only");

        _state.Db.AckAlerts(alerts.Select(alert => alert.Id)).Should().Be(2);
        var second = await client.RefreshThreatIntelAsync(new Empty());

        second.Ok.Should().BeTrue();
        second.Message.Should().Contain("0 new alerts");
        _state.Db.GetAlerts(new AlertFilter(
            IncludeRead: true,
            SurfaceOnly: false,
            Type: "threat_hit")).Rows.Should().HaveCount(2);
    }

    [Fact]
    public async Task Corrupt_geoip_download_never_replaces_state()
    {
        var junk = new byte[2048];
        Random.Shared.NextBytes(junk);
        using var compressedStream = new MemoryStream();
        using (var gz = new GZipStream(compressedStream, CompressionMode.Compress, leaveOpen: true))
        {
            gz.Write(junk);
        }

        _fetcher.BinaryResponses[GeoIpService.DefaultUrl] = compressedStream.ToArray();

        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var ack = await new ListControl.ListControlClient(channel).RefreshGeoIpAsync(new Empty());

        ack.Ok.Should().BeFalse();
        ack.Message.Should().Contain("invalid");
        _state.GeoIp.IsLoaded.Should().BeFalse();
        File.Exists(Path.Combine(_dir, "geoip.mmdb")).Should().BeFalse();
    }

    [Fact]
    public void Unloaded_geoip_lookup_is_empty_not_crashing()
        => _state.GeoIp.Lookup("8.8.8.8").Should().BeEmpty();

    [Fact]
    public void Dns_bypass_alert_is_opt_in_flags_direct_port53_and_ignores_the_system_resolver()
    {
        // Off by default: an app's direct port-53 to a public resolver records nothing.
        _state.PublishConnection(new ConnectionInfo("UDP", "10.0.0.5", 55000, "1.1.1.1", 53, "ESTABLISHED", 4321, "curl.exe"));
        _state.Db.GetAlerts(new AlertFilter(SurfaceOnly: false, Type: "dns_bypass")).Rows.Should().BeEmpty();

        // Enable the opt-in type.
        _state.Db.SetAlertTypeSurface("dns_bypass", true);

        // The Windows DNS Client (svchost) owns the system resolver — never flagged.
        _state.PublishConnection(new ConnectionInfo("UDP", "10.0.0.5", 55001, "8.8.8.8", 53, "ESTABLISHED", 900, "svchost.exe"));
        _state.Db.GetAlerts(new AlertFilter(Type: "dns_bypass")).Rows.Should().BeEmpty();

        // A private/LAN resolver on 53 is the normal path — not a bypass.
        _state.PublishConnection(new ConnectionInfo("UDP", "10.0.0.5", 55002, "192.168.1.1", 53, "ESTABLISHED", 4321, "curl.exe"));
        _state.Db.GetAlerts(new AlertFilter(Type: "dns_bypass")).Rows.Should().BeEmpty();

        // An app talking DNS directly to a public resolver IS a bypass; fires once.
        _state.PublishConnection(new ConnectionInfo("UDP", "10.0.0.5", 55003, "1.1.1.1", 53, "ESTABLISHED", 4321, "curl.exe"));
        _state.PublishConnection(new ConnectionInfo("UDP", "10.0.0.5", 55004, "9.9.9.9", 53, "ESTABLISHED", 4321, "curl.exe"));
        _state.Db.GetAlerts(new AlertFilter(Type: "dns_bypass")).Rows
            .Should().ContainSingle(a => a.Process == "curl.exe");
    }

    [Fact]
    public void Inbound_dns_reply_is_not_reported_as_an_outbound_dns_bypass()
    {
        _state.Db.SetAlertTypeSurface("dns_bypass", true);

        _state.PublishConnection(new ConnectionInfo("UDP", "10.0.0.5", 55000,
            "1.1.1.1", 53, "STATELESS", 4321, "curl.exe", "inbound"));

        _state.Db.GetAlerts(new AlertFilter(Type: "dns_bypass")).Rows.Should().BeEmpty();
    }

    [Fact]
    public async Task Encrypted_dns_plaintext_fallback_is_alert_only_and_excludes_false_positives()
    {
        _dns.EncryptedResolverAddresses.Add("1.1.1.1");
        _dns.EncryptedResolverAddresses.Add("192.168.1.1");
        using var connectionEvents = _state.Bus.Subscribe<ConnectionEvent>();

        // Windows DNS Client traffic to a configured public DoH resolver on port 53 is fallback evidence.
        _state.PublishConnection(new ConnectionInfo("udp", "10.0.0.5", 55000,
            "1.1.1.1", 53, "STATELESS", 900, "svchost.exe"));
        connectionEvents.Reader.TryRead(out var fallbackEvent).Should().BeTrue();
        fallbackEvent!.Category.Should().Be("DNS plaintext fallback");
        _state.PublishConnection(new ConnectionInfo("UDP", "10.0.0.5", 55001,
            "1.1.1.1", 53, "STATELESS", 900, "svchost.exe"));

        // An intentional plaintext resolver, private resolver, direct app, and inbound reply are not fallback.
        _state.PublishConnection(new ConnectionInfo("UDP", "10.0.0.5", 55002,
            "8.8.8.8", 53, "STATELESS", 900, "svchost.exe"));
        _state.PublishConnection(new ConnectionInfo("UDP", "10.0.0.5", 55003,
            "192.168.1.1", 53, "STATELESS", 900, "svchost.exe"));
        _state.PublishConnection(new ConnectionInfo("UDP", "10.0.0.5", 55004,
            "1.1.1.1", 53, "STATELESS", 4321, "curl.exe"));
        _state.PublishConnection(new ConnectionInfo("UDP", "10.0.0.5", 55005,
            "1.1.1.1", 53, "STATELESS", 900, "svchost.exe", "inbound"));

        var alerts = _state.Db.GetAlerts(new AlertFilter(
            IncludeRead: true,
            SurfaceOnly: false,
            Type: "dns_plaintext_fallback")).Rows;
        alerts.Should().ContainSingle();
        alerts[0].Subject.Should().Be("1.1.1.1");
        alerts[0].Process.Should().Be("svchost.exe");
        alerts[0].Surfaced.Should().BeTrue();
        alerts[0].Details.Should().Contain("interface-specific DoH template")
            .And.Contain("alert only")
            .And.Contain("did not change DNS or firewall policy");
        _dns.EncryptedResolverReads.Should().Be(1, "high-volume DNS observations reuse a bounded posture snapshot");
        _state.Db.GetFwState().Should().BeEmpty();
        File.ReadAllText(Path.Combine(_dir, "hosts")).Should().Be("# hosts\n");

        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var status = await new DnsControl.DnsControlClient(channel).GetDohStatusAsync(new Empty());
        status.ConfiguredEncryptedResolvers.Should().Be(2);
        status.PlaintextFallbackFindings.Should().Be(1);
        status.PlaintextFallbackLastResolver.Should().Be("1.1.1.1");
        status.PlaintextFallbackLastSeen.Should().NotBeEmpty();
    }

    [Fact]
    public void Gzip_expansion_cap_stops_bombs()
    {
        var payload = new byte[1_000_000]; // zeros compress extremely well
        using var compressedStream = new MemoryStream();
        using (var gz = new GZipStream(compressedStream, CompressionMode.Compress, leaveOpen: true))
        {
            gz.Write(payload);
        }

        var act = () => GzipLimited.Decompress(compressedStream.ToArray(), 100_000, "test payload");

        act.Should().Throw<InvalidOperationException>().WithMessage("*exceeds 100000 bytes*");
        GzipLimited.Decompress(compressedStream.ToArray(), 2_000_000).Should().HaveCount(1_000_000);
    }
}
