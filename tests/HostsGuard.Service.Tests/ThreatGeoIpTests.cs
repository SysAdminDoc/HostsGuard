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
    private string _pipe = null!;
    private string _token = null!;

    public async Task InitializeAsync()
    {
        _dir = Path.Combine(Path.GetTempPath(), "hg_threat_" + Guid.NewGuid().ToString("N"));
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
        _pipe = "HostsGuard.ThreatTest." + Guid.NewGuid().ToString("N");
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
