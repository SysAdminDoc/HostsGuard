using System.Runtime.Versioning;
using FluentAssertions;
using HostsGuard.Contracts;
using HostsGuard.Data;
using HostsGuard.Windows;
using Xunit;

namespace HostsGuard.Service.Tests;

[SupportedOSPlatform("windows")]
public sealed class IdnHomographServiceTests : IDisposable
{
    private readonly string _dir;
    private readonly HostsDatabase _db;
    private readonly ServiceState _state;

    public IdnHomographServiceTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "hg_idn_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        var hostsPath = Path.Combine(_dir, "hosts");
        File.WriteAllText(hostsPath, "# hosts\n");
        _db = new HostsDatabase(Path.Combine(_dir, "hostsguard.db"));
        _state = new ServiceState(new HostsEngine(hostsPath), _db, dataDir: _dir);
    }

    [Fact]
    public async Task Setting_defaults_off_persists_and_status_exposes_local_corpus_and_standard()
    {
        _db.AddDomain("paypal.com", "whitelisted", "manual");
        var service = new DnsControlServiceImpl(_state);

        var before = await service.GetIdnHomographStatus(new Empty(), null!);
        before.Enabled.Should().BeFalse();
        before.CorpusSize.Should().Be(1);
        before.Standard.Should().Contain("Unicode 17.0.0").And.Contain("UTS #39");

        var enabled = await service.SetIdnHomograph(new IdnHomographRequest { Enabled = true }, null!);

        enabled.Ok.Should().BeTrue();
        _db.GetMeta(IdnHomographMonitor.EnabledMetaKey).Should().Be("on");
        (await service.GetIdnHomographStatus(new Empty(), null!)).Enabled.Should().BeTrue();
        new IdnHomographMonitor(_db).Enabled.Should().BeTrue("the setting is database-persisted");
    }

    [Fact]
    public void Unicode_observation_is_normalized_alerted_once_and_never_blocked()
    {
        _db.AddDomain("paypal.com", "whitelisted", "manual");
        _state.IdnHomographs.SetEnabled(true);

        _state.RecordDns("раураl.com", "browser.exe");
        _state.RecordDns("раураl.com", "browser.exe");

        var alert = _db.GetAlerts(new AlertFilter(Type: "idn_homograph", SurfaceOnly: false)).Rows
            .Should().ContainSingle().Subject;
        alert.Title.Should().Be("Potential IDN homograph");
        alert.Subject.Should().StartWith("xn--");
        alert.Process.Should().Be("browser.exe");
        alert.Details.Should().Contain("decoded=раураl.com")
            .And.Contain("punycode=xn--")
            .And.Contain("skeleton=paypal.corn")
            .And.Contain("scripts=")
            .And.Contain("restriction=")
            .And.Contain("confusable_target=paypal.com (trusted)")
            .And.Contain("Alert only; no domain was blocked.");
        _db.GetDomainStatus(alert.Subject).Should().BeNullOrEmpty();
        _state.Hosts.GetBlocked().Should().NotContain(alert.Subject);
    }

    [Fact]
    public void Disabled_detector_and_safe_ascii_domain_do_not_alert()
    {
        _db.AddDomain("paypal.com", "whitelisted", "manual");
        _state.RecordDns("раураl.com", "browser.exe");
        _state.IdnHomographs.SetEnabled(true);
        _state.RecordDns("paypal.com", "browser.exe");

        _db.GetAlerts(new AlertFilter(Type: "idn_homograph", SurfaceOnly: false)).Rows.Should().BeEmpty();
    }

    [Fact]
    public void Recent_ascii_domain_corpus_can_supply_the_confusable_target()
    {
        _db.RecordFeed("paypal.com", "browser.exe");
        _state.IdnHomographs.SetEnabled(true);

        _state.RecordDns("раураl.com", "browser.exe");

        _db.GetAlerts(new AlertFilter(Type: "idn_homograph", SurfaceOnly: false)).Rows
            .Should().ContainSingle(alert => alert.Details.Contains("confusable_target=paypal.com (recent)", StringComparison.Ordinal));
    }

    [Fact]
    public void Alert_evidence_escapes_bidi_and_control_characters()
    {
        IdnHomographMonitor.EscapeUnsafe("safe\u202Etxt\n")
            .Should().Be("safe\\u202Etxt\\u000A");
    }

    public void Dispose()
    {
        _state.Dispose();
        try { Directory.Delete(_dir, true); } catch (IOException) { }
    }
}
