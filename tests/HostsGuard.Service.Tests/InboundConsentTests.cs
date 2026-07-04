using System.Runtime.Versioning;
using FluentAssertions;
using HostsGuard.Contracts;
using HostsGuard.Core;
using HostsGuard.Data;
using HostsGuard.Windows;
using Microsoft.Data.Sqlite;
using Xunit;

namespace HostsGuard.Service.Tests;

/// <summary>
/// NET-104 inbound-connection consent: the broker handles inbound blocks the same
/// way it handles outbound, but inbound prompting is opt-in — unsolicited inbound
/// blocks are dropped (no prompt) unless the user turns inbound consent on, and an
/// inbound decision produces an inbound-scoped rule.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class InboundConsentTests : IDisposable
{
    private readonly string _dir;
    private readonly ServiceState _state;
    private readonly FakeFirewallEngine _fw;

    public InboundConsentTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "hg_inbound_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        File.WriteAllText(Path.Combine(_dir, "hosts"), "# hosts\n");
        _fw = new FakeFirewallEngine();
        _state = new ServiceState(
            new HostsEngine(Path.Combine(_dir, "hosts")),
            new HostsDatabase(Path.Combine(_dir, "hostsguard.db")),
            _fw,
            new FirewallIdentity(Path.Combine(_dir, "fw_identities.json")),
            dataDir: _dir);
        _state.Consent.SetMode(ConsentBroker.ModeNotify);
    }

    private static BlockedConnection Inbound(string app)
        => new(DateTime.UtcNow, app, "In", "203.0.113.9", 445, "TCP", 7000, 5157);

    private static BlockedConnection Outbound(string app)
        => new(DateTime.UtcNow, app, "Out", "203.0.113.9", 443, "TCP", 7000, 5157);

    [Fact]
    public void Inbound_is_dropped_by_default_to_avoid_prompt_noise()
    {
        // InboundConsent defaults off.
        _state.Consent.InboundConsent.Should().BeFalse();

        _state.Consent.OnBlocked(Inbound(@"C:\apps\server.exe"));

        _state.Consent.PendingCount.Should().Be(0); // no prompt
    }

    [Fact]
    public void Inbound_prompts_when_inbound_consent_is_on()
    {
        _state.Consent.SetInboundConsent(true);

        _state.Consent.OnBlocked(Inbound(@"C:\apps\server.exe"));

        _state.Consent.PendingCount.Should().Be(1);
    }

    [Fact]
    public void Outbound_still_prompts_when_inbound_consent_is_off()
    {
        // The inbound gate must not affect the normal outbound path.
        _state.Consent.OnBlocked(Outbound(@"C:\apps\client.exe"));

        _state.Consent.PendingCount.Should().Be(1);
    }

    [Fact]
    public void Inbound_allow_decision_creates_an_inbound_scoped_rule()
    {
        var ack = _state.Consent.Decide(new ConnectionDecision
        {
            Application = @"C:\apps\server.exe",
            Direction = "In",
            Verdict = "allow",
        });

        ack.Ok.Should().BeTrue();
        _fw.Rules.Values.Should().Contain(r =>
            r.Direction == "In" &&
            r.Action == "Allow" &&
            r.Program.EndsWith("server.exe", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void InboundConsent_setting_persists_across_broker_restart()
    {
        _state.Consent.SetInboundConsent(true);
        _state.Consent.InboundConsent.Should().BeTrue();

        using var reloaded = new ConsentBroker(_state.Db, _state.Bus, _fw, null, _dir);
        reloaded.InboundConsent.Should().BeTrue();
    }

    public void Dispose()
    {
        _state.Dispose();
        SqliteConnection.ClearAllPools();
        try { Directory.Delete(_dir, true); } catch (IOException) { /* best effort */ }
    }
}
