using System.Runtime.Versioning;
using FluentAssertions;
using HostsGuard.Data;
using HostsGuard.Windows;
using Microsoft.Data.Sqlite;
using Xunit;

namespace HostsGuard.Service.Tests;

/// <summary>
/// NET-113: a binary signed by a user-trusted Authenticode publisher is
/// auto-allowed without a prompt; an untrusted signer still prompts; the trusted
/// set persists across a broker restart.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class TrustedPublisherTests : IDisposable
{
    private readonly string _dir;
    private readonly ServiceState _state;
    private readonly FakeFirewallEngine _fw;

    public TrustedPublisherTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "hg_pub_" + Guid.NewGuid().ToString("N"));
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

    private static BlockedConnection Blocked(string app)
        => new(DateTime.UtcNow, app, "Out", "203.0.113.7", 443, "TCP", 4711, 5157);

    [Fact]
    public void Signed_by_a_trusted_publisher_auto_allows_without_prompt()
    {
        _state.Consent.LookupSigner = _ => "CN=Trusted Corp, O=Trusted Corp, C=US";
        _state.Consent.SetTrustedPublishers(new[] { "Trusted Corp" });

        _state.Consent.OnBlocked(Blocked(@"C:\apps\trusted.exe"));

        _state.Consent.PendingCount.Should().Be(0);
        _fw.Rules.Keys.Should().Contain(k => k.StartsWith("HG_Pub_trusted_Out", StringComparison.Ordinal));
    }

    [Fact]
    public void Untrusted_signer_still_prompts()
    {
        _state.Consent.LookupSigner = _ => "CN=Some Other Corp";
        _state.Consent.SetTrustedPublishers(new[] { "Trusted Corp" });

        _state.Consent.OnBlocked(Blocked(@"C:\apps\other.exe"));

        _state.Consent.PendingCount.Should().Be(1);
        _fw.Rules.Keys.Should().NotContain(k => k.StartsWith("HG_Pub_", StringComparison.Ordinal));
    }

    [Fact]
    public void Review_trust_evidence_uses_current_explicit_publisher_without_mutating_rules()
    {
        _state.Consent.LookupSigner = _ => "CN=Trusted Corp, O=Trusted Corp, C=US";
        _state.Consent.SetTrustedPublishers(["Trusted Corp"]);

        var evidence = _state.Consent.GetTrustEvidence(@"C:\apps\trusted.exe");

        evidence.Should().Be(new TrustedApplicationEvidence("publisher", "Trusted Corp"));
        _fw.Rules.Should().BeEmpty("review evidence must never auto-allow");
    }

    [Fact]
    public void Trusted_set_persists_across_restart()
    {
        _state.Consent.SetTrustedPublishers(new[] { "Acme", "Acme", "  " }); // dedup + blanks dropped
        _state.Consent.TrustedPublishers.Should().ContainSingle().Which.Should().Be("Acme");

        using var reloaded = new ConsentBroker(_state.Db, _state.Bus, _fw, null, _dir);
        reloaded.TrustedPublishers.Should().ContainSingle().Which.Should().Be("Acme");
    }

    public void Dispose()
    {
        _state.Dispose();
        try { Directory.Delete(_dir, true); } catch (IOException) { /* best effort */ }
    }
}
