using System.Runtime.Versioning;
using FluentAssertions;
using HostsGuard.Contracts;
using HostsGuard.Data;
using HostsGuard.Windows;
using Microsoft.Data.Sqlite;
using Xunit;

namespace HostsGuard.Service.Tests;

/// <summary>
/// NET-099: a blanket "allow/block all from this app" answers every pending prompt
/// from the same application with one whole-app rule and clears the queue.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class DecideAllTests : IDisposable
{
    private readonly string _dir;
    private readonly ServiceState _state;
    private readonly FakeFirewallEngine _fw;

    private const string App = @"C:\apps\chatty.exe";

    public DecideAllTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "hg_decideall_" + Guid.NewGuid().ToString("N"));
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

    private void QueueBurst()
    {
        var now = DateTime.UtcNow;
        for (var i = 0; i < 5; i++)
        {
            _state.Consent.OnBlocked(new BlockedConnection(now.AddMilliseconds(i * 10), App, "Out", $"203.0.113.{i}", 443, "TCP", 5000, 5157));
        }
    }

    [Fact]
    public void Allow_all_writes_one_whole_app_rule_and_clears_the_queue()
    {
        QueueBurst();
        _state.Consent.PendingCount.Should().Be(5);

        var pendingId = string.Empty; // re-decide path (id empty is fine for apply-to-app)
        var ack = _state.Consent.Decide(new ConnectionDecision
        {
            Id = pendingId,
            Application = App,
            Direction = "Out",
            Verdict = "allow",
            ApplyToApp = true,
        });

        ack.Ok.Should().BeTrue();
        _state.Consent.PendingCount.Should().Be(0);
        _fw.Rules.Keys.Should().Contain("HG_Consent_Allow_chatty_Out");
        _fw.Rules["HG_Consent_Allow_chatty_Out"].Action.Should().Be("Allow");
    }

    [Fact]
    public void Block_all_clears_the_queue_with_a_block_rule()
    {
        QueueBurst();
        var ack = _state.Consent.Decide(new ConnectionDecision { Application = App, Direction = "Out", Verdict = "block", ApplyToApp = true });

        ack.Ok.Should().BeTrue();
        _state.Consent.PendingCount.Should().Be(0);
        _fw.Rules.Keys.Should().Contain("HG_Consent_Block_chatty_Out");
    }

    public void Dispose()
    {
        _state.Dispose();
        SqliteConnection.ClearAllPools();
        try { Directory.Delete(_dir, true); } catch (IOException) { /* best effort */ }
    }
}
