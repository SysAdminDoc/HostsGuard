using System.Runtime.Versioning;
using FluentAssertions;
using HostsGuard.Contracts;
using HostsGuard.Data;
using HostsGuard.Windows;
using Microsoft.Data.Sqlite;
using Xunit;

namespace HostsGuard.Service.Tests;

/// <summary>
/// NET-073: svchost attribution in the consent pipeline — prompt enrichment,
/// per-service rule scoping, and the service-aware covering-rule check.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class ServiceAttributionConsentTests : IDisposable
{
    private const string Svchost = @"C:\Windows\System32\svchost.exe";

    private readonly string _dir;
    private readonly HostsDatabase _db;
    private readonly EventBus _bus;
    private readonly FakeFirewallEngine _fw = new();
    private readonly ConsentBroker _broker;

    public ServiceAttributionConsentTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "hg_svc_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        _db = new HostsDatabase(Path.Combine(_dir, "hostsguard.db"));
        _bus = new EventBus();
        _broker = new ConsentBroker(_db, _bus, _fw, null, _dir);
        _broker.SetMode(ConsentBroker.ModeNotify);
        _broker.LookupSoleService = pid => pid == 1234 ? ("Dnscache", "DNS Client") : null;
    }

    public void Dispose()
    {
        _broker.Dispose();
        _db.Dispose();
        SqliteConnection.ClearAllPools();
        try
        {
            Directory.Delete(_dir, true);
        }
        catch (IOException)
        {
            // best effort
        }
    }

    private static BlockedConnection Blocked(int pid, string remote = "1.2.3.4") =>
        new(DateTime.UtcNow, Svchost, "Out", remote, 443, "TCP", pid, 5157);

    [Fact]
    public void Prompt_carries_the_owning_service_when_unambiguous()
    {
        using var sub = _bus.Subscribe<ConnectionDecisionRequest>();
        _broker.OnBlocked(Blocked(pid: 1234));

        sub.Reader.TryRead(out var request).Should().BeTrue();
        request!.Service.Should().Be("DNS Client");
        request.ServiceKey.Should().Be("Dnscache");
    }

    [Fact]
    public void Prompt_omits_the_service_scope_for_plain_processes()
    {
        using var sub = _bus.Subscribe<ConnectionDecisionRequest>();
        _broker.OnBlocked(Blocked(pid: 999));

        sub.Reader.TryRead(out var request).Should().BeTrue();
        request!.Service.Should().BeEmpty();
        request.ServiceKey.Should().BeEmpty();
    }

    [Fact]
    public void Service_scoped_decision_writes_a_service_bound_rule()
    {
        var ack = _broker.Decide(new ConnectionDecision
        {
            Application = Svchost,
            Direction = "Out",
            Verdict = "block",
            Duration = "always",
            ScopeService = true,
            ServiceKey = "Dnscache",
        });

        ack.Ok.Should().BeTrue();
        var rule = _fw.Rules.Values.Should().ContainSingle().Subject;
        rule.ServiceName.Should().Be("Dnscache");
        rule.Program.Should().Be(Svchost);
        rule.Name.Should().Contain("Dnscache");
    }

    [Fact]
    public void Service_scoped_rule_covers_only_its_own_service()
    {
        // Allow rule scoped to Dnscache…
        _broker.Decide(new ConnectionDecision
        {
            Application = Svchost,
            Direction = "Out",
            Verdict = "allow",
            Duration = "always",
            ScopeService = true,
            ServiceKey = "Dnscache",
        }).Ok.Should().BeTrue();

        using var sub = _bus.Subscribe<ConnectionDecisionRequest>();

        // …covers a Dnscache-attributed connection (no re-prompt)…
        _broker.OnBlocked(Blocked(pid: 1234));
        _broker.PendingCount.Should().Be(0);

        // …but a different (unattributed) svchost connection still prompts.
        _broker.OnBlocked(Blocked(pid: 999, remote: "5.6.7.8"));
        _broker.PendingCount.Should().Be(1);
    }
}
