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
/// NET-095: adopt existing (non-HG_) Windows Firewall rules into HostsGuard's
/// view — opt-in, non-destructive, and visually distinct from HG_-authored rules.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class AdoptRulesTests : IAsyncLifetime
{
    private string _dir = null!;
    private WebApplication _app = null!;
    private ServiceState _state = null!;
    private FakeFirewallEngine _fw = null!;
    private string _pipe = null!;
    private string _token = null!;

    public async Task InitializeAsync()
    {
        _dir = Path.Combine(Path.GetTempPath(), "hg_adopt_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        File.WriteAllText(Path.Combine(_dir, "hosts"), "# hosts\n");
        _fw = new FakeFirewallEngine();
        // Seed one existing (system) WF rule and one HG_ rule.
        _fw.Rules["CoreNet-DNS-Out"] = new FwRule("CoreNet-DNS-Out", "Out", "Allow", true, "Any", "UDP", @"C:\Windows\System32\svchost.exe", "system");
        _fw.Rules["HG_Consent_Allow_app_Out"] = new FwRule("HG_Consent_Allow_app_Out", "Out", "Allow", true, "Any", "Any", @"C:\app.exe", "hostsguard");
        _state = new ServiceState(new HostsEngine(Path.Combine(_dir, "hosts")), new HostsDatabase(Path.Combine(_dir, "hostsguard.db")), _fw, dataDir: _dir);
        _token = SessionToken.Generate();
        _pipe = "HostsGuard.AdoptTest." + Guid.NewGuid().ToString("N");
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
    public async Task Adopt_records_existing_rules_and_marks_them_distinctly()
    {
        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var fw = new FirewallControl.FirewallControlClient(channel);

        var before = await fw.ListRulesAsync(new Empty());
        before.Rules.Single(r => r.Name == "CoreNet-DNS-Out").Adopted.Should().BeFalse();

        var result = await fw.AdoptFirewallRulesAsync(new Empty());
        result.Ok.Should().BeTrue();
        result.Adopted.Should().Be(1);  // only the non-HG_ rule
        result.Total.Should().Be(1);

        var after = await fw.ListRulesAsync(new Empty());
        after.Rules.Single(r => r.Name == "CoreNet-DNS-Out").Adopted.Should().BeTrue();
        after.Rules.Single(r => r.Name == "HG_Consent_Allow_app_Out").Adopted.Should().BeFalse();

        // Non-destructive: the live rule set is unchanged.
        _fw.Rules.Should().ContainKey("CoreNet-DNS-Out");
        _fw.Rules["CoreNet-DNS-Out"].Source.Should().Be("system");
    }

    [Fact]
    public async Task Adopt_is_idempotent()
    {
        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var fw = new FirewallControl.FirewallControlClient(channel);

        await fw.AdoptFirewallRulesAsync(new Empty());
        var second = await fw.AdoptFirewallRulesAsync(new Empty());
        second.Ok.Should().BeTrue();
        _state.Db.GetAdoptedRuleNames().Should().ContainSingle().Which.Should().Be("CoreNet-DNS-Out");
    }
}
