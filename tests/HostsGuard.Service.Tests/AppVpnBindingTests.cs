using System.Runtime.Versioning;
using FluentAssertions;
using HostsGuard.Contracts;
using HostsGuard.Core;
using HostsGuard.Data;
using HostsGuard.Windows;
using Xunit;

namespace HostsGuard.Service.Tests;

[SupportedOSPlatform("windows")]
public sealed class AppVpnBindingTests : IDisposable
{
    private readonly string _dir;
    private readonly HostsDatabase _db;
    private readonly FakeFirewallEngine _fw = new();
    private List<AdapterInfo> _adapters = new();

    public AppVpnBindingTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "hg_appvpn_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        _db = new HostsDatabase(Path.Combine(_dir, "hostsguard.db"));
    }

    public void Dispose()
    {
        _db.Dispose();
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        try { Directory.Delete(_dir, true); } catch (IOException) { /* best effort */ }
    }

    [Fact]
    public void Set_creates_block_rule_for_active_non_selected_interfaces()
    {
        _adapters =
        [
            new AdapterInfo("WireGuard", "Wintun Userspace Tunnel", true, true),
            new AdapterInfo("Ethernet", "Intel Ethernet", true, false),
            new AdapterInfo("Wi-Fi", "Wireless", false, false),
        ];
        var coordinator = NewCoordinator();

        var ack = coordinator.Set(@"C:\Apps\sync.exe", "WireGuard", enabled: true);

        ack.Ok.Should().BeTrue();
        _fw.OutboundBlock.Should().BeFalse();
        var rule = _fw.Rules.Values.Should().ContainSingle().Subject;
        rule.Name.Should().StartWith("HG_VPNBind_");
        rule.Program.Should().Be(@"C:\Apps\sync.exe");
        rule.Action.Should().Be("Block");
        rule.Direction.Should().Be("Out");
        rule.Interfaces.Should().Be("Ethernet");
        _db.ListAppVpnBindings().Should().ContainSingle(b =>
            b.Program == @"C:\Apps\sync.exe" && b.Adapter == "WireGuard" && b.RuleName == rule.Name);
    }

    [Fact]
    public void Reconcile_updates_interfaces_as_networks_change()
    {
        _adapters =
        [
            new AdapterInfo("WireGuard", "Wintun Userspace Tunnel", true, true),
            new AdapterInfo("Ethernet", "Intel Ethernet", true, false),
        ];
        var coordinator = NewCoordinator();
        coordinator.Set(@"C:\Apps\sync.exe", "WireGuard", enabled: true).Ok.Should().BeTrue();
        var ruleName = _fw.Rules.Keys.Single();

        _adapters =
        [
            new AdapterInfo("WireGuard", "Wintun Userspace Tunnel", false, true),
            new AdapterInfo("Ethernet", "Intel Ethernet", true, false),
            new AdapterInfo("Wi-Fi", "Wireless", true, false),
        ];
        coordinator.ReconcileAll();

        _fw.Rules[ruleName].Interfaces.Should().Be("Ethernet,Wi-Fi");
        var view = coordinator.List().Single();
        view.SelectedAdapterUp.Should().BeFalse();
        view.BlockedInterfaces.Should().Equal("Ethernet", "Wi-Fi");
    }

    [Fact]
    public void Reconcile_removes_live_rule_when_only_selected_adapter_is_active()
    {
        _adapters =
        [
            new AdapterInfo("WireGuard", "Wintun Userspace Tunnel", true, true),
            new AdapterInfo("Ethernet", "Intel Ethernet", true, false),
        ];
        var coordinator = NewCoordinator();
        coordinator.Set(@"C:\Apps\sync.exe", "WireGuard", enabled: true).Ok.Should().BeTrue();

        _adapters = [new AdapterInfo("WireGuard", "Wintun Userspace Tunnel", true, true)];
        coordinator.ReconcileAll();

        _fw.Rules.Should().BeEmpty();
        _db.ListAppVpnBindings().Should().ContainSingle();
        _db.GetFwStateNames().Should().BeEmpty();
    }

    [Fact]
    public void Disabling_binding_removes_rule_and_persisted_intent()
    {
        _adapters =
        [
            new AdapterInfo("WireGuard", "Wintun Userspace Tunnel", true, true),
            new AdapterInfo("Ethernet", "Intel Ethernet", true, false),
        ];
        var coordinator = NewCoordinator();
        coordinator.Set(@"C:\Apps\sync.exe", "WireGuard", enabled: true).Ok.Should().BeTrue();

        var ack = coordinator.Set(@"C:\Apps\sync.exe", "WireGuard", enabled: false);

        ack.Ok.Should().BeTrue();
        _fw.Rules.Should().BeEmpty();
        _db.ListAppVpnBindings().Should().BeEmpty();
        _db.GetFwStateNames().Should().BeEmpty();
    }

    [Fact]
    public async Task Firewall_rpc_lists_and_sets_bindings()
    {
        _adapters =
        [
            new AdapterInfo("WireGuard", "Wintun Userspace Tunnel", true, true),
            new AdapterInfo("Ethernet", "Intel Ethernet", true, false),
        ];
        var hosts = Path.Combine(_dir, "hosts");
        File.WriteAllText(hosts, "# hosts\n");
        using var state = new ServiceState(new HostsEngine(hosts), _db, firewall: _fw, dataDir: _dir)
        {
            AppVpnBindings = NewCoordinator(),
        };
        var service = new FirewallControlServiceImpl(state);

        var ack = await service.SetAppVpnBinding(new AppVpnBindingRequest
        {
            ProgramPath = @"C:\Apps\sync.exe",
            Adapter = "WireGuard",
            Enabled = true,
        }, null!);
        var status = await service.GetAppVpnBindings(new Empty(), null!);

        ack.Ok.Should().BeTrue();
        status.Bindings.Should().ContainSingle(b =>
            b.ProgramPath == @"C:\Apps\sync.exe" &&
            b.Adapter == "WireGuard" &&
            b.BlockedInterfaces.Contains("Ethernet"));
        status.Adapters.Should().Contain(a => a.Name == "WireGuard" && a.IsVpnLikely);
    }

    [Fact]
    public async Task Deleting_vpn_bind_rule_removes_persisted_binding()
    {
        _adapters =
        [
            new AdapterInfo("WireGuard", "Wintun Userspace Tunnel", true, true),
            new AdapterInfo("Ethernet", "Intel Ethernet", true, false),
        ];
        var hosts = Path.Combine(_dir, "hosts");
        File.WriteAllText(hosts, "# hosts\n");
        var coordinator = NewCoordinator();
        using var state = new ServiceState(new HostsEngine(hosts), _db, firewall: _fw, dataDir: _dir)
        {
            AppVpnBindings = coordinator,
        };
        coordinator.Set(@"C:\Apps\sync.exe", "WireGuard", enabled: true).Ok.Should().BeTrue();
        var ruleName = _fw.Rules.Keys.Single();
        var service = new FirewallControlServiceImpl(state);

        var ack = await service.DeleteRule(new RuleNameRequest { Name = ruleName }, null!);

        ack.Ok.Should().BeTrue();
        _fw.Rules.Should().BeEmpty();
        _db.ListAppVpnBindings().Should().BeEmpty();
    }

    private AppVpnBindingCoordinator NewCoordinator()
        => new(_fw, _db, () => _adapters);
}
