using System.IO;
using System.Runtime.Versioning;
using FluentAssertions;
using HostsGuard.App.Services;
using HostsGuard.App.ViewModels;
using HostsGuard.Contracts;
using HostsGuard.Data;
using HostsGuard.Ipc;
using HostsGuard.Service;
using HostsGuard.Windows;
using Microsoft.AspNetCore.Builder;
using Microsoft.Data.Sqlite;
using Xunit;

namespace HostsGuard.App.Tests;

/// <summary>
/// NET-024: no destructive path (domain remove, bulk remove, FW rule delete,
/// bulk delete, emergency reset) is reachable without the shared confirm flow.
/// A declined confirm must leave state untouched; an accepted one proceeds.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class ConfirmGuardrailTests : IAsyncLifetime
{
    private string _dir = null!;
    private WebApplication _app = null!;
    private ServiceState _state = null!;
    private FakeFirewall _fw = null!;
    private HostsServiceClient _client = null!;

    private sealed class FakeFirewall : IFirewallEngine
    {
        public Dictionary<string, Core.FwRule> Rules { get; } = new(StringComparer.Ordinal);

        public IReadOnlyList<Core.FwRule> ListRules() => Rules.Values.ToList();

        public IReadOnlyList<Core.FwAppPackage> ListPackages() => Array.Empty<Core.FwAppPackage>();

        public bool CreateRule(Core.FwRule rule)
        {
            if (Rules.ContainsKey(rule.Name))
            {
                return false;
            }

            Rules[rule.Name] = rule;
            return true;
        }

        public bool DeleteRule(string name) => Rules.Remove(name);

        public bool SetRuleEnabled(string name, bool enabled) => Rules.ContainsKey(name);

        public bool RuleExists(string name) => Rules.ContainsKey(name);

        public bool OutboundBlock { get; set; }

        public IReadOnlyList<Core.FwProfilePosture> GetPosture() => new[]
        {
            new Core.FwProfilePosture("Domain", true, OutboundBlock),
            new Core.FwProfilePosture("Private", true, OutboundBlock),
            new Core.FwProfilePosture("Public", true, OutboundBlock),
        };

        public void SetDefaultOutboundBlock(bool block) => OutboundBlock = block;

        public void SetDefaultOutboundBlock(IReadOnlyDictionary<string, bool> perProfile)
            => OutboundBlock = perProfile.Values.All(v => v);

        public bool SetRuleProgram(string name, string programPath)
        {
            if (!Rules.TryGetValue(name, out var rule))
            {
                return false;
            }

            Rules[name] = rule with { Program = programPath };
            return true;
        }

        public bool SetRuleRemoteAddresses(string name, string remoteAddresses)
        {
            if (!Rules.TryGetValue(name, out var rule))
            {
                return false;
            }

            Rules[name] = rule with { RemoteAddr = remoteAddresses };
            return true;
        }
    }

    public async Task InitializeAsync()
    {
        _dir = Path.Combine(Path.GetTempPath(), "hg_confirm_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        var hostsPath = Path.Combine(_dir, "hosts");
        File.WriteAllText(hostsPath, "# hosts\n");

        _fw = new FakeFirewall();
        _state = new ServiceState(
            new HostsEngine(hostsPath),
            new HostsDatabase(Path.Combine(_dir, "db.sqlite")),
            _fw,
            dataDir: _dir);
        var token = SessionToken.Generate();
        var pipe = "HostsGuard.ConfirmTest." + Guid.NewGuid().ToString("N");
        _app = ServiceHost.Build(_state, token, pipe);
        await _app.StartAsync();
        _client = new HostsServiceClient(NamedPipeChannel.Create(token, pipe));
    }

    public async Task DisposeAsync()
    {
        _client.Dispose();
        await _app.DisposeAsync();
        _state.Dispose();
        SqliteConnection.ClearAllPools();
        try { Directory.Delete(_dir, true); } catch (IOException) { /* best effort */ }
    }

    [Fact]
    public async Task Declined_domain_remove_changes_nothing()
    {
        await _client.Hosts.BlockAsync(new DomainRequest { Domain = "keep.example.com" });
        var confirm = new FakeConfirm(false);
        var vm = new HostsViewModel(_client, confirm);

        await vm.UnblockCommand.ExecuteAsync("keep.example.com");

        confirm.Prompts.Should().ContainSingle();
        _state.Hosts.GetBlocked().Should().Contain("keep.example.com");
    }

    [Fact]
    public async Task Accepted_domain_remove_proceeds()
    {
        await _client.Hosts.BlockAsync(new DomainRequest { Domain = "gone.example.com" });
        var vm = new HostsViewModel(_client, new FakeConfirm(true));

        await vm.UnblockCommand.ExecuteAsync("gone.example.com");

        _state.Hosts.GetBlocked().Should().NotContain("gone.example.com");
    }

    [Fact]
    public async Task Declined_bulk_remove_changes_nothing()
    {
        await _client.Hosts.BlockAsync(new DomainRequest { Domain = "a.example.com" });
        var confirm = new FakeConfirm(false);
        var vm = new HostsViewModel(_client, confirm);
        await vm.RefreshCommand.ExecuteAsync(null);

        await vm.RemoveSelectedCommand.ExecuteAsync(vm.Domains.ToList());

        confirm.Prompts.Should().ContainSingle();
        _state.Hosts.GetBlocked().Should().Contain("a.example.com");
    }

    [Fact]
    public async Task Declined_fw_delete_changes_nothing()
    {
        await _client.Firewall.BlockIpAsync(new FirewallIpRequest { Address = "203.0.113.5" });
        var confirm = new FakeConfirm(false);
        var vm = new FwRulesViewModel(_client, confirm);

        await vm.DeleteRuleCommand.ExecuteAsync("HG_Block_203.0.113.5_Out");

        confirm.Prompts.Should().ContainSingle();
        _fw.Rules.Should().ContainKey("HG_Block_203.0.113.5_Out");
    }

    [Fact]
    public async Task Accepted_bulk_fw_delete_proceeds()
    {
        await _client.Firewall.BlockIpAsync(new FirewallIpRequest { Address = "203.0.113.6" });
        var vm = new FwRulesViewModel(_client, new FakeConfirm(true));
        await vm.RefreshCommand.ExecuteAsync(null);

        await vm.DeleteSelectedCommand.ExecuteAsync(vm.Rules.ToList());

        _fw.Rules.Should().BeEmpty();
    }

    [Fact]
    public async Task Declined_emergency_reset_changes_nothing()
    {
        await _client.Hosts.BlockAsync(new DomainRequest { Domain = "still.example.com" });
        var confirm = new FakeConfirm(false);
        var vm = new ToolsViewModel(_client, confirm);

        await vm.EmergencyResetCommand.ExecuteAsync(null);

        confirm.Prompts.Should().ContainSingle();
        _state.Hosts.GetBlocked().Should().Contain("still.example.com");
    }

    [Fact]
    public async Task Accepted_emergency_reset_resets_hosts()
    {
        await _client.Hosts.BlockAsync(new DomainRequest { Domain = "wiped.example.com" });
        var vm = new ToolsViewModel(_client, new FakeConfirm(true));

        await vm.EmergencyResetCommand.ExecuteAsync(null);

        _state.Hosts.GetBlocked().Should().BeEmpty();
    }
}
