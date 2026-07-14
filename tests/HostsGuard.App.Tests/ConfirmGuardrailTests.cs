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
    private AppVpnBindingCoordinator _appVpnBindings = null!;
    private HostsServiceClient _client = null!;

    private sealed class EmptyListFetcher : IListFetcher
    {
        public Task<string> FetchAsync(string url, int maxBytes, CancellationToken ct) => Task.FromResult(string.Empty);

        public Task<byte[]> FetchBytesAsync(string url, int maxBytes, CancellationToken ct) => Task.FromResult(Array.Empty<byte>());
    }

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
            dataDir: _dir,
            listFetcher: new EmptyListFetcher());
        _appVpnBindings = new AppVpnBindingCoordinator(
            _fw,
            _state.Db,
            () => Array.Empty<AdapterInfo>());
        _state.AppVpnBindings = _appVpnBindings;
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
        _appVpnBindings.Dispose();
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
    public async Task Declined_activity_block_selected_changes_nothing()
    {
        var confirm = new FakeConfirm(false);
        var vm = new HostsActivityViewModel(_client, confirm: confirm);
        var selected = new System.Collections.ArrayList
        {
            new ActivityRowViewModel { Domain = "accidental.example.com" },
        };

        await vm.BlockSelectedCommand.ExecuteAsync(selected);

        confirm.Prompts.Should().ContainSingle()
            .Which.Should().Contain("accidental.example.com");
        _state.Hosts.GetBlocked().Should().NotContain("accidental.example.com");
        _state.Db.GetDomainStatus("accidental.example.com").Should().BeNull();
    }

    [Fact]
    public async Task Accepted_activity_block_selected_proceeds()
    {
        var vm = new HostsActivityViewModel(_client, confirm: new FakeConfirm(true));
        var selected = new System.Collections.ArrayList
        {
            new ActivityRowViewModel { Domain = "blocked-from-feed.example.com" },
        };

        await vm.BlockSelectedCommand.ExecuteAsync(selected);

        _state.Hosts.GetBlocked().Should().Contain("blocked-from-feed.example.com");
        _state.Db.GetDomainStatus("blocked-from-feed.example.com").Should().Be("blocked");
    }

    [Fact]
    public async Task Declined_activity_unblock_selected_changes_nothing()
    {
        await _client.Hosts.BlockAsync(new DomainRequest { Domain = "still-blocked.example.com" });
        var confirm = new FakeConfirm(false);
        var vm = new HostsActivityViewModel(_client, confirm: confirm);
        var selected = new System.Collections.ArrayList
        {
            new ActivityRowViewModel { Domain = "still-blocked.example.com" },
        };

        await vm.UnblockSelectedCommand.ExecuteAsync(selected);

        confirm.Prompts.Should().ContainSingle();
        _state.Hosts.GetBlocked().Should().Contain("still-blocked.example.com");
    }

    [Fact]
    public async Task Declined_activity_allow_selected_changes_nothing()
    {
        await _client.Hosts.BlockAsync(new DomainRequest { Domain = "not-allowed.example.com" });
        var confirm = new FakeConfirm(false);
        var vm = new HostsActivityViewModel(_client, confirm: confirm);
        var selected = new System.Collections.ArrayList
        {
            new ActivityRowViewModel { Domain = "not-allowed.example.com" },
        };

        await vm.AllowSelectedCommand.ExecuteAsync(selected);

        confirm.Prompts.Should().ContainSingle();
        _state.Db.GetDomainStatus("not-allowed.example.com").Should().Be("blocked");
        _state.Hosts.GetBlocked().Should().Contain("not-allowed.example.com");
    }

    [Fact]
    public async Task Declined_activity_block_root_changes_nothing()
    {
        var confirm = new FakeConfirm(false);
        var vm = new HostsActivityViewModel(_client, confirm: confirm);

        await vm.BlockRootCommand.ExecuteAsync("cdn.example.com");

        confirm.Prompts.Should().ContainSingle();
        _state.Hosts.GetBlocked().Should().NotContain("example.com");
        _state.Db.GetDomainStatus("example.com").Should().BeNull();
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

    [Fact]
    public async Task Blocklist_remove_requires_targeted_confirmation_for_decline_and_accept()
    {
        const string name = "privacy-list";
        const string url = "https://lists.example/privacy.txt";
        _state.Db.UpsertBlocklistSub(name, url, 1);
        var row = new BlocklistSourceViewModel
        {
            Name = name,
            Url = url,
            Subscribed = true,
            OwnedDomainCount = 1,
        };
        var decline = new FakeConfirm(false);

        await new BlocklistsViewModel(_client, decline).UnsubscribeCommand.ExecuteAsync(row);

        _state.Db.GetBlocklistSub(name).Should().NotBeNull("a declined prompt must send no removal RPC");
        decline.Prompts.Should().ContainSingle()
            .Which.Should().Contain(name).And.Contain(url).And.Contain("source-owned domains");

        var accept = new FakeConfirm(true);
        await new BlocklistsViewModel(_client, accept).UnsubscribeCommand.ExecuteAsync(row);

        _state.Db.GetBlocklistSub(name).Should().BeNull();
        accept.Prompts.Should().ContainSingle();
    }

    [Fact]
    public async Task Blocklist_rollback_requires_targeted_confirmation_for_decline_and_accept()
    {
        const string name = "restore-list";
        const string url = "https://lists.example/restore.txt";
        var checkpoint = _state.Db.CreateBlocklistCheckpoint(
            name, url, "old-hash", 1, "new-hash", 1, "test", new[] { "old.example.com" });
        _state.Db.UpsertBlocklistSub(name, url, 1, lastCheckpointId: checkpoint);
        _state.Db.AddDomainsBulk(new[] { ("new.example.com", "blocked", $"list:{name}") });
        _state.Db.ReplaceBlocklistSourceDomains(name, new[] { "new.example.com" });
        var row = new BlocklistSourceViewModel
        {
            Name = name,
            Url = url,
            Subscribed = true,
            RollbackCheckpointId = checkpoint,
        };
        var decline = new FakeConfirm(false);

        await new BlocklistsViewModel(_client, decline).RollbackCommand.ExecuteAsync(row);

        _state.Db.GetBlocklistSourceDomains(name).Should().Equal("new.example.com");
        decline.Prompts.Should().ContainSingle()
            .Which.Should().Contain(name).And.Contain($"checkpoint {checkpoint}").And.Contain("previous verified refresh");

        var accept = new FakeConfirm(true);
        await new BlocklistsViewModel(_client, accept).RollbackCommand.ExecuteAsync(row);

        _state.Db.GetBlocklistSourceDomains(name).Should().Equal("old.example.com");
        accept.Prompts.Should().ContainSingle();
    }

    [Fact]
    public async Task Ip_blocklist_remove_requires_targeted_confirmation_for_decline_and_accept()
    {
        const string name = "threat-ips";
        _state.Db.UpsertIpBlocklistSource(
            name,
            "https://lists.example/threat-ips.txt",
            new[] { "203.0.113.10" },
            "new-hash",
            "old-hash",
            1,
            new[] { "198.51.100.10" },
            ruleCount: 1,
            truncated: false);
        var row = new IpBlocklistRowViewModel
        {
            Name = name,
            Url = "https://lists.example/threat-ips.txt",
            AddressCount = 1,
            RuleCount = 1,
        };
        var decline = new FakeConfirm(false);
        var deniedVm = new ToolsViewModel(_client, decline) { SelectedIpBlocklist = row };

        await deniedVm.RemoveIpBlocklistCommand.ExecuteAsync(null);

        _state.Db.GetIpBlocklistSource(name).Should().NotBeNull("a declined prompt must send no removal RPC");
        decline.Prompts.Should().ContainSingle()
            .Which.Should().Contain(name).And.Contain("1 addresses").And.Contain("firewall rules");

        var accept = new FakeConfirm(true);
        var acceptedVm = new ToolsViewModel(_client, accept) { SelectedIpBlocklist = row };
        await acceptedVm.RemoveIpBlocklistCommand.ExecuteAsync(null);

        _state.Db.GetIpBlocklistSource(name).Should().BeNull();
        accept.Prompts.Should().ContainSingle();
    }

    [Fact]
    public async Task Ip_blocklist_rollback_requires_targeted_confirmation_for_decline_and_accept()
    {
        const string name = "rollback-ips";
        _state.Db.UpsertIpBlocklistSource(
            name,
            "https://lists.example/rollback-ips.txt",
            new[] { "203.0.113.20" },
            "new-hash",
            "old-hash",
            1,
            new[] { "198.51.100.20" },
            ruleCount: 1,
            truncated: false);
        var row = new IpBlocklistRowViewModel
        {
            Name = name,
            Url = "https://lists.example/rollback-ips.txt",
            AddressCount = 1,
            RuleCount = 1,
        };
        var decline = new FakeConfirm(false);
        var deniedVm = new ToolsViewModel(_client, decline) { SelectedIpBlocklist = row };

        await deniedVm.RollbackIpBlocklistCommand.ExecuteAsync(null);

        _state.Db.GetIpBlocklistAddresses(name).Should().Equal("203.0.113.20");
        decline.Prompts.Should().ContainSingle()
            .Which.Should().Contain(name).And.Contain("retained previous refresh");

        var accept = new FakeConfirm(true);
        var acceptedVm = new ToolsViewModel(_client, accept) { SelectedIpBlocklist = row };
        await acceptedVm.RollbackIpBlocklistCommand.ExecuteAsync(null);

        _state.Db.GetIpBlocklistAddresses(name).Should().Equal("198.51.100.20");
        accept.Prompts.Should().ContainSingle();
    }

    [Fact]
    public async Task Full_state_restore_requires_confirmation_after_preview_for_decline_and_accept()
    {
        var snapshot = await _client.Recovery.CreateFullStateSnapshotAsync(new Empty());
        var pendingPath = Path.Combine(_dir, "pending_state_restore.json");
        var decline = new FakeConfirm(false);
        var deniedVm = new ToolsViewModel(_client, decline);
        await deniedVm.LoadFullStateSnapshotsCommand.ExecuteAsync(null);
        await deniedVm.PreviewFullStateRestoreCommand.ExecuteAsync(null);

        deniedVm.RestoreFullStateSnapshotCommand.CanExecute(null).Should().BeTrue();
        await deniedVm.RestoreFullStateSnapshotCommand.ExecuteAsync(null);

        File.Exists(pendingPath).Should().BeFalse("a declined prompt must not stage a restore RPC");
        decline.Prompts.Should().ContainSingle()
            .Which.Should().Contain(snapshot.SnapshotId).And.Contain(snapshot.Sha256).And.Contain("pre-restore recovery point");

        var accept = new FakeConfirm(true);
        var acceptedVm = new ToolsViewModel(_client, accept);
        await acceptedVm.LoadFullStateSnapshotsCommand.ExecuteAsync(null);
        await acceptedVm.PreviewFullStateRestoreCommand.ExecuteAsync(null);
        await acceptedVm.RestoreFullStateSnapshotCommand.ExecuteAsync(null);

        File.Exists(pendingPath).Should().BeTrue();
        accept.Prompts.Should().ContainSingle();
    }

    [Fact]
    public async Task Vpn_unbind_requires_targeted_confirmation_for_decline_and_accept()
    {
        const string program = @"C:\Apps\vpn-only.exe";
        const string adapter = "Test VPN";
        _state.Db.UpsertAppVpnBinding(program, adapter, "HG_VPNBind_test");
        var row = AppVpnBindingRowViewModel.From(new AppVpnBinding
        {
            ProgramPath = program,
            Adapter = adapter,
            RuleName = "HG_VPNBind_test",
        });
        var decline = new FakeConfirm(false);

        await new ToolsViewModel(_client, decline).RemoveAppVpnBindingCommand.ExecuteAsync(row);

        _state.Db.ListAppVpnBindings().Should().ContainSingle("a declined prompt must send no unbind RPC");
        decline.Prompts.Should().ContainSingle()
            .Which.Should().Contain(program).And.Contain(adapter).And.Contain("any active network interface");

        var accept = new FakeConfirm(true);
        await new ToolsViewModel(_client, accept).RemoveAppVpnBindingCommand.ExecuteAsync(row);

        _state.Db.ListAppVpnBindings().Should().BeEmpty();
        accept.Prompts.Should().ContainSingle();
    }
}
