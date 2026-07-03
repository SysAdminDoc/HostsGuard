using FluentAssertions;
using HostsGuard.App.Services;
using HostsGuard.App.ViewModels;
using HostsGuard.Ipc;
using Xunit;

namespace HostsGuard.App.Tests;

/// <summary>UI command contracts: required inputs disable their actions.</summary>
public sealed class CommandStateTests
{
    private static HostsServiceClient LazyClient()
        => new(NamedPipeChannel.Create(SessionToken.Generate(), "hg-command-state-none"));

    [Fact]
    public void Managed_domain_block_requires_a_domain()
    {
        var vm = new HostsViewModel(LazyClient(), new FakeConfirm(true));

        vm.BlockCommand.CanExecute(null).Should().BeFalse();

        vm.NewDomain = "ads.example.com";

        vm.BlockCommand.CanExecute(null).Should().BeTrue();
    }

    [Fact]
    public void Raw_hosts_save_requires_dirty_text()
    {
        var vm = new RawHostsViewModel(LazyClient());

        vm.SaveCommand.CanExecute(null).Should().BeFalse();

        vm.Text = "# changed";

        vm.SaveCommand.CanExecute(null).Should().BeTrue();
    }

    [Fact]
    public void Firewall_rule_create_requires_a_name()
    {
        var vm = new FwRulesViewModel(LazyClient(), new FakeConfirm(true));

        vm.CreateRuleCommand.CanExecute(null).Should().BeFalse();

        vm.NewRuleName = "Block example";

        vm.CreateRuleCommand.CanExecute(null).Should().BeTrue();
    }

    [Fact]
    public void Tools_actions_require_their_visible_inputs()
    {
        var vm = new ToolsViewModel(LazyClient(), new FakeConfirm(true));

        vm.InspectCommand.CanExecute(null).Should().BeFalse();
        vm.SaveProfileCommand.CanExecute(null).Should().BeFalse();
        vm.SwitchProfileCommand.CanExecute(null).Should().BeFalse();
        vm.DeleteProfileCommand.CanExecute(null).Should().BeFalse();
        vm.RestoreBackupCommand.CanExecute(null).Should().BeFalse();

        vm.InspectDomain = "example.com";
        vm.NewProfileName = "Home";
        vm.SelectedProfile = "Home";
        vm.SelectedBackup = new BackupRowViewModel { FileName = "hosts.bak", Created = "now" };

        vm.InspectCommand.CanExecute(null).Should().BeTrue();
        vm.SaveProfileCommand.CanExecute(null).Should().BeTrue();
        vm.SwitchProfileCommand.CanExecute(null).Should().BeTrue();
        vm.DeleteProfileCommand.CanExecute(null).Should().BeTrue();
        vm.RestoreBackupCommand.CanExecute(null).Should().BeTrue();
    }
}
