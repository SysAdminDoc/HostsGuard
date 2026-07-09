using FluentAssertions;
using HostsGuard.App.Services;
using HostsGuard.App.ViewModels;
using HostsGuard.Contracts;
using HostsGuard.Ipc;
using Xunit;

namespace HostsGuard.App.Tests;

/// <summary>
/// NET-106: "See everything" is the combined state of the QUIC and DoH-bootstrap
/// blocks — on only when both are, and it notifies when either flips. Lazy
/// channel; nothing here hits the wire.
/// </summary>
public sealed class ToolsViewModelTests
{
    private static ToolsViewModel CreateVm() => new(
        new HostsServiceClient(NamedPipeChannel.Create(SessionToken.Generate(), "hg-tools-none")),
        new FakeConfirm(true));

    [Fact]
    public void SeeEverything_is_on_only_when_both_quic_and_doh_blocks_are_active()
    {
        var vm = CreateVm();
        vm.SeeEverythingActive.Should().BeFalse();

        vm.QuicBlockingActive = true;
        vm.SeeEverythingActive.Should().BeFalse("DoH bootstrap is still open");

        vm.DohBlockingActive = true;
        vm.SeeEverythingActive.Should().BeTrue("both bypass paths are now closed");

        vm.QuicBlockingActive = false;
        vm.SeeEverythingActive.Should().BeFalse();
    }

    [Fact]
    public void SeeEverything_raises_change_notification_when_a_block_flips()
    {
        var vm = CreateVm();
        var raised = 0;
        vm.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(ToolsViewModel.SeeEverythingActive))
            {
                raised++;
            }
        };

        vm.DohBlockingActive = true;
        vm.QuicBlockingActive = true;

        raised.Should().BeGreaterThanOrEqualTo(2, "each block toggle re-evaluates the combined state");
    }

    [Fact]
    public void Lan_attack_surface_row_exposes_action_and_state_text()
    {
        var row = LanAttackSurfaceToggleViewModel.From(new LanAttackSurfaceToggle
        {
            Key = "llmnr",
            Label = "LLMNR",
            Blocked = false,
            Status = "Allowed",
            BreakNote = "Legacy discovery may stop.",
        });

        row.ActionText.Should().Be("Block");
        row.StateText.Should().Be("Allowed");

        row.Blocked = true;

        row.ActionText.Should().Be("Restore");
        row.StateText.Should().Be("Allowed");
    }

    [Fact]
    public void Dns_cache_row_exposes_service_binding_privacy_role()
    {
        var row = DnsCacheEntryViewModel.From(new DnsCacheEntry
        {
            Name = "svc.example.com",
            Type = "HTTPS",
            DataLength = 48,
            Flags = 4,
            ServiceBinding = true,
            PrivacyRole = "HTTPS service binding cached by Windows",
        });

        row.ServiceBinding.Should().BeTrue();
        row.PrivacyRole.Should().Contain("service binding");
        row.DataLengthText.Should().Be("48 B");
        row.FlagsText.Should().Be("0x00000004");
    }
}
