using System.Globalization;
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
    public async Task Policy_subscription_view_text_uses_i18n_resources()
    {
        var original = CultureInfo.CurrentUICulture;
        try
        {
            CultureInfo.CurrentUICulture = CultureInfo.GetCultureInfo("qps-ploc");
            var confirm = new FakeConfirm(false);
            var vm = new ToolsViewModel(
                new HostsServiceClient(NamedPipeChannel.Create(SessionToken.Generate(), "hg-policy-sub-none")),
                confirm);

            vm.PolicySubscriptionStatusText.Should().StartWith("[!! ");

            await vm.RefreshPolicySubscriptionsAsync();
            confirm.Prompts.Should().ContainSingle()
                .Which.Should().StartWith("[!! ").And.Contain("!!]: [!! ");

            var row = PolicySubscriptionViewModel.From(new PolicySubscription
            {
                Name = "Example",
                Url = "https://example.com/policy.json",
                Enabled = false,
                AutoApply = false,
            });

            row.StateText.Should().StartWith("[!! ");
            row.ApplyModeText.Should().StartWith("[!! ");
            row.TrustText.Should().StartWith("[!! ");
            row.LastAppliedText.Should().StartWith("[!! ");

            row.Enabled = true;
            row.AutoApply = true;
            row.PinHash = "abc123";

            row.StateText.Should().StartWith("[!! ");
            row.ApplyModeText.Should().StartWith("[!! ");
            row.TrustText.Should().StartWith("[!! ");
        }
        finally
        {
            CultureInfo.CurrentUICulture = original;
        }
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

    [Fact]
    public void Direct_service_binding_row_preserves_exact_parameters_and_ech_semantics()
    {
        var record = new ServiceBindingRecord
        {
            OwnerName = "example.com",
            DnsType = "HTTPS",
            TtlSeconds = 300,
            Priority = 1,
            Target = "svc.example.net",
            EchAdvertised = true,
        };
        record.Parameters.Add(new ServiceBindingParameter { Key = 1, Name = "alpn", Value = "h2,h3" });
        record.Parameters.Add(new ServiceBindingParameter { Key = 3, Name = "port", Value = "8443" });

        var row = ServiceBindingRecordViewModel.From(record);

        row.OwnerName.Should().Be("example.com");
        row.Target.Should().Be("svc.example.net");
        row.ModeText.Should().Be("Service");
        row.ParametersText.Should().Be("alpn=h2,h3; port=8443");
        row.EchText.Should().Be("advertised");
        row.HealthText.Should().Be("OK");
    }

    [Fact]
    public void Full_state_snapshot_row_exposes_only_redacted_manifest_metadata()
    {
        var row = FullStateSnapshotRowViewModel.From(new FullStateSnapshot
        {
            SnapshotId = "20260712T120000Z-abc123",
            Created = "2026-07-12T12:00:00Z",
            AppVersion = "0.12.80",
            SchemaVersion = 33,
            Sha256 = new string('a', 64),
            SizeBytes = 2 * 1024 * 1024,
            Verified = true,
            Components = { "database", "hosts", "service settings (3)" },
        });

        row.Label.Should().Contain("20260712T120000Z-abc123").And.Contain("2 MB").And.Contain("verified");
        row.Components.Should().Equal("database", "hosts", "service settings (3)");
        row.Sha256.Should().HaveLength(64);
    }

    [Fact]
    public void Proxy_baseline_row_preserves_presence_and_change_semantics()
    {
        var row = ProxyBaselineRowViewModel.From(new ProxyBaselineEntry
        {
            Scope = "WinINET",
            Sid = "S-1-5-21-test",
            Setting = "AutoConfigURL",
            BaselinePresent = false,
            CurrentPresent = true,
            CurrentValue = "https://proxy.example/pac",
            Changed = true,
        });

        row.Scope.Should().Be("WinINET");
        row.Identity.Should().Be("S-1-5-21-test");
        row.Baseline.Should().Be(I18n.T("Proxy_NotRecorded", "Not recorded"));
        row.Current.Should().Be("https://proxy.example/pac");
        row.Changed.Should().BeTrue();
        row.State.Should().Be(I18n.T("Proxy_StateChanged", "Changed"));
    }
}
