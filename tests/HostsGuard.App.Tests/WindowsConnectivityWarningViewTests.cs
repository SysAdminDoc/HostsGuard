using FluentAssertions;
using HostsGuard.App.Services;
using HostsGuard.App.ViewModels;
using HostsGuard.Contracts;
using HostsGuard.Ipc;
using Xunit;

namespace HostsGuard.App.Tests;

public sealed class WindowsConnectivityWarningViewTests
{
    private static BlocklistsViewModel CreateVm() => new(
        new HostsServiceClient(NamedPipeChannel.Create(SessionToken.Generate(), "hg-ncsi-none")),
        new FakeConfirm(true));

    private static BlocklistResult Result(bool preview)
    {
        var result = new BlocklistResult { Ok = true, Preview = preview };
        result.ConnectivityWarnings.Add(new WindowsConnectivityWarning
        {
            Domain = "www.msftconnecttest.com",
            ProbeKind = "web",
            Era = "current",
            Reason = "Windows NCSI active web probe",
        });
        return result;
    }

    [Fact]
    public void Preview_warns_but_does_not_offer_recovery_before_a_block_exists()
    {
        var vm = CreateVm();

        vm.CaptureConnectivityWarnings(Result(preview: true));

        vm.HasConnectivityWarnings.Should().BeTrue();
        vm.ConnectivityWarnings.Should().ContainSingle()
            .Which.StateText.Should().Be("would be blocked by this list");
        vm.RecoverWindowsConnectivityCommand.CanExecute(null).Should().BeFalse();
        vm.ConnectivityWarningStatus.Should().Contain("recovery becomes available after import");
    }

    [Fact]
    public void Import_warning_enables_exact_domain_recovery_without_blocking_import()
    {
        var vm = CreateVm();

        vm.CaptureConnectivityWarnings(Result(preview: false));

        vm.ConnectivityWarnings.Should().ContainSingle()
            .Which.Domain.Should().Be("www.msftconnecttest.com");
        vm.ConnectivityWarnings[0].StateText.Should().Be("blocked by this list");
        vm.RecoverWindowsConnectivityCommand.CanExecute(null).Should().BeTrue();
    }

    [Fact]
    public void Warning_rows_are_limited_to_exact_service_findings()
    {
        var result = Result(preview: false);
        result.ConnectivityWarnings.Add(new WindowsConnectivityWarning
        {
            Domain = "www.msftconnecttest.com",
            ProbeKind = "web",
            Reason = "duplicate",
        });
        var vm = CreateVm();

        vm.CaptureConnectivityWarnings(result);

        vm.ConnectivityWarnings.Should().ContainSingle();
        vm.ConnectivityWarnings.Should().NotContain(row => row.Domain == "microsoft.com");
    }

    [Theory]
    [InlineData("web", "current", "Windows active web connectivity probe", "web probe | current Windows")]
    [InlineData("dns", "legacy", "Windows DNS connectivity probe", "DNS probe | legacy Windows")]
    public void Known_probe_evidence_uses_localizable_structured_labels(
        string kind, string era, string reason, string metadata)
    {
        var row = WindowsConnectivityWarningViewModel.From(new WindowsConnectivityWarning
        {
            Domain = "probe.example",
            ProbeKind = kind,
            Era = era,
            Reason = "raw service fallback",
        });

        row.DisplayReason.Should().Be(reason);
        row.DisplayMetadata.Should().Be(metadata);
    }
}
