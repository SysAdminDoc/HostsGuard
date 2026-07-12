using FluentAssertions;
using HostsGuard.App.Services;
using HostsGuard.App.ViewModels;
using HostsGuard.Contracts;
using HostsGuard.Ipc;
using Xunit;

namespace HostsGuard.App.Tests;

public sealed class IdnHomographSurfaceTests
{
    [Fact]
    public void Alert_mapping_preserves_structured_homograph_explanation()
    {
        var entry = new AlertEntry
        {
            Id = 7,
            Type = "idn_homograph",
            Title = "Potential IDN homograph",
            Subject = "xn--pple-43d.com",
            Details = "decoded: Ð°pple.com; Scripts: Cyrillic, Latin; restriction: moderately_restrictive; " +
                      "skeleton: apple.com; confusable with: apple.com; alert only - no block was applied.",
            Action = "idn_homograph",
        };

        var row = AlertRowViewModel.From(entry);

        row.IsIdnHomograph.Should().BeTrue();
        row.Subject.Should().Be(entry.Subject);
        row.Details.Should().Contain("decoded: Ð°pple.com")
            .And.Contain("Scripts: Cyrillic, Latin")
            .And.Contain("restriction: moderately_restrictive")
            .And.Contain("confusable with: apple.com")
            .And.Contain("no block was applied");
    }

    [Theory]
    [InlineData("IDN_HOMOGRAPH", true)]
    [InlineData("idn_homograph", true)]
    [InlineData("dga_domain", false)]
    [InlineData("", false)]
    public void Homograph_alert_identification_is_case_insensitive(string type, bool expected)
    {
        new AlertRowViewModel { Type = type }.IsIdnHomograph.Should().Be(expected);
    }

    [Fact]
    public void Tools_control_starts_off_without_implying_automatic_protection()
    {
        var vm = new ToolsViewModel(
            new HostsServiceClient(NamedPipeChannel.Create(SessionToken.Generate(), "hg-idn-none")),
            new FakeConfirm(true));

        vm.IdnHomographEnabled.Should().BeFalse();
        vm.IdnHomographStatus.Should().Contain("not loaded");
    }
}
