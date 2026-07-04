using System.Windows.Data;
using FluentAssertions;
using HostsGuard.App.Services;
using HostsGuard.App.ViewModels;
using HostsGuard.Ipc;
using Xunit;

namespace HostsGuard.App.Tests;

/// <summary>
/// Group-by-root feed view: subdomain noise collapses under expandable root
/// headers, and toggling off restores the flat feed. Lazy channel — no wire.
/// </summary>
public sealed class HostsActivityGroupingTests
{
    private static HostsActivityViewModel CreateVm() => new(
        new HostsServiceClient(NamedPipeChannel.Create(SessionToken.Generate(), "hg-actgroup-none")));

    [Fact]
    public void Toggling_group_by_root_adds_and_removes_the_group_description()
    {
        var vm = CreateVm();
        vm.Rows.Add(new ActivityRowViewModel { Domain = "a.cdn.example.com", Root = "example.com" });
        vm.Rows.Add(new ActivityRowViewModel { Domain = "b.cdn.example.com", Root = "example.com" });
        vm.Rows.Add(new ActivityRowViewModel { Domain = "tracker.other.net", Root = "other.net" });

        var view = vm.RowsView;
        view.GroupDescriptions.Should().BeEmpty("the flat feed is the default");

        vm.GroupByRoot = true;
        view.GroupDescriptions.Should().ContainSingle()
            .Which.Should().BeOfType<PropertyGroupDescription>()
            .Which.PropertyName.Should().Be(nameof(ActivityRowViewModel.Root));
        view.Groups.Should().HaveCount(2, "three rows share two roots");

        vm.GroupByRoot = false;
        view.GroupDescriptions.Should().BeEmpty();
    }

    [Fact]
    public void SelectedDomains_collects_every_selected_row_deduped_not_just_one()
    {
        // Regression: bulk hide used to send only the primary SelectedItem, so a
        // multi-selection hid one row. It must collect ALL selected domains.
        var selection = new System.Collections.ArrayList
        {
            new ActivityRowViewModel { Domain = "a.example.com" },
            new ActivityRowViewModel { Domain = "b.example.com" },
            new ActivityRowViewModel { Domain = "a.example.com" }, // dup
            new ActivityRowViewModel { Domain = "" },              // skipped
            "not a row",                                           // ignored
        };

        HostsActivityViewModel.SelectedDomains(selection)
            .Should().BeEquivalentTo(new[] { "a.example.com", "b.example.com" });

        HostsActivityViewModel.SelectedDomains(null).Should().BeEmpty();
    }
}
