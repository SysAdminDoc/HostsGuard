using System.Reflection;
using System.Windows.Data;
using FluentAssertions;
using HostsGuard.App.Services;
using HostsGuard.App.ViewModels;
using HostsGuard.Contracts;
using HostsGuard.Ipc;
using Xunit;

namespace HostsGuard.App.Tests;

/// <summary>
/// Group-by-root feed view: subdomain noise collapses under expandable root
/// headers, and toggling off restores the flat feed. Lazy channel — no wire.
/// </summary>
public sealed class HostsActivityGroupingTests
{
    private static readonly MethodInfo UpsertMethod =
        typeof(HostsActivityViewModel).GetMethod("Upsert", BindingFlags.Instance | BindingFlags.NonPublic)
        ?? throw new MissingMethodException(nameof(HostsActivityViewModel), "Upsert");

    private static readonly FieldInfo HideBlockedField =
        typeof(HostsActivityViewModel).GetField("_hideBlocked", BindingFlags.Instance | BindingFlags.NonPublic)
        ?? throw new MissingFieldException(nameof(HostsActivityViewModel), "_hideBlocked");

    private static readonly int MaxRows =
        (int)(typeof(HostsActivityViewModel).GetField("MaxRows", BindingFlags.Static | BindingFlags.NonPublic)
            ?.GetRawConstantValue() ?? 1000);

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

    [Fact]
    public void Live_upsert_index_removes_rows_dropped_by_filters()
    {
        var vm = CreateVm();
        UpsertDns(vm, "ads.example.com", process: "first.exe");
        vm.Rows.Should().ContainSingle(r => r.Domain == "ads.example.com");

        HideBlockedField.SetValue(vm, true);
        UpsertDns(vm, "ads.example.com", blocked: true, process: "blocked.exe");
        vm.Rows.Should().BeEmpty();

        HideBlockedField.SetValue(vm, false);
        UpsertDns(vm, "ads.example.com", process: "second.exe");
        vm.Rows.Should().ContainSingle(r =>
            r.Domain == "ads.example.com" && r.Hits == 1 && r.Process == "second.exe");
    }

    [Fact]
    public void Live_upsert_index_removes_evicted_rows()
    {
        var vm = CreateVm();
        var evictedDomain = "domain-0000.example.com";
        for (var i = 0; i <= MaxRows; i++)
        {
            UpsertDns(vm, $"domain-{i:D4}.example.com", process: "burst.exe");
        }

        vm.Rows.Should().HaveCount(MaxRows);
        vm.Rows.Should().NotContain(r => r.Domain == evictedDomain);

        UpsertDns(vm, evictedDomain, process: "again.exe");
        vm.Rows.Should().HaveCount(MaxRows);
        vm.Rows[0].Domain.Should().Be(evictedDomain);
        vm.Rows[0].Hits.Should().Be(1);
        vm.Rows[0].Process.Should().Be("again.exe");
    }

    [Fact]
    public void Activity_row_maps_resolution_hops_for_the_inspector()
    {
        var contract = new ActivityRow { Domain = "shop.example.com" };
        contract.ResolutionChain.Add(new[]
        {
            new ResolutionHop { Value = "shop.example.com", Kind = "query", Verdict = "observed" },
            new ResolutionHop { Value = "tracker.example.net", Kind = "cname", Verdict = "listed", Blocklists = { "Tracker list" } },
            new ResolutionHop { Value = "203.0.113.10", Kind = "A", Verdict = "resolved" },
        });

        var row = ActivityRowViewModel.From(contract);

        row.HasResolutionChain.Should().BeTrue();
        row.ResolutionChain.Select(hop => hop.KindText).Should().Equal("Query", "CNAME", "A");
        row.ResolutionChain[1].VerdictText.Should().Be("Listed");
        row.ResolutionChain[1].BlocklistsText.Should().Be("Tracker list");
    }

    private static void UpsertDns(
        HostsActivityViewModel vm,
        string domain,
        bool blocked = false,
        bool hidden = false,
        string process = "proc.exe")
    {
        UpsertMethod.Invoke(vm, new object[]
        {
            new DnsEvent
            {
                Domain = domain,
                Blocked = blocked,
                Hidden = hidden,
                Process = process,
            },
        });
    }
}
