using FluentAssertions;
using HostsGuard.App.Services;
using HostsGuard.App.ViewModels;
using HostsGuard.Ipc;
using Xunit;

namespace HostsGuard.App.Tests;

/// <summary>
/// NET-071 group-by-app live view: the shared search DSL over connection rows
/// and the process group toggle. The client channel is lazy — nothing here
/// touches the wire.
/// </summary>
public sealed class FwActivityGroupingTests
{
    private static FwActivityViewModel CreateVm() => new(
        new HostsServiceClient(NamedPipeChannel.Create(SessionToken.Generate(), "hg-group-none")),
        new FakeConfirm(true));

    private static ConnectionRowViewModel Row(string process = "chrome", string remote = "1.2.3.4",
        int port = 443, string country = "US", string fw = "") => new()
    {
        Process = process,
        Pid = 42,
        Protocol = "TCP",
        RemoteAddr = remote,
        RemotePort = port,
        State = "ESTABLISHED",
        Country = country,
        FwStatus = fw,
    };

    [Theory]
    [InlineData("", true)]
    [InlineData("chrome", true)]
    [InlineData("process:chrome", true)]
    [InlineData("app:chrome", true)]          // alias
    [InlineData("port:443", true)]
    [InlineData("proto:tcp", true)]           // alias + case-insensitive
    [InlineData("country!=US", false)]
    [InlineData("!chrome", false)]
    [InlineData("process:svchost", false)]
    [InlineData("fw:threat", false)]
    public void Filter_uses_the_shared_search_dsl(string query, bool expected)
    {
        var vm = CreateVm();
        vm.Filter = query;

        vm.MatchesFilter(Row()).Should().Be(expected);
    }

    [Fact]
    public void Threat_rows_are_findable_by_fw_field()
    {
        var vm = CreateVm();
        vm.Filter = "fw:threat";

        vm.MatchesFilter(Row(fw: "THREAT")).Should().BeTrue();
        vm.MatchesFilter(Row()).Should().BeFalse();
    }

    [Fact]
    public void View_groups_by_process_and_toggle_removes_grouping()
    {
        var vm = CreateVm();

        vm.ConnectionsView.GroupDescriptions.Should().ContainSingle();

        vm.GroupByApp = false;
        vm.ConnectionsView.GroupDescriptions.Should().BeEmpty();

        vm.GroupByApp = true;
        vm.ConnectionsView.GroupDescriptions.Should().ContainSingle();
    }

    [Fact]
    public void View_filters_rows_live()
    {
        var vm = CreateVm();
        vm.Rows.Add(Row("chrome"));
        vm.Rows.Add(Row("svchost", remote: "9.9.9.9"));

        vm.Filter = "process:chrome";

        vm.ConnectionsView.Cast<ConnectionRowViewModel>().Should().ContainSingle()
            .Which.Process.Should().Be("chrome");
    }
}
