using FluentAssertions;
using HostsGuard.App.Services;
using HostsGuard.App.ViewModels;
using HostsGuard.Ipc;
using Xunit;

namespace HostsGuard.App.Tests;

public sealed class ListenerExposureViewTests
{
    private static FwActivityViewModel CreateVm() => new(
        new HostsServiceClient(NamedPipeChannel.Create(SessionToken.Generate(), "hg-listener-none")),
        new FakeConfirm(true));

    private static ListenerExposureRowViewModel Row() => new()
    {
        Protocol = "TCP",
        LocalAddress = "0.0.0.0",
        LocalPort = 445,
        Process = "System",
        Pid = 4,
        Service = "LanmanServer",
        BindScope = "all interfaces",
        ActiveProfiles = "Domain, Private",
        Coverage = "allowed inbound",
        Risk = "high",
        Reason = "Inbound allow rule covers this port",
    };

    [Theory]
    [InlineData("", true)]
    [InlineData("process:System", true)]
    [InlineData("app:System", true)]
    [InlineData("port:445", true)]
    [InlineData("profile:private", true)]
    [InlineData("risk:high", true)]
    [InlineData("status:blocked", false)]
    [InlineData("!LanmanServer", false)]
    public void Listener_filter_uses_shared_search_syntax(string query, bool expected)
    {
        var vm = CreateVm();
        vm.ListenerFilter = query;

        vm.MatchesListenerFilter(Row()).Should().Be(expected);
    }

    [Fact]
    public void Listener_view_filters_live_and_orders_high_risk_first()
    {
        var vm = CreateVm();
        var low = Row();
        low.Risk = "low";
        low.LocalPort = 80;
        var high = Row();
        vm.Listeners.Add(low);
        vm.Listeners.Add(high);

        vm.ListenerView.Cast<ListenerExposureRowViewModel>().First().Risk.Should().Be("high");

        vm.ListenerFilter = "port:80";
        vm.ListenerView.Cast<ListenerExposureRowViewModel>().Should().ContainSingle()
            .Which.LocalPort.Should().Be(80);
    }

    [Theory]
    [InlineData("127.0.0.1", "127.0.0.1:445")]
    [InlineData("::", "[::]:445")]
    [InlineData("fe80::1", "[fe80::1]:445")]
    public void Endpoint_disambiguates_ipv6_addresses(string address, string expected)
    {
        var row = Row();
        row.LocalAddress = address;

        row.Endpoint.Should().Be(expected);
    }
}
