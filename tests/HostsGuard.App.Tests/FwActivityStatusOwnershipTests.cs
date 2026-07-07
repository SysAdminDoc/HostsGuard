using System.Reflection;
using FluentAssertions;
using HostsGuard.App.Services;
using HostsGuard.App.ViewModels;
using HostsGuard.Contracts;
using HostsGuard.Ipc;
using Xunit;

namespace HostsGuard.App.Tests;

public sealed class FwActivityStatusOwnershipTests
{
    private static FwActivityViewModel CreateVm() => new(
        new HostsServiceClient(NamedPipeChannel.Create(SessionToken.Generate(), "hg-fw-status-none")),
        new FakeConfirm(true));

    [Fact]
    public async Task Live_connection_counts_do_not_overwrite_operator_results()
    {
        var vm = CreateVm();

        Upsert(vm, "203.0.113.10", 443);
        vm.StatusText.Should().Be("1 connection");

        await vm.QuickBlockIpAsync("");
        vm.StatusText.Should().Be("Select a row first");

        Upsert(vm, "203.0.113.11", 443);
        vm.StatusText.Should().Be("Select a row first");
    }

    [Fact]
    public async Task Forced_live_transition_reclaims_status_ownership()
    {
        var vm = CreateVm();

        Upsert(vm, "203.0.113.10", 443);
        vm.StatusText.Should().Be("1 connection");

        await vm.QuickBlockIpAsync("");
        SetLiveStatus(vm, "Live feed disconnected", force: true);
        vm.StatusText.Should().Be("Live feed disconnected");

        Upsert(vm, "203.0.113.11", 443);
        vm.StatusText.Should().Be("2 connections");
    }

    private static void Upsert(FwActivityViewModel vm, string remoteAddr, int remotePort)
    {
        var method = typeof(FwActivityViewModel).GetMethod(
            "Upsert",
            BindingFlags.Instance | BindingFlags.NonPublic);
        method.Should().NotBeNull("the live stream path should remain covered by this regression test");
        method!.Invoke(vm, new object[]
        {
            new ConnectionEvent
            {
                Protocol = "TCP",
                LocalAddr = "127.0.0.1",
                LocalPort = 50000 + remotePort,
                RemoteAddr = remoteAddr,
                RemotePort = remotePort,
                Process = "browser.exe",
                Pid = 1234 + remotePort,
                State = "ESTABLISHED",
                Country = "US",
                FwStatus = "Observed",
            },
        });
    }

    private static void SetLiveStatus(FwActivityViewModel vm, string text, bool force)
    {
        var method = typeof(FwActivityViewModel).GetMethod(
            "SetLiveStatus",
            BindingFlags.Instance | BindingFlags.NonPublic);
        method.Should().NotBeNull("status ownership transitions should remain explicit");
        method!.Invoke(vm, new object[] { text, force });
    }
}
