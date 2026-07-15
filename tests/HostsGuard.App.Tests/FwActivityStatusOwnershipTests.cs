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

    [Fact]
    public void Quic_rollup_counts_udp_443_by_executable_and_distinct_endpoint()
    {
        var vm = CreateVm();
        var browserPath = @"C:\Apps\Browser\browser.exe";
        var syncPath = @"C:\Apps\Sync\sync.exe";

        vm.RecordQuicObservation(Connection("UDP", "203.0.113.10", 443, "browser.exe", 100), browserPath);
        vm.RecordQuicObservation(Connection("udp", "203.0.113.11", 443, "browser.exe", 101), browserPath);
        vm.RecordQuicObservation(Connection("UDP", "203.0.113.11", 443, "browser.exe", 101), browserPath);
        vm.RecordQuicObservation(Connection("UDP", "198.51.100.8", 443, "sync.exe", 200), syncPath);
        vm.RecordQuicObservation(Connection("TCP", "203.0.113.12", 443, "ignored.exe", 300), @"C:\ignored.exe");
        vm.RecordQuicObservation(Connection("UDP", "203.0.113.13", 53, "dns.exe", 400), @"C:\dns.exe");

        vm.QuicProcesses.Should().HaveCount(2);
        var browser = vm.QuicProcesses[0];
        browser.Process.Should().Be("browser.exe");
        browser.ProgramPath.Should().Be(browserPath);
        browser.ConnectionCount.Should().Be(3);
        browser.EndpointCount.Should().Be(2);
        browser.LastEndpoint.Should().Be("203.0.113.11:443");
        browser.CanSteer.Should().BeTrue();
        vm.QuicProcesses[1].Process.Should().Be("sync.exe");
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

    private static ConnectionRowViewModel Connection(
        string protocol,
        string remoteAddress,
        int remotePort,
        string process,
        int pid) => new()
        {
            Protocol = protocol,
            RemoteAddr = remoteAddress,
            RemotePort = remotePort,
            Process = process,
            Pid = pid,
        };
}
