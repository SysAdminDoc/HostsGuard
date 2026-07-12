using System.Net;
using System.Reflection;
using System.Net.Sockets;
using FluentAssertions;
using HostsGuard.Windows;

namespace HostsGuard.Windows.Tests;

public sealed class BandwidthMonitorTests
{
    private static readonly MethodInfo AddMethod =
        typeof(BandwidthMonitor).GetMethod("Add", BindingFlags.Instance | BindingFlags.NonPublic)
        ?? throw new MissingMethodException(nameof(BandwidthMonitor), "Add");

    private static readonly FieldInfo AddressTextCacheField =
        typeof(BandwidthMonitor).GetField("_addressTextCache", BindingFlags.Instance | BindingFlags.NonPublic)
        ?? throw new MissingFieldException(nameof(BandwidthMonitor), "_addressTextCache");

    [Fact]
    public void Remote_endpoint_text_cache_reuses_equal_ip_addresses()
    {
        using var monitor = new BandwidthMonitor("HostsGuardBandwidthTest");
        var first = IPAddress.Parse("203.0.113.77");
        var sameAddress = IPAddress.Parse("203.0.113.77");

        AddRemote(monitor, 4242, sent: 10, recv: 0, first);
        AddRemote(monitor, 4242, sent: 0, recv: 20, sameAddress);

        CacheCount(monitor).Should().Be(1);
        var endpoints = monitor.DrainByEndpoint();
        endpoints.Should().ContainKey((4242, "203.0.113.77"));
        endpoints[(4242, "203.0.113.77")].Should().Be((10, 20));
    }

    [Theory]
    [InlineData("TCP", true, "10.0.0.5", 51000, "203.0.113.7", 443, "OBSERVED")]
    [InlineData("UDP", false, "2001:db8::5", 53000, "2001:db8::7", 53, "STATELESS")]
    public void Packet_observations_normalize_direction_and_protocol_state(
        string protocol,
        bool outbound,
        string localAddress,
        int localPort,
        string remoteAddress,
        int remotePort,
        string state)
    {
        ConnectionInfo? observed = null;
        using var monitor = new BandwidthMonitor("HostsGuardBandwidthTest", info => observed = info);
        var sourceAddress = IPAddress.Parse(outbound ? localAddress : remoteAddress);
        var sourcePort = outbound ? localPort : remotePort;
        var destinationAddress = IPAddress.Parse(outbound ? remoteAddress : localAddress);
        var destinationPort = outbound ? remotePort : localPort;

        monitor.PublishEndpoint(protocol, outbound, 4242, "app.exe", sourceAddress, sourcePort,
            destinationAddress, destinationPort);

        observed.Should().Be(new ConnectionInfo(protocol, localAddress, localPort, remoteAddress,
            remotePort, state, 4242, "app.exe", outbound ? "outbound" : "inbound"));
    }

    [Fact]
    public async Task Live_etw_session_observes_udp_when_explicitly_enabled()
    {
        if (Environment.GetEnvironmentVariable("HOSTSGUARD_LIVE_ETW_TESTS") != "1")
        {
            return;
        }

        var observed = new TaskCompletionSource<ConnectionInfo>(TaskCreationOptions.RunContinuationsAsynchronously);
        using var listener = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var port = ((IPEndPoint)listener.Client.LocalEndPoint!).Port;
        using var monitor = new BandwidthMonitor(
            $"HostsGuardBandwidthTest-{Guid.NewGuid():N}",
            info =>
            {
                if (info.Protocol == "UDP" && info.Pid == Environment.ProcessId && info.RemotePort == port)
                {
                    observed.TrySetResult(info);
                }
            });

        monitor.Start().Should().Be(DnsMonitorStatus.Started);
        using var sender = new UdpClient();
        await sender.SendAsync(new byte[] { 1 }, new IPEndPoint(IPAddress.Loopback, port));

        var result = await observed.Task.WaitAsync(TimeSpan.FromSeconds(10));
        result.LocalAddress.Should().Be("127.0.0.1");
        result.RemoteAddress.Should().Be("127.0.0.1");
        result.State.Should().Be("STATELESS");
    }

    [Fact]
    public void Dispose_is_idempotent_without_a_started_session()
    {
        var monitor = new BandwidthMonitor("HostsGuardBandwidthTest");

        var dispose = () =>
        {
            monitor.Dispose();
            monitor.Dispose();
        };

        dispose.Should().NotThrow();
        monitor.Active.Should().BeFalse();
    }

    [Fact]
    public void Throwing_endpoint_observer_is_reported_without_escaping()
    {
        Exception? reported = null;
        using var monitor = new BandwidthMonitor(
            "HostsGuardBandwidthTest",
            _ => throw new InvalidOperationException("observer failed"),
            ex => reported = ex);

        var publish = () => monitor.PublishEndpoint("TCP", true, 42, "app.exe",
            IPAddress.Loopback, 51000, IPAddress.Parse("203.0.113.7"), 443);

        publish.Should().NotThrow();
        reported.Should().BeOfType<InvalidOperationException>()
            .Which.Message.Should().Be("observer failed");
    }

    private static void AddRemote(BandwidthMonitor monitor, int pid, long sent, long recv, IPAddress remote)
        => AddMethod.Invoke(monitor, new object?[] { pid, sent, recv, remote });

    private static int CacheCount(BandwidthMonitor monitor)
    {
        var cache = AddressTextCacheField.GetValue(monitor) ?? throw new InvalidOperationException("cache missing");
        var count = cache.GetType().GetProperty("Count")?.GetValue(cache);
        return count is int value ? value : throw new InvalidOperationException("cache count missing");
    }
}
