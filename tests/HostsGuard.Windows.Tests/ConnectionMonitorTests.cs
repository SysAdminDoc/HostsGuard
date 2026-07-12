using System.Net;
using System.Net.Sockets;
using System.Runtime.Versioning;
using FluentAssertions;
using HostsGuard.Windows;
using Xunit;

namespace HostsGuard.Windows.Tests;

[SupportedOSPlatform("windows")]
public class ConnectionMonitorTests
{
    [Fact]
    public void Snapshot_returns_valid_pid_attributed_rows()
    {
        var monitor = new ConnectionMonitor();
        var conns = monitor.Snapshot();

        conns.Should().NotBeNull();
        conns.Should().OnlyContain(c =>
            (c.Protocol == "TCP" || c.Protocol == "UDP") &&
            c.LocalPort >= 0 && c.LocalPort <= 65535 && c.Pid >= 0);
    }

    [Fact]
    public void A_listening_socket_is_observed_with_our_pid()
    {
        // Open a listener so there is a deterministic TCP row owned by this process.
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try
        {
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            var myPid = Environment.ProcessId;

            var conns = new ConnectionMonitor().Snapshot();

            conns.Should().Contain(c =>
                c.LocalPort == port && c.Pid == myPid && c.State == "LISTEN",
                "the listener we just opened must appear attributed to this process");
        }
        finally
        {
            listener.Stop();
        }
    }

    [Fact]
    public void Udp_endpoint_is_observed_with_injected_owner_identity()
    {
        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        var port = ((IPEndPoint)socket.LocalEndPoint!).Port;
        var owner = new ConnectionOwnerInfo("test-process", @"C:\Apps\test.exe", "Contoso.Test_123");

        var conns = new ConnectionMonitor(_ => owner).Snapshot();

        conns.Should().Contain(c =>
            c.Protocol == "UDP" && c.LocalPort == port && c.Pid == Environment.ProcessId &&
            c.State == "LISTEN" && c.Direction == "inbound" &&
            c.Process == owner.Process && c.ProcessPath == owner.ProcessPath &&
            c.PackageFamilyName == owner.PackageFamilyName);
    }
}
