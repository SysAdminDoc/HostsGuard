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
            c.Protocol == "TCP" && c.LocalPort >= 0 && c.LocalPort <= 65535 && c.Pid >= 0);
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
}
