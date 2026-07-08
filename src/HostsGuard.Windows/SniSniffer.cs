using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.Versioning;

namespace HostsGuard.Windows;

/// <summary>An observed TLS SNI: the remote IP and the recovered hostname (or ECH-unavailable).</summary>
public sealed record SniObservation(string RemoteAddress, string Host, bool EchUnavailable);

/// <summary>
/// Driver-free TLS SNI capture (NET-109). Opens a raw, promiscuous IPv4 socket
/// (SIO_RCVALL — requires elevation, which the LocalSystem service has) on each
/// active interface and parses outbound TCP/443 ClientHello records with
/// <see cref="Core.TlsClientHello"/>. Recovers the hostname for HTTPS connections
/// even when DNS was resolved out-of-band (DoH), and notes ECH as unavailable.
///
/// No kernel driver and no third-party capture library: SIO_RCVALL is a built-in
/// Winsock ioctl. Best-effort and non-throwing — capture failures degrade to
/// "no SNI", never to a service fault. Off unless explicitly started.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class SniSniffer : IDisposable
{
    private const int SioRcvAll = unchecked((int)0x98000001);
    private const int HttpsPort = 443;
    private static readonly TimeSpan PumpJoinTimeout = TimeSpan.FromMilliseconds(500);

    private readonly Action<SniObservation> _onSni;
    private readonly Action<string>? _log;
    private readonly object _gate = new();
    private readonly List<Socket> _sockets = new();
    private readonly List<Thread> _pumps = new();
    private CancellationTokenSource _cts = new();
    private volatile bool _active;

    public SniSniffer(Action<SniObservation> onSni, Action<string>? log = null)
    {
        _onSni = onSni ?? throw new ArgumentNullException(nameof(onSni));
        _log = log;
    }

    public bool Active => _active;

    /// <summary>Start capture on every up, non-loopback IPv4 interface. Non-throwing.</summary>
    public DnsMonitorStatus Start()
    {
        if (!DnsMonitor.IsElevated())
        {
            return DnsMonitorStatus.RequiresElevation;
        }

        lock (_gate)
        {
            if (_active)
            {
                return DnsMonitorStatus.Started;
            }

            if (_cts.IsCancellationRequested)
            {
                _cts.Dispose();
                _cts = new CancellationTokenSource();
            }

            var token = _cts.Token;
            var started = 0;
            foreach (var ip in LocalIPv4Addresses())
            {
                try
                {
                    var socket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);
                    socket.Bind(new IPEndPoint(ip, 0));
                    socket.IOControl(SioRcvAll, BitConverter.GetBytes(1), null);
                    socket.ReceiveBufferSize = 1 << 20;
                    _sockets.Add(socket);
                    var pump = new Thread(() => Pump(socket, token)) { IsBackground = true, Name = "HostsGuardSni" };
                    _pumps.Add(pump);
                    pump.Start();
                    started++;
                }
                catch (SocketException ex)
                {
                    _log?.Invoke($"SNI capture unavailable on {ip}: {ex.Message}");
                }
            }

            _active = started > 0;
            return _active ? DnsMonitorStatus.Started : DnsMonitorStatus.Unavailable;
        }
    }

    private static IEnumerable<IPAddress> LocalIPv4Addresses()
    {
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.OperationalStatus != OperationalStatus.Up ||
                nic.NetworkInterfaceType == NetworkInterfaceType.Loopback)
            {
                continue;
            }

            foreach (var addr in nic.GetIPProperties().UnicastAddresses)
            {
                if (addr.Address.AddressFamily == AddressFamily.InterNetwork)
                {
                    yield return addr.Address;
                }
            }
        }
    }

    private void Pump(Socket socket, CancellationToken token)
    {
        var buffer = new byte[65535];
        while (!token.IsCancellationRequested)
        {
            int read;
            try
            {
                read = socket.Receive(buffer);
            }
            catch (SocketException)
            {
                return; // socket closed on shutdown
            }
            catch (ObjectDisposedException)
            {
                return;
            }

            try
            {
                Inspect(buffer.AsSpan(0, read));
            }
            catch (Exception ex) when (ex is IndexOutOfRangeException or ArgumentOutOfRangeException)
            {
                // Malformed packet — skip; capture never faults the service.
            }
        }
    }

    /// <summary>
    /// Parse an IPv4 packet: if it's a TCP segment to port 443 carrying a TLS
    /// ClientHello, recover the SNI and publish it. Exposed for tests.
    /// </summary>
    public void Inspect(ReadOnlySpan<byte> packet)
    {
        if (packet.Length < 20 || (packet[0] >> 4) != 4)
        {
            return; // not IPv4
        }

        var ihl = (packet[0] & 0x0F) * 4;
        if (ihl < 20 || packet.Length < ihl + 20 || packet[9] != 6)
        {
            return; // not TCP
        }

        var tcp = packet[ihl..];
        var destPort = (tcp[2] << 8) | tcp[3];
        if (destPort != HttpsPort)
        {
            return; // only outbound HTTPS ClientHellos
        }

        var dataOffset = (tcp[12] >> 4) * 4;
        if (dataOffset < 20 || tcp.Length <= dataOffset)
        {
            return;
        }

        var result = Core.TlsClientHello.TryParse(tcp[dataOffset..]);
        if (!result.Found && !result.EchUnavailable)
        {
            return;
        }

        // Destination IP is bytes 16..19 of the IPv4 header.
        var remote = new IPAddress(packet.Slice(16, 4).ToArray()).ToString();
        _onSni(new SniObservation(remote, result.Host, result.EchUnavailable));
    }

    /// <summary>Stop capture and release the sockets; the sniffer can be restarted.</summary>
    public void Stop()
    {
        lock (_gate)
        {
            if (!_active && _sockets.Count == 0)
            {
                return;
            }

            _cts.Cancel();
            foreach (var socket in _sockets)
            {
                try { socket.Dispose(); } catch (ObjectDisposedException) { /* already gone */ }
            }

            _sockets.Clear();
            foreach (var pump in _pumps)
            {
                if (pump == Thread.CurrentThread)
                {
                    continue;
                }

                if (!pump.Join(PumpJoinTimeout))
                {
                    _log?.Invoke("SNI capture pump did not stop before timeout");
                }
            }

            _pumps.Clear();
            _active = false;
        }
    }

    public void Dispose()
    {
        Stop();
        _cts.Dispose();
    }
}
