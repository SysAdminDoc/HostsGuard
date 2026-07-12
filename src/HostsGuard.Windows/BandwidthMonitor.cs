using System.Collections.Concurrent;
using System.Net;
using System.Runtime.Versioning;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;

namespace HostsGuard.Windows;

/// <summary>
/// Per-PID byte counters, drained and reset in one call. Interface so the
/// service-side aggregator is testable without an ETW session.
/// </summary>
public interface IBandwidthSource
{
    /// <summary>Counters are live (the ETW session started; elevation-gated).</summary>
    bool Active { get; }

    /// <summary>Snapshot and reset the accumulated per-PID (sent, recv) bytes.</summary>
    IReadOnlyDictionary<int, (long Sent, long Recv)> Drain();

    /// <summary>
    /// Snapshot and reset per-(PID, remote-IP) byte tallies (NET-108). The remote
    /// IP lets the aggregator attribute bytes to a resolved domain. Default: none
    /// (sources that don't track endpoints, e.g. test fakes, opt out for free).
    /// </summary>
    IReadOnlyDictionary<(int Pid, string RemoteAddress), (long Sent, long Recv)> DrainByEndpoint()
        => new Dictionary<(int, string), (long, long)>();
}

/// <summary>
/// Per-process network byte counters via the ETW kernel NetworkTCPIP provider
/// (TraceEvent) — the same GlassWire-style source, no polling and no packet
/// capture. TCP+UDP, IPv4+IPv6 send/recv sizes are accumulated per PID;
/// <see cref="Drain"/> hands the totals to the aggregator and resets. A kernel
/// session requires elevation; <see cref="Start"/> reports that cleanly so the
/// caller can degrade to inactive counters.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class BandwidthMonitor : IBandwidthSource, IDisposable
{
    private sealed class Counter
    {
        public long Sent;
        public long Recv;
    }

    private sealed record AddressTextCacheEntry(string Text, long ExpiresAtMs);

    private const int AddressTextCacheMaxEntries = 4096;
    private static readonly long AddressTextCacheTtlMs = (long)TimeSpan.FromMinutes(5).TotalMilliseconds;
    private static readonly long AddressTextCacheSweepMs = (long)TimeSpan.FromMinutes(1).TotalMilliseconds;

    private readonly string _sessionName;
    private readonly Action<ConnectionInfo>? _endpointObserver;
    private readonly Action<Exception>? _endpointObserverError;
    private TraceEventSession? _session;
    private Thread? _pump;
    private ConcurrentDictionary<int, Counter> _counters = new();
    private ConcurrentDictionary<(int, string), Counter> _endpoints = new();
    private readonly ConcurrentDictionary<IPAddress, AddressTextCacheEntry> _addressTextCache = new();
    private long _nextAddressTextSweepMs;

    public BandwidthMonitor(
        string sessionName = "HostsGuardBandwidth",
        Action<ConnectionInfo>? endpointObserver = null,
        Action<Exception>? endpointObserverError = null)
    {
        _sessionName = sessionName;
        _endpointObserver = endpointObserver;
        _endpointObserverError = endpointObserverError;
    }

    public bool Active => _session is not null;

    /// <summary>Attempt to start the kernel ETW session. Non-throwing; returns a status.</summary>
    public DnsMonitorStatus Start()
    {
        if (!DnsMonitor.IsElevated())
        {
            return DnsMonitorStatus.RequiresElevation;
        }

        try
        {
            _session = new TraceEventSession(_sessionName) { StopOnDispose = true };
            _session.EnableKernelProvider(KernelTraceEventParser.Keywords.NetworkTCPIP);
            var kernel = _session.Source.Kernel;
            // On send the remote is the destination (daddr); on recv it's the
            // source (saddr). Track both a per-PID total and a per-(PID, remote-IP)
            // tally so bytes can be attributed to a resolved domain (NET-108).
            kernel.TcpIpSend += d => Add(d.ProcessID, d.size, 0, d.daddr);
            kernel.TcpIpRecv += d => Add(d.ProcessID, 0, d.size, d.saddr);
            kernel.TcpIpSendIPV6 += d => Add(d.ProcessID, d.size, 0, d.daddr);
            kernel.TcpIpRecvIPV6 += d => Add(d.ProcessID, 0, d.size, d.saddr);
            kernel.TcpIpConnect += d => PublishEndpoint("TCP", true, d.ProcessID, d.ProcessName,
                d.saddr, d.sport, d.daddr, d.dport);
            kernel.TcpIpAccept += d => PublishEndpoint("TCP", false, d.ProcessID, d.ProcessName,
                d.saddr, d.sport, d.daddr, d.dport);
            kernel.TcpIpConnectIPV6 += d => PublishEndpoint("TCP", true, d.ProcessID, d.ProcessName,
                d.saddr, d.sport, d.daddr, d.dport);
            kernel.TcpIpAcceptIPV6 += d => PublishEndpoint("TCP", false, d.ProcessID, d.ProcessName,
                d.saddr, d.sport, d.daddr, d.dport);
            kernel.UdpIpSend += d => ObserveUdpPacket(true, d.ProcessID, d.ProcessName,
                d.saddr, d.sport, d.daddr, d.dport, d.size);
            kernel.UdpIpRecv += d => ObserveUdpPacket(false, d.ProcessID, d.ProcessName,
                d.saddr, d.sport, d.daddr, d.dport, d.size);
            kernel.UdpIpSendIPV6 += d => ObserveUdpPacket(true, d.ProcessID, d.ProcessName,
                d.saddr, d.sport, d.daddr, d.dport, d.size);
            kernel.UdpIpRecvIPV6 += d => ObserveUdpPacket(false, d.ProcessID, d.ProcessName,
                d.saddr, d.sport, d.daddr, d.dport, d.size);
            _pump = new Thread(() => _session.Source.Process()) { IsBackground = true, Name = "HostsGuardBwEtw" };
            _pump.Start();
            return DnsMonitorStatus.Started;
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or InvalidOperationException)
        {
            Dispose();
            return DnsMonitorStatus.Unavailable;
        }
    }

    private void ObserveUdpPacket(
        bool outbound,
        int pid,
        string? process,
        IPAddress sourceAddress,
        int sourcePort,
        IPAddress destinationAddress,
        int destinationPort,
        int size)
    {
        var remoteAddress = outbound ? destinationAddress : sourceAddress;
        Add(pid, outbound ? size : 0, outbound ? 0 : size, remoteAddress);
        PublishEndpoint("UDP", outbound, pid, process, sourceAddress, sourcePort,
            destinationAddress, destinationPort);
    }

    internal void PublishEndpoint(
        string protocol,
        bool outbound,
        int pid,
        string? process,
        IPAddress sourceAddress,
        int sourcePort,
        IPAddress destinationAddress,
        int destinationPort)
    {
        var localAddress = outbound ? sourceAddress : destinationAddress;
        var localPort = outbound ? sourcePort : destinationPort;
        var remoteAddress = outbound ? destinationAddress : sourceAddress;
        var remotePort = outbound ? destinationPort : sourcePort;

        if (_endpointObserver is null || pid <= 0 || localPort < 0 || remotePort < 0)
        {
            return;
        }

        try
        {
            _endpointObserver(new ConnectionInfo(
                protocol,
                localAddress.ToString(),
                localPort,
                remoteAddress.ToString(),
                remotePort,
                protocol == "UDP" ? "STATELESS" : "OBSERVED",
                pid,
                string.IsNullOrWhiteSpace(process) ? "?" : process,
                outbound ? "outbound" : "inbound"));
        }
        catch (Exception ex)
        {
            try
            {
                _endpointObserverError?.Invoke(ex);
            }
            catch (Exception)
            {
                // A diagnostic callback must not terminate the kernel ETW pump.
            }
        }
    }

    private void Add(int pid, long sent, long recv, IPAddress? remote = null)
    {
        if (pid <= 0)
        {
            return;
        }

        var c = _counters.GetOrAdd(pid, static _ => new Counter());
        if (sent != 0)
        {
            Interlocked.Add(ref c.Sent, sent);
        }

        if (recv != 0)
        {
            Interlocked.Add(ref c.Recv, recv);
        }

        if (remote is null)
        {
            return;
        }

        var e = _endpoints.GetOrAdd((pid, RemoteAddressText(remote)), static _ => new Counter());
        if (sent != 0)
        {
            Interlocked.Add(ref e.Sent, sent);
        }

        if (recv != 0)
        {
            Interlocked.Add(ref e.Recv, recv);
        }
    }

    private string RemoteAddressText(IPAddress remote)
    {
        var now = Environment.TickCount64;
        if (_addressTextCache.TryGetValue(remote, out var cached) && cached.ExpiresAtMs > now)
        {
            return cached.Text;
        }

        var text = remote.ToString();
        _addressTextCache[remote] = new AddressTextCacheEntry(text, now + AddressTextCacheTtlMs);
        if (_addressTextCache.Count > AddressTextCacheMaxEntries)
        {
            SweepAddressTextCache(now);
            TrimAddressTextCache();
        }

        return text;
    }

    private void SweepAddressTextCache(long now)
    {
        var next = Interlocked.Read(ref _nextAddressTextSweepMs);
        if (next > now)
        {
            return;
        }

        if (Interlocked.CompareExchange(ref _nextAddressTextSweepMs, now + AddressTextCacheSweepMs, next) != next)
        {
            return;
        }

        foreach (var (address, cached) in _addressTextCache)
        {
            if (cached.ExpiresAtMs <= now)
            {
                _addressTextCache.TryRemove(address, out _);
            }
        }
    }

    private void TrimAddressTextCache()
    {
        var overflow = _addressTextCache.Count - AddressTextCacheMaxEntries;
        if (overflow <= 0)
        {
            return;
        }

        foreach (var address in _addressTextCache.Keys)
        {
            if (overflow-- <= 0)
            {
                break;
            }

            _addressTextCache.TryRemove(address, out _);
        }
    }

    public IReadOnlyDictionary<(int Pid, string RemoteAddress), (long Sent, long Recv)> DrainByEndpoint()
    {
        var drained = Interlocked.Exchange(ref _endpoints, new ConcurrentDictionary<(int, string), Counter>());
        var result = new Dictionary<(int, string), (long, long)>(drained.Count);
        foreach (var (key, c) in drained)
        {
            var sent = Interlocked.Read(ref c.Sent);
            var recv = Interlocked.Read(ref c.Recv);
            if (sent != 0 || recv != 0)
            {
                result[key] = (sent, recv);
            }
        }

        return result;
    }

    public IReadOnlyDictionary<int, (long Sent, long Recv)> Drain()
    {
        var drained = Interlocked.Exchange(ref _counters, new ConcurrentDictionary<int, Counter>());
        var result = new Dictionary<int, (long, long)>(drained.Count);
        foreach (var (pid, c) in drained)
        {
            var sent = Interlocked.Read(ref c.Sent);
            var recv = Interlocked.Read(ref c.Recv);
            if (sent != 0 || recv != 0)
            {
                result[pid] = (sent, recv);
            }
        }

        return result;
    }

    public void Dispose()
    {
        var session = Interlocked.Exchange(ref _session, null);
        var pump = Interlocked.Exchange(ref _pump, null);
        try
        {
            session?.Dispose();
        }
        catch (InvalidOperationException)
        {
            // session already torn down
        }

        if (pump is not null && pump != Thread.CurrentThread)
        {
            pump.Join(TimeSpan.FromSeconds(5));
        }
    }
}
