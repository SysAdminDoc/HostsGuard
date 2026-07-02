using System.Collections.Concurrent;
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

    private readonly string _sessionName;
    private TraceEventSession? _session;
    private Thread? _pump;
    private ConcurrentDictionary<int, Counter> _counters = new();

    public BandwidthMonitor(string sessionName = "HostsGuardBandwidth") => _sessionName = sessionName;

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
            kernel.TcpIpSend += d => Add(d.ProcessID, d.size, 0);
            kernel.TcpIpRecv += d => Add(d.ProcessID, 0, d.size);
            kernel.TcpIpSendIPV6 += d => Add(d.ProcessID, d.size, 0);
            kernel.TcpIpRecvIPV6 += d => Add(d.ProcessID, 0, d.size);
            kernel.UdpIpSend += d => Add(d.ProcessID, d.size, 0);
            kernel.UdpIpRecv += d => Add(d.ProcessID, 0, d.size);
            kernel.UdpIpSendIPV6 += d => Add(d.ProcessID, d.size, 0);
            kernel.UdpIpRecvIPV6 += d => Add(d.ProcessID, 0, d.size);
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

    private void Add(int pid, long sent, long recv)
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
        try
        {
            _session?.Dispose();
        }
        catch (InvalidOperationException)
        {
            // session already torn down
        }

        _session = null;
    }
}
