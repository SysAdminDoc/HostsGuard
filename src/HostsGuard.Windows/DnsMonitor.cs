using System.Runtime.Versioning;
using System.Security.Principal;
using HostsGuard.Core;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;

namespace HostsGuard.Windows;

/// <summary>An observed DNS query.</summary>
public sealed class DnsObservedEventArgs(string domain, int pid) : EventArgs
{
    public string Domain { get; } = domain;

    public int Pid { get; } = pid;
}

/// <summary>Result of attempting to start the monitor.</summary>
public enum DnsMonitorStatus
{
    Started,
    RequiresElevation,
    Unavailable,
}

/// <summary>
/// Real-time DNS monitor over the ETW <c>Microsoft-Windows-DNS-Client</c> provider
/// (via TraceEvent) — replaces PowerShell Get-DnsClientCache polling. A real-time
/// ETW session requires elevation; <see cref="Start"/> reports that cleanly rather
/// than throwing, so the caller can fall back. Event names are normalized/filtered
/// through <see cref="DnsEventNormalizer"/>.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class DnsMonitor : IDisposable
{
    // {1C95126E-7EEA-49A9-A3FE-A378B03DDB4D} — Microsoft-Windows-DNS-Client
    private static readonly Guid DnsClientProvider = new("1C95126E-7EEA-49A9-A3FE-A378B03DDB4D");
    private const int QueryStartEventId = 3006;

    private readonly string _sessionName;
    private TraceEventSession? _session;
    private Thread? _pump;

    public DnsMonitor(string sessionName = "HostsGuardDns") => _sessionName = sessionName;

    /// <summary>Fires for each reportable DNS query with owning PID.</summary>
    public event EventHandler<DnsObservedEventArgs>? DnsObserved;

    public static bool IsElevated()
    {
        try
        {
            using var id = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch (InvalidOperationException)
        {
            return false;
        }
    }

    /// <summary>Attempt to start the ETW session. Non-throwing; returns a status.</summary>
    public DnsMonitorStatus Start()
    {
        if (!IsElevated())
        {
            return DnsMonitorStatus.RequiresElevation;
        }

        try
        {
            _session = new TraceEventSession(_sessionName) { StopOnDispose = true };
            _session.EnableProvider(DnsClientProvider);
            _session.Source.Dynamic.All += OnEvent;
            _pump = new Thread(() => _session.Source.Process()) { IsBackground = true, Name = "HostsGuardDnsEtw" };
            _pump.Start();
            return DnsMonitorStatus.Started;
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or InvalidOperationException)
        {
            Dispose();
            return DnsMonitorStatus.Unavailable;
        }
    }

    private void OnEvent(TraceEvent data)
    {
        if ((int)data.ID != QueryStartEventId)
        {
            return;
        }

        var raw = data.PayloadByName("QueryName") as string;
        if (DnsEventNormalizer.TryNormalize(raw, out var domain))
        {
            DnsObserved?.Invoke(this, new DnsObservedEventArgs(domain, data.ProcessID));
        }
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
