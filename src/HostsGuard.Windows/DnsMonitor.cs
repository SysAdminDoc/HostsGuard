using System.Runtime.Versioning;
using System.Security.Principal;
using HostsGuard.Core;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;

namespace HostsGuard.Windows;

/// <summary>An observed DNS query.</summary>
public sealed class DnsObservedEventArgs(string domain, int pid, string queryType = "A") : EventArgs
{
    public string Domain { get; } = domain;

    public int Pid { get; } = pid;

    /// <summary>Normalized DNS record type (for example A, AAAA, TXT, HTTPS).</summary>
    public string QueryType { get; } = queryType;
}

/// <summary>A completed DNS resolution with its CNAME chain and resolved addresses.</summary>
public sealed class DnsResolvedEventArgs(string queryName, IReadOnlyList<string> cnames, IReadOnlyList<string> addresses) : EventArgs
{
    public string QueryName { get; } = queryName;

    public IReadOnlyList<string> Cnames { get; } = cnames;

    /// <summary>Resolved A/AAAA addresses (NET-076 direct-IP heuristic).</summary>
    public IReadOnlyList<string> Addresses { get; } = addresses;
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
    private const int QueryCompletedEventId = 3008;

    private readonly string _sessionName;
    private TraceEventSession? _session;
    private Thread? _pump;

    public DnsMonitor(string sessionName = "HostsGuardDns") => _sessionName = sessionName;

    /// <summary>Fires for each reportable DNS query with owning PID.</summary>
    public event EventHandler<DnsObservedEventArgs>? DnsObserved;

    /// <summary>Fires when a resolution completes with a CNAME chain (cloak defense).</summary>
    public event EventHandler<DnsResolvedEventArgs>? DnsResolved;

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
        switch ((int)data.ID)
        {
            case QueryStartEventId:
                if (DnsEventNormalizer.TryNormalize(data.PayloadByName("QueryName") as string, out var domain))
                {
                    DnsObserved?.Invoke(this, new DnsObservedEventArgs(
                        domain,
                        data.ProcessID,
                        NormalizeQueryType(data.PayloadByName("QueryType"))));
                }

                break;

            case QueryCompletedEventId:
                if (DnsResolved is not null &&
                    DnsEventNormalizer.TryNormalize(data.PayloadByName("QueryName") as string, out var qn))
                {
                    var results = data.PayloadByName("QueryResults") as string;
                    var cnames = DnsQueryResults.ExtractCnames(results);
                    var addresses = DnsQueryResults.ExtractAddresses(results);
                    if (cnames.Count != 0 || addresses.Count != 0)
                    {
                        DnsResolved.Invoke(this, new DnsResolvedEventArgs(qn, cnames, addresses));
                    }
                }

                break;
        }
    }

    internal static string NormalizeQueryType(object? value)
    {
        var token = Convert.ToString(value, System.Globalization.CultureInfo.InvariantCulture)?.Trim() ?? string.Empty;
        return token.ToUpperInvariant() switch
        {
            "" or "1" => "A",
            "5" => "CNAME",
            "10" => "NULL",
            "16" => "TXT",
            "28" => "AAAA",
            "64" => "SVCB",
            "65" => "HTTPS",
            _ => token.ToUpperInvariant(),
        };
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
