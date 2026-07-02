using System.Reflection;
using System.Runtime.Versioning;
using System.Security.Principal;
using Grpc.Core;
using HostsGuard.Contracts;

namespace HostsGuard.Service;

/// <summary>Implements the Diagnostics gRPC service (health + counts).</summary>
[SupportedOSPlatform("windows")]
public sealed class DiagnosticsServiceImpl : Diagnostics.DiagnosticsBase
{
    private readonly ServiceState _state;

    public DiagnosticsServiceImpl(ServiceState state) => _state = state;

    public override Task<ServiceStatus> GetStatus(Empty request, ServerCallContext context)
    {
        var stats = _state.Db.GetStats();
        var status = new ServiceStatus
        {
            Version = Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "0.0.0",
            Elevated = IsElevated(),
            UptimeSeconds = (long)(DateTime.UtcNow - _state.StartedAtUtc).TotalSeconds,
            HostsBlocked = _state.Hosts.GetBlocked().Count,
            DbBlocked = stats.Blocked,
            DbAllowed = stats.Whitelisted,
            FeedTotal = stats.FeedTotal,
            DnsMonitorActive = false,
            ConnectionMonitorActive = false,
        };
        return Task.FromResult(status);
    }

    private static bool IsElevated()
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
}
