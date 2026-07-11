using System.IO;
using System.Runtime.Versioning;
using Grpc.Core.Interceptors;
using Grpc.Net.Client;
using HostsGuard.Contracts;
using HostsGuard.Ipc;

namespace HostsGuard.App.Services;

/// <summary>
/// The UI's typed connection to the elevated service over the ACL'd named pipe.
/// Wraps the generated gRPC clients so the ViewModels never touch transport
/// details. The channel is injectable for testing against an in-process service.
/// Every call runs through <see cref="ClientCorrelationInterceptor"/> (NET-180)
/// so the app's log line and the service's handling share one W3C TraceId.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class HostsServiceClient : IDisposable
{
    private static readonly Lazy<Serilog.Core.Logger> AppLog = new(() =>
        HostsGuard.Diagnostics.Logging.CreateFileLogger(Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "HostsGuard", "logs")));

    private readonly GrpcChannel _channel;

    public HostsServiceClient(GrpcChannel channel)
    {
        _channel = channel ?? throw new ArgumentNullException(nameof(channel));
        var invoker = _channel.Intercept(new ClientCorrelationInterceptor(
            (method, traceId) => AppLog.Value.Information("rpc {Method} sent (trace {TraceId})", method, traceId)));
        Diagnostics = new Contracts.Diagnostics.DiagnosticsClient(invoker);
        Hosts = new HostsControl.HostsControlClient(invoker);
        Firewall = new FirewallControl.FirewallControlClient(invoker);
        Dns = new DnsControl.DnsControlClient(invoker);
        Monitoring = new Monitoring.MonitoringClient(invoker);
        Policy = new Policy.PolicyClient(invoker);
        Lists = new ListControl.ListControlClient(invoker);
        Consent = new Consent.ConsentClient(invoker);
    }

    public Contracts.Diagnostics.DiagnosticsClient Diagnostics { get; }

    public HostsControl.HostsControlClient Hosts { get; }

    public FirewallControl.FirewallControlClient Firewall { get; }

    public DnsControl.DnsControlClient Dns { get; }

    public Monitoring.MonitoringClient Monitoring { get; }

    public Policy.PolicyClient Policy { get; }

    public ListControl.ListControlClient Lists { get; }

    public Consent.ConsentClient Consent { get; }

    /// <summary>
    /// Connect to the running service: read the ACL'd handshake token from
    /// %ProgramData%\HostsGuard\session_token and open a named-pipe channel.
    /// </summary>
    public static HostsServiceClient Connect()
    {
        var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        var handshake = Path.Combine(programData, "HostsGuard", "session_token");
        var token = SessionToken.ReadHandshake(handshake);
        return new HostsServiceClient(NamedPipeChannel.Create(token));
    }

    public void Dispose() => _channel.Dispose();
}
