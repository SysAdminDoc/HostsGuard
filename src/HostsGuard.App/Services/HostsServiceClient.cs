using System.IO;
using System.Runtime.Versioning;
using Grpc.Net.Client;
using HostsGuard.Contracts;
using HostsGuard.Ipc;

namespace HostsGuard.App.Services;

/// <summary>
/// The UI's typed connection to the elevated service over the ACL'd named pipe.
/// Wraps the generated gRPC clients so the ViewModels never touch transport
/// details. The channel is injectable for testing against an in-process service.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class HostsServiceClient : IDisposable
{
    private readonly GrpcChannel _channel;

    public HostsServiceClient(GrpcChannel channel)
    {
        _channel = channel ?? throw new ArgumentNullException(nameof(channel));
        Diagnostics = new Contracts.Diagnostics.DiagnosticsClient(_channel);
        Hosts = new HostsControl.HostsControlClient(_channel);
        Firewall = new FirewallControl.FirewallControlClient(_channel);
        Dns = new DnsControl.DnsControlClient(_channel);
        Monitoring = new Monitoring.MonitoringClient(_channel);
        Policy = new Policy.PolicyClient(_channel);
        Lists = new ListControl.ListControlClient(_channel);
    }

    public Contracts.Diagnostics.DiagnosticsClient Diagnostics { get; }

    public HostsControl.HostsControlClient Hosts { get; }

    public FirewallControl.FirewallControlClient Firewall { get; }

    public DnsControl.DnsControlClient Dns { get; }

    public Monitoring.MonitoringClient Monitoring { get; }

    public Policy.PolicyClient Policy { get; }

    public ListControl.ListControlClient Lists { get; }

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
