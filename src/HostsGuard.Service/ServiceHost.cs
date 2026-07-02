using System.Runtime.Versioning;
using HostsGuard.Ipc;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

namespace HostsGuard.Service;

/// <summary>
/// Wires the gRPC service implementations onto the ACL'd named-pipe transport.
/// Shared by the executable entry point and the integration tests so the exact
/// production hosting graph is exercised in test.
/// </summary>
[SupportedOSPlatform("windows")]
public static class ServiceHost
{
    public static WebApplication Build(ServiceState state, string token, string pipeName = NamedPipeSecurity.PipeName)
    {
        ArgumentNullException.ThrowIfNull(state);
        ArgumentException.ThrowIfNullOrWhiteSpace(token);

        return NamedPipeServer.Build(
            token,
            app =>
            {
                app.MapGrpcService<DiagnosticsServiceImpl>();
                app.MapGrpcService<HostsControlServiceImpl>();
                app.MapGrpcService<MonitoringServiceImpl>();
                app.MapGrpcService<FirewallControlServiceImpl>();
            },
            pipeName,
            services => services.AddSingleton(state));
    }
}
