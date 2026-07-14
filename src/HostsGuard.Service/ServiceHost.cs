using System.Runtime.Versioning;
using HostsGuard.Core;
using HostsGuard.Ipc;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Hosting.WindowsServices;

namespace HostsGuard.Service;

/// <summary>
/// Wires the gRPC service implementations onto the ACL'd named-pipe transport.
/// Shared by the executable entry point and the integration tests so the exact
/// production hosting graph is exercised in test.
/// </summary>
[SupportedOSPlatform("windows")]
public static class ServiceHost
{
    // The application accepts exactly 25,000,000 content bytes. gRPC's receive
    // ceiling covers the whole protobuf envelope, so reserve bounded headroom
    // for the field tags and list name while keeping this exception service-local.
    internal const int ListControlMaxReceiveMessageBytes = BlocklistCatalog.MaxBlocklistBytes + (64 * 1024);

    public static WebApplication Build(
        ServiceState state,
        string token,
        string pipeName = NamedPipeSecurity.PipeName,
        Action<string, string>? rpcLog = null)
    {
        ArgumentNullException.ThrowIfNull(state);
        ArgumentException.ThrowIfNullOrWhiteSpace(token);

        return NamedPipeServer.Build(
            token,
            app =>
            {
                app.MapGrpcService<DiagnosticsServiceImpl>();
                app.MapGrpcService<RecoveryServiceImpl>();
                app.MapGrpcService<HostsControlServiceImpl>();
                app.MapGrpcService<MonitoringServiceImpl>();
                app.MapGrpcService<FirewallControlServiceImpl>();
                app.MapGrpcService<DnsControlServiceImpl>();
                app.MapGrpcService<PolicyServiceImpl>();
                app.MapGrpcService<ListControlServiceImpl>();
                app.MapGrpcService<ConsentServiceImpl>();
            },
            pipeName,
            services =>
            {
                services.AddSingleton(state);
                services.AddGrpc().AddServiceOptions<ListControlServiceImpl>(options =>
                {
                    options.MaxReceiveMessageSize = ListControlMaxReceiveMessageBytes;
                });
                if (WindowsServiceHelpers.IsWindowsService())
                {
                    // Hosted by the SCM (WFCP-000a): adopt the Windows Service
                    // lifetime so start/stop/shutdown flow through cleanly.
                    services.AddWindowsService(options => options.ServiceName = "HostsGuardSvc");
                }
            },
            rpcLog);
    }
}
