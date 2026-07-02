using System.Runtime.Versioning;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace HostsGuard.Ipc;

/// <summary>
/// Server-side helper: hosts gRPC over the ACL'd named pipe with the session-token
/// interceptor. The service supplies gRPC service registrations via
/// <paramref name="mapServices"/>.
/// </summary>
[SupportedOSPlatform("windows")]
public static class NamedPipeServer
{
    public static WebApplication Build(
        string token,
        Action<WebApplication> mapServices,
        string pipeName = NamedPipeSecurity.PipeName,
        Action<IServiceCollection>? configureServices = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(token);
        ArgumentNullException.ThrowIfNull(mapServices);

        var builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.ConfigureKestrel(options =>
        {
            options.ListenNamedPipe(pipeName, listen => listen.Protocols = HttpProtocols.Http2);
        });

        // ACL the pipe: per-user for console/dev runs, cross-session (SYSTEM +
        // Admins own it, Authenticated Users connect) when hosted as a service.
        builder.WebHost.UseNamedPipes(opts =>
        {
            opts.PipeSecurity = NamedPipeSecurity.CreateDefault();
            opts.CurrentUserOnly = false;
        });

        builder.Services.AddGrpc(o => o.Interceptors.Add<TokenAuthInterceptor>());
        builder.Services.AddSingleton(new TokenAuthInterceptor(token));
        configureServices?.Invoke(builder.Services);

        var app = builder.Build();
        mapServices(app);
        return app;
    }
}
