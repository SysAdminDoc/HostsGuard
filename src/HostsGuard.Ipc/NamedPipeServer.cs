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
        string pipeName = NamedPipeSecurity.PipeName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(token);
        ArgumentNullException.ThrowIfNull(mapServices);

        var builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.ConfigureKestrel(options =>
        {
            options.ListenNamedPipe(pipeName, listen => listen.Protocols = HttpProtocols.Http2);
        });

        // Restrict the pipe ACL to the current user + Administrators.
        builder.WebHost.UseNamedPipes(opts =>
        {
            opts.PipeSecurity = NamedPipeSecurity.CreateForCurrentUserAndAdmins();
            opts.CurrentUserOnly = false;
        });

        builder.Services.AddGrpc(o => o.Interceptors.Add<TokenAuthInterceptor>());
        builder.Services.AddSingleton(new TokenAuthInterceptor(token));

        var app = builder.Build();
        mapServices(app);
        return app;
    }
}
