using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Security.Principal;
using Grpc.Core;
using Grpc.Net.Client;

namespace HostsGuard.Ipc;

/// <summary>
/// Client-side factory: a <see cref="GrpcChannel"/> that connects over the ACL'd
/// named pipe and attaches the session token to every call.
/// </summary>
[SupportedOSPlatform("windows")]
public static class NamedPipeChannel
{
    /// <summary>Create a channel to the local HostsGuard service pipe.</summary>
    public static GrpcChannel Create(string token, string pipeName = NamedPipeSecurity.PipeName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(token);

        var handler = new SocketsHttpHandler
        {
            ConnectCallback = async (_, ct) =>
            {
                var pipe = new NamedPipeClientStream(
                    ".",
                    pipeName,
                    PipeDirection.InOut,
                    PipeOptions.Asynchronous | PipeOptions.WriteThrough,
                    TokenImpersonationLevel.Anonymous);
                await pipe.ConnectAsync(ct).ConfigureAwait(false);
                return pipe;
            },
        };

        var credentials = CallCredentials.FromInterceptor((_, metadata) =>
        {
            metadata.Add(SessionToken.MetadataKey, token);
            return Task.CompletedTask;
        });

        return GrpcChannel.ForAddress("http://localhost", new GrpcChannelOptions
        {
            HttpHandler = handler,
            // Named pipe carries the OS ACL; layer call credentials for the token.
            Credentials = ChannelCredentials.Create(ChannelCredentials.Insecure, credentials),
            UnsafeUseInsecureChannelCallCredentials = true,
        });
    }
}
