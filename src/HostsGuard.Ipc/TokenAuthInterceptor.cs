using Grpc.Core;
using Grpc.Core.Interceptors;

namespace HostsGuard.Ipc;

/// <summary>
/// Server interceptor enforcing the per-session token on every call. Requests
/// without a matching <c>x-hg-token</c> are rejected Unauthenticated before any
/// privileged work runs.
/// </summary>
public sealed class TokenAuthInterceptor : Interceptor
{
    private readonly string _expected;

    public TokenAuthInterceptor(string expectedToken) =>
        _expected = expectedToken ?? throw new ArgumentNullException(nameof(expectedToken));

    public override Task<TResponse> UnaryServerHandler<TRequest, TResponse>(
        TRequest request,
        ServerCallContext context,
        UnaryServerMethod<TRequest, TResponse> continuation)
    {
        Authorize(context);
        return continuation(request, context);
    }

    public override Task ServerStreamingServerHandler<TRequest, TResponse>(
        TRequest request,
        IServerStreamWriter<TResponse> responseStream,
        ServerCallContext context,
        ServerStreamingServerMethod<TRequest, TResponse> continuation)
    {
        Authorize(context);
        return continuation(request, responseStream, context);
    }

    private void Authorize(ServerCallContext context)
    {
        var token = context.RequestHeaders.GetValue(SessionToken.MetadataKey);
        if (!SessionToken.ConstantTimeEquals(token, _expected))
        {
            throw new RpcException(new Status(StatusCode.Unauthenticated, "missing or invalid session token"));
        }
    }
}
