using System.Diagnostics;
using Grpc.Core;
using Grpc.Core.Interceptors;

namespace HostsGuard.Ipc;

/// <summary>
/// Client-side correlation (NET-180): every call runs inside a W3C
/// <see cref="Activity"/> whose traceparent is sent as a request header, so the
/// service's handling of a GUI action shares the caller's TraceId in both logs.
/// The optional callback receives (method, traceId) for the caller's log sink;
/// Serilog also captures the ambient activity on any event logged inside it.
/// </summary>
public sealed class ClientCorrelationInterceptor : Interceptor
{
    /// <summary>W3C trace-context request header.</summary>
    public const string TraceparentHeader = "traceparent";

    private readonly Action<string, string>? _onCall;

    public ClientCorrelationInterceptor(Action<string, string>? onCall = null) => _onCall = onCall;

    public override AsyncUnaryCall<TResponse> AsyncUnaryCall<TRequest, TResponse>(
        TRequest request,
        ClientInterceptorContext<TRequest, TResponse> context,
        AsyncUnaryCallContinuation<TRequest, TResponse> continuation)
    {
        var activity = StartActivity(context.Method.FullName, ref context);
        try
        {
            return continuation(request, context);
        }
        finally
        {
            activity.Stop();
        }
    }

    public override AsyncServerStreamingCall<TResponse> AsyncServerStreamingCall<TRequest, TResponse>(
        TRequest request,
        ClientInterceptorContext<TRequest, TResponse> context,
        AsyncServerStreamingCallContinuation<TRequest, TResponse> continuation)
    {
        var activity = StartActivity(context.Method.FullName, ref context);
        try
        {
            return continuation(request, context);
        }
        finally
        {
            activity.Stop();
        }
    }

    public override TResponse BlockingUnaryCall<TRequest, TResponse>(
        TRequest request,
        ClientInterceptorContext<TRequest, TResponse> context,
        BlockingUnaryCallContinuation<TRequest, TResponse> continuation)
    {
        var activity = StartActivity(context.Method.FullName, ref context);
        try
        {
            return continuation(request, context);
        }
        finally
        {
            activity.Stop();
        }
    }

    private Activity StartActivity<TRequest, TResponse>(
        string method,
        ref ClientInterceptorContext<TRequest, TResponse> context)
        where TRequest : class
        where TResponse : class
    {
        var activity = new Activity($"rpc {method}");
        activity.SetIdFormat(ActivityIdFormat.W3C);
        activity.Start();

        var headers = context.Options.Headers ?? new Metadata();
        headers.Add(TraceparentHeader, activity.Id!);
        if (context.Options.Headers is null)
        {
            context = new ClientInterceptorContext<TRequest, TResponse>(
                context.Method, context.Host, context.Options.WithHeaders(headers));
        }

        _onCall?.Invoke(method, activity.TraceId.ToHexString());
        return activity;
    }
}

/// <summary>
/// Server-side correlation (NET-180): adopts the caller's traceparent header as
/// the parent of a per-call <see cref="Activity"/>, so everything the handler
/// logs (Serilog captures the ambient activity) carries the GUI's TraceId.
/// </summary>
public sealed class ServerCorrelationInterceptor : Interceptor
{
    private readonly Action<string, string>? _onCall;

    public ServerCorrelationInterceptor(Action<string, string>? onCall = null) => _onCall = onCall;

    public override async Task<TResponse> UnaryServerHandler<TRequest, TResponse>(
        TRequest request,
        ServerCallContext context,
        UnaryServerMethod<TRequest, TResponse> continuation)
    {
        using var activity = StartFromHeaders(context);
        return await continuation(request, context);
    }

    public override async Task ServerStreamingServerHandler<TRequest, TResponse>(
        TRequest request,
        IServerStreamWriter<TResponse> responseStream,
        ServerCallContext context,
        ServerStreamingServerMethod<TRequest, TResponse> continuation)
    {
        using var activity = StartFromHeaders(context);
        await continuation(request, responseStream, context);
    }

    private Activity StartFromHeaders(ServerCallContext context)
    {
        var activity = new Activity($"rpc {context.Method}");
        activity.SetIdFormat(ActivityIdFormat.W3C);
        var traceparent = context.RequestHeaders.GetValue(ClientCorrelationInterceptor.TraceparentHeader);
        if (!string.IsNullOrEmpty(traceparent))
        {
            activity.SetParentId(traceparent);
        }

        activity.Start();
        _onCall?.Invoke(context.Method, activity.TraceId.ToHexString());
        return activity;
    }
}
