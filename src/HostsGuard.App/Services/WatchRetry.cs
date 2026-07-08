using System.IO;
using Grpc.Core;

namespace HostsGuard.App.Services;

/// <summary>Shared bounded backoff policy for long-lived service streams.</summary>
public static class WatchRetry
{
    public static bool IsStreamFailure(Exception ex)
        => ex is RpcException or IOException or OperationCanceledException;

    public static bool IsAuthenticationFailure(Exception ex)
        => ex is RpcException { StatusCode: StatusCode.Unauthenticated };

    public static TimeSpan Delay(int failures)
    {
        var shift = Math.Clamp(failures, 0, 5);
        var ms = Math.Min(5000, 250 * (1 << shift));
        return TimeSpan.FromMilliseconds(ms);
    }
}
