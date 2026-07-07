using Grpc.Core;

namespace HostsGuard.App.Services;

/// <summary>Small UI helper for action-specific service/RPC failure status text.</summary>
public static class ServiceActionGuard
{
    public static async Task RunAsync(string action, Action<string> setStatus, Func<Task> work)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(action);
        ArgumentNullException.ThrowIfNull(setStatus);
        ArgumentNullException.ThrowIfNull(work);

        try
        {
            await work();
        }
        catch (Exception ex) when (ex is RpcException || ServiceErrors.IsConnectivity(ex))
        {
            setStatus(ServiceErrors.DescribeActionFailure(action, ex));
        }
    }
}
