using System.IO;
using Grpc.Core;

namespace HostsGuard.App.Services;

/// <summary>Classifies and describes failures from the service channel.</summary>
public static class ServiceErrors
{
    /// <summary>
    /// True only when the failure means the service can't be reached (pipe
    /// down, timeout). A handler exception arrives as StatusCode.Unknown and
    /// must NOT be treated as connectivity — the service is up and answering.
    /// </summary>
    public static bool IsConnectivity(Exception ex)
    {
        for (var e = ex; e is not null; e = e.InnerException!)
        {
            if (e is RpcException rpc)
            {
                return rpc.StatusCode is StatusCode.Unavailable or StatusCode.DeadlineExceeded or StatusCode.Cancelled;
            }

            if (e is IOException or TimeoutException or OperationCanceledException)
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>Human description for a non-connectivity failure.</summary>
    public static string Describe(Exception ex)
    {
        for (var e = ex; e is not null; e = e.InnerException!)
        {
            if (e is RpcException rpc)
            {
                return rpc.Status.Detail.Length != 0 && rpc.Status.Detail != "Exception was thrown by handler."
                    ? $"The HostsGuard service reported an error: {rpc.Status.Detail}"
                    : "The HostsGuard service hit an internal error handling this action. "
                      + "The service is still running — the action was not applied. "
                      + "Details are in the service log (Tools → Export support bundle).";
            }
        }

        return ex.Message;
    }

    /// <summary>Action-specific status line for a command that failed against the service.</summary>
    public static string DescribeActionFailure(string action, Exception ex)
        => IsConnectivity(ex)
            ? $"{action} failed — service unavailable; reconnect from the status bar"
            : $"{action} failed — {Describe(ex)}";
}
