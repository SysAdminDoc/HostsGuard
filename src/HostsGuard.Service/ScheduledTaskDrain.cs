namespace HostsGuard.Service;

/// <summary>
/// Tracks one timer-started asynchronous operation, suppresses overlapping
/// ticks, and cancels/drains the active task during owner disposal.
/// </summary>
internal sealed class ScheduledTaskDrain : IDisposable
{
    private static readonly TimeSpan StopTimeout = TimeSpan.FromSeconds(5);

    private readonly object _gate = new();
    private readonly CancellationTokenSource _shutdown = new();
    private Task _active = Task.CompletedTask;
    private bool _disposed;

    internal bool TryRun(Func<CancellationToken, Task> operation)
    {
        ArgumentNullException.ThrowIfNull(operation);
        lock (_gate)
        {
            if (_disposed || !_active.IsCompleted)
            {
                return false;
            }

            _active = Task.Run(() => operation(_shutdown.Token), CancellationToken.None);
            return true;
        }
    }

    public void Dispose()
    {
        Task active;
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            active = _active;
        }

        _shutdown.Cancel();
        try
        {
            active.Wait(StopTimeout);
        }
        catch (AggregateException ex) when (ex.InnerExceptions.All(error => error is OperationCanceledException))
        {
            // Cooperative cancellation is the normal shutdown path.
        }
        finally
        {
            _shutdown.Dispose();
        }
    }
}
