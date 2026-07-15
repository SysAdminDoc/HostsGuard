namespace HostsGuard.App.Services;

internal sealed record ShellHydrationWork(string Name, Func<CancellationToken, Task> Run);

internal sealed record ShellHydrationFailure(string Name, Exception Error);

/// <summary>
/// Runs independent shell reads with one shared concurrency bound. Work starts
/// on the caller's synchronization context so WPF-bound collections remain on
/// the UI thread after their asynchronous RPC continuations.
/// </summary>
internal sealed class ShellHydrationCoordinator
{
    private readonly SemaphoreSlim _gate;

    public ShellHydrationCoordinator(int maxConcurrency = 4)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(maxConcurrency, 1);
        _gate = new SemaphoreSlim(maxConcurrency, maxConcurrency);
    }

    public async Task<IReadOnlyList<ShellHydrationFailure>> RunAsync(
        IEnumerable<ShellHydrationWork> work,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(work);

        var failures = new List<ShellHydrationFailure>();
        var tasks = work.Select(RunOneAsync).ToArray();
        await Task.WhenAll(tasks);
        return failures;

        async Task RunOneAsync(ShellHydrationWork item)
        {
            await _gate.WaitAsync(cancellationToken);
            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                await item.Run(cancellationToken);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                lock (failures)
                {
                    failures.Add(new ShellHydrationFailure(item.Name, ex));
                }
            }
            finally
            {
                _gate.Release();
            }
        }
    }
}
