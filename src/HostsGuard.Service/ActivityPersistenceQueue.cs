using System.Threading.Channels;
using HostsGuard.Data;

namespace HostsGuard.Service;

/// <summary>
/// Bounded async writer for ETW/SNI persistence. Producers keep live stamping on
/// their own thread and enqueue durable feed/resolved-host writes for one DB
/// reader to batch.
/// </summary>
public sealed class ActivityPersistenceQueue : IDisposable
{
    private const int DefaultCapacity = 4096;
    private const int DefaultMaxBatch = 512;
    private static readonly TimeSpan CoalesceDelay = TimeSpan.FromMilliseconds(5);
    private static readonly TimeSpan StopDrainTimeout = TimeSpan.FromSeconds(5);

    private readonly HostsDatabase _db;
    private readonly Channel<WorkItem> _queue;
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _worker;
    private readonly int _maxBatch;
    private readonly Func<int, string> _parentPathResolver;
    private long _writeBatches;
    private long _largestDnsBatch;
    private long _droppedWrites;

    public ActivityPersistenceQueue(
        HostsDatabase db,
        int capacity = DefaultCapacity,
        int maxBatch = DefaultMaxBatch,
        Func<int, string>? parentPathResolver = null)
    {
        _db = db ?? throw new ArgumentNullException(nameof(db));
        _maxBatch = Math.Clamp(maxBatch, 1, 4096);
        _parentPathResolver = parentPathResolver ?? (_ => string.Empty);

        // Wait mode (not DropOldest): TryWrite returns false when saturated so a
        // shed sighting is countable rather than silently evicted, and — crucially
        // — a Flush marker can never bump a pending sighting out of the queue.
        // Producers stay non-blocking by using TryWrite; Flush uses WriteAsync off
        // the hot path so it is inserted in order without dropping anything.
        _queue = Channel.CreateBounded<WorkItem>(new BoundedChannelOptions(Math.Max(1, capacity))
        {
            FullMode = BoundedChannelFullMode.Wait,
            SingleReader = true,
            SingleWriter = false,
        });
        _worker = Task.Run(ProcessAsync);
    }

    public long WriteBatchCount => Interlocked.Read(ref _writeBatches);

    public long LargestDnsBatchSize => Interlocked.Read(ref _largestDnsBatch);

    /// <summary>DNS sightings/resolved-host writes shed because the queue was saturated (NET-168).</summary>
    public long DroppedWriteCount => Interlocked.Read(ref _droppedWrites);

    public void EnqueueDnsSighting(string domain, string process, string? reason, DateTime seenAt, int pid = 0)
    {
        if (string.IsNullOrWhiteSpace(domain))
        {
            return;
        }

        if (!_queue.Writer.TryWrite(new DnsItem(domain, process ?? string.Empty, reason, seenAt, pid)))
        {
            Interlocked.Increment(ref _droppedWrites);
        }
    }

    public void EnqueueResolvedHosts(IEnumerable<(string Ip, string Host)> pairs, string source)
    {
        ArgumentNullException.ThrowIfNull(pairs);
        var rows = pairs
            .Where(p => !string.IsNullOrWhiteSpace(p.Ip) && !string.IsNullOrWhiteSpace(p.Host))
            .Select(p => (p.Ip, p.Host))
            .ToArray();
        if (rows.Length == 0)
        {
            return;
        }

        if (!_queue.Writer.TryWrite(new ResolvedHostsItem(rows, source ?? string.Empty)))
        {
            Interlocked.Increment(ref _droppedWrites);
        }
    }

    public void EnqueueResolutionChain(
        string queryName,
        IEnumerable<string> cnames,
        IEnumerable<string> addresses)
    {
        ArgumentNullException.ThrowIfNull(cnames);
        ArgumentNullException.ThrowIfNull(addresses);
        if (string.IsNullOrWhiteSpace(queryName))
        {
            return;
        }

        if (!_queue.Writer.TryWrite(new ResolutionChainItem(
                queryName,
                cnames.Where(value => !string.IsNullOrWhiteSpace(value)).Take(30).ToArray(),
                addresses.Where(value => !string.IsNullOrWhiteSpace(value)).Take(16).ToArray())))
        {
            Interlocked.Increment(ref _droppedWrites);
        }
    }

    public async Task FlushAsync(CancellationToken cancellationToken = default)
    {
        var completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        // WriteAsync waits for room instead of dropping, so the marker rides the
        // same ordered channel behind every already-enqueued sighting and can
        // never evict one — guaranteeing prior sightings are persisted on flush.
        try
        {
            await _queue.Writer.WriteAsync(new FlushItem(completion), cancellationToken).ConfigureAwait(false);
        }
        catch (ChannelClosedException)
        {
            // Queue completed (shutdown) — nothing left to flush.
            return;
        }

        if (cancellationToken.CanBeCanceled)
        {
            await completion.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
        else
        {
            await completion.Task.ConfigureAwait(false);
        }
    }

    private async Task ProcessAsync()
    {
        var batch = new List<WorkItem>(_maxBatch);
        try
        {
            while (await _queue.Reader.WaitToReadAsync(_cts.Token).ConfigureAwait(false))
            {
                await Task.Delay(CoalesceDelay, _cts.Token).ConfigureAwait(false);
                batch.Clear();
                while (batch.Count < _maxBatch && _queue.Reader.TryRead(out var item))
                {
                    batch.Add(item);
                }

                if (batch.Count != 0)
                {
                    ProcessBatch(batch);
                }
            }
        }
        catch (OperationCanceledException)
        {
            CompleteRemainingFlushes(batch, canceled: true);
            while (_queue.Reader.TryRead(out var item))
            {
                CompleteIfFlush(item, canceled: true);
            }
        }
    }

    private void ProcessBatch(IReadOnlyList<WorkItem> batch)
    {
        var sightings = new List<DnsSightingWrite>();
        var parentPaths = new Dictionary<int, string>();
        var resolved = new Dictionary<string, List<(string Ip, string Host)>>(StringComparer.Ordinal);
        var chains = new Dictionary<string, ResolutionChainItem>(StringComparer.Ordinal);
        var flushes = new List<TaskCompletionSource>();

        foreach (var item in batch)
        {
            switch (item)
            {
                case DnsItem dns:
                    var parentPath = string.Empty;
                    if (dns.Pid > 0 && !parentPaths.TryGetValue(dns.Pid, out parentPath))
                    {
                        try
                        {
                            parentPath = _parentPathResolver(dns.Pid) ?? string.Empty;
                        }
                        catch (Exception ex) when (ex is InvalidOperationException or UnauthorizedAccessException)
                        {
                            parentPath = string.Empty;
                        }

                        parentPaths[dns.Pid] = parentPath;
                    }

                    sightings.Add(new DnsSightingWrite(
                        dns.Domain, dns.Process, dns.Reason, dns.SeenAt, dns.Pid, parentPath));
                    break;
                case ResolvedHostsItem hosts:
                    if (!resolved.TryGetValue(hosts.Source, out var list))
                    {
                        list = new List<(string, string)>();
                        resolved[hosts.Source] = list;
                    }

                    list.AddRange(hosts.Pairs);
                    break;
                case ResolutionChainItem chain:
                    chains[chain.QueryName] = chain;
                    break;
                case FlushItem flush:
                    flushes.Add(flush.Completion);
                    break;
            }
        }

        try
        {
            var wrote = false;
            if (sightings.Count != 0)
            {
                _db.RecordDnsSightings(sightings);
                UpdateLargestDnsBatch(sightings.Count);
                wrote = true;
            }

            foreach (var (source, pairs) in resolved)
            {
                _db.UpsertResolvedHosts(pairs, source);
                wrote = true;
            }

            foreach (var chain in chains.Values)
            {
                _db.ReplaceDnsResolutionChain(chain.QueryName, chain.Cnames, chain.Addresses);
                wrote = true;
            }

            if (wrote)
            {
                Interlocked.Increment(ref _writeBatches);
            }

            foreach (var flush in flushes)
            {
                flush.TrySetResult();
            }
        }
        catch (Exception ex) when (ex is Microsoft.Data.Sqlite.SqliteException or InvalidOperationException)
        {
            foreach (var flush in flushes)
            {
                flush.TrySetException(ex);
            }
        }
    }

    private void UpdateLargestDnsBatch(int count)
    {
        while (true)
        {
            var current = Interlocked.Read(ref _largestDnsBatch);
            if (count <= current ||
                Interlocked.CompareExchange(ref _largestDnsBatch, count, current) == current)
            {
                return;
            }
        }
    }

    private static void CompleteRemainingFlushes(IEnumerable<WorkItem> batch, bool canceled)
    {
        foreach (var item in batch)
        {
            CompleteIfFlush(item, canceled);
        }
    }

    private static void CompleteIfFlush(WorkItem item, bool canceled)
    {
        if (item is not FlushItem flush)
        {
            return;
        }

        if (canceled)
        {
            flush.Completion.TrySetCanceled();
        }
        else
        {
            flush.Completion.TrySetResult();
        }
    }

    public void Dispose()
    {
        _queue.Writer.TryComplete();
        if (!_worker.Wait(StopDrainTimeout))
        {
            _cts.Cancel();
            try
            {
                _worker.Wait(TimeSpan.FromSeconds(1));
            }
            catch (AggregateException ex) when (ex.InnerExceptions.All(e => e is OperationCanceledException))
            {
                // Normal after a timed-out drain.
            }
        }

        _cts.Dispose();
    }

    private abstract record WorkItem;

    private sealed record DnsItem(string Domain, string Process, string? Reason, DateTime SeenAt, int Pid) : WorkItem;

    private sealed record ResolvedHostsItem(IReadOnlyList<(string Ip, string Host)> Pairs, string Source) : WorkItem;

    private sealed record ResolutionChainItem(
        string QueryName,
        IReadOnlyList<string> Cnames,
        IReadOnlyList<string> Addresses) : WorkItem;

    private sealed record FlushItem(TaskCompletionSource Completion) : WorkItem;
}
