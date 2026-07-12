using System.Collections.Concurrent;
using System.Runtime.Versioning;
using System.Threading.Channels;
using HostsGuard.Windows;

namespace HostsGuard.Service;

/// <summary>
/// Merges authoritative IPHLPAPI TCP snapshots with short-lived TCP and UDP
/// endpoints observed by kernel ETW. Incoming packet observations are
/// coalesced by tuple before the bounded queue so high-volume connections
/// cannot evict quieter endpoints.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class ConnectionFeed : IDisposable
{
    private readonly record struct ConnectionKey(
        string Protocol,
        string LocalAddress,
        int LocalPort,
        string RemoteAddress,
        int RemotePort,
        int Pid);

    private const int MaxPendingObservations = 4096;
    private const int MaxObservationBatch = 256;
    private static readonly TimeSpan StopTimeout = TimeSpan.FromSeconds(5);

    private readonly ServiceState _state;
    private readonly Func<IReadOnlyList<ConnectionInfo>> _snapshot;
    private readonly Func<long> _clock;
    private readonly CancellationTokenSource _cts = new();
    private readonly TimeSpan _interval;
    private readonly long _observationTtlMs;
    private readonly ConcurrentDictionary<ConnectionKey, ConnectionInfo> _pending = new();
    private readonly Channel<bool> _wake = Channel.CreateBounded<bool>(
        new BoundedChannelOptions(1)
        {
            FullMode = BoundedChannelFullMode.DropWrite,
            SingleReader = true,
            SingleWriter = false,
        });

    private Task? _loop;
    private int _stopping;
    private long _coalescedObservations;
    private long _droppedObservations;

    public ConnectionFeed(ServiceState state, TimeSpan? interval = null)
        : this(state, new ConnectionMonitor().Snapshot, interval, TimeSpan.FromSeconds(30),
            static () => Environment.TickCount64)
    {
    }

    internal ConnectionFeed(
        ServiceState state,
        Func<IReadOnlyList<ConnectionInfo>> snapshot,
        TimeSpan? interval = null,
        TimeSpan? observationTtl = null,
        Func<long>? clock = null)
    {
        _state = state ?? throw new ArgumentNullException(nameof(state));
        _snapshot = snapshot ?? throw new ArgumentNullException(nameof(snapshot));
        _interval = interval ?? TimeSpan.FromSeconds(2);
        _observationTtlMs = Math.Max(1, (long)(observationTtl ?? TimeSpan.FromSeconds(30)).TotalMilliseconds);
        _clock = clock ?? (static () => Environment.TickCount64);
    }

    internal long CoalescedObservations => Interlocked.Read(ref _coalescedObservations);

    internal long DroppedObservations => Interlocked.Read(ref _droppedObservations);

    public void Start() => _loop ??= Task.Run(() => LoopAsync(_cts.Token));

    internal bool Observe(ConnectionInfo connection)
    {
        ArgumentNullException.ThrowIfNull(connection);
        if (Volatile.Read(ref _stopping) != 0)
        {
            return false;
        }

        var key = Key(connection);
        if (_pending.TryGetValue(key, out _))
        {
            _pending[key] = connection;
            Interlocked.Increment(ref _coalescedObservations);
            _wake.Writer.TryWrite(true);
            return true;
        }

        if (_pending.Count >= MaxPendingObservations || !_pending.TryAdd(key, connection))
        {
            if (_pending.ContainsKey(key))
            {
                _pending[key] = connection;
                Interlocked.Increment(ref _coalescedObservations);
                _wake.Writer.TryWrite(true);
                return true;
            }

            Interlocked.Increment(ref _droppedObservations);
            return false;
        }

        _wake.Writer.TryWrite(true);
        return true;
    }

    private async Task LoopAsync(CancellationToken ct)
    {
        var active = new Dictionary<ConnectionKey, string>();
        var observedUntil = new Dictionary<ConnectionKey, long>();
        var nextSnapshotAt = 0L;

        while (!ct.IsCancellationRequested)
        {
            try
            {
                var processed = 0;
                foreach (var entry in _pending)
                {
                    if (processed >= MaxObservationBatch)
                    {
                        break;
                    }

                    if (_pending.TryRemove(entry.Key, out var observed))
                    {
                        PublishObservation(observed, active, observedUntil, _clock());
                        processed++;
                    }
                }

                if (Volatile.Read(ref _stopping) != 0 && _pending.IsEmpty)
                {
                    return;
                }

                var now = _clock();
                if (now >= nextSnapshotAt)
                {
                    nextSnapshotAt = now + Math.Max(1, (long)_interval.TotalMilliseconds);
                    PublishSnapshot(active, observedUntil, now);
                }

                foreach (var expired in observedUntil.Where(entry => entry.Value <= now).Select(entry => entry.Key).ToList())
                {
                    observedUntil.Remove(expired);
                }

                if (!_pending.IsEmpty)
                {
                    continue;
                }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                return;
            }
            catch (Exception ex)
            {
                TryLogLoopError(ex);
                nextSnapshotAt = _clock() + Math.Max(1, (long)_interval.TotalMilliseconds);
            }

            try
            {
                while (_wake.Reader.TryRead(out _))
                {
                }

                var waitMs = Math.Max(1, nextSnapshotAt - _clock());
                using var wake = CancellationTokenSource.CreateLinkedTokenSource(ct);
                var ready = _wake.Reader.WaitToReadAsync(wake.Token).AsTask();
                var delay = Task.Delay(TimeSpan.FromMilliseconds(waitMs), wake.Token);
                await Task.WhenAny(ready, delay);
                wake.Cancel();
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                return;
            }
        }
    }

    private void PublishObservation(
        ConnectionInfo connection,
        Dictionary<ConnectionKey, string> active,
        Dictionary<ConnectionKey, long> observedUntil,
        long now)
    {
        var key = Key(connection);
        if (active.ContainsKey(key))
        {
            observedUntil[key] = now + _observationTtlMs;
            return;
        }

        if (observedUntil.TryGetValue(key, out var expiresAt) && expiresAt > now)
        {
            // Sliding expiry: a continuously active UDP tuple never creates
            // duplicate history rows merely because the first TTL elapsed.
            observedUntil[key] = now + _observationTtlMs;
            return;
        }

        observedUntil[key] = now + _observationTtlMs;
        _state.PublishConnection(connection, recordHistory: true);
    }

    private void PublishSnapshot(
        Dictionary<ConnectionKey, string> active,
        Dictionary<ConnectionKey, long> observedUntil,
        long now)
    {
        var current = new HashSet<ConnectionKey>();
        foreach (var connection in _snapshot())
        {
            var key = Key(connection);
            current.Add(key);
            var isNew = !active.TryGetValue(key, out var state);
            var recentlyObserved = observedUntil.TryGetValue(key, out var expiresAt) && expiresAt > now;
            if ((isNew && !recentlyObserved) || (!isNew && state != connection.State) ||
                (isNew && recentlyObserved && connection.State != "OBSERVED"))
            {
                _state.PublishConnection(connection, recordHistory: isNew && !recentlyObserved);
            }

            active[key] = connection.State;
        }

        foreach (var gone in active.Keys.Where(key => !current.Contains(key)).ToList())
        {
            active.Remove(gone);
        }
    }

    private static ConnectionKey Key(ConnectionInfo connection)
        => new(connection.Protocol, connection.LocalAddress, connection.LocalPort,
            connection.RemoteAddress, connection.RemotePort, connection.Pid);

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _stopping, 1) != 0)
        {
            return;
        }

        _wake.Writer.TryComplete();
        if (!WaitForLoop())
        {
            _cts.Cancel();
            WaitForLoop();
        }

        _cts.Dispose();
    }

    private bool WaitForLoop()
    {
        if (_loop is null)
        {
            return true;
        }

        try
        {
            if (_loop.Wait(StopTimeout))
            {
                return true;
            }

            TryLogLoopError(new TimeoutException("connection feed loop did not stop before timeout"));
        }
        catch (AggregateException ex) when (ex.InnerExceptions.All(e => e is OperationCanceledException))
        {
            return true;
        }
        catch (AggregateException ex)
        {
            TryLogLoopError(ex.Flatten().InnerExceptions.FirstOrDefault() ?? ex);
        }

        return false;
    }

    private void TryLogLoopError(Exception ex)
    {
        try
        {
            _state.Db.LogEvent("connection_feed", "loop_error", details: $"{ex.GetType().Name}: {ex.Message}");
        }
        catch (Exception logEx) when (logEx is Microsoft.Data.Sqlite.SqliteException or InvalidOperationException)
        {
            // If the DB itself is unavailable, keep the feed alive.
        }
        catch (Exception)
        {
            // Logging must not fault the background feed.
        }
    }
}
