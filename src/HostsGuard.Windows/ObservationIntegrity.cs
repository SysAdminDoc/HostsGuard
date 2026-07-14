namespace HostsGuard.Windows;

/// <summary>Current completeness of an operating-system observation source.</summary>
public enum ObservationIntegrityState
{
    Healthy,
    Degraded,
    Unavailable,
}

/// <summary>
/// Immutable health snapshot for an ETW or Event Log source. Counters are
/// process-lifetime totals; <see cref="IncompleteSinceUtc"/> marks the current
/// interval whose evidence must not be presented as complete.
/// </summary>
public sealed record ObservationIntegritySnapshot(
    string Source,
    ObservationIntegrityState State,
    long LossCount,
    long GapCount,
    long RestartCount,
    DateTime LastTransitionUtc,
    DateTime? IncompleteSinceUtc,
    string Detail);

/// <summary>
/// Thread-safe transition/counter tracker shared by the ETW and Security-log
/// monitors. It deliberately separates cumulative evidence loss from current
/// liveness: a source can recover while retaining an honest loss history.
/// </summary>
public sealed class ObservationIntegrityTracker
{
    private readonly object _gate = new();
    private readonly string _source;
    private ObservationIntegrityState _state = ObservationIntegrityState.Unavailable;
    private long _lossCount;
    private long _gapCount;
    private long _restartCount;
    private long _lastSourceLossTotal;
    private bool _everStarted;
    private bool _lossPendingRecovery;
    private DateTime _lastTransitionUtc;
    private DateTime? _incompleteSinceUtc;
    private string _detail = "not started";

    public ObservationIntegrityTracker(string source, DateTime? createdAtUtc = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(source);
        _source = source;
        _lastTransitionUtc = EnsureUtc(createdAtUtc ?? DateTime.UtcNow);
        _incompleteSinceUtc = _lastTransitionUtc;
    }

    public ObservationIntegritySnapshot Snapshot()
    {
        lock (_gate)
        {
            return new ObservationIntegritySnapshot(
                _source,
                _state,
                _lossCount,
                _gapCount,
                _restartCount,
                _lastTransitionUtc,
                _incompleteSinceUtc,
                _detail);
        }
    }

    public void Started(string detail = "observing")
    {
        lock (_gate)
        {
            if (_everStarted)
            {
                _restartCount++;
            }

            _everStarted = true;
            _lossPendingRecovery = false;
            TransitionNoLock(ObservationIntegrityState.Healthy, detail, incomplete: false);
        }
    }

    public void Unavailable(string detail, bool countGap = true)
    {
        lock (_gate)
        {
            if (countGap && _state != ObservationIntegrityState.Unavailable)
            {
                _gapCount++;
            }

            TransitionNoLock(ObservationIntegrityState.Unavailable, detail, incomplete: true);
        }
    }

    public void Degraded(string detail)
    {
        lock (_gate)
        {
            TransitionNoLock(ObservationIntegrityState.Degraded, detail, incomplete: true);
        }
    }

    public void Healthy(string detail = "observing")
    {
        lock (_gate)
        {
            _lossPendingRecovery = false;
            TransitionNoLock(ObservationIntegrityState.Healthy, detail, incomplete: false);
        }
    }

    public void RecordLoss(long count, string detail)
    {
        if (count <= 0)
        {
            return;
        }

        lock (_gate)
        {
            _lossCount += count;
            _lossPendingRecovery = true;
            TransitionNoLock(ObservationIntegrityState.Degraded, detail, incomplete: true);
        }
    }

    /// <summary>
    /// Reconcile a monotonic source-level loss counter such as
    /// TraceEventSession.EventsLost. One stable sample closes the incomplete
    /// interval; the cumulative total remains visible.
    /// </summary>
    public void ObserveSourceLossTotal(long total)
    {
        total = Math.Max(0, total);
        lock (_gate)
        {
            var delta = total >= _lastSourceLossTotal ? total - _lastSourceLossTotal : total;
            _lastSourceLossTotal = total;
            if (delta > 0)
            {
                _lossCount += delta;
                _lossPendingRecovery = true;
                TransitionNoLock(
                    ObservationIntegrityState.Degraded,
                    $"{delta} operating-system event(s) lost",
                    incomplete: true);
            }
            else if (_lossPendingRecovery && _state == ObservationIntegrityState.Degraded)
            {
                _lossPendingRecovery = false;
                TransitionNoLock(ObservationIntegrityState.Healthy, "observing after event loss", incomplete: false);
            }
        }
    }

    public void RecordGap(long count, string detail)
    {
        if (count <= 0)
        {
            return;
        }

        lock (_gate)
        {
            _gapCount += count;
            TransitionNoLock(ObservationIntegrityState.Degraded, detail, incomplete: true);
        }
    }

    private void TransitionNoLock(ObservationIntegrityState state, string detail, bool incomplete)
    {
        var now = DateTime.UtcNow;
        if (_state != state)
        {
            _state = state;
            _lastTransitionUtc = now;
        }

        if (incomplete)
        {
            _incompleteSinceUtc ??= now;
        }
        else
        {
            _incompleteSinceUtc = null;
        }

        _detail = string.IsNullOrWhiteSpace(detail) ? state.ToString().ToLowerInvariant() : detail.Trim();
    }

    private static DateTime EnsureUtc(DateTime value) => value.Kind switch
    {
        DateTimeKind.Utc => value,
        DateTimeKind.Local => value.ToUniversalTime(),
        _ => DateTime.SpecifyKind(value, DateTimeKind.Utc),
    };
}
