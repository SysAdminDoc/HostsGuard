using HostsGuard.Data;
using HostsGuard.Windows;

namespace HostsGuard.Service;

internal sealed record ResolverHealthSnapshot(
    IReadOnlyList<DnsResolverHealthResult> Entries,
    string Host,
    string Source,
    DateTime? CheckedAtUtc,
    bool Running,
    bool ScheduleEnabled,
    int ScheduleIntervalMinutes,
    DateTime? NextScheduledAtUtc,
    string Message);

/// <summary>
/// Owns report-only resolver checks. The schedule is opt-in, overlap is
/// suppressed, and the probe engine has no resolver-mutation capability.
/// </summary>
internal sealed class ResolverHealthCoordinator : IDisposable
{
    internal const int MinimumIntervalMinutes = 15;
    internal const int MaximumIntervalMinutes = 24 * 60;
    internal const int DefaultIntervalMinutes = 60;
    internal const string DefaultProbeHost = "example.com";

    private const string EnabledMetaKey = "resolver_health_schedule_enabled";
    private const string IntervalMetaKey = "resolver_health_schedule_minutes";
    private static readonly TimeSpan PerProbeTimeout = TimeSpan.FromSeconds(3);
    private static readonly TimeSpan WholeRunTimeout = TimeSpan.FromSeconds(30);

    private readonly object _gate = new();
    private readonly IDnsConfig? _dns;
    private readonly HostsDatabase _db;
    private readonly ScheduledTaskDrain _scheduledRun = new();
    private readonly SemaphoreSlim _runGate = new(1, 1);
    private Timer? _timer;
    private IReadOnlyList<DnsResolverHealthResult> _entries = [];
    private string _host = DefaultProbeHost;
    private string _source = string.Empty;
    private DateTime? _checkedAtUtc;
    private DateTime? _nextScheduledAtUtc;
    private string _message = "No resolver health check has run";
    private bool _running;
    private bool _disposed;
    private bool _scheduleEnabled;
    private int _intervalMinutes;

    internal ResolverHealthCoordinator(IDnsConfig? dns, HostsDatabase db)
    {
        _dns = dns;
        _db = db;
        _intervalMinutes = ReadInterval(db.GetMeta(IntervalMetaKey));
        _scheduleEnabled = string.Equals(db.GetMeta(EnabledMetaKey), "true", StringComparison.OrdinalIgnoreCase);
        if (_scheduleEnabled)
        {
            ArmTimer();
        }
    }

    internal ResolverHealthSnapshot Snapshot()
    {
        lock (_gate)
        {
            return SnapshotLocked();
        }
    }

    internal async Task<ResolverHealthSnapshot> RunManualAsync(string host, CancellationToken cancellationToken)
    {
        var acquired = await _runGate.WaitAsync(0, cancellationToken).ConfigureAwait(false);
        if (!acquired)
        {
            lock (_gate)
            {
                return SnapshotLocked() with { Running = true, Message = "A resolver health check is already running" };
            }
        }

        try
        {
            return await RunOwnedAsync(host, "manual", cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _runGate.Release();
        }
    }

    internal ResolverHealthSnapshot ConfigureSchedule(bool enabled, int intervalMinutes)
    {
        if (enabled && (intervalMinutes < MinimumIntervalMinutes || intervalMinutes > MaximumIntervalMinutes))
        {
            throw new ArgumentOutOfRangeException(nameof(intervalMinutes),
                $"Scheduled resolver checks require {MinimumIntervalMinutes}..{MaximumIntervalMinutes} minutes");
        }

        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            _scheduleEnabled = enabled;
            if (enabled)
            {
                _intervalMinutes = intervalMinutes;
            }

            _db.SetMeta(EnabledMetaKey, enabled ? "true" : "false");
            _db.SetMeta(IntervalMetaKey, _intervalMinutes.ToString(System.Globalization.CultureInfo.InvariantCulture));
            _timer?.Dispose();
            _timer = null;
            _nextScheduledAtUtc = null;
            if (enabled)
            {
                ArmTimerLocked();
            }

            return SnapshotLocked();
        }
    }

    internal Task TriggerScheduledForTestAsync(CancellationToken cancellationToken = default) =>
        RunScheduledAsync(cancellationToken);

    private void ArmTimer()
    {
        lock (_gate)
        {
            ArmTimerLocked();
        }
    }

    private void ArmTimerLocked()
    {
        var interval = TimeSpan.FromMinutes(_intervalMinutes);
        _nextScheduledAtUtc = DateTime.UtcNow.Add(interval);
        _timer = new Timer(_ => KickScheduledRun(), null, interval, interval);
    }

    private void KickScheduledRun()
    {
        lock (_gate)
        {
            if (_disposed || !_scheduleEnabled)
            {
                return;
            }

            _nextScheduledAtUtc = DateTime.UtcNow.AddMinutes(_intervalMinutes);
        }

        _scheduledRun.TryRun(RunScheduledAsync);
    }

    private async Task RunScheduledAsync(CancellationToken cancellationToken)
    {
        if (!await _runGate.WaitAsync(0, cancellationToken).ConfigureAwait(false))
        {
            return;
        }

        try
        {
            await RunOwnedAsync(DefaultProbeHost, "scheduled", cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _runGate.Release();
        }
    }

    private async Task<ResolverHealthSnapshot> RunOwnedAsync(
        string host,
        string source,
        CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            _running = true;
            _message = "Resolver health check is running";
        }

        IReadOnlyList<DnsResolverHealthResult> entries = [];
        string message;
        try
        {
            if (_dns is null)
            {
                message = "DNS engine is not attached to this service instance";
            }
            else
            {
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                timeout.CancelAfter(WholeRunTimeout);
                entries = await _dns.CheckResolverHealthAsync(host, PerProbeTimeout, timeout.Token).ConfigureAwait(false);
                message = entries.Count == 0
                    ? "No eligible resolver endpoints were found"
                    : $"Checked {entries.Count} resolver endpoint/protocol rows without changing DNS settings";
            }
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            message = "Resolver health check timed out after 30 seconds";
        }
        catch (OperationCanceledException)
        {
            lock (_gate)
            {
                _running = false;
                _message = "Resolver health check was cancelled; cached results were retained";
            }

            throw;
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException or System.Net.Sockets.SocketException)
        {
            message = $"Resolver health check failed: {ex.GetType().Name}";
        }
        finally
        {
            lock (_gate)
            {
                _running = false;
                if (string.Equals(_message, "Resolver health check is running", StringComparison.Ordinal))
                {
                    _message = "Resolver health check ended before producing a result";
                }
            }
        }

        lock (_gate)
        {
            _entries = entries;
            _host = host;
            _source = source;
            _checkedAtUtc = DateTime.UtcNow;
            _message = message;
            _db.LogEvent("dns", "resolver_health_check", details: $"source={source}; host={host}; rows={entries.Count}; {message}");
            return SnapshotLocked();
        }
    }

    private ResolverHealthSnapshot SnapshotLocked() => new(
        _entries,
        _host,
        _source,
        _checkedAtUtc,
        _running,
        _scheduleEnabled,
        _intervalMinutes,
        _nextScheduledAtUtc,
        _message);

    private static int ReadInterval(string? value) =>
        int.TryParse(value, System.Globalization.NumberStyles.None,
            System.Globalization.CultureInfo.InvariantCulture, out var parsed)
            ? Math.Clamp(parsed, MinimumIntervalMinutes, MaximumIntervalMinutes)
            : DefaultIntervalMinutes;

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            _timer?.Dispose();
            _timer = null;
        }

        _scheduledRun.Dispose();
    }
}
