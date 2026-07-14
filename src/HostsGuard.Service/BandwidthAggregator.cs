using System.Collections.Concurrent;
using System.Runtime.Versioning;
using HostsGuard.Data;
using HostsGuard.Windows;

namespace HostsGuard.Service;

/// <summary>
/// Flushes drained per-PID byte counters into per-process per-minute DB buckets
/// (NET-070). PID→name resolution is injectable (and cached) so tests can drive
/// <see cref="FlushOnce"/> deterministically with a fake source; production
/// wires a <see cref="BandwidthMonitor"/> and a periodic flush loop. Runs the
/// database retention sweep on a coarse cadence.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class BandwidthAggregator : IDisposable
{
    private const int PruneEveryFlushes = 60;
    private static readonly TimeSpan StopTimeout = TimeSpan.FromSeconds(5);

    private readonly HostsDatabase _db;
    private readonly IBandwidthSource _source;
    private readonly Func<int, string> _resolve;
    private readonly Func<string, string>? _resolveHost;
    private readonly IClock _clock;
    private readonly ConcurrentDictionary<int, string> _nameCache = new();
    private readonly CancellationTokenSource _cts = new();
    private readonly TimeSpan _interval;
    private Task? _loop;
    private int _flushes;

    public BandwidthAggregator(
        HostsDatabase db, IBandwidthSource source, Func<int, string>? resolveProcess = null,
        TimeSpan? flushInterval = null, Func<string, string>? resolveHost = null,
        IClock? clock = null)
    {
        _db = db ?? throw new ArgumentNullException(nameof(db));
        _source = source ?? throw new ArgumentNullException(nameof(source));
        _resolve = resolveProcess ?? DefaultResolve;
        _resolveHost = resolveHost;
        _clock = clock ?? SystemClock.Instance;
        _interval = flushInterval ?? TimeSpan.FromSeconds(15);
    }

    public bool CountersActive => _source.Active;

    /// <summary>Optional block-on-exceed enforcement swept after every flush (NET-172).</summary>
    public UsageQuotaEnforcer? QuotaEnforcer { get; set; }

    public void Start() => _loop ??= Task.Run(() => LoopAsync(_cts.Token));

    private async Task LoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(_interval, ct);
            }
            catch (OperationCanceledException)
            {
                return;
            }

            try
            {
                FlushOnce(_clock.Now);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                return;
            }
            catch (Exception ex)
            {
                TryLogLoopError(ex);
            }
        }
    }

    /// <summary>Drain the source into minute buckets for <paramref name="now"/>.</summary>
    public void FlushOnce(DateTime now)
    {
        var drained = _source.Drain();
        if (drained.Count != 0)
        {
            var minute = now.ToString("yyyy-MM-ddTHH:mm", System.Globalization.CultureInfo.InvariantCulture);
            var byProcess = new Dictionary<string, (long Sent, long Recv)>(StringComparer.OrdinalIgnoreCase);
            foreach (var (pid, bytes) in drained)
            {
                var name = _nameCache.GetOrAdd(pid, _resolve);
                var acc = byProcess.GetValueOrDefault(name);
                byProcess[name] = (acc.Sent + bytes.Sent, acc.Recv + bytes.Recv);
            }

            foreach (var (process, bytes) in byProcess)
            {
                if (!_db.IsHistoryPersistenceExcluded(process, null))
                    _db.AddBandwidth(process, minute, bytes.Sent, bytes.Recv);
            }
        }

        // NET-108: attribute per-(PID, remote-IP) bytes to the resolved domain so
        // the feed can show per-domain data volume and its requesting process.
        var usageChanged = false;
        if (_resolveHost is { } resolveHost)
        {
            foreach (var (key, bytes) in _source.DrainByEndpoint())
            {
                var domain = resolveHost(key.RemoteAddress);
                if (string.IsNullOrEmpty(domain))
                {
                    continue; // no DNS name for this IP (e.g. bare-IP dial) — skip
                }

                var process = _nameCache.GetOrAdd(key.Pid, _resolve);
                if (_db.IsHistoryPersistenceExcluded(process, domain))
                {
                    continue;
                }
                _db.AddDomainUsage(domain, process, bytes.Sent, bytes.Recv);
                _db.AddUsageRollup(domain, process, now.Date, bytes.Sent, bytes.Recv);
                usageChanged = true;
            }
        }

        if (usageChanged)
        {
            EmitUsageBudgetAlerts(now);
        }

        // Runs every flush (not only on new usage): auto-clear depends on the
        // rolling window sliding under the limit even when traffic has stopped.
        QuotaEnforcer?.Sweep(now);

        if (++_flushes % PruneEveryFlushes == 0)
        {
            _db.RunRetentionSweep(now);
            _nameCache.Clear(); // PIDs get recycled — don't let stale names stick
        }
    }

    private void EmitUsageBudgetAlerts(DateTime now)
    {
        foreach (var evaluation in _db.EvaluateUsageQuotas(now, triggeredOnly: true))
        {
            var rule = evaluation.Rule;
            var subject = $"{rule.Scope}:{rule.Match}";
            var details = $"{rule.Match} used {FormatBytes(evaluation.UsedBytes)} of {FormatBytes(rule.LimitBytes)} over {rule.WindowDays} day{(rule.WindowDays == 1 ? string.Empty : "s")}.";
            _db.AddAlert(
                "usage_budget",
                "warning",
                "Usage budget reached",
                subject,
                details,
                action: "usage_quota",
                process: rule.Scope == "app" ? rule.Match : string.Empty);
            _db.LogEvent(rule.Match, "usage_budget_alert", process: rule.Scope == "app" ? rule.Match : string.Empty,
                details: $"{rule.Scope} quota {FormatBytes(rule.LimitBytes)} reached with {FormatBytes(evaluation.UsedBytes)} used",
                reason: "usage_budget");
            _db.MarkUsageQuotaAlerted(rule.Id, evaluation.UsedBytes, now);
        }
    }

    private static string DefaultResolve(int pid)
    {
        try
        {
            using var proc = System.Diagnostics.Process.GetProcessById(pid);
            return proc.ProcessName;
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
        {
            return "(exited)";
        }
    }

    private static string FormatBytes(long bytes)
    {
        string[] units = ["B", "KB", "MB", "GB", "TB"];
        double value = Math.Max(0, bytes);
        var unit = 0;
        while (value >= 1024 && unit < units.Length - 1)
        {
            value /= 1024;
            unit++;
        }

        return string.Create(System.Globalization.CultureInfo.InvariantCulture, $"{value:0.#} {units[unit]}");
    }

    public void Dispose()
    {
        _cts.Cancel();
        WaitForLoop();
        _cts.Dispose();
    }

    private void WaitForLoop()
    {
        if (_loop is null)
        {
            return;
        }

        try
        {
            if (!_loop.Wait(StopTimeout))
            {
                TryLogLoopError(new TimeoutException("bandwidth loop did not stop before timeout"));
            }
        }
        catch (AggregateException ex) when (ex.InnerExceptions.All(e => e is OperationCanceledException))
        {
            // Normal cancellation.
        }
        catch (AggregateException ex)
        {
            TryLogLoopError(ex.Flatten().InnerExceptions.FirstOrDefault() ?? ex);
        }
    }

    private void TryLogLoopError(Exception ex)
    {
        try
        {
            _db.LogEvent("bandwidth", "loop_error", details: $"{ex.GetType().Name}: {ex.Message}");
        }
        catch (Exception logEx) when (logEx is Microsoft.Data.Sqlite.SqliteException or InvalidOperationException)
        {
            // If the DB itself is unavailable, keep the flush loop alive.
        }
        catch (Exception)
        {
            // Logging must not fault the background flush loop.
        }
    }
}
