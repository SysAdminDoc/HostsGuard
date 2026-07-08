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

    private readonly HostsDatabase _db;
    private readonly IBandwidthSource _source;
    private readonly Func<int, string> _resolve;
    private readonly Func<string, string>? _resolveHost;
    private readonly ConcurrentDictionary<int, string> _nameCache = new();
    private readonly CancellationTokenSource _cts = new();
    private readonly TimeSpan _interval;
    private Task? _loop;
    private int _flushes;

    public BandwidthAggregator(
        HostsDatabase db, IBandwidthSource source, Func<int, string>? resolveProcess = null,
        TimeSpan? flushInterval = null, Func<string, string>? resolveHost = null)
    {
        _db = db ?? throw new ArgumentNullException(nameof(db));
        _source = source ?? throw new ArgumentNullException(nameof(source));
        _resolve = resolveProcess ?? DefaultResolve;
        _resolveHost = resolveHost;
        _interval = flushInterval ?? TimeSpan.FromSeconds(15);
    }

    public bool CountersActive => _source.Active;

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
                FlushOnce(DateTime.Now);
            }
            catch (Microsoft.Data.Sqlite.SqliteException)
            {
                // Transient DB contention — counters were drained, this window's
                // bytes are lost; the next flush proceeds normally.
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
                _db.AddBandwidth(process, minute, bytes.Sent, bytes.Recv);
            }
        }

        // NET-108: attribute per-(PID, remote-IP) bytes to the resolved domain so
        // the feed can show per-domain data volume and its requesting process.
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
                _db.AddDomainUsage(domain, process, bytes.Sent, bytes.Recv);
            }
        }

        if (++_flushes % PruneEveryFlushes == 0)
        {
            _db.RunRetentionSweep(now);
            _nameCache.Clear(); // PIDs get recycled — don't let stale names stick
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

    public void Dispose()
    {
        _cts.Cancel();
        _cts.Dispose();
    }
}
