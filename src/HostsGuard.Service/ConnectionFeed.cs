using System.Runtime.Versioning;
using HostsGuard.Windows;

namespace HostsGuard.Service;

/// <summary>
/// Polls the IPHLPAPI connection table and publishes new or state-changed
/// connections onto the event bus for WatchConnections streams. Reading the
/// table needs no elevation; polling every 2s matches the Python cadence.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class ConnectionFeed : IDisposable
{
    private readonly ServiceState _state;
    private readonly ConnectionMonitor _monitor = new();
    private readonly CancellationTokenSource _cts = new();
    private readonly TimeSpan _interval;
    private Task? _loop;

    public ConnectionFeed(ServiceState state, TimeSpan? interval = null)
    {
        _state = state ?? throw new ArgumentNullException(nameof(state));
        _interval = interval ?? TimeSpan.FromSeconds(2);
    }

    public void Start() => _loop ??= Task.Run(() => LoopAsync(_cts.Token));

    private async Task LoopAsync(CancellationToken ct)
    {
        var seen = new Dictionary<(string, string, int, string, int, int), string>();
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var snapshot = _monitor.Snapshot();
                var current = new HashSet<(string, string, int, string, int, int)>();
                foreach (var c in snapshot)
                {
                    var key = (c.Protocol, c.LocalAddress, c.LocalPort, c.RemoteAddress, c.RemotePort, c.Pid);
                    current.Add(key);
                    if (!seen.TryGetValue(key, out var state) || state != c.State)
                    {
                        seen[key] = c.State;
                        _state.PublishConnection(c);
                    }
                }

                foreach (var gone in seen.Keys.Where(k => !current.Contains(k)).ToList())
                {
                    seen.Remove(gone);
                }
            }
            catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException)
            {
                // Table read hiccup — retry next tick.
            }

            try
            {
                await Task.Delay(_interval, ct);
            }
            catch (OperationCanceledException)
            {
                return;
            }
        }
    }

    public void Dispose()
    {
        _cts.Cancel();
        _cts.Dispose();
    }
}
