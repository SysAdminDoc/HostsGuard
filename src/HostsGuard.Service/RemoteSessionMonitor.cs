using System.Globalization;
using HostsGuard.Data;
using HostsGuard.Windows;

namespace HostsGuard.Service;

/// <summary>
/// Polls read-only WTS state and emits one inbox entry for a newly observed
/// active RDP session. Repeated polls and quick reconnects refresh the same
/// in-memory identity instead of producing duplicate alerts.
/// </summary>
internal sealed class RemoteSessionMonitor : IDisposable
{
    private static readonly TimeSpan ReconnectCoalesceWindow = TimeSpan.FromMinutes(30);
    private readonly IRemoteSessionSource _source;
    private readonly HostsDatabase _db;
    private readonly Func<DateTime> _utcNow;
    private readonly Timer _timer;
    private readonly object _gate = new();
    private readonly Dictionary<string, DateTime> _lastActive = new(StringComparer.Ordinal);
    private string _lastError = string.Empty;
    private bool _started;

    public RemoteSessionMonitor(
        IRemoteSessionSource source,
        HostsDatabase db,
        Func<DateTime>? utcNow = null)
    {
        _source = source ?? throw new ArgumentNullException(nameof(source));
        _db = db ?? throw new ArgumentNullException(nameof(db));
        _utcNow = utcNow ?? (() => DateTime.UtcNow);
        _timer = new Timer(_ => PollSafely(), null, Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);
    }

    public void Start()
    {
        lock (_gate)
        {
            if (_started)
            {
                return;
            }

            _started = true;
        }

        PollSafely();
        _timer.Change(TimeSpan.FromSeconds(15), TimeSpan.FromSeconds(15));
    }

    internal void Poll()
    {
        var snapshot = _source.Snapshot();
        var now = _utcNow();
        lock (_gate)
        {
            if (!snapshot.Available)
            {
                if (!string.Equals(_lastError, snapshot.ErrorCode, StringComparison.Ordinal))
                {
                    _lastError = snapshot.ErrorCode;
                    _db.LogEvent(
                        "remote_desktop",
                        "rdp_observer_unavailable",
                        details: snapshot.ErrorCode,
                        reason: "observation_incomplete");
                }

                return;
            }

            if (_lastError.Length != 0)
            {
                _db.LogEvent(
                    "remote_desktop",
                    "rdp_observer_restored",
                    details: "WTS session observation restored",
                    reason: "observation_recovered");
                _lastError = string.Empty;
            }

            foreach (var stale in _lastActive
                         .Where(pair => now - pair.Value > ReconnectCoalesceWindow)
                         .Select(pair => pair.Key)
                         .ToArray())
            {
                _lastActive.Remove(stale);
            }

            foreach (var session in snapshot.Sessions.Where(session => session.Active))
            {
                var key = string.Join('|',
                    session.SessionId.ToString(CultureInfo.InvariantCulture),
                    session.SourceAddress,
                    session.ClientName);
                var firstObservation = !_lastActive.ContainsKey(key);
                _lastActive[key] = now;
                if (!firstObservation)
                {
                    continue;
                }

                var source = session.SourceAddress.Length != 0
                    ? session.SourceAddress
                    : session.ClientName.Length != 0
                        ? session.ClientName
                        : "source unavailable";
                var details = $"Active Remote Desktop session {session.SessionId.ToString(CultureInfo.InvariantCulture)} from {source}. Restrictive network changes may disconnect this operator; alert only, no posture was changed.";
                _db.AddAlert(
                    "remote_session",
                    "warning",
                    "Remote Desktop session active",
                    $"session {session.SessionId.ToString(CultureInfo.InvariantCulture)}",
                    details,
                    action: "review_remote_session");
                _db.LogEvent(
                    "remote_desktop",
                    "rdp_session_active",
                    details: details,
                    reason: "operator_safety");
            }
        }
    }

    private void PollSafely()
    {
        try
        {
            Poll();
        }
        catch (Exception ex) when (ex is InvalidOperationException or UnauthorizedAccessException or IOException)
        {
            lock (_gate)
            {
                if (_lastError.Length == 0)
                {
                    _lastError = "wts_poll_failed";
                    _db.LogEvent(
                        "remote_desktop",
                        "rdp_observer_unavailable",
                        details: _lastError,
                        reason: "observation_incomplete");
                }
            }
        }
    }

    public void Dispose() => _timer.Dispose();
}
