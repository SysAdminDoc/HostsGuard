using System.Runtime.Versioning;
using System.Text.Json;
using Google.Protobuf.WellKnownTypes;
using HostsGuard.Contracts;
using HostsGuard.Data;
using HostsGuard.Windows;

namespace HostsGuard.Service;

/// <summary>
/// Timed global pause (NET-149): temporarily clears managed hosts-file blocks
/// and sets firewall default-outbound to Allow, then restores both automatically.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class EnforcementPauseCoordinator : IDisposable
{
    private static readonly HashSet<int> AllowedMinutes = new([5, 15, 60]);

    private readonly HostsEngine _hosts;
    private readonly HostsDatabase _db;
    private readonly IFirewallEngine? _firewall;
    private readonly string _statePath;
    private readonly Timer _timer;
    private readonly object _gate = new();
    private PauseState _state;
    private bool _disposed;

    public EnforcementPauseCoordinator(HostsEngine hosts, HostsDatabase db, IFirewallEngine? firewall, string dataDir)
    {
        _hosts = hosts ?? throw new ArgumentNullException(nameof(hosts));
        _db = db ?? throw new ArgumentNullException(nameof(db));
        _firewall = firewall;
        _statePath = Path.Combine(dataDir, "enforcement_pause_state.json");
        _state = LoadState();
        _timer = new Timer(_ => Sweep(DateTime.UtcNow), null, Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);
    }

    public Func<bool>? IsKillSwitchEngaged { get; set; }

    public Ack Pause(int minutes)
    {
        if (!AllowedMinutes.Contains(minutes))
        {
            return Error("invalid_duration", "pause minutes must be 5, 15, or 60");
        }

        if (_firewall is not { } fw)
        {
            return Error("firewall_unavailable", "firewall engine is not attached to this service instance");
        }

        if (IsKillSwitchEngaged?.Invoke() == true)
        {
            return Error("killswitch_engaged", "cannot pause enforcement while the VPN kill-switch is engaged");
        }

        var expires = DateTime.UtcNow.AddMinutes(minutes);
        lock (_gate)
        {
            if (_disposed)
            {
                return Error("disposed", "pause coordinator is shutting down");
            }

            var prior = IsActiveNoLock()
                ? _state.PriorOutboundBlock!
                : fw.GetPosture().ToDictionary(p => p.Name, p => p.OutboundBlock, StringComparer.Ordinal);

            try
            {
                ApplyPauseNoLock(fw);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Runtime.InteropServices.COMException)
            {
                TryRestoreNoLock(prior, restoreFirewall: true);
                return Error("pause_failed", $"could not pause enforcement: {ex.Message}");
            }

            _state = new PauseState
            {
                ExpiresUtc = expires,
                PriorOutboundBlock = new Dictionary<string, bool>(prior, StringComparer.Ordinal),
                SuspendedByKillSwitch = false,
            };
            SaveStateNoLock();
            RearmNoLock();
        }

        _db.LogEvent("enforcement", "enforcement_paused", details: $"{minutes} min", reason: "manual");
        return new Ack
        {
            Ok = true,
            Message = $"enforcement paused for {minutes} minutes - hosts blocks removed and outbound default set to Allow",
        };
    }

    public EnforcementPauseStatus Status()
    {
        Sweep(DateTime.UtcNow);
        lock (_gate)
        {
            var status = new EnforcementPauseStatus();
            if (!IsActiveNoLock())
            {
                return status;
            }

            var expires = _state.ExpiresUtc!.Value;
            status.Active = true;
            status.SuspendedByKillSwitch = _state.SuspendedByKillSwitch;
            status.Expires = Timestamp.FromDateTime(DateTime.SpecifyKind(expires, DateTimeKind.Utc));
            status.MinutesRemaining = Math.Max(1, (int)Math.Ceiling((expires - DateTime.UtcNow).TotalMinutes));
            return status;
        }
    }

    public void Resume()
    {
        lock (_gate)
        {
            if (_disposed || !IsActiveNoLock())
            {
                return;
            }

            if (_state.ExpiresUtc!.Value <= DateTime.UtcNow)
            {
                CompleteExpiredNoLock();
                return;
            }

            if (!_state.SuspendedByKillSwitch && _firewall is { } fw)
            {
                ApplyPauseNoLock(fw);
            }

            RearmNoLock();
        }
    }

    public void Sweep(DateTime nowUtc)
    {
        lock (_gate)
        {
            if (_disposed || !IsActiveNoLock() || _state.ExpiresUtc!.Value > nowUtc)
            {
                return;
            }

            CompleteExpiredNoLock();
        }
    }

    public void SuspendForKillSwitch()
    {
        lock (_gate)
        {
            if (_disposed || !IsActiveNoLock() || _state.SuspendedByKillSwitch)
            {
                return;
            }

            TryRestoreNoLock(_state.PriorOutboundBlock!, restoreFirewall: true);
            _state.SuspendedByKillSwitch = true;
            SaveStateNoLock();
            RearmNoLock();
        }

        _db.LogEvent("enforcement", "enforcement_pause_suspended", details: "VPN kill-switch engaged", reason: "killswitch");
    }

    public void TryResumeAfterKillSwitch()
    {
        lock (_gate)
        {
            if (_disposed || !IsActiveNoLock() || !_state.SuspendedByKillSwitch)
            {
                return;
            }

            if (_state.ExpiresUtc!.Value <= DateTime.UtcNow)
            {
                CompleteExpiredNoLock();
                return;
            }

            if (_firewall is not { } fw)
            {
                return;
            }

            ApplyPauseNoLock(fw);
            _state.SuspendedByKillSwitch = false;
            SaveStateNoLock();
            RearmNoLock();
        }

        _db.LogEvent("enforcement", "enforcement_pause_reapplied", details: "VPN kill-switch released", reason: "killswitch");
    }

    private bool IsActiveNoLock() => _state.ExpiresUtc is not null && _state.PriorOutboundBlock is not null;

    private void ApplyPauseNoLock(IFirewallEngine fw)
    {
        _hosts.Reconcile(Array.Empty<string>());
        fw.SetDefaultOutboundBlock(false);
    }

    private void CompleteExpiredNoLock()
    {
        var suspended = _state.SuspendedByKillSwitch;
        var prior = _state.PriorOutboundBlock;
        if (prior is not null && !suspended && IsKillSwitchEngaged?.Invoke() != true)
        {
            TryRestoreNoLock(prior, restoreFirewall: true);
        }
        else
        {
            TryRestoreNoLock(prior, restoreFirewall: false);
        }

        _state = new PauseState();
        SaveStateNoLock();
        _timer.Change(Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);
        _db.LogEvent(
            "enforcement",
            "enforcement_resumed",
            details: suspended ? "pause expired while kill-switch controlled firewall posture" : "pause expired",
            reason: "pause_expired");
    }

    private void TryRestoreNoLock(IReadOnlyDictionary<string, bool>? prior, bool restoreFirewall)
    {
        try
        {
            if (restoreFirewall && prior is not null && _firewall is not null)
            {
                _firewall.SetDefaultOutboundBlock(prior);
            }

            var blocked = _db.GetDomains(status: "blocked").Select(r => r.Domain).ToList();
            _hosts.Reconcile(blocked);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Runtime.InteropServices.COMException)
        {
            _db.LogEvent("enforcement", "enforcement_resume_failed", details: ex.Message, reason: "pause_expired");
        }
    }

    private void RearmNoLock()
    {
        if (!IsActiveNoLock())
        {
            _timer.Change(Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);
            return;
        }

        var due = _state.ExpiresUtc!.Value - DateTime.UtcNow;
        if (due < TimeSpan.FromSeconds(1))
        {
            due = TimeSpan.FromSeconds(1);
        }

        _timer.Change(due, Timeout.InfiniteTimeSpan);
    }

    private PauseState LoadState()
    {
        try
        {
            if (File.Exists(_statePath))
            {
                var loaded = JsonSerializer.Deserialize<PauseState>(File.ReadAllText(_statePath));
                if (loaded is not null)
                {
                    return loaded;
                }
            }
        }
        catch (Exception ex) when (ex is IOException or JsonException)
        {
            _db.LogEvent("enforcement", "enforcement_pause_state_reset", details: ex.Message, reason: "startup");
        }

        return new PauseState();
    }

    private void SaveStateNoLock()
    {
        try
        {
            var tmp = _statePath + ".tmp";
            File.WriteAllText(tmp, JsonSerializer.Serialize(_state));
            File.Move(tmp, _statePath, overwrite: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _db.LogEvent("enforcement", "enforcement_pause_state_save_failed", details: ex.Message, reason: "io_error");
        }
    }

    private static Ack Error(string code, string message) => new()
    {
        Ok = false,
        Message = message,
        ErrorCode = $"hostsguard.error.v1/{code}",
    };

    public void Dispose()
    {
        lock (_gate)
        {
            _disposed = true;
            _timer.Dispose();
        }
    }

    private sealed class PauseState
    {
        public DateTime? ExpiresUtc { get; set; }
        public Dictionary<string, bool>? PriorOutboundBlock { get; set; }
        public bool SuspendedByKillSwitch { get; set; }
    }
}
