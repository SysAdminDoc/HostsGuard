using System.Runtime.Versioning;
using System.Text.Json;
using System.Text.Json.Serialization;
using HostsGuard.Core;

namespace HostsGuard.Service;

public sealed record SettingsLockActionResult(
    bool Ok,
    string Message,
    string ErrorCode = "",
    bool ReportSecurityEvent = false,
    int RetryAfterSeconds = 0);

public sealed record SettingsLockStatus(
    bool Enabled,
    bool Locked,
    bool Degraded,
    int FailedAttempts,
    int RetryAfterSeconds,
    string Message);

/// <summary>
/// Settings/rule lock (NET-079): when armed, changing filtering modes, firewall
/// posture, or HG_ rules requires the lock password. The verifier persists in
/// the ACL-locked data directory; timed unlock and attempt throttling are
/// memory-only so a service restart always returns to a locked, recoverable
/// state. Corrupt persisted state fails closed instead of silently disarming.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class SettingsLock
{
    internal const int FailureAlertThreshold = 3;
    internal const int MaxFailureCount = 10;
    internal static readonly TimeSpan FailureResetWindow = TimeSpan.FromMinutes(15);
    internal static readonly TimeSpan MaxRetryDelay = TimeSpan.FromSeconds(30);

    private const string RecoveryMessage =
        "settings lock state is unreadable; automatic unlock is blocked. Stop HostsGuardSvc as an administrator, remove lock_state.json from the HostsGuard ProgramData directory, and restart the service";

    private static readonly JsonSerializerOptions LoadOptions = new(JsonSerializerDefaults.Web)
    {
        AllowDuplicateProperties = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };

    private readonly string _statePath;
    private readonly object _gate = new();
    private State _state;
    private readonly bool _degraded;
    private DateTime _unlockedUntilUtc = DateTime.MinValue;
    private int _failedAttempts;
    private DateTime _lastFailureUtc = DateTime.MinValue;
    private DateTime _nextAttemptUtc = DateTime.MinValue;
    private bool _failureEventReported;

    public SettingsLock(string dataDir)
    {
        _statePath = Path.Combine(dataDir ?? throw new ArgumentNullException(nameof(dataDir)), "lock_state.json");
        var loaded = Load();
        _state = loaded.State;
        _degraded = loaded.Degraded;
    }

    /// <summary>Whether the lock is armed, including fail-closed degraded state.</summary>
    public bool Enabled
    {
        get { lock (_gate) { return _degraded || _state.Enabled; } }
    }

    public bool Degraded => _degraded;

    public string DegradedMessage => _degraded ? RecoveryMessage : string.Empty;

    public bool IsLocked(DateTime nowUtc)
    {
        lock (_gate)
        {
            return _degraded || (_state.Enabled && nowUtc >= _unlockedUntilUtc);
        }
    }

    public SettingsLockStatus GetStatus(DateTime nowUtc)
    {
        lock (_gate)
        {
            ResetFailuresAfterQuietNoLock(nowUtc);
            return new SettingsLockStatus(
                Enabled: _degraded || _state.Enabled,
                Locked: _degraded || (_state.Enabled && nowUtc >= _unlockedUntilUtc),
                Degraded: _degraded,
                FailedAttempts: _failedAttempts,
                RetryAfterSeconds: RetryAfterSecondsNoLock(nowUtc),
                Message: _degraded ? RecoveryMessage : string.Empty);
        }
    }

    /// <summary>Arm a currently unarmed lock. An armed verifier is never replaced.</summary>
    public SettingsLockActionResult Enable(string password)
    {
        if (string.IsNullOrWhiteSpace(password) || password.Length < 4)
        {
            return Error("password must be at least 4 characters", "lock");
        }

        lock (_gate)
        {
            if (_degraded)
            {
                return Error(RecoveryMessage, "lock_state_corrupt");
            }

            if (_state.Enabled)
            {
                return Error(
                    "settings lock is already armed; disarm it with the current password before setting a new password",
                    "lock_already_enabled");
            }

            _state = new State { Enabled = true, Hash = PasswordHash.Hash(password) };
            _unlockedUntilUtc = DateTime.MinValue;
            ResetFailuresNoLock();
            Save();
        }

        return Success("settings lock armed");
    }

    /// <summary>Disarm the lock after verifying the current password.</summary>
    public SettingsLockActionResult Disable(string password, DateTime nowUtc)
    {
        lock (_gate)
        {
            if (_degraded)
            {
                return Error(RecoveryMessage, "lock_state_corrupt");
            }

            if (!_state.Enabled)
            {
                ResetFailuresNoLock();
                return Success("settings lock was not armed");
            }

            if (TryGetThrottleNoLock(nowUtc) is { } throttled)
            {
                return throttled;
            }

            if (!PasswordHash.Verify(password, _state.Hash))
            {
                return RegisterFailureNoLock(nowUtc);
            }

            _state = new State();
            _unlockedUntilUtc = DateTime.MinValue;
            ResetFailuresNoLock();
            Save();
        }

        return Success("settings lock disarmed");
    }

    public SettingsLockActionResult Disable(string password) => Disable(password, DateTime.UtcNow);

    /// <summary>
    /// Unlock for <paramref name="minutes"/> (0 = one minute). Verification is
    /// throttled without sleeping or blocking a service thread between attempts.
    /// </summary>
    public SettingsLockActionResult Unlock(string password, int minutes, DateTime nowUtc)
    {
        lock (_gate)
        {
            if (_degraded)
            {
                return Error(RecoveryMessage, "lock_state_corrupt");
            }

            if (!_state.Enabled)
            {
                ResetFailuresNoLock();
                return Success("settings lock is not armed");
            }

            if (TryGetThrottleNoLock(nowUtc) is { } throttled)
            {
                return throttled;
            }

            if (!PasswordHash.Verify(password, _state.Hash, out var needsRehash))
            {
                return RegisterFailureNoLock(nowUtc);
            }

            if (needsRehash)
            {
                _state.Hash = PasswordHash.Hash(password);
                Save();
            }

            ResetFailuresNoLock();
            var unlockMinutes = Math.Clamp(minutes <= 0 ? 1 : minutes, 1, 240);
            _unlockedUntilUtc = nowUtc + TimeSpan.FromMinutes(unlockMinutes);
            return Success($"unlocked for {unlockMinutes} minutes");
        }
    }

    /// <summary>Export the current verifier for legacy portable-policy compatibility.</summary>
    public (bool Enabled, string Hash) ExportState()
    {
        lock (_gate)
        {
            if (_degraded)
            {
                throw new InvalidOperationException("settings lock state is corrupt and cannot be exported");
            }

            return (_state.Enabled, _state.Hash);
        }
    }

    public void ImportState(bool enabled, string hash)
    {
        hash ??= string.Empty;
        if ((enabled && !PasswordHash.IsValidEncoding(hash)) || (!enabled && hash.Length != 0))
        {
            throw new ArgumentException("settings-lock hash encoding is not supported", nameof(hash));
        }

        lock (_gate)
        {
            if (_degraded)
            {
                throw new InvalidOperationException("corrupt settings-lock state requires administrator recovery");
            }

            _state = new State { Enabled = enabled, Hash = hash };
            _unlockedUntilUtc = DateTime.MinValue;
            ResetFailuresNoLock();
            Save();
        }
    }

    private SettingsLockActionResult? TryGetThrottleNoLock(DateTime nowUtc)
    {
        ResetFailuresAfterQuietNoLock(nowUtc);
        var retryAfter = RetryAfterSecondsNoLock(nowUtc);
        return retryAfter <= 0
            ? null
            : Error($"password verification is temporarily throttled; try again in {retryAfter} seconds",
                "lock_throttled", retryAfterSeconds: retryAfter);
    }

    private SettingsLockActionResult RegisterFailureNoLock(DateTime nowUtc)
    {
        ResetFailuresAfterQuietNoLock(nowUtc);
        _failedAttempts = Math.Min(MaxFailureCount, _failedAttempts + 1);
        _lastFailureUtc = nowUtc;
        var delaySeconds = Math.Min(
            (int)MaxRetryDelay.TotalSeconds,
            1 << Math.Min(_failedAttempts - 1, 5));
        _nextAttemptUtc = nowUtc + TimeSpan.FromSeconds(delaySeconds);
        var report = !_failureEventReported && _failedAttempts >= FailureAlertThreshold;
        _failureEventReported |= report;
        return Error(
            "incorrect password",
            "lock",
            reportSecurityEvent: report,
            retryAfterSeconds: delaySeconds);
    }

    private int RetryAfterSecondsNoLock(DateTime nowUtc)
        => nowUtc >= _nextAttemptUtc
            ? 0
            : Math.Max(1, (int)Math.Ceiling((_nextAttemptUtc - nowUtc).TotalSeconds));

    private void ResetFailuresAfterQuietNoLock(DateTime nowUtc)
    {
        if (_failedAttempts > 0 && nowUtc - _lastFailureUtc >= FailureResetWindow)
        {
            ResetFailuresNoLock();
        }
    }

    private void ResetFailuresNoLock()
    {
        _failedAttempts = 0;
        _lastFailureUtc = DateTime.MinValue;
        _nextAttemptUtc = DateTime.MinValue;
        _failureEventReported = false;
    }

    private static SettingsLockActionResult Success(string message) => new(true, message);

    private static SettingsLockActionResult Error(
        string message,
        string errorCode,
        bool reportSecurityEvent = false,
        int retryAfterSeconds = 0)
        => new(false, message, errorCode, reportSecurityEvent, retryAfterSeconds);

    private sealed class State
    {
        public bool Enabled { get; set; }

        public string Hash { get; set; } = string.Empty;
    }

    private sealed record LoadResult(State State, bool Degraded);

    private LoadResult Load()
    {
        if (!File.Exists(_statePath))
        {
            return new LoadResult(new State(), false);
        }

        try
        {
            var state = JsonSerializer.Deserialize<State>(File.ReadAllText(_statePath), LoadOptions);
            if (state is null)
            {
                return new LoadResult(new State(), true);
            }

            state.Hash ??= string.Empty;
            if ((state.Enabled && !PasswordHash.IsValidEncoding(state.Hash)) ||
                (!state.Enabled && state.Hash.Length != 0))
            {
                return new LoadResult(new State(), true);
            }

            return new LoadResult(state, false);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or NotSupportedException)
        {
            return new LoadResult(new State(), true);
        }
    }

    private void Save()
    {
        var tmp = _statePath + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(_state));
        File.Move(tmp, _statePath, overwrite: true);
    }
}
