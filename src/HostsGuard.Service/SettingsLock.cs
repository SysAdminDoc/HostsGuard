using System.Runtime.Versioning;
using System.Text.Json;
using HostsGuard.Core;

namespace HostsGuard.Service;

/// <summary>
/// Settings/rule lock (NET-079): when armed, changing filtering modes, firewall
/// posture, or HG_ rules requires the lock password (optionally with a timed
/// unlock so the user isn't re-prompted for a few minutes — TinyWall's pattern).
/// State (enabled + password hash) persists in lock_state.json under the
/// ACL-locked data dir; the timed-unlock deadline is in-memory only so a
/// service restart re-locks. Thread-safe.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class SettingsLock
{
    private readonly string _statePath;
    private readonly object _gate = new();
    private State _state;
    private DateTime _unlockedUntilUtc = DateTime.MinValue;

    public SettingsLock(string dataDir)
    {
        _statePath = Path.Combine(dataDir ?? throw new ArgumentNullException(nameof(dataDir)), "lock_state.json");
        _state = Load();
    }

    /// <summary>Whether the lock is armed.</summary>
    public bool Enabled
    {
        get { lock (_gate) { return _state.Enabled; } }
    }

    /// <summary>
    /// Whether a mutating action is currently blocked: armed AND not inside a
    /// timed-unlock window.
    /// </summary>
    public bool IsLocked(DateTime nowUtc)
    {
        lock (_gate)
        {
            return _state.Enabled && nowUtc >= _unlockedUntilUtc;
        }
    }

    /// <summary>Arm the lock with a password (or replace the existing password).</summary>
    public (bool Ok, string Message) Enable(string password)
    {
        if (string.IsNullOrWhiteSpace(password) || password.Length < 4)
        {
            return (false, "password must be at least 4 characters");
        }

        lock (_gate)
        {
            _state = new State { Enabled = true, Hash = PasswordHash.Hash(password) };
            _unlockedUntilUtc = DateTime.MinValue;
            Save();
        }

        return (true, "settings lock armed");
    }

    /// <summary>Disarm the lock — requires the current password.</summary>
    public (bool Ok, string Message) Disable(string password)
    {
        lock (_gate)
        {
            if (!_state.Enabled)
            {
                return (true, "settings lock was not armed");
            }

            if (!PasswordHash.Verify(password, _state.Hash))
            {
                return (false, "incorrect password");
            }

            _state = new State();
            _unlockedUntilUtc = DateTime.MinValue;
            Save();
        }

        return (true, "settings lock disarmed");
    }

    /// <summary>
    /// Unlock for <paramref name="minutes"/> (0 = single action window of ~1
    /// minute). Requires the current password.
    /// </summary>
    public (bool Ok, string Message) Unlock(string password, int minutes, DateTime nowUtc)
    {
        lock (_gate)
        {
            if (!_state.Enabled)
            {
                return (true, "settings lock is not armed");
            }

            if (!PasswordHash.Verify(password, _state.Hash))
            {
                return (false, "incorrect password");
            }

            var window = TimeSpan.FromMinutes(Math.Clamp(minutes <= 0 ? 1 : minutes, 1, 240));
            _unlockedUntilUtc = nowUtc + window;
        }

        return (true, $"unlocked for {Math.Clamp(minutes <= 0 ? 1 : minutes, 1, 240)} minutes");
    }

    /// <summary>Export the raw lock state (armed + hash) for a portable-policy snapshot (NET-089).</summary>
    public (bool Enabled, string Hash) ExportState()
    {
        lock (_gate)
        {
            return (_state.Enabled, _state.Hash);
        }
    }

    /// <summary>
    /// Replace the lock state from an imported policy (NET-089). Clears any
    /// timed-unlock window so the imported armed state takes effect immediately.
    /// </summary>
    public void ImportState(bool enabled, string hash)
    {
        lock (_gate)
        {
            _state = new State { Enabled = enabled, Hash = hash ?? string.Empty };
            _unlockedUntilUtc = DateTime.MinValue;
            Save();
        }
    }

    private sealed class State
    {
        public bool Enabled { get; set; }

        public string Hash { get; set; } = string.Empty;
    }

    private State Load()
    {
        try
        {
            if (File.Exists(_statePath))
            {
                return JsonSerializer.Deserialize<State>(File.ReadAllText(_statePath)) ?? new State();
            }
        }
        catch (Exception ex) when (ex is IOException or JsonException)
        {
            // Corrupt/locked state — fail unlocked rather than brick the service.
        }

        return new State();
    }

    private void Save()
    {
        var tmp = _statePath + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(_state));
        File.Move(tmp, _statePath, overwrite: true);
    }
}
