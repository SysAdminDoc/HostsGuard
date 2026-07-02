using System.Runtime.Versioning;
using System.Text.Json;
using Google.Protobuf.WellKnownTypes;
using HostsGuard.Contracts;
using HostsGuard.Core;
using HostsGuard.Data;
using HostsGuard.Windows;

namespace HostsGuard.Service;

/// <summary>
/// The WFC-parity consent pipeline (WFCP-010/012/020/021/022). Blocked
/// connections flow in from <see cref="BlockedConnectionWatch"/>; per the
/// filtering mode they are dropped (normal), auto-allowed and recorded
/// (learning), or deduped and pushed to the UI as pending decisions (notify).
/// Decisions come back as HG_ COM rules — permanent, or once-rules reaped
/// after a timeout — with <see cref="FirewallIdentity.Remember"/> on every
/// write so rebind history exists before the next app update.
///
/// Posture rails: arming detection (notify/learning) saves the current
/// default-outbound posture and sets Block; returning to normal restores the
/// saved posture. Mode + saved posture persist in consent_state.json so a
/// service restart re-arms (or stays disarmed) faithfully — the WFC-conflict
/// lesson is that firewall posture must never change without an explicit,
/// reversible opt-in.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class ConsentBroker : IDisposable
{
    public const string ModeNormal = "normal";
    public const string ModeNotify = "notify";
    public const string ModeLearning = "learning";

    public static readonly TimeSpan DedupWindow = TimeSpan.FromSeconds(5);
    public static readonly TimeSpan PendingTtl = TimeSpan.FromSeconds(60);
    public static readonly TimeSpan OnceRuleLifetime = TimeSpan.FromMinutes(15);

    private const string OncePrefix = "HG_Once_";
    private const string ConsentPrefix = "HG_Consent_";
    private const string LearnPrefix = "HG_Learn_";
    private const string BasePrefix = "HG_Base_";

    private readonly IFirewallEngine? _firewall;
    private readonly FirewallIdentity? _identity;
    private readonly HostsDatabase _db;
    private readonly EventBus _bus;
    private readonly string _statePath;
    private readonly object _gate = new();
    private readonly Dictionary<string, DateTime> _recent = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, (ConnectionDecisionRequest Request, DateTime ExpiresUtc)> _pending = new(StringComparer.Ordinal);
    private readonly List<(string RuleName, DateTime ExpiresUtc)> _onceRules = new();
    private readonly System.Threading.Timer _sweepTimer;

    private PersistedState _state;

    /// <summary>
    /// Production hook that enables audit policy + starts the Security-log
    /// watch; returns whether detection is live. Null (tests, unwired hosts)
    /// means posture rails still run but no OS-level arming is attempted.
    /// </summary>
    public Func<bool>? ArmDetection { get; set; }

    /// <summary>Production hook that stops the Security-log watch.</summary>
    public Action? DisarmDetection { get; set; }

    /// <summary>GeoIP country lookup for a remote IP (NET-066 prompt enrichment).</summary>
    public Func<string, string>? LookupCountry { get; set; }

    /// <summary>Threat-intel membership test for a remote IP (NET-066 prompt enrichment).</summary>
    public Func<string, bool>? LookupThreat { get; set; }

    public ConsentBroker(HostsDatabase db, EventBus bus, IFirewallEngine? firewall, FirewallIdentity? identity, string dataDir)
    {
        _db = db ?? throw new ArgumentNullException(nameof(db));
        _bus = bus ?? throw new ArgumentNullException(nameof(bus));
        _firewall = firewall;
        _identity = identity;
        _statePath = Path.Combine(dataDir ?? throw new ArgumentNullException(nameof(dataDir)), "consent_state.json");
        _state = LoadState();
        ReapExpiredOnceRules(DateTime.UtcNow, startup: true);
        _sweepTimer = new System.Threading.Timer(_ => Sweep(DateTime.UtcNow), null,
            TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(30));
    }

    public string Mode
    {
        get
        {
            lock (_gate)
            {
                return _state.Mode;
            }
        }
    }

    public bool DetectionArmed { get; private set; }

    /// <summary>Re-arm on service start when the persisted mode wants detection (WFCP-000c).</summary>
    public void ResumeFromPersistedMode()
    {
        if (Mode is ModeNotify or ModeLearning)
        {
            DetectionArmed = ArmDetection?.Invoke() ?? false;
            _db.LogEvent("consent", "mode_resumed", details: $"{Mode}; detection {(DetectionArmed ? "armed" : "unavailable")}");
        }
    }

    /// <summary>Switch filtering mode with the posture rails applied.</summary>
    public Ack SetMode(string requested)
    {
        var mode = (requested ?? string.Empty).Trim().ToLowerInvariant();
        if (mode is not (ModeNormal or ModeNotify or ModeLearning))
        {
            return new Ack { Ok = false, Message = $"unknown mode '{requested}'", ErrorCode = "hostsguard.error.v1/invalid_mode" };
        }

        lock (_gate)
        {
            if (_state.Mode == mode)
            {
                return new Ack { Ok = true, Message = $"already in {mode} mode" };
            }

            var wasDetecting = _state.Mode is ModeNotify or ModeLearning;
            var wantsDetection = mode is ModeNotify or ModeLearning;

            if (wantsDetection && !wasDetecting)
            {
                // Save the user's posture before we own it; restore on the way out.
                if (_firewall is { } fw)
                {
                    _state.PriorOutboundBlock = fw.GetPosture().ToDictionary(p => p.Name, p => p.OutboundBlock);
                    fw.SetDefaultOutboundBlock(true);
                }

                DetectionArmed = ArmDetection?.Invoke() ?? false;
            }
            else if (!wantsDetection && wasDetecting)
            {
                RestorePosture();
                DisarmDetection?.Invoke();
                DetectionArmed = false;
                _pending.Clear();
            }

            _state.Mode = mode;
            SaveState();
        }

        _db.LogEvent("consent", "mode_changed", details: mode);
        return new Ack
        {
            Ok = true,
            Message = mode switch
            {
                ModeNotify => "notify mode — unruled connections prompt for a decision (default outbound: Block)",
                ModeLearning => "learning mode — unruled connections are auto-allowed and recorded (default outbound: Block)",
                _ => "normal mode — rules enforce silently (default outbound restored)",
            },
        };
    }

    private void RestorePosture()
    {
        if (_firewall is not { } fw || _state.PriorOutboundBlock is not { Count: > 0 } prior)
        {
            return;
        }

        // Restore each profile to exactly what it was before we armed — a mixed
        // prior posture (e.g. Public=Block, others Allow) round-trips faithfully
        // instead of collapsing to a single all-profiles value.
        fw.SetDefaultOutboundBlock(prior);
        _state.PriorOutboundBlock = null;
    }

    /// <summary>
    /// Restore the pre-arm default-outbound posture on service stop/uninstall so
    /// the machine is never left in default-block with the only way back sitting
    /// in a state file a stopped service will never read. Safe to call always;
    /// no-op when disarmed. Keeps the persisted mode so a restart re-arms.
    /// </summary>
    public void RestorePostureOnShutdown()
    {
        lock (_gate)
        {
            if (_state.Mode is ModeNotify or ModeLearning && _state.PriorOutboundBlock is { Count: > 0 })
            {
                RestorePosture();
                SaveState();
                _db.LogEvent("consent", "posture_restored_on_stop",
                    details: "default outbound restored for service shutdown; mode persists for restart");
            }
        }
    }

    /// <summary>Entry point for blocked-connection events (watch or tests).</summary>
    public void OnBlocked(BlockedConnection blocked)
    {
        ArgumentNullException.ThrowIfNull(blocked);
        if (blocked.Application.Length == 0)
        {
            return;
        }

        string mode;
        lock (_gate)
        {
            mode = _state.Mode;
            if (mode == ModeNormal)
            {
                return;
            }

            // Dedup identical app+direction+remote+proto bursts (WFCP-010).
            var key = $"{blocked.Application}|{blocked.Direction}|{blocked.RemoteAddress}|{blocked.Protocol}";
            if (_recent.TryGetValue(key, out var last) && blocked.TsUtc - last < DedupWindow)
            {
                return;
            }

            _recent[key] = blocked.TsUtc;
            if (_recent.Count > 4096)
            {
                foreach (var stale in _recent.Where(kv => blocked.TsUtc - kv.Value > DedupWindow).Select(kv => kv.Key).ToList())
                {
                    _recent.Remove(stale);
                }
            }
        }

        // Apps that already have an HG rule covering this direction were
        // decided already — never re-prompt (WFCP-010 trust check).
        if (HasCoveringRule(blocked.Application, blocked.Direction))
        {
            return;
        }

        // Essential OS binaries (Windows Update, Defender, kernel) are auto-
        // allowed silently so Notify mode targets interesting traffic (NET-068).
        if (KnownSafeBaseline.IsBaseline(blocked.Application))
        {
            AutoAllowBaseline(blocked.Application, blocked.Direction);
            return;
        }

        if (mode == ModeLearning)
        {
            AutoAllow(blocked);
            return;
        }

        var request = new ConnectionDecisionRequest
        {
            Id = Guid.NewGuid().ToString("N"),
            Application = blocked.Application,
            Direction = blocked.Direction,
            RemoteAddress = blocked.RemoteAddress,
            RemotePort = blocked.RemotePort,
            Protocol = blocked.Protocol,
            ProcessId = blocked.ProcessId,
            Ts = Timestamp.FromDateTime(DateTime.SpecifyKind(blocked.TsUtc, DateTimeKind.Utc)),
            // Best-effort decision-quality enrichment (NET-066).
            Country = SafeInvoke(() => LookupCountry?.Invoke(blocked.RemoteAddress)) ?? string.Empty,
            Threat = SafeInvoke(() => LookupThreat?.Invoke(blocked.RemoteAddress)) ?? false,
            Signer = SafeSigner(blocked.Application),
        };
        lock (_gate)
        {
            _pending[request.Id] = (request, blocked.TsUtc + PendingTtl);
        }

        _bus.Publish(request);
    }

    private static T? SafeInvoke<T>(Func<T?> f)
    {
        try
        {
            return f();
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException or FormatException)
        {
            return default;
        }
    }

    /// <summary>Best-effort Authenticode signer subject for the prompt; blank on failure.</summary>
    private static string SafeSigner(string application)
    {
        try
        {
            if (application.Length == 0 || !File.Exists(application))
            {
                return string.Empty;
            }

            return Windows.FirewallIdentity.Compute(application).Signer ?? string.Empty;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.Cryptography.CryptographicException or ArgumentException)
        {
            return string.Empty;
        }
    }

    private bool HasCoveringRule(string application, string direction)
    {
        if (_firewall is not { } fw)
        {
            return false;
        }

        foreach (var r in fw.ListRules())
        {
            if (r.Source != "hostsguard" || !r.Enabled || r.Direction != direction || r.Program.Length == 0)
            {
                continue;
            }

            if (!r.Program.Split(',')[0].Trim().Equals(application, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            // Identity guard (NET-069): when the binary's identity was recorded at
            // rule-creation time, the file on disk must still match it (same hash
            // or signer). A renamed impostor dropped at a whitelisted path fails
            // the check, so it is NOT covered and gets re-prompted.
            if (_identity is { } id && id.Get(r.Name).Count > 0 && !id.MatchesRemembered(r.Name, application))
            {
                continue;
            }

            return true;
        }

        return false;
    }

    private void AutoAllow(BlockedConnection blocked)
    {
        var name = $"{LearnPrefix}{Path.GetFileNameWithoutExtension(blocked.Application)}_{blocked.Direction}";
        if (_firewall is { } fw &&
            fw.CreateRule(new FwRule(name, blocked.Direction, "Allow", true, "Any", "Any", blocked.Application, "hostsguard")))
        {
            _db.UpsertFwState(name, blocked.Direction, "Allow", "Any", "Any", blocked.Application);
            _identity?.Remember(name, blocked.Application);
        }

        LogDecision(blocked.Application, blocked.Direction, blocked.RemoteAddress, blocked.Protocol, "learn", permanent: true);
    }

    /// <summary>Silently allow a known-safe OS binary (NET-068 baseline).</summary>
    private void AutoAllowBaseline(string application, string direction)
    {
        if (_firewall is not { } fw)
        {
            return;
        }

        var name = $"{BasePrefix}{Path.GetFileNameWithoutExtension(application)}_{direction}";
        if (fw.RuleExists(name))
        {
            return;
        }

        if (fw.CreateRule(new FwRule(name, direction, "Allow", true, "Any", "Any", application, "hostsguard")))
        {
            _db.UpsertFwState(name, direction, "Allow", "Any", "Any", application);
            _db.LogEvent(application, "consent_baseline", details: $"{direction}|Any|Any|permanent", reason: "consent");
        }
    }

    /// <summary>
    /// Proactively write allow rules for every baseline binary present on this
    /// machine (NET-068 "apply baseline now"). Returns the count created.
    /// </summary>
    public int ApplyBaseline()
    {
        if (_firewall is not { } fw)
        {
            return 0;
        }

        var system32 = Environment.GetFolderPath(Environment.SpecialFolder.System);
        var created = 0;
        foreach (var entry in KnownSafeBaseline.Entries)
        {
            var path = Path.Combine(system32, entry.FileName);
            if (!File.Exists(path))
            {
                continue; // "System" and absent binaries are handled reactively
            }

            var name = $"{BasePrefix}{Path.GetFileNameWithoutExtension(entry.FileName)}_Out";
            if (fw.RuleExists(name) ||
                !fw.CreateRule(new FwRule(name, "Out", "Allow", true, "Any", "Any", path, "hostsguard")))
            {
                continue;
            }

            _db.UpsertFwState(name, "Out", "Allow", "Any", "Any", path);
            created++;
        }

        if (created != 0)
        {
            _db.LogEvent("consent", "baseline_applied", details: $"{created} known-safe rules", reason: "consent");
        }

        return created;
    }

    /// <summary>Apply a decision from the UI (WFCP-012): rule write + identity + history.</summary>
    public Ack Decide(ConnectionDecision decision)
    {
        ArgumentNullException.ThrowIfNull(decision);
        var verdict = (decision.Verdict ?? string.Empty).ToLowerInvariant();
        if (verdict is not ("allow" or "block"))
        {
            return new Ack { Ok = false, Message = $"unknown verdict '{decision.Verdict}'", ErrorCode = "hostsguard.error.v1/invalid_verdict" };
        }

        var application = (decision.Application ?? string.Empty).Trim();
        if (application.Length == 0)
        {
            return new Ack { Ok = false, Message = "application path is required", ErrorCode = "hostsguard.error.v1/invalid_program" };
        }

        if (decision.Id.Length != 0)
        {
            lock (_gate)
            {
                _pending.Remove(decision.Id);
            }
        }

        if (_firewall is not { } fw)
        {
            return new Ack { Ok = false, Message = "firewall engine is not attached to this service instance", ErrorCode = "hostsguard.error.v1/firewall_unavailable" };
        }

        var direction = decision.Direction == "In" ? "In" : "Out";
        var action = verdict == "allow" ? "Allow" : "Block";
        var stem = Path.GetFileNameWithoutExtension(application);

        // Scope (NET-067): whole-app by default; optionally narrow to the remote
        // IP, protocol, and/or port. Port scoping implies a TCP/UDP protocol.
        var remote = "Any";
        if (decision.ScopeRemote && decision.RemoteAddress.Length != 0)
        {
            if (!FirewallAddress.IsValid(decision.RemoteAddress))
            {
                return new Ack { Ok = false, Message = $"'{decision.RemoteAddress}' is not a valid IP/CIDR/range", ErrorCode = "hostsguard.error.v1/invalid_address" };
            }

            remote = decision.RemoteAddress;
        }

        var protoIsPortable = decision.Protocol is "TCP" or "UDP";
        var protocol = (decision.ScopeProtocol || decision.ScopePort) && protoIsPortable ? decision.Protocol : "Any";
        var ports = decision.ScopePort && decision.RemotePort > 0 && protocol is "TCP" or "UDP"
            ? decision.RemotePort.ToString(System.Globalization.CultureInfo.InvariantCulture)
            : "Any";

        // Duration (NET-067): "always" → permanent COM rule; "once"/"1h"/"session"
        // → ephemeral HG_Once_ rule. Blank falls back to the legacy permanent flag.
        var (permanent, expiresUtc, label) = ResolveDuration(decision.Duration, decision.Permanent);

        var name = permanent
            ? $"{ConsentPrefix}{action}_{stem}_{direction}"
            : $"{OncePrefix}{action}_{stem}_{direction}_{Guid.NewGuid().ToString("N")[..8]}";

        var created = fw.CreateRule(new FwRule(name, direction, action, true, remote, protocol, application, "hostsguard", RemotePorts: ports));
        if (created)
        {
            _db.UpsertFwState(name, direction, action, remote, protocol, application);
            _identity?.Remember(name, application);
            if (!permanent)
            {
                lock (_gate)
                {
                    _onceRules.Add((name, expiresUtc));
                    SaveState();
                }
            }
        }

        LogDecision(application, direction, remote == "Any" ? decision.RemoteAddress : remote, decision.Protocol, verdict, permanent);
        return new Ack
        {
            Ok = true,
            Message = created ? $"{verdict} {stem} ({label}) — {name}" : $"{name} already exists",
        };
    }

    /// <summary>Map a duration token to (permanent, ephemeral-expiry, human label).</summary>
    private (bool Permanent, DateTime ExpiresUtc, string Label) ResolveDuration(string? duration, bool legacyPermanent)
    {
        var d = (duration ?? string.Empty).Trim().ToLowerInvariant();
        if (d.Length == 0)
        {
            d = legacyPermanent ? "always" : "once";
        }

        var now = DateTime.UtcNow;
        return d switch
        {
            "always" => (true, DateTime.MaxValue, "permanent"),
            "1h" => (false, now + TimeSpan.FromHours(1), "1 hour"),
            // "session" survives until the service restarts (startup reap clears
            // all HG_Once_), so it's never timer-reaped.
            "session" => (false, DateTime.MaxValue, "this session"),
            _ => (false, now + OnceRuleLifetime, $"once, reaped in {OnceRuleLifetime.TotalMinutes:0} min"),
        };
    }

    /// <summary>Expire pending prompts (safe action: stays blocked) and reap once-rules.</summary>
    public void Sweep(DateTime nowUtc)
    {
        List<ConnectionDecisionRequest> expired;
        lock (_gate)
        {
            expired = _pending.Values.Where(p => p.ExpiresUtc <= nowUtc).Select(p => p.Request).ToList();
            foreach (var request in expired)
            {
                _pending.Remove(request.Id);
            }
        }

        foreach (var request in expired)
        {
            // Default-block already holds the connection; a timeout writes no
            // rule — it just records that nobody answered.
            LogDecision(request.Application, request.Direction, request.RemoteAddress, request.Protocol, "timeout", permanent: false);
        }

        ReapExpiredOnceRules(nowUtc, startup: false);
    }

    private void ReapExpiredOnceRules(DateTime nowUtc, bool startup)
    {
        if (_firewall is not { } fw)
        {
            return;
        }

        if (startup)
        {
            // Once-rules never outlive their window across restarts: anything
            // persisted (or orphaned live with the prefix) from a prior run is
            // overdue by definition.
            foreach (var rule in fw.ListRules().Where(r => r.Name.StartsWith(OncePrefix, StringComparison.Ordinal)))
            {
                fw.DeleteRule(rule.Name);
                _db.RemoveFwState(rule.Name);
            }

            lock (_gate)
            {
                _onceRules.Clear();
                SaveState();
            }

            return;
        }

        List<string> due;
        lock (_gate)
        {
            due = _onceRules.Where(r => r.ExpiresUtc <= nowUtc).Select(r => r.RuleName).ToList();
            _onceRules.RemoveAll(r => r.ExpiresUtc <= nowUtc);
            if (due.Count != 0)
            {
                SaveState();
            }
        }

        foreach (var name in due)
        {
            fw.DeleteRule(name);
            _db.RemoveFwState(name);
            _db.LogEvent(name, "consent_once_reaped", reason: "consent");
        }
    }

    /// <summary>Pending count for tests/diagnostics.</summary>
    public int PendingCount
    {
        get
        {
            lock (_gate)
            {
                return _pending.Count;
            }
        }
    }

    private void LogDecision(string application, string direction, string remote, string protocol, string verdict, bool permanent)
        => _db.LogEvent(
            application,
            $"consent_{verdict}",
            details: $"{direction}|{remote}|{protocol}|{(permanent ? "permanent" : "once")}",
            reason: "consent");

    /// <summary>Read persisted consent decisions back out of the event log.</summary>
    public DecisionHistory History(int limit)
    {
        var history = new DecisionHistory();
        foreach (var row in _db.GetLog(limit is > 0 and <= 2000 ? limit * 4 : 800))
        {
            if (!row.Action.StartsWith("consent_", StringComparison.Ordinal) || row.Action == "consent_once_reaped")
            {
                continue;
            }

            var parts = (row.Details ?? string.Empty).Split('|');
            history.Entries.Add(new DecisionEntry
            {
                DecidedAt = row.Ts,
                Application = row.Domain,
                Direction = parts.Length > 0 ? parts[0] : string.Empty,
                RemoteAddress = parts.Length > 1 ? parts[1] : string.Empty,
                Protocol = parts.Length > 2 ? parts[2] : string.Empty,
                Verdict = row.Action["consent_".Length..],
                Permanent = parts.Length > 3 && parts[3] == "permanent",
            });
            if (history.Entries.Count >= (limit is > 0 and <= 2000 ? limit : 200))
            {
                break;
            }
        }

        return history;
    }

    // ─── Persistence ──────────────────────────────────────────────────────────

    private sealed class PersistedState
    {
        public string Mode { get; set; } = ModeNormal;

        public Dictionary<string, bool>? PriorOutboundBlock { get; set; }

        public List<OnceRule> OnceRules { get; set; } = new();
    }

    private sealed class OnceRule
    {
        public string Name { get; set; } = string.Empty;

        public DateTime ExpiresUtc { get; set; }
    }

    private PersistedState LoadState()
    {
        try
        {
            if (File.Exists(_statePath))
            {
                var loaded = JsonSerializer.Deserialize<PersistedState>(File.ReadAllText(_statePath));
                if (loaded is not null)
                {
                    _onceRules.AddRange(loaded.OnceRules.Select(r => (r.Name, r.ExpiresUtc)));
                    return loaded;
                }
            }
        }
        catch (Exception ex) when (ex is IOException or JsonException)
        {
            // Corrupt state — fall back to normal mode rather than fail startup.
        }

        return new PersistedState();
    }

    private void SaveState()
    {
        _state.OnceRules = _onceRules.Select(r => new OnceRule { Name = r.RuleName, ExpiresUtc = r.ExpiresUtc }).ToList();
        var tmp = _statePath + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(_state));
        File.Move(tmp, _statePath, overwrite: true);
    }

    public void Dispose() => _sweepTimer.Dispose();
}
