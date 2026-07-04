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

    /// <summary>How long a child auto-allow rule lives before it's reaped (NET-093).</summary>
    public static readonly TimeSpan ChildRuleLifetime = TimeSpan.FromHours(1);

    private const string OncePrefix = "HG_Once_";
    private const string ConsentPrefix = "HG_Consent_";
    private const string LearnPrefix = "HG_Learn_";
    private const string BasePrefix = "HG_Base_";
    private const string ChildPrefix = "HG_Child_";
    private const string PublisherPrefix = "HG_Pub_";

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

    /// <summary>
    /// Authenticode signer-subject lookup for an application (NET-113); overrides
    /// the default file-based probe (injectable for tests). Returns null/"" when
    /// unsigned or unknown.
    /// </summary>
    public Func<string, string?>? LookupSigner { get; set; }

    /// <summary>
    /// PID→sole-owning-service resolution (NET-073): (SCM key, display name),
    /// or null when the process hosts no service or several.
    /// </summary>
    public Func<int, (string Key, string Display)?>? LookupSoleService { get; set; }

    /// <summary>
    /// PID→(parent PID, parent image path) resolution (NET-093 child auto-allow),
    /// or null when the parent is dead/unreadable. Wired by the host.
    /// </summary>
    public Func<int, (int ParentPid, string ParentPath)?>? LookupParent { get; set; }

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

    /// <summary>
    /// Child-process auto-allow (NET-093): when on, a blocked connection whose
    /// direct parent already has an HG allow rule is auto-allowed (bounded TTL)
    /// instead of prompting. Off by default — deny-by-default is preserved.
    /// </summary>
    public bool ChildInherit
    {
        get
        {
            lock (_gate)
            {
                return _state.ChildInherit;
            }
        }
    }

    /// <summary>Toggle child-process auto-allow (NET-093).</summary>
    public Ack SetChildInherit(bool enabled)
    {
        lock (_gate)
        {
            _state.ChildInherit = enabled;
            SaveState();
        }

        _db.LogEvent("consent", "child_inherit", details: enabled ? "on" : "off", reason: "consent");
        return new Ack
        {
            Ok = true,
            Message = enabled
                ? "child-process auto-allow ON — direct children of an allowed app inherit its allow for 1 hour"
                : "child-process auto-allow OFF — every unruled child prompts",
        };
    }

    /// <summary>Re-arm on service start when the persisted mode wants detection (WFCP-000c).</summary>
    public void ResumeFromPersistedMode()
    {
        if (Mode is ModeNotify or ModeLearning)
        {
            DetectionArmed = ArmDetection?.Invoke() ?? false;
            _db.LogEvent("consent", "mode_resumed", details: $"{Mode}; detection {(DetectionArmed ? "armed" : "unavailable")}");
        }
    }

    /// <summary>Minutes remaining in a time-boxed Learning window (NET-101); 0 = none/unbounded.</summary>
    public int LearnMinutesRemaining
    {
        get
        {
            lock (_gate)
            {
                if (_state.Mode != ModeLearning || _state.LearnUntilUtc is not { } until)
                {
                    return 0;
                }

                var remaining = (int)Math.Ceiling((until - DateTime.UtcNow).TotalMinutes);
                return remaining > 0 ? remaining : 0;
            }
        }
    }

    /// <summary>Switch filtering mode with the posture rails applied.</summary>
    public Ack SetMode(string requested) => SetMode(requested, 0);

    /// <summary>
    /// Switch filtering mode. When switching to Learning with
    /// <paramref name="learnMinutes"/> &gt; 0 (NET-101), the window auto-reverts to
    /// Normal on expiry (checked by <see cref="Sweep"/>) and the batch is left for
    /// review.
    /// </summary>
    public Ack SetMode(string requested, int learnMinutes)
    {
        var mode = (requested ?? string.Empty).Trim().ToLowerInvariant();
        if (mode is not (ModeNormal or ModeNotify or ModeLearning))
        {
            return new Ack { Ok = false, Message = $"unknown mode '{requested}'", ErrorCode = "hostsguard.error.v1/invalid_mode" };
        }

        lock (_gate)
        {
            // Setting a bounded window while already learning just re-arms the timer.
            if (_state.Mode == mode)
            {
                if (mode == ModeLearning)
                {
                    _state.LearnUntilUtc = learnMinutes > 0
                        ? DateTime.UtcNow + TimeSpan.FromMinutes(Math.Clamp(learnMinutes, 1, 1440))
                        : null;
                    SaveState();
                    return new Ack { Ok = true, Message = learnMinutes > 0 ? $"learning for {learnMinutes} more minutes" : "already in learning mode" };
                }

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
            _state.LearnUntilUtc = mode == ModeLearning && learnMinutes > 0
                ? DateTime.UtcNow + TimeSpan.FromMinutes(Math.Clamp(learnMinutes, 1, 1440))
                : null;
            SaveState();
        }

        _db.LogEvent("consent", "mode_changed", details: mode + (mode == ModeLearning && learnMinutes > 0 ? $" ({learnMinutes}m)" : string.Empty));
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
        bool childInherit;
        lock (_gate)
        {
            mode = _state.Mode;
            childInherit = _state.ChildInherit;
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

        // svchost attribution (NET-073): the responsible service, when exactly
        // one owns the PID. Resolved before the covering-rule check so a
        // service-scoped rule only covers its own service's connections.
        var service = SafeInvoke(() => LookupSoleService?.Invoke(blocked.ProcessId));

        // Apps that already have an HG rule covering this direction were
        // decided already — never re-prompt (WFCP-010 trust check).
        if (HasCoveringRule(blocked.Application, blocked.Direction, service?.Key))
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

        // Trust-by-publisher (NET-113): a binary signed by a user-trusted publisher
        // is auto-allowed without a prompt, like a known-safe baseline binary.
        if (IsTrustedPublisher(blocked.Application))
        {
            AutoAllowPublisher(blocked);
            return;
        }

        if (mode == ModeLearning)
        {
            AutoAllow(blocked);
            return;
        }

        // Child-process auto-allow (NET-093, opt-in): if the direct parent already
        // has an HG allow rule, inherit that verdict to this child for a bounded
        // TTL instead of prompting. Only one level deep; only allow verdicts.
        if (childInherit && TryInheritFromParent(blocked))
        {
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
            Service = service?.Display ?? string.Empty,
            ServiceKey = service?.Key ?? string.Empty,
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
    private string SafeSigner(string application)
    {
        if (LookupSigner is { } hook)
        {
            return SafeInvoke(() => hook(application)) ?? string.Empty;
        }

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

    private bool HasCoveringRule(string application, string direction, string? serviceKey = null, string? requireAction = null)
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

            if (requireAction is not null && !r.Action.Equals(requireAction, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (!r.Program.Split(',')[0].Trim().Equals(application, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            // A service-scoped rule (NET-073) only covers connections from that
            // service — svchost's other services still get their own prompt.
            if (r.ServiceName.Length != 0 &&
                !r.ServiceName.Equals(serviceKey ?? string.Empty, StringComparison.OrdinalIgnoreCase))
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

    /// <summary>
    /// NET-093: if the connection's direct parent has an HG allow rule for this
    /// direction, auto-allow the child with a TTL-bounded rule and return true.
    /// </summary>
    private bool TryInheritFromParent(BlockedConnection blocked)
    {
        var parent = SafeInvoke(() => LookupParent?.Invoke(blocked.ProcessId));
        if (parent is not { } p || p.ParentPath.Length == 0 ||
            p.ParentPath.Equals(blocked.Application, StringComparison.OrdinalIgnoreCase))
        {
            return false; // no readable parent, or self-parent — nothing to inherit
        }

        if (!HasCoveringRule(p.ParentPath, blocked.Direction, requireAction: "Allow"))
        {
            return false; // parent isn't trusted (no allow verdict) — prompt as usual
        }

        AutoAllowChild(blocked, p.ParentPath);
        return true;
    }

    /// <summary>Write a bounded-TTL child allow rule and record it for reaping (NET-093).</summary>
    private void AutoAllowChild(BlockedConnection blocked, string parentPath)
    {
        if (_firewall is not { } fw)
        {
            return;
        }

        var name = $"{ChildPrefix}{Path.GetFileNameWithoutExtension(blocked.Application)}_{blocked.Direction}_{Guid.NewGuid().ToString("N")[..8]}";
        if (fw.CreateRule(new FwRule(name, blocked.Direction, "Allow", true, "Any", "Any", blocked.Application, "hostsguard")))
        {
            _db.UpsertFwState(name, blocked.Direction, "Allow", "Any", "Any", blocked.Application);
            _identity?.Remember(name, blocked.Application);
            lock (_gate)
            {
                _onceRules.Add((name, DateTime.UtcNow + ChildRuleLifetime));
                SaveState();
            }
        }

        _db.LogEvent(blocked.Application, "consent_child_allow",
            details: $"{blocked.Direction}|inherited from {Path.GetFileName(parentPath)}|1h", reason: "consent");
    }

    // ─── Trust-by-publisher (NET-113) ────────────────────────────────────────

    /// <summary>Publisher CNs whose signed binaries auto-allow without a prompt.</summary>
    public IReadOnlyList<string> TrustedPublishers
    {
        get
        {
            lock (_gate)
            {
                return _state.TrustedPublishers.ToList();
            }
        }
    }

    /// <summary>Replace the trusted-publisher set.</summary>
    public Ack SetTrustedPublishers(IEnumerable<string> publishers)
    {
        ArgumentNullException.ThrowIfNull(publishers);
        var cleaned = publishers.Select(p => (p ?? string.Empty).Trim())
            .Where(p => p.Length != 0)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        lock (_gate)
        {
            _state.TrustedPublishers = cleaned;
            SaveState();
        }

        _db.LogEvent("consent", "trusted_publishers", details: $"{cleaned.Count} publishers", reason: "consent");
        return new Ack { Ok = true, Message = $"{cleaned.Count} trusted publisher(s)" };
    }

    /// <summary>Add one publisher CN to the trusted set (idempotent).</summary>
    public void AddTrustedPublisher(string publisher)
    {
        var p = (publisher ?? string.Empty).Trim();
        if (p.Length == 0)
        {
            return;
        }

        lock (_gate)
        {
            if (!_state.TrustedPublishers.Contains(p, StringComparer.OrdinalIgnoreCase))
            {
                _state.TrustedPublishers.Add(p);
                SaveState();
            }
        }
    }

    private bool IsTrustedPublisher(string application)
    {
        List<string> trusted;
        lock (_gate)
        {
            if (_state.TrustedPublishers.Count == 0)
            {
                return false;
            }

            trusted = _state.TrustedPublishers.ToList();
        }

        var publisher = Core.PublisherName.Of(SafeSigner(application));
        return publisher.Length != 0 && trusted.Any(t => string.Equals(t, publisher, StringComparison.OrdinalIgnoreCase));
    }

    private void AutoAllowPublisher(BlockedConnection blocked)
    {
        var name = $"{PublisherPrefix}{Path.GetFileNameWithoutExtension(blocked.Application)}_{blocked.Direction}";
        if (_firewall is { } fw && !fw.RuleExists(name) &&
            fw.CreateRule(new FwRule(name, blocked.Direction, "Allow", true, "Any", "Any", blocked.Application, "hostsguard")))
        {
            _db.UpsertFwState(name, blocked.Direction, "Allow", "Any", "Any", blocked.Application);
            _identity?.Remember(name, blocked.Application);
        }

        _db.LogEvent(blocked.Application, "consent_publisher_allow",
            details: $"{blocked.Direction}|trusted publisher", reason: "consent");
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

        // NET-113: "trust the publisher" remembers the app's signer CN so future
        // binaries signed by it auto-allow without prompting.
        if (decision.TrustPublisher)
        {
            AddTrustedPublisher(Core.PublisherName.Of(SafeSigner(application)));
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

        // Prompt-burst blanket decision (NET-099): a single whole-app rule per
        // direction present in the queue, clearing every pending prompt from this
        // app. Ignores per-connection scoping (the point is one broad decision).
        if (decision.ApplyToApp)
        {
            return DecideAll(fw, application, verdict == "allow" ? "Allow" : "Block");
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

        // Service scope (NET-073): narrow the rule to the one SCM service that
        // owns the connection, so blocking Dnscache doesn't block all of svchost.
        var serviceKey = decision.ScopeService && decision.ServiceKey.Length != 0
            ? decision.ServiceKey.Trim()
            : string.Empty;
        if (serviceKey.Length != 0)
        {
            stem = $"{stem}.{serviceKey}";
        }

        // Duration (NET-067): "always" → permanent COM rule; "once"/"1h"/"session"
        // → ephemeral HG_Once_ rule. Blank falls back to the legacy permanent flag.
        var (permanent, expiresUtc, label) = ResolveDuration(decision.Duration, decision.Permanent);

        var name = permanent
            ? $"{ConsentPrefix}{action}_{stem}_{direction}"
            : $"{OncePrefix}{action}_{stem}_{direction}_{Guid.NewGuid().ToString("N")[..8]}";

        var created = fw.CreateRule(new FwRule(name, direction, action, true, remote, protocol, application, "hostsguard",
            RemotePorts: ports, ServiceName: serviceKey));
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

    /// <summary>
    /// NET-099: apply one whole-app verdict to every pending prompt from
    /// <paramref name="application"/>. Writes a permanent HG_ rule per direction
    /// seen in the queue (plus the just-answered direction) and drops all matching
    /// pending requests so the burst is answered in one click.
    /// </summary>
    private Ack DecideAll(IFirewallEngine fw, string application, string action)
    {
        List<string> directions;
        lock (_gate)
        {
            directions = _pending.Values
                .Select(p => p.Request)
                .Where(r => r.Application.Equals(application, StringComparison.OrdinalIgnoreCase))
                .Select(r => r.Direction == "In" ? "In" : "Out")
                .Append("Out")
                .Distinct(StringComparer.Ordinal)
                .ToList();

            foreach (var id in _pending
                         .Where(kv => kv.Value.Request.Application.Equals(application, StringComparison.OrdinalIgnoreCase))
                         .Select(kv => kv.Key).ToList())
            {
                _pending.Remove(id);
            }
        }

        var stem = Path.GetFileNameWithoutExtension(application);
        var written = 0;
        foreach (var direction in directions)
        {
            var name = $"{ConsentPrefix}{action}_{stem}_{direction}";
            if (fw.RuleExists(name))
            {
                continue;
            }

            if (fw.CreateRule(new FwRule(name, direction, action, true, "Any", "Any", application, "hostsguard")))
            {
                _db.UpsertFwState(name, direction, action, "Any", "Any", application);
                _identity?.Remember(name, application);
                written++;
            }

            LogDecision(application, direction, "Any", "Any", action == "Allow" ? "allow" : "block", permanent: true);
        }

        return new Ack
        {
            Ok = true,
            Message = $"{(action == "Allow" ? "allowed" : "blocked")} all pending from {stem} ({written} rule{(written == 1 ? "" : "s")})",
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
        // NET-101: a time-boxed Learning window auto-reverts to Normal on expiry;
        // the auto-allowed batch stays for review (GetLearned).
        bool autoLock;
        lock (_gate)
        {
            autoLock = _state.Mode == ModeLearning && _state.LearnUntilUtc is { } until && nowUtc >= until;
        }

        if (autoLock)
        {
            _db.LogEvent("consent", "learning_autolock", details: "learning window expired — reverted to Normal; batch left for review");
            SetMode(ModeNormal);
        }

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
            // Once-rules and child auto-allows never outlive their window across
            // restarts: anything persisted (or orphaned live with the prefix)
            // from a prior run is overdue by definition.
            foreach (var rule in fw.ListRules().Where(r =>
                r.Name.StartsWith(OncePrefix, StringComparison.Ordinal) ||
                r.Name.StartsWith(ChildPrefix, StringComparison.Ordinal)))
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

    // ─── "Decide later" review of Learning-mode auto-decisions (NET-074) ─────

    /// <summary>The Learning-mode auto-allow rules awaiting review.</summary>
    public LearnedList ListLearned()
    {
        var list = new LearnedList();
        if (_firewall is not { } fw)
        {
            return list;
        }

        foreach (var r in fw.ListRules()
                     .Where(r => r.Name.StartsWith(LearnPrefix, StringComparison.Ordinal))
                     .OrderBy(r => r.Name, StringComparer.OrdinalIgnoreCase))
        {
            list.Entries.Add(new LearnedEntry
            {
                RuleName = r.Name,
                Application = r.Program,
                Direction = r.Direction,
                ServiceName = r.ServiceName,
            });
        }

        return list;
    }

    /// <summary>
    /// Apply review verdicts to learned rules: <c>promote</c> converts the
    /// auto-allow into a permanent consent allow, <c>block</c> reverses it into
    /// a permanent consent block, <c>discard</c> just removes it (the app
    /// prompts again next time). Unknown rules/actions are skipped and counted.
    /// </summary>
    public Ack ReviewLearned(LearnedReviewRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (_firewall is not { } fw)
        {
            return new Ack { Ok = false, Message = "firewall engine is not attached to this service instance", ErrorCode = "hostsguard.error.v1/firewall_unavailable" };
        }

        var byName = fw.ListRules()
            .Where(r => r.Name.StartsWith(LearnPrefix, StringComparison.Ordinal))
            .ToDictionary(r => r.Name, StringComparer.Ordinal);
        int promoted = 0, blocked = 0, discarded = 0, skipped = 0;
        foreach (var action in request.Actions)
        {
            if (!byName.TryGetValue(action.RuleName, out var learned))
            {
                skipped++;
                continue;
            }

            var verdict = (action.Action ?? string.Empty).Trim().ToLowerInvariant();
            if (verdict is not ("promote" or "block" or "discard"))
            {
                skipped++;
                continue;
            }

            fw.DeleteRule(learned.Name);
            _db.RemoveFwState(learned.Name);
            if (verdict == "discard")
            {
                discarded++;
                _db.LogEvent(learned.Program, "consent_discarded", details: $"{learned.Direction}|reviewed", reason: "consent");
                continue;
            }

            var ruleAction = verdict == "promote" ? "Allow" : "Block";
            var stem = Path.GetFileNameWithoutExtension(learned.Program);
            if (learned.ServiceName.Length != 0)
            {
                stem = $"{stem}.{learned.ServiceName}";
            }

            var name = $"{ConsentPrefix}{ruleAction}_{stem}_{learned.Direction}";
            if (!fw.RuleExists(name) &&
                fw.CreateRule(learned with { Name = name, Action = ruleAction }))
            {
                _db.UpsertFwState(name, learned.Direction, ruleAction, learned.RemoteAddr, learned.Protocol, learned.Program);
                _identity?.Remember(name, learned.Program);
            }

            _ = verdict == "promote" ? promoted++ : blocked++;
            LogDecision(learned.Program, learned.Direction, learned.RemoteAddr, learned.Protocol,
                verdict == "promote" ? "allow" : "block", permanent: true);
        }

        return new Ack
        {
            Ok = true,
            Message = $"reviewed: {promoted} promoted, {blocked} blocked, {discarded} discarded" +
                      (skipped > 0 ? $", {skipped} skipped" : string.Empty),
        };
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

        public bool ChildInherit { get; set; }

        /// <summary>Deadline for a time-boxed Learning window (NET-101); null = unbounded.</summary>
        public DateTime? LearnUntilUtc { get; set; }

        /// <summary>Publisher CNs whose signed binaries auto-allow without a prompt (NET-113).</summary>
        public List<string> TrustedPublishers { get; set; } = new();

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
