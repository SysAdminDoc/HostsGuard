using System.Runtime.Versioning;
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
/// Decisions come back as HG_ COM rules â€” permanent, or once-rules reaped
/// after a timeout â€” with <see cref="FirewallIdentity.Remember"/> on every
/// write so rebind history exists before the next app update.
///
/// Posture rails: arming detection (notify/learning) saves the current
/// default-outbound posture and sets Block; returning to normal restores the
/// saved posture. Mode + saved posture persist in consent_state.json so a
/// service restart re-arms (or stays disarmed) faithfully â€” the WFC-conflict
/// lesson is that firewall posture must never change without an explicit,
/// reversible opt-in.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed partial class ConsentBroker : IDisposable
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
    private const string FolderPrefix = "HG_Folder_";
    private const string CommandLinePrefix = "HG_Cmd_";
    private const string CommandLineOncePrefix = "HG_Once_Cmd_";

    private readonly IFirewallEngine? _firewall;
    private readonly FirewallIdentity? _identity;
    private readonly HostsDatabase _db;
    private readonly EventBus _bus;
    private readonly IClock _clock;
    private readonly string _statePath;
    private readonly object _gate = new();
    private readonly object _sweepGate = new();
    private readonly Dictionary<string, DateTime> _recent = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, (ConnectionDecisionRequest Request, DateTime ExpiresUtc)> _pending = new(StringComparer.Ordinal);
    private readonly List<(string RuleName, DateTime ExpiresUtc)> _onceRules = new();
    private readonly System.Threading.Timer _sweepTimer;
    private bool _disposed;

    // Covering-rule cache: the COM rule enumeration is expensive, and Notify/
    // Learning mode runs HasCoveringRule on EVERY blocked event. A short TTL
    // collapses event bursts; the broker's own rule writes invalidate eagerly.
    internal static readonly TimeSpan RuleCacheTtl = TimeSpan.FromSeconds(5);
    private readonly object _ruleCacheGate = new();
    private IReadOnlyList<FwRule>? _cachedRules;
    private DateTime _rulesCachedAtUtc = DateTime.MinValue;

    private PersistedState _state;

    /// <summary>
    /// Production hook that enables audit policy + starts the Security-log
    /// watch; returns whether detection is live. Null (tests, unwired hosts)
    /// means posture rails still run but no OS-level arming is attempted.
    /// </summary>
    public Func<bool>? ArmDetection { get; set; }

    /// <summary>
    /// Production hook invoked when consent leaves a detecting mode. A shared
    /// Security-log subscriber may remain active for independent detectors.
    /// </summary>
    public Action? DisarmDetection { get; set; }

    /// <summary>GeoIP country lookup for a remote IP (NET-066 prompt enrichment).</summary>
    public Func<string, string>? LookupCountry { get; set; }

    /// <summary>Threat-intel membership test for a remote IP (NET-066 prompt enrichment).</summary>
    public Func<string, bool>? LookupThreat { get; set; }

    public FlowTeardownCoordinator? FlowTeardown { get; set; }

    /// <summary>
    /// Authenticode signer-subject lookup for an application (NET-113); overrides
    /// the default file-based probe (injectable for tests). Returns null/"" when
    /// unsigned or unknown.
    /// </summary>
    public Func<string, string?>? LookupSigner { get; set; }

    /// <summary>
    /// PIDâ†’sole-owning-service resolution (NET-073): (SCM key, display name),
    /// or null when the process hosts no service or several.
    /// </summary>
    public Func<int, (string Key, string Display)?>? LookupSoleService { get; set; }

    /// <summary>
    /// PIDâ†’(parent PID, parent image path) resolution (NET-093 child auto-allow),
    /// or null when the parent is dead/unreadable. Wired by the host.
    /// </summary>
    public Func<int, (int ParentPid, string ParentPath)?>? LookupParent { get; set; }

    /// <summary>PID→command-line reader for interpreter-aware prompts (NET-156).</summary>
    public Func<int, string?>? LookupCommandLine { get; set; }

    public ConsentBroker(
        HostsDatabase db,
        EventBus bus,
        IFirewallEngine? firewall,
        FirewallIdentity? identity,
        string dataDir,
        IClock? clock = null)
    {
        _db = db ?? throw new ArgumentNullException(nameof(db));
        _bus = bus ?? throw new ArgumentNullException(nameof(bus));
        _clock = clock ?? SystemClock.Instance;
        _firewall = firewall;
        _identity = identity;
        _statePath = Path.Combine(dataDir ?? throw new ArgumentNullException(nameof(dataDir)), "consent_state.json");
        _state = LoadState();
        ReapExpiredOnceRules(_clock.UtcNow, startup: true);
        _sweepTimer = new System.Threading.Timer(_ => Sweep(), null,
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
    /// instead of prompting. Off by default â€” deny-by-default is preserved.
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

    /// <summary>Whether unruled inbound connections prompt (NET-104).</summary>
    public bool InboundConsent
    {
        get
        {
            lock (_gate)
            {
                return _state.InboundConsent;
            }
        }
    }

    /// <summary>Toggle inbound-connection consent prompting (NET-104).</summary>
    public Ack SetInboundConsent(bool enabled)
    {
        lock (_gate)
        {
            _state.InboundConsent = enabled;
            SaveState();
        }

        _db.LogEvent("consent", "inbound_consent", details: enabled ? "on" : "off", reason: "consent");
        return new Ack
        {
            Ok = true,
            Message = enabled
                ? "inbound consent ON â€” unruled inbound connections prompt in Notify mode"
                : "inbound consent OFF â€” inbound connections are not prompted",
        };
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
                ? "child-process auto-allow ON â€” direct children of an allowed app inherit its allow for 1 hour"
                : "child-process auto-allow OFF â€” every unruled child prompts",
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

                var remaining = (int)Math.Ceiling((until - _clock.UtcNow).TotalMinutes);
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
                        ? _clock.UtcNow + TimeSpan.FromMinutes(Math.Clamp(learnMinutes, 1, 1440))
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
                ? _clock.UtcNow + TimeSpan.FromMinutes(Math.Clamp(learnMinutes, 1, 1440))
                : null;
            SaveState();
        }

        _db.LogEvent("consent", "mode_changed", details: mode + (mode == ModeLearning && learnMinutes > 0 ? $" ({learnMinutes}m)" : string.Empty));
        return new Ack
        {
            Ok = true,
            Message = mode switch
            {
                ModeNotify => "notify mode â€” unruled connections prompt for a decision (default outbound: Block)",
                ModeLearning => "learning mode â€” unruled connections are auto-allowed and recorded (default outbound: Block)",
                _ => "normal mode â€” rules enforce silently (default outbound restored)",
            },
        };
    }

    private void RestorePosture()
    {
        if (_firewall is not { } fw || _state.PriorOutboundBlock is not { Count: > 0 } prior)
        {
            return;
        }

        // Restore each profile to exactly what it was before we armed â€” a mixed
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
        bool inboundConsent;
        lock (_gate)
        {
            mode = _state.Mode;
            childInherit = _state.ChildInherit;
            inboundConsent = _state.InboundConsent;
            if (mode == ModeNormal)
            {
                return;
            }

            // Inbound consent (NET-104) is opt-in â€” unsolicited inbound blocks are
            // noisy, so drop them unless the user enabled inbound prompting.
            if (blocked.Direction == "In" && !inboundConsent)
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

        AddExternalFilterAlert(blocked);

        // svchost attribution (NET-073): the responsible service, when exactly
        // one owns the PID. Resolved before the covering-rule check so a
        // service-scoped rule only covers its own service's connections.
        var service = SafeInvoke(() => LookupSoleService?.Invoke(blocked.ProcessId));
        var commandBinding = InterpreterCommandLine.TryCreate(
            blocked.Application,
            SafeInvoke(() => LookupCommandLine?.Invoke(blocked.ProcessId)) ?? string.Empty);
        if (commandBinding is not null && TryApplyCommandLineDecision(blocked, commandBinding))
        {
            return;
        }

        // Apps that already have an HG rule covering this direction were
        // decided already â€” never re-prompt (WFCP-010 trust check).
        if (HasCoveringRule(blocked.Application, blocked.Direction, service?.Key))
        {
            return;
        }

        // Essential OS binaries (Windows Update, Defender, kernel) are auto-
        // allowed silently so Notify mode targets interesting traffic (NET-068).
        if (KnownSafeBaseline.IsBaseline(blocked.Application))
        {
            AutoAllowBaseline(blocked);
            return;
        }

        // Trust-by-publisher (NET-113): a binary signed by a user-trusted publisher
        // is auto-allowed without a prompt, like a known-safe baseline binary.
        if (IsTrustedPublisher(blocked.Application))
        {
            AutoAllowPublisher(blocked);
            return;
        }

        // Trust-by-folder (NET-117): a binary under a user-trusted folder is
        // auto-allowed â€” the driver-free "trust this whole install directory".
        if (IsTrustedFolder(blocked.Application))
        {
            AutoAllowFolder(blocked);
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
            CommandLine = commandBinding?.Display ?? string.Empty,
            ScriptPath = commandBinding?.ScriptPath ?? string.Empty,
            ScriptBindingKey = commandBinding?.ScriptKey ?? string.Empty,
            FilterRuntimeId = blocked.FilterRuntimeId,
            FilterOrigin = blocked.FilterOrigin,
            LayerName = blocked.LayerName,
            LayerRuntimeId = blocked.LayerRuntimeId,
            InterfaceIndex = blocked.InterfaceIndex,
            InterfaceName = blocked.InterfaceName,
            FilterOwner = blocked.Provenance.OwnerLabel,
            ExternalFilter = blocked.Provenance.IsExternalRule,
        };
        lock (_gate)
        {
            _pending[request.Id] = (request, blocked.TsUtc + PendingTtl);
        }

        _bus.Publish(request);
    }

    private void AddExternalFilterAlert(BlockedConnection blocked)
    {
        var provenance = blocked.Provenance;
        if (!provenance.IsExternalRule)
        {
            return;
        }

        var iface = provenance.InterfaceLabel.Length != 0 ? $"; interface={provenance.InterfaceLabel}" : string.Empty;
        var runtime = provenance.FilterRuntimeId.Length != 0 ? $"; filterRTID={provenance.FilterRuntimeId}" : string.Empty;
        var layer = provenance.LayerName.Length != 0 ? $"; layer={provenance.LayerName}" : string.Empty;
        _db.AddAlert(
            "wfp_external_filter",
            "info",
            "Blocked by external firewall rule",
            provenance.FilterOrigin,
            $"{Path.GetFileName(blocked.Application)} {blocked.Direction} {blocked.Protocol} {blocked.RemoteAddress}:{blocked.RemotePort}{iface}{runtime}{layer}",
            action: "wfp_external_filter",
            process: blocked.Application,
            sourceEventId: blocked.EventId);
    }

    private static WfpAuditProvenance? ProvenanceFrom(ConnectionDecisionRequest? request)
    {
        if (request is null)
        {
            return null;
        }

        var provenance = new WfpAuditProvenance(
            request.FilterRuntimeId,
            request.FilterOrigin,
            request.LayerName,
            request.LayerRuntimeId,
            request.InterfaceIndex,
            request.InterfaceName);
        return provenance.HasAny ? provenance : null;
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

    /// <summary>Rule snapshot for covering-rule checks: TTL-cached, invalidated on our own writes.</summary>
    private IReadOnlyList<FwRule> CachedRules(IFirewallEngine fw)
    {
        lock (_ruleCacheGate)
        {
            if (_cachedRules is not null && _clock.UtcNow - _rulesCachedAtUtc < RuleCacheTtl)
            {
                return _cachedRules;
            }
        }

        var rules = fw.ListRules();
        lock (_ruleCacheGate)
        {
            _cachedRules = rules;
            _rulesCachedAtUtc = _clock.UtcNow;
        }

        return rules;
    }

    private void InvalidateRuleCache()
    {
        lock (_ruleCacheGate)
        {
            _cachedRules = null;
            _rulesCachedAtUtc = DateTime.MinValue;
        }
    }

    private bool CreateRuleTracked(IFirewallEngine fw, FwRule rule)
    {
        var created = fw.CreateRule(rule);
        InvalidateRuleCache();
        return created;
    }

    private bool DeleteRuleTracked(IFirewallEngine fw, string name)
    {
        var deleted = fw.DeleteRule(name);
        InvalidateRuleCache();
        return deleted;
    }

    private bool HasCoveringRule(string application, string direction, string? serviceKey = null, string? requireAction = null)
    {
        if (_firewall is not { } fw)
        {
            return false;
        }

        foreach (var r in CachedRules(fw))
        {
            if (r.Source != "hostsguard" || !r.Enabled || r.Direction != direction || r.Program.Length == 0)
            {
                continue;
            }

            if (r.Name.StartsWith(CommandLinePrefix, StringComparison.Ordinal)
                || r.Name.StartsWith(CommandLineOncePrefix, StringComparison.Ordinal))
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
            // service â€” svchost's other services still get their own prompt.
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
                _db.AddAlert(
                    "binary_identity",
                    "warning",
                    "Binary identity changed",
                    application,
                    $"Rule {r.Name} no longer matches the remembered signer or hash; the connection will prompt again.",
                    action: "identity_mismatch",
                    process: application);
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
            CreateRuleTracked(fw, new FwRule(name, blocked.Direction, "Allow", true, "Any", "Any", blocked.Application, "hostsguard")))
        {
            _db.UpsertFwState(name, blocked.Direction, "Allow", "Any", "Any", blocked.Application);
            _identity?.Remember(name, blocked.Application);
        }

        LogDecision(blocked.Application, blocked.Direction, blocked.RemoteAddress, blocked.Protocol, "learn", permanent: true,
            provenance: blocked.Provenance);
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
            return false; // no readable parent, or self-parent â€” nothing to inherit
        }

        if (!HasCoveringRule(p.ParentPath, blocked.Direction, requireAction: "Allow"))
        {
            return false; // parent isn't trusted (no allow verdict) â€” prompt as usual
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
        if (CreateRuleTracked(fw, new FwRule(name, blocked.Direction, "Allow", true, "Any", "Any", blocked.Application, "hostsguard")))
        {
            _db.UpsertFwState(name, blocked.Direction, "Allow", "Any", "Any", blocked.Application);
            _identity?.Remember(name, blocked.Application);
            lock (_gate)
            {
                _onceRules.Add((name, _clock.UtcNow + ChildRuleLifetime));
                SaveState();
            }
        }

        _db.LogEvent(blocked.Application, "consent_child_allow",
            details: $"{blocked.Direction}|inherited from {Path.GetFileName(parentPath)}|1h", reason: "consent",
            provenance: blocked.Provenance);
    }

    // â”€â”€â”€ Trust-by-publisher (NET-113) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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
            CreateRuleTracked(fw, new FwRule(name, blocked.Direction, "Allow", true, "Any", "Any", blocked.Application, "hostsguard")))
        {
            _db.UpsertFwState(name, blocked.Direction, "Allow", "Any", "Any", blocked.Application);
            _identity?.Remember(name, blocked.Application);
        }

        _db.LogEvent(blocked.Application, "consent_publisher_allow",
            details: $"{blocked.Direction}|trusted publisher", reason: "consent",
            provenance: blocked.Provenance);
    }

    // â”€â”€â”€ Trust-by-folder (NET-117) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /// <summary>Folders whose binaries auto-allow without a prompt.</summary>
    public IReadOnlyList<string> TrustedFolders
    {
        get
        {
            lock (_gate)
            {
                return _state.TrustedFolders.ToList();
            }
        }
    }

    /// <summary>Replace the trusted-folder set.</summary>
    public Ack SetTrustedFolders(IEnumerable<string> folders)
    {
        ArgumentNullException.ThrowIfNull(folders);
        var cleaned = folders.Select(f => (f ?? string.Empty).Trim().TrimEnd('\\', '/'))
            .Where(f => f.Length != 0)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        lock (_gate)
        {
            _state.TrustedFolders = cleaned;
            SaveState();
        }

        _db.LogEvent("consent", "trusted_folders", details: $"{cleaned.Count} folders", reason: "consent");
        return new Ack { Ok = true, Message = $"{cleaned.Count} trusted folder(s)" };
    }

    /// <summary>Add one folder to the trusted set (idempotent).</summary>
    public void AddTrustedFolder(string folder)
    {
        var f = (folder ?? string.Empty).Trim().TrimEnd('\\', '/');
        if (f.Length == 0)
        {
            return;
        }

        lock (_gate)
        {
            if (!_state.TrustedFolders.Contains(f, StringComparer.OrdinalIgnoreCase))
            {
                _state.TrustedFolders.Add(f);
                SaveState();
            }
        }
    }

    private bool IsTrustedFolder(string application)
    {
        List<string> trusted;
        lock (_gate)
        {
            if (_state.TrustedFolders.Count == 0)
            {
                return false;
            }

            trusted = _state.TrustedFolders.ToList();
        }

        return trusted.Any(f => Core.PathScope.IsUnder(application, f));
    }

    private void AutoAllowFolder(BlockedConnection blocked)
    {
        var name = $"{FolderPrefix}{Path.GetFileNameWithoutExtension(blocked.Application)}_{blocked.Direction}";
        if (_firewall is { } fw && !fw.RuleExists(name) &&
            CreateRuleTracked(fw, new FwRule(name, blocked.Direction, "Allow", true, "Any", "Any", blocked.Application, "hostsguard")))
        {
            _db.UpsertFwState(name, blocked.Direction, "Allow", "Any", "Any", blocked.Application);
            _identity?.Remember(name, blocked.Application);
        }

        _db.LogEvent(blocked.Application, "consent_folder_allow",
            details: $"{blocked.Direction}|trusted folder", reason: "consent",
            provenance: blocked.Provenance);
    }

    /// <summary>Silently allow a known-safe OS binary (NET-068 baseline).</summary>
    private void AutoAllowBaseline(BlockedConnection blocked)
    {
        if (_firewall is not { } fw)
        {
            return;
        }

        var application = blocked.Application;
        var direction = blocked.Direction;
        var name = $"{BasePrefix}{Path.GetFileNameWithoutExtension(application)}_{direction}";
        if (fw.RuleExists(name))
        {
            return;
        }

        if (CreateRuleTracked(fw, new FwRule(name, direction, "Allow", true, "Any", "Any", application, "hostsguard")))
        {
            _db.UpsertFwState(name, direction, "Allow", "Any", "Any", application);
            _db.LogEvent(application, "consent_baseline", details: $"{direction}|Any|Any|permanent", reason: "consent",
                provenance: blocked.Provenance);
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
                !CreateRuleTracked(fw, new FwRule(name, "Out", "Allow", true, "Any", "Any", path, "hostsguard")))
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

        // NET-117: "trust the folder" remembers the app's parent directory so any
        // binary under it (e.g. a portable app's versioned exes) auto-allows.
        if (decision.TrustFolder)
        {
            AddTrustedFolder(Core.PathScope.ParentFolder(application));
        }

        ConnectionDecisionRequest? pendingRequest = null;
        if (decision.Id.Length != 0)
        {
            lock (_gate)
            {
                if (_pending.TryGetValue(decision.Id, out var pending))
                {
                    pendingRequest = pending.Request;
                }

                _pending.Remove(decision.Id);
            }
        }
        var provenance = ProvenanceFrom(pendingRequest);

        if (_firewall is not { } fw)
        {
            return new Ack { Ok = false, Message = "firewall engine is not attached to this service instance", ErrorCode = "hostsguard.error.v1/firewall_unavailable" };
        }

        if (decision.ScopeCommandLine && decision.ScriptBindingKey.Length != 0)
        {
            return DecideCommandLine(fw, decision, application, verdict, provenance);
        }

        // Prompt-burst blanket decision (NET-099): a single whole-app rule per
        // direction present in the queue, clearing every pending prompt from this
        // app. Ignores per-connection scoping (the point is one broad decision).
        if (decision.ApplyToApp)
        {
            return DecideAll(fw, application, verdict == "allow" ? "Allow" : "Block", provenance);
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

        // Duration (NET-067): "always" â†’ permanent COM rule; "once"/"1h"/"session"
        // â†’ ephemeral HG_Once_ rule. Blank falls back to the legacy permanent flag.
        var (permanent, expiresUtc, label) = ResolveDuration(decision.Duration, decision.Permanent);

        var name = permanent
            ? $"{ConsentPrefix}{action}_{stem}_{direction}"
            : $"{OncePrefix}{action}_{stem}_{direction}_{Guid.NewGuid().ToString("N")[..8]}";

        var created = CreateRuleTracked(fw, new FwRule(name, direction, action, true, remote, protocol, application, "hostsguard",
            RemotePorts: ports, ServiceName: serviceKey));
        if (created)
        {
            _db.UpsertFwState(name, direction, action, remote, protocol, application, ports, serviceName: serviceKey);
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

        LogDecision(application, direction, remote == "Any" ? decision.RemoteAddress : remote, decision.Protocol, verdict, permanent,
            provenance);
        if (action == "Block")
        {
            FlowTeardown?.CloseForProgram(application, "consent_block", decision.RemoteAddress, decision.RemotePort);
        }

        return new Ack
        {
            Ok = true,
            Message = created ? $"{verdict} {stem} ({label}) â€” {name}" : $"{name} already exists",
        };
    }

    /// <summary>
    /// NET-099: apply one whole-app verdict to every pending prompt from
    /// <paramref name="application"/>. Writes a permanent HG_ rule per direction
    /// seen in the queue (plus the just-answered direction) and drops all matching
    /// pending requests so the burst is answered in one click.
    /// </summary>
    private Ack DecideAll(IFirewallEngine fw, string application, string action, WfpAuditProvenance? provenance = null)
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

            if (CreateRuleTracked(fw, new FwRule(name, direction, action, true, "Any", "Any", application, "hostsguard")))
            {
                _db.UpsertFwState(name, direction, action, "Any", "Any", application);
                _identity?.Remember(name, application);
                written++;
            }

            LogDecision(application, direction, "Any", "Any", action == "Allow" ? "allow" : "block", permanent: true,
                provenance);
        }

        if (action == "Block")
        {
            FlowTeardown?.CloseForProgram(application, "consent_block_all");
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

        var now = _clock.UtcNow;
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
        lock (_sweepGate)
        {
            if (_disposed)
            {
                return;
            }

            SweepCore(nowUtc);
        }
    }

    public void Sweep() => Sweep(_clock.UtcNow);

    private void SweepCore(DateTime nowUtc)
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
            _db.LogEvent("consent", "learning_autolock", details: "learning window expired â€” reverted to Normal; batch left for review");
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
            // rule â€” it just records that nobody answered.
            LogDecision(request.Application, request.Direction, request.RemoteAddress, request.Protocol, "timeout", permanent: false,
                ProvenanceFrom(request));
        }

        ReapExpiredOnceRules(nowUtc, startup: false);
        lock (_gate)
        {
            ReapExpiredCommandLineRulesNoLock(nowUtc);
        }

        _db.RunRetentionSweep(nowUtc.ToLocalTime());
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
                DeleteRuleTracked(fw, rule.Name);
                _db.RemoveFwState(rule.Name);
            }

            lock (_gate)
            {
                _onceRules.Clear();
                _state.CommandLineRules.RemoveAll(r => r.ExpiresUtc is not null);
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
            DeleteRuleTracked(fw, name);
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

    public void Dispose()
    {
        lock (_sweepGate)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            _sweepTimer.Dispose();
        }
    }
}
