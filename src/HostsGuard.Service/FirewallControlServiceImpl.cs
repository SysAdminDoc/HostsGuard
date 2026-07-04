using System.IO;
using System.Runtime.Versioning;
using Grpc.Core;
using HostsGuard.Contracts;
using HostsGuard.Core;
using HostsGuard.Windows;

namespace HostsGuard.Service;

/// <summary>
/// Implements the FirewallControl gRPC service on the COM firewall engine.
/// Mutation is restricted to HG_-prefixed rules: the service never lets a
/// client delete or disable system firewall rules. Created rules are tracked
/// in fw_state so drift (deleted behind our back) is detectable, and program
/// rules remember their binary's identity for orphan rebinding.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class FirewallControlServiceImpl : FirewallControl.FirewallControlBase
{
    private readonly ServiceState _state;

    public FirewallControlServiceImpl(ServiceState state) => _state = state;

    public override Task<AdoptResult> AdoptFirewallRules(Empty request, ServerCallContext context)
    {
        if (_state.Firewall is not { } fw)
        {
            return Task.FromResult(new AdoptResult { Ok = false, Message = "firewall engine is not attached", ErrorCode = "hostsguard.error.v1/firewall_unavailable" });
        }

        // Only non-HG_ (system-authored) rules are candidates — HostsGuard's own
        // rules are already modelled. Nothing on the live firewall is mutated.
        var candidates = fw.ListRules()
            .Where(r => r.Source != "hostsguard" && r.Name.Length != 0)
            .ToList();
        var adopted = _state.Db.AdoptRules(candidates.Select(r =>
            (r.Name, r.Direction, r.Action, r.RemoteAddr, r.Protocol, r.Program, r.Enabled)));
        _state.Db.LogEvent("firewall", "rules_adopted", details: $"{adopted} of {candidates.Count} existing rules", reason: "manual");
        return Task.FromResult(new AdoptResult
        {
            Ok = true,
            Adopted = adopted,
            Total = candidates.Count,
            Message = $"adopted {adopted} of {candidates.Count} existing firewall rules (read-only; nothing was changed)",
        });
    }

    // ─── Subscribable rule groups (NET-103) ──────────────────────────────────

    public override Task<Ack> AssignRuleGroup(RuleGroupAssignment request, ServerCallContext context)
    {
        var name = (request.RuleName ?? string.Empty).Trim();
        if (name.Length == 0)
        {
            return Task.FromResult(Error("invalid_rule", "rule name is required"));
        }

        // Only HostsGuard's own rules can be grouped/toggled.
        if (!name.StartsWith(FwRuleMapper.HostsGuardPrefix, StringComparison.Ordinal))
        {
            return Task.FromResult(Error("not_ours", "only HG_-prefixed rules can be grouped"));
        }

        _state.Db.AssignRuleToGroup(name, request.Group ?? string.Empty);
        return Task.FromResult(Ok(string.IsNullOrWhiteSpace(request.Group)
            ? $"removed {name} from all groups"
            : $"added {name} to group '{request.Group.Trim()}'"));
    }

    public override Task<RuleGroupList> ListRuleGroups(Empty request, ServerCallContext context)
    {
        var list = new RuleGroupList();
        var enabled = _state.Firewall is { } fw
            ? fw.ListRules().Where(r => r.Enabled).Select(r => r.Name).ToHashSet(StringComparer.Ordinal)
            : new HashSet<string>(StringComparer.Ordinal);

        foreach (var byGroup in _state.Db.GetRuleGroups().GroupBy(g => g.Group, StringComparer.Ordinal))
        {
            var rules = byGroup.Select(g => g.RuleName).ToList();
            var info = new RuleGroupInfo
            {
                Name = byGroup.Key,
                EnabledCount = rules.Count(enabled.Contains),
                Total = rules.Count,
            };
            info.Rules.AddRange(rules);
            list.Groups.Add(info);
        }

        return Task.FromResult(list);
    }

    public override Task<Ack> ToggleRuleGroup(RuleGroupToggle request, ServerCallContext context)
    {
        if (_state.Firewall is not { } fw)
        {
            return Task.FromResult(Unavailable());
        }

        if (_state.GateWhenLocked() is { } gate)
        {
            return Task.FromResult(gate);
        }

        var group = (request.Group ?? string.Empty).Trim();
        if (group.Length == 0)
        {
            return Task.FromResult(Error("invalid_group", "group name is required"));
        }

        var rules = _state.Db.GetRulesInGroup(group);
        if (rules.Count == 0)
        {
            return Task.FromResult(Error("empty_group", $"group '{group}' has no rules"));
        }

        var changed = 0;
        foreach (var name in rules.Where(n => n.StartsWith(FwRuleMapper.HostsGuardPrefix, StringComparison.Ordinal)))
        {
            if (fw.SetRuleEnabled(name, request.Enabled))
            {
                changed++;
            }
        }

        _state.Db.LogEvent("firewall", request.Enabled ? "group_enabled" : "group_disabled",
            details: $"{group} ({changed}/{rules.Count})", reason: "manual");
        return Task.FromResult(Ok($"{(request.Enabled ? "enabled" : "disabled")} group '{group}' ({changed} of {rules.Count} rules)"));
    }

    public override Task<Ack> BlockIp(FirewallIpRequest request, ServerCallContext context)
    {
        if (_state.Firewall is not { } fw)
        {
            return Task.FromResult(Unavailable());
        }

        var addr = (request.Address ?? string.Empty).Trim();
        if (!FirewallAddress.IsValid(addr))
        {
            return Task.FromResult(Error("invalid_address", $"'{request.Address}' is not a valid IP/CIDR/range"));
        }

        var dir = MapDirection(request.Direction);
        var name = $"{FwRuleMapper.HostsGuardPrefix}Block_{addr}_{dir}";
        var rule = new FwRule(name, dir, "Block", Enabled: true, addr, "Any", string.Empty, "hostsguard");
        var created = fw.CreateRule(rule);
        if (created)
        {
            _state.Db.UpsertFwState(name, dir, "Block", addr, "Any", string.Empty);
            _state.Db.LogEvent(addr, "fw_blocked", details: name, reason: "manual");
        }

        return Task.FromResult(Ok(created ? $"created {name}" : $"{name} already exists"));
    }

    public override Task<Ack> BlockProgram(FirewallProgramRequest request, ServerCallContext context)
    {
        if (_state.Firewall is not { } fw)
        {
            return Task.FromResult(Unavailable());
        }

        var path = (request.ProgramPath ?? string.Empty).Trim();
        if (path.Length == 0 || path.IndexOfAny(Path.GetInvalidPathChars()) >= 0)
        {
            return Task.FromResult(Error("invalid_program", "program path is empty or invalid"));
        }

        var dir = MapDirection(request.Direction);
        var name = $"{FwRuleMapper.HostsGuardPrefix}BlockApp_{Path.GetFileNameWithoutExtension(path)}_{dir}";
        var rule = new FwRule(name, dir, "Block", Enabled: true, "Any", "Any", path, "hostsguard");
        var created = fw.CreateRule(rule);
        if (created)
        {
            _state.Db.UpsertFwState(name, dir, "Block", "Any", "Any", path);
            _state.Identity?.Remember(name, path);
            _state.Db.LogEvent(path, "fw_blocked", details: name, reason: "manual");
        }

        return Task.FromResult(Ok(created ? $"created {name}" : $"{name} already exists"));
    }

    public override Task<Ack> CreateRule(FirewallRule request, ServerCallContext context)
    {
        if (_state.Firewall is not { } fw)
        {
            return Task.FromResult(Unavailable());
        }

        var name = (request.Name ?? string.Empty).Trim();
        if (name.Length == 0)
        {
            return Task.FromResult(Error("invalid_rule", "rule name is required"));
        }

        if (_state.GateWhenLocked() is { } gate)
        {
            return Task.FromResult(gate);
        }

        if (!name.StartsWith(FwRuleMapper.HostsGuardPrefix, StringComparison.Ordinal))
        {
            name = FwRuleMapper.HostsGuardPrefix + name;
        }

        var remote = (request.RemoteAddr ?? string.Empty).Trim();
        if (remote is not ("" or "Any") && !remote.Split(',').All(a => FirewallAddress.IsValid(a)))
        {
            return Task.FromResult(Error("invalid_address", $"'{remote}' is not a valid IP/CIDR/range list"));
        }

        var rule = new FwRule(
            name,
            FwRuleMapper.MapDirection(request.Direction),
            FwRuleMapper.MapAction(request.Action),
            request.Enabled,
            remote.Length == 0 ? "Any" : remote,
            FwRuleMapper.MapProtocol(request.Protocol),
            (request.Program ?? string.Empty).Trim(),
            "hostsguard",
            FwRuleMapper.MapPorts(request.RemotePorts),
            FwRuleMapper.MapService(request.ServiceName));
        var created = fw.CreateRule(rule);
        if (created)
        {
            _state.Db.UpsertFwState(rule.Name, rule.Direction, rule.Action, rule.RemoteAddr, rule.Protocol, rule.Program);
            if (rule.Program.Length != 0)
            {
                _state.Identity?.Remember(rule.Name, rule.Program);
            }
        }

        return Task.FromResult(Ok(created ? $"created {rule.Name}" : $"{rule.Name} already exists"));
    }

    public override Task<Ack> DeleteRule(RuleNameRequest request, ServerCallContext context)
    {
        if (_state.Firewall is not { } fw)
        {
            return Task.FromResult(Unavailable());
        }

        if (_state.GateWhenLocked() is { } gate)
        {
            return Task.FromResult(gate);
        }

        var name = (request.Name ?? string.Empty).Trim();
        if (!name.StartsWith(FwRuleMapper.HostsGuardPrefix, StringComparison.Ordinal))
        {
            return Task.FromResult(Error("not_ours", "only HG_-prefixed rules can be deleted through HostsGuard"));
        }

        var deleted = fw.DeleteRule(name);
        _state.Db.RemoveFwState(name);
        return Task.FromResult(deleted ? Ok($"deleted {name}") : Error("not_found", $"{name} does not exist"));
    }

    public override Task<Ack> SetRuleEnabled(RuleEnabledRequest request, ServerCallContext context)
    {
        if (_state.Firewall is not { } fw)
        {
            return Task.FromResult(Unavailable());
        }

        var name = (request.Name ?? string.Empty).Trim();
        if (!name.StartsWith(FwRuleMapper.HostsGuardPrefix, StringComparison.Ordinal))
        {
            return Task.FromResult(Error("not_ours", "only HG_-prefixed rules can be toggled through HostsGuard"));
        }

        return Task.FromResult(fw.SetRuleEnabled(name, request.Enabled)
            ? Ok($"{name} {(request.Enabled ? "enabled" : "disabled")}")
            : Error("not_found", $"{name} does not exist"));
    }

    public override Task<FirewallRuleList> ListRules(Empty request, ServerCallContext context)
    {
        var list = new FirewallRuleList();
        if (_state.Firewall is not { } fw)
        {
            return Task.FromResult(list);
        }

        var live = fw.ListRules();
        var liveNames = new HashSet<string>(live.Select(r => r.Name), StringComparer.Ordinal);
        var adoptedNames = _state.Db.GetAdoptedRuleNames();
        foreach (var r in live)
        {
            list.Rules.Add(new FirewallRule
            {
                Name = r.Name,
                Direction = r.Direction,
                Action = r.Action,
                Enabled = r.Enabled,
                RemoteAddr = r.RemoteAddr,
                Protocol = r.Protocol,
                Program = r.Program,
                Source = r.Source,
                Orphaned = FirewallIdentity.IsOrphaned(r),
                RemotePorts = r.RemotePorts,
                ServiceName = r.ServiceName,
                Adopted = r.Source != "hostsguard" && adoptedNames.Contains(r.Name),
            });
        }

        // Tracked rules missing live = drift (deleted behind our back).
        foreach (var name in _state.Db.GetFwStateNames().Where(n => !liveNames.Contains(n)))
        {
            list.Rules.Add(new FirewallRule
            {
                Name = name,
                Source = "hostsguard",
                Drifted = true,
            });
        }

        return Task.FromResult(list);
    }

    /// <summary>HG_DoH_* rule names (kept in parity with the Python DOH_RULES).</summary>
    public static readonly IReadOnlyList<string> DohRuleNames = new[] { "HG_DoH_IPs", "HG_DoT_TCP", "HG_DoT_UDP" };

    public override Task<Ack> BlockEncryptedDns(DohBlockRequest request, ServerCallContext context)
    {
        if (_state.Firewall is not { } fw)
        {
            return Task.FromResult(Unavailable());
        }

        // The user's own resolvers (request) plus the machine's current ones
        // are never blocked, so their chosen DNS keeps working.
        var exempt = new HashSet<string>(request.Exempt.Select(e => e.Trim()), StringComparer.Ordinal);
        foreach (var resolver in Windows.DnsConfig.CurrentResolvers())
        {
            exempt.Add(resolver.ToString());
        }

        var ips = _state.Doh.CurrentIps().Where(ip => !exempt.Contains(ip))
            .OrderBy(ip => ip, StringComparer.Ordinal).ToList();

        // Recreate from scratch so a stale resolver set never lingers.
        foreach (var name in DohRuleNames)
        {
            fw.DeleteRule(name);
            _state.Db.RemoveFwState(name);
        }

        var created = new List<string>();
        if (ips.Count != 0)
        {
            var addr = string.Join(",", ips);
            if (fw.CreateRule(new FwRule("HG_DoH_IPs", "Out", "Block", true, addr, "Any", string.Empty, "hostsguard")))
            {
                _state.Db.UpsertFwState("HG_DoH_IPs", "Out", "Block", addr, "Any", string.Empty);
                created.Add("HG_DoH_IPs");
            }
        }

        foreach (var (proto, name) in new[] { ("TCP", "HG_DoT_TCP"), ("UDP", "HG_DoT_UDP") })
        {
            if (fw.CreateRule(new FwRule(name, "Out", "Block", true, "Any", proto, string.Empty, "hostsguard", RemotePorts: "853")))
            {
                _state.Db.UpsertFwState(name, "Out", "Block", "Any", proto, string.Empty);
                created.Add(name);
            }
        }

        _state.Db.LogEvent("doh", "fw_blocked", details: $"encrypted DNS blocked ({ips.Count} resolver IPs, port 853)", reason: "doh");
        return Task.FromResult(Ok($"encrypted DNS blocked: {ips.Count} resolver IPs + DoT/DoQ port 853 ({string.Join(", ", created)})"));
    }

    /// <summary>Outbound QUIC block rule (UDP/443) — forces TCP/HTTP2 fallback.</summary>
    public const string QuicRuleName = "HG_QUIC_UDP443";

    public override Task<Ack> BlockQuic(Empty request, ServerCallContext context)
    {
        if (_state.Firewall is not { } fw)
        {
            return Task.FromResult(Unavailable());
        }

        if (fw.RuleExists(QuicRuleName))
        {
            return Task.FromResult(Ok("QUIC/HTTP3 already blocked"));
        }

        // Block outbound UDP to remote port 443 (QUIC/HTTP3, incl. DoH3). Clients
        // transparently fall back to HTTP/2 over TCP — no user-visible breakage.
        var created = fw.CreateRule(new FwRule(QuicRuleName, "Out", "Block", true, "Any", "UDP", string.Empty, "hostsguard", RemotePorts: "443"));
        if (created)
        {
            _state.Db.UpsertFwState(QuicRuleName, "Out", "Block", "Any", "UDP", string.Empty);
            _state.Db.LogEvent("quic", "fw_blocked", details: "QUIC/HTTP3 blocked (outbound UDP/443)", reason: "doh");
        }

        return Task.FromResult(Ok(created
            ? "QUIC/HTTP3 blocked — clients fall back to TCP so DoH3/QUIC can't bypass blocking"
            : $"{QuicRuleName} already exists"));
    }

    public override Task<Ack> UnblockQuic(Empty request, ServerCallContext context)
    {
        if (_state.Firewall is not { } fw)
        {
            return Task.FromResult(Unavailable());
        }

        var removed = fw.DeleteRule(QuicRuleName);
        _state.Db.RemoveFwState(QuicRuleName);
        _state.Db.LogEvent("quic", "fw_unblocked", details: "QUIC/HTTP3 unblocked", reason: "doh");
        return Task.FromResult(Ok(removed ? "QUIC/HTTP3 unblocked (outbound UDP/443 allowed)" : "QUIC was not blocked"));
    }

    public override Task<Ack> UnblockEncryptedDns(Empty request, ServerCallContext context)
    {
        if (_state.Firewall is not { } fw)
        {
            return Task.FromResult(Unavailable());
        }

        var removed = 0;
        foreach (var name in DohRuleNames)
        {
            if (fw.DeleteRule(name))
            {
                removed++;
            }

            _state.Db.RemoveFwState(name);
        }

        _state.Db.LogEvent("doh", "fw_unblocked", details: "encrypted DNS unblocked", reason: "doh");
        return Task.FromResult(Ok($"encrypted DNS unblocked ({removed} rules removed)"));
    }

    public override Task<FirewallPosture> GetPosture(Empty request, ServerCallContext context)
    {
        var posture = new FirewallPosture();
        if (_state.Firewall is not { } fw)
        {
            return Task.FromResult(posture);
        }

        try
        {
            var profiles = fw.GetPosture();
            posture.Available = true;
            posture.Lockdown = profiles.Count != 0 && profiles.All(p => p.OutboundBlock);
            foreach (var p in profiles)
            {
                posture.Profiles.Add(new ProfilePosture { Name = p.Name, Enabled = p.Enabled, OutboundBlock = p.OutboundBlock });
            }
        }
        catch (System.Runtime.InteropServices.COMException)
        {
            posture.Available = false;
        }

        return Task.FromResult(posture);
    }

    public override Task<Ack> SetDefaultOutbound(OutboundRequest request, ServerCallContext context)
    {
        if (_state.Firewall is not { } fw)
        {
            return Task.FromResult(Unavailable());
        }

        if (_state.GateWhenLocked() is { } gate)
        {
            return Task.FromResult(gate);
        }

        try
        {
            fw.SetDefaultOutboundBlock(request.Block);
        }
        catch (System.Runtime.InteropServices.COMException ex)
        {
            return Task.FromResult(Error("posture_failed", $"could not change the outbound policy: {ex.Message}"));
        }

        _state.Db.LogEvent("firewall", request.Block ? "lockdown_on" : "lockdown_off",
            details: $"default outbound action: {(request.Block ? "Block" : "Allow")} (all profiles)");
        return Task.FromResult(Ok(request.Block
            ? "lockdown ON — all outbound blocked unless a rule allows it"
            : "lockdown OFF — outbound allowed by default"));
    }

    public override async Task<RebindSuggestions> SuggestRebind(RuleNameRequest request, ServerCallContext context)
    {
        var result = new RebindSuggestions();
        if (_state.Firewall is not { } fw)
        {
            return result;
        }

        var name = (request.Name ?? string.Empty).Trim();
        var rule = fw.ListRules().FirstOrDefault(r => r.Name == name);
        if (rule is null || rule.Program.Length == 0)
        {
            return result;
        }

        result.OldPath = rule.Program.Split(',')[0].Trim();
        var history = _state.Identity?.Get(name) ?? (IReadOnlyList<FileIdentity>)Array.Empty<FileIdentity>();
        var ranked = await Task.Run(() =>
            RebindScanner.Rank(result.OldPath, history, RebindScanner.ScanCandidates(result.OldPath)));

        result.Ambiguous = ranked.Count > 1 && ranked[0].Score - ranked[1].Score <= RebindScanner.AmbiguousDelta;
        foreach (var candidate in ranked.Take(10))
        {
            result.Candidates.Add(new RebindCandidate { Path = candidate.Path, Score = candidate.Score, Reasons = candidate.Reasons });
        }

        return result;
    }

    public override Task<Ack> RebindRule(RebindRequest request, ServerCallContext context)
    {
        if (_state.Firewall is not { } fw)
        {
            return Task.FromResult(Unavailable());
        }

        var name = (request.Name ?? string.Empty).Trim();
        if (!name.StartsWith(FwRuleMapper.HostsGuardPrefix, StringComparison.Ordinal))
        {
            return Task.FromResult(Error("not_ours", "only HG_-prefixed rules can be rebound through HostsGuard"));
        }

        var newPath = (request.NewProgram ?? string.Empty).Trim();
        if (newPath.Length == 0 || !File.Exists(newPath))
        {
            return Task.FromResult(Error("invalid_program", "replacement program does not exist on disk"));
        }

        var rule = fw.ListRules().FirstOrDefault(r => r.Name == name);
        if (rule is null || !fw.SetRuleProgram(name, newPath))
        {
            return Task.FromResult(Error("not_found", $"{name} does not exist"));
        }

        _state.Db.UpsertFwState(name, rule.Direction, rule.Action, rule.RemoteAddr, rule.Protocol, newPath);
        _state.Identity?.Remember(name, newPath);
        _state.Db.LogEvent(newPath, "fw_rebound", details: $"{name}: {rule.Program} → {newPath}", reason: "rebind");
        return Task.FromResult(Ok($"rebound {name} to {newPath}"));
    }

    public override Task<SecureRulesStatus> GetSecureRules(Empty request, ServerCallContext context)
        => Task.FromResult(new SecureRulesStatus
        {
            Enabled = _state.SecureRules.Enabled,
            Tracked = _state.SecureRules.TrackedCount,
        });

    public override Task<Ack> SetSecureRules(SecureRulesRequest request, ServerCallContext context)
    {
        _state.SecureRules.SetEnabled(request.Enabled);
        return Task.FromResult(Ok(request.Enabled
            ? $"Secure Rules armed — {_state.SecureRules.TrackedCount} HG_ rules protected against tampering"
            : "Secure Rules disarmed"));
    }

    // ─── Global posture selector + per-app scope blocks (NET-076) ────────────

    public override Task<Ack> SetGlobalMode(GlobalModeRequest request, ServerCallContext context)
    {
        if (_state.Firewall is not { } fw)
        {
            return Task.FromResult(Unavailable());
        }

        if (_state.GateWhenLocked() is { } gate)
        {
            return Task.FromResult(gate);
        }

        var mode = (request.Mode ?? string.Empty).Trim().ToLowerInvariant();
        bool block;
        switch (mode)
        {
            case "block-all": block = true; break;
            case "allow-all": block = false; break;
            default:
                return Task.FromResult(Error("invalid_mode", $"unknown global mode '{request.Mode}' (block-all|allow-all)"));
        }

        try
        {
            fw.SetDefaultOutboundBlock(block);
        }
        catch (System.Runtime.InteropServices.COMException ex)
        {
            return Task.FromResult(Error("firewall_error", $"could not set default outbound action: {ex.Message}"));
        }

        _state.Db.LogEvent("firewall", "global_mode", details: mode, reason: "manual");
        return Task.FromResult(Ok(block
            ? "Block-all outbound — new outbound connections are blocked unless a rule allows them"
            : "Allow-all outbound — default outbound action restored to Allow"));
    }

    /// <summary>HG_ rule name for a per-app scope block.</summary>
    internal static string ScopeRuleName(string program, NetworkScope scope) =>
        $"{FwRuleMapper.HostsGuardPrefix}Scope_{scope}_{Path.GetFileNameWithoutExtension(program)}";

    public override Task<Ack> BlockAppScope(AppScopeRequest request, ServerCallContext context)
    {
        if (_state.Firewall is not { } fw)
        {
            return Task.FromResult(Unavailable());
        }

        if (_state.GateWhenLocked() is { } gate)
        {
            return Task.FromResult(gate);
        }

        var path = (request.ProgramPath ?? string.Empty).Trim();
        if (path.Length == 0 || path.IndexOfAny(Path.GetInvalidPathChars()) >= 0)
        {
            return Task.FromResult(Error("invalid_program", "program path is empty or invalid"));
        }

        if (!NetworkScopes.TryParse(request.Scope, out var scope))
        {
            return Task.FromResult(Error("invalid_scope", $"unknown scope '{request.Scope}' (internet|lan|localhost|inbound)"));
        }

        var name = ScopeRuleName(path, scope);
        var direction = scope == NetworkScope.Inbound ? "In" : "Out";
        var remote = NetworkScopes.RemoteAddresses(scope);
        var created = fw.CreateRule(new FwRule(name, direction, "Block", true, remote, "Any", path, "hostsguard"));
        if (created)
        {
            _state.Db.UpsertFwState(name, direction, "Block", remote, "Any", path);
            _state.Identity?.Remember(name, path);
            _state.Db.LogEvent(path, "fw_scope_blocked", details: $"{scope}", reason: "manual");
        }

        return Task.FromResult(Ok(created
            ? $"blocked {Path.GetFileName(path)} → {scope}"
            : $"{Path.GetFileName(path)} → {scope} already blocked"));
    }

    public override Task<Ack> UnblockAppScope(AppScopeRequest request, ServerCallContext context)
    {
        if (_state.Firewall is not { } fw)
        {
            return Task.FromResult(Unavailable());
        }

        var path = (request.ProgramPath ?? string.Empty).Trim();
        if (!NetworkScopes.TryParse(request.Scope, out var scope))
        {
            return Task.FromResult(Error("invalid_scope", $"unknown scope '{request.Scope}'"));
        }

        var name = ScopeRuleName(path, scope);
        var removed = fw.DeleteRule(name);
        _state.Db.RemoveFwState(name);
        return Task.FromResult(Ok(removed ? $"unblocked {Path.GetFileName(path)} → {scope}" : "scope was not blocked"));
    }

    private static string MapDirection(string? direction)
        => FwRuleMapper.MapDirection(direction);

    private static Ack Ok(string message) => new() { Ok = true, Message = message };

    private static Ack Error(string code, string message) =>
        new() { Ok = false, Message = message, ErrorCode = $"hostsguard.error.v1/{code}" };

    private static Ack Unavailable() => Error("firewall_unavailable", "firewall engine is not attached to this service instance");
}
