using System.IO;
using System.Net;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Grpc.Core;
using HostsGuard.Contracts;
using HostsGuard.Core;
using HostsGuard.Data;
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

        var closed = _state.FlowTeardown.CloseForRemoteAddress(addr, "ip_block");
        var suffix = closed > 0 ? $" and closed {closed} IPv4 TCP flow{(closed == 1 ? string.Empty : "s")}" : string.Empty;
        return Task.FromResult(Ok((created ? $"created {name}" : $"{name} already exists") + suffix));
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

        var closed = _state.FlowTeardown.CloseForProgram(path, "program_block");
        var suffix = closed > 0 ? $" and closed {closed} IPv4 TCP flow{(closed == 1 ? string.Empty : "s")}" : string.Empty;
        return Task.FromResult(Ok((created ? $"created {name}" : $"{name} already exists") + suffix));
    }

    public override Task<Ack> CreateRule(FirewallRule request, ServerCallContext context)
    {
        if (_state.Firewall is not { } fw)
        {
            return Task.FromResult(Unavailable());
        }

        if (_state.GateWhenLocked() is { } gate)
        {
            return Task.FromResult(gate);
        }

        if (!TryBuildAuthoredRule(fw, request, requireExistingPrefix: false, out var rule, out var error))
        {
            return Task.FromResult(error!);
        }

        var created = fw.CreateRule(rule);
        if (created)
        {
            _state.Db.UpsertFwState(
                rule.Name,
                rule.Direction,
                rule.Action,
                rule.RemoteAddr,
                rule.Protocol,
                rule.Program,
                rule.RemotePorts,
                rule.LocalPorts,
                rule.ServiceName,
                rule.Interfaces,
                rule.PackageFamilyName,
                rule.PackageSid,
                rule.PackageDisplayName,
                rule.PackageFullName,
                rule.PackageBinaries);
            if (rule.Program.Length != 0)
            {
                _state.Identity?.Remember(rule.Name, rule.Program);
            }
        }

        return Task.FromResult(Ok(created ? $"created {rule.Name}" : $"{rule.Name} already exists"));
    }

    public override Task<Ack> UpdateRule(FirewallRule request, ServerCallContext context)
    {
        if (_state.Firewall is not { } fw) return Task.FromResult(Unavailable());
        if (_state.GateWhenLocked() is { } gate) return Task.FromResult(gate);
        if (!TryBuildAuthoredRule(fw, request, requireExistingPrefix: true, out var rule, out var error))
            return Task.FromResult(error!);
        if (!fw.RuleExists(rule.Name)) return Task.FromResult(Error("not_found", $"{rule.Name} does not exist"));
        if (!fw.ReplaceRule(rule)) return Task.FromResult(Error("update_failed", $"could not replace {rule.Name}; prior rule was restored"));

        _state.Db.UpsertFwState(rule.Name, rule.Direction, rule.Action, rule.RemoteAddr, rule.Protocol,
            rule.Program, rule.RemotePorts, rule.LocalPorts, rule.ServiceName, rule.Interfaces,
            rule.PackageFamilyName, rule.PackageSid, rule.PackageDisplayName, rule.PackageFullName, rule.PackageBinaries);
        if (rule.Program.Length != 0) _state.Identity?.Remember(rule.Name, rule.Program);
        _state.Db.LogEvent(rule.Name, "fw_rule_updated", process: rule.Program,
            details: $"{rule.Protocol} local={rule.LocalPorts} remote={rule.RemotePorts} interfaces={rule.Interfaces}", reason: "manual");
        return Task.FromResult(Ok($"updated {rule.Name}"));
    }

    public override Task<FirewallInterfaceList> ListInterfaceAliases(Empty request, ServerCallContext context)
    {
        var response = new FirewallInterfaceList();
        if (_state.Firewall is not { } fw) return Task.FromResult(response);
        foreach (var item in fw.ListInterfaceAliases())
        {
            response.Interfaces.Add(new FirewallInterface
            {
                Alias = item.Alias,
                Description = item.Description,
                IsUp = item.IsUp,
                InterfaceType = item.InterfaceType,
            });
        }

        return Task.FromResult(response);
    }

    private static bool TryBuildAuthoredRule(IFirewallEngine fw, FirewallRule request, bool requireExistingPrefix,
        out FwRule rule, out Ack? error)
    {
        rule = null!;
        error = null;
        var name = (request.Name ?? string.Empty).Trim();
        if (name.Length == 0)
        {
            error = Error("invalid_rule", "rule name is required");
            return false;
        }

        if (requireExistingPrefix && !name.StartsWith(FwRuleMapper.HostsGuardPrefix, StringComparison.Ordinal))
        {
            error = Error("not_ours", "only HG_-prefixed rules can be edited through HostsGuard");
            return false;
        }

        if (!name.StartsWith(FwRuleMapper.HostsGuardPrefix, StringComparison.Ordinal)) name = FwRuleMapper.HostsGuardPrefix + name;
        var remote = (request.RemoteAddr ?? string.Empty).Trim();
        if (remote is not ("" or "Any") && !remote.Split(',').All(a => FirewallAddress.IsValid(a)))
        {
            error = Error("invalid_address", $"'{remote}' is not a valid IP/CIDR/range list");
            return false;
        }

        var program = (request.Program ?? string.Empty).Trim();
        var family = (request.PackageFamilyName ?? string.Empty).Trim();
        var sid = (request.PackageSid ?? string.Empty).Trim();
        if (program.Length != 0 && (family.Length != 0 || sid.Length != 0))
        {
            error = Error("ambiguous_target", "use either a program path or a package family name, not both");
            return false;
        }

        var package = ResolvePackage(fw, family, sid);
        if ((family.Length != 0 || sid.Length != 0) && package is null)
        {
            error = Error("package_not_found", $"package '{(family.Length == 0 ? sid : family)}' was not found on this machine");
            return false;
        }

        var candidate = new FwRule(name, FwRuleMapper.MapDirection(request.Direction), FwRuleMapper.MapAction(request.Action),
            request.Enabled, remote.Length == 0 ? "Any" : remote, FwRuleMapper.MapProtocol(request.Protocol), program, "hostsguard",
            FwRuleMapper.MapPorts(request.RemotePorts), FwRuleMapper.MapService(request.ServiceName),
            FwRuleMapper.MapPorts(request.LocalPorts), FwRuleMapper.MapInterfaces(request.Interfaces),
            package?.PackageFamilyName ?? string.Empty, package?.PackageSid ?? string.Empty,
            package?.DisplayName ?? string.Empty, package?.PackageFullName ?? string.Empty, package?.Binaries ?? string.Empty);
        if (!FirewallRuleAuthoring.TryNormalize(candidate, out rule, out var validation,
                fw.ListInterfaceAliases().Select(static item => item.Alias)))
        {
            error = Error("invalid_rule", validation);
            return false;
        }

        return true;
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
        if (name.StartsWith("HG_VPNBind_", StringComparison.Ordinal))
        {
            _state.Db.RemoveAppVpnBindingByRuleName(name);
        }

        return Task.FromResult(deleted ? Ok($"deleted {name}") : Error("not_found", $"{name} does not exist"));
    }

    public override Task<DecisionExplanation> ExplainDecision(DecisionExplainRequest request, ServerCallContext context)
    {
        var input = BuildDecisionInput(request);
        var domain = input.Domain;
        if (domain.Length == 0 && input.RemoteAddress.Length != 0)
        {
            domain = _state.ResolveKnownHost(input.RemoteAddress).Trim().ToLowerInvariant();
            input = input with { Domain = domain };
        }

        var root = Domains.LooksLikeDomain(domain) ? Domains.GetRoot(domain) : string.Empty;
        IReadOnlyList<FwRule> rules = _state.Firewall?.ListRules() ?? Array.Empty<FwRule>();
        IReadOnlyList<FwProfilePosture> profiles = Array.Empty<FwProfilePosture>();
        if (_state.Firewall is { } fw)
        {
            try
            {
                profiles = fw.GetPosture();
            }
            catch (System.Runtime.InteropServices.COMException)
            {
                profiles = Array.Empty<FwProfilePosture>();
            }
        }

        var groups = _state.Db.GetRuleGroups()
            .GroupBy(g => g.RuleName, StringComparer.Ordinal)
            .ToDictionary(
                g => g.Key,
                g => (IReadOnlyList<string>)g.Select(x => x.Group).Distinct(StringComparer.Ordinal).ToList(),
                StringComparer.Ordinal);
        var facts = new DecisionPolicyFacts(
            DomainStatus: domain.Length == 0 ? null : _state.Db.GetDomainStatus(domain),
            DomainSource: domain.Length == 0 ? null : _state.Db.GetDomainSource(domain),
            RootStatus: root.Length == 0 || string.Equals(root, domain, StringComparison.Ordinal) ? null : _state.Db.GetDomainStatus(root),
            RootSource: root.Length == 0 || string.Equals(root, domain, StringComparison.Ordinal) ? null : _state.Db.GetDomainSource(root),
            Rules: rules,
            DomainFirewallRules: _state.Db.ListDomainFirewallRules()
                .Select(r => new DomainFirewallRuleFact(r.Domain, r.Program, r.RuleName, r.Action, r.Enabled, r.RemoteAddr))
                .ToList(),
            RuleGroups: groups,
            Profiles: profiles,
            ActiveProfile: _state.Db.GetMeta("active_profile") ?? string.Empty,
            TrustedPublishers: _state.Consent.TrustedPublishers,
            TrustedFolders: _state.Consent.TrustedFolders,
            KillSwitchEnabled: _state.KillSwitch?.Enabled ?? false,
            KillSwitchEngaged: _state.KillSwitch?.IsEngaged ?? false,
            KillSwitchAdapter: _state.KillSwitch?.Adapter ?? string.Empty);
        var explanation = DecisionExplainer.Explain(input, facts);
        return Task.FromResult(ToProto(explanation));
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

    public override Task<AppPackageList> ListAppPackages(Empty request, ServerCallContext context)
    {
        var result = new AppPackageList();
        if (_state.Firewall is not { } fw)
        {
            return Task.FromResult(result);
        }

        foreach (var package in fw.ListPackages())
        {
            result.Packages.Add(new AppPackage
            {
                PackageFamilyName = package.PackageFamilyName,
                PackageSid = package.PackageSid,
                DisplayName = package.DisplayName,
                PackageFullName = package.PackageFullName,
                Binaries = package.Binaries,
            });
        }

        return Task.FromResult(result);
    }

    public override Task<FirewallRuleList> ListRules(Empty request, ServerCallContext context)
    {
        var list = new FirewallRuleList();
        if (_state.Firewall is not { } fw)
        {
            return Task.FromResult(list);
        }

        var live = fw.ListRules(includePackageBinaries: true);
        _state.FirewallDrift.CaptureNow(live);
        var snapshots = _state.Db.GetFirewallRuleSnapshots()
            .ToDictionary(s => s.Name, StringComparer.Ordinal);
        var liveNames = new HashSet<string>(live.Select(r => r.Name), StringComparer.Ordinal);
        var adoptedNames = _state.Db.GetAdoptedRuleNames();
        foreach (var r in live)
        {
            snapshots.TryGetValue(r.Name, out var snapshot);
            list.Rules.Add(ToRule(r, snapshot, r.Source != "hostsguard" && adoptedNames.Contains(r.Name)));
        }

        foreach (var snapshot in snapshots.Values.Where(s => !s.Present && !liveNames.Contains(s.Name)))
        {
            list.Rules.Add(ToRule(snapshot));
        }

        // Tracked rules missing live = drift (deleted behind our back).
        foreach (var tracked in _state.Db.GetFwState().Where(n => !liveNames.Contains(n.Name)))
        {
            if (list.Rules.Any(r => string.Equals(r.Name, tracked.Name, StringComparison.Ordinal)))
            {
                continue;
            }

            list.Rules.Add(new FirewallRule
            {
                Name = tracked.Name,
                Source = "hostsguard",
                Drifted = true,
                DriftStatus = "missing",
                DriftDetail = "tracked HostsGuard rule is missing from Windows Firewall",
                PackageFamilyName = tracked.PackageFamilyName ?? string.Empty,
                PackageSid = tracked.PackageSid ?? string.Empty,
                PackageDisplayName = tracked.PackageDisplayName ?? string.Empty,
                PackageFullName = tracked.PackageFullName ?? string.Empty,
                PackageBinaries = tracked.PackageBinaries ?? string.Empty,
            });
        }

        return Task.FromResult(list);
    }

    public override Task<FirewallRuleAnalysisResult> AnalyzeRules(FirewallRuleAnalysisRequest request, ServerCallContext context)
    {
        if (_state.Firewall is not { } fw)
        {
            return Task.FromResult(new FirewallRuleAnalysisResult { LocalPolicyModifyState = "unavailable" });
        }

        var snapshot = CaptureRuleAnalysis(fw);
        var response = new FirewallRuleAnalysisResult
        {
            AnalysisHash = snapshot.Hash,
            LocalPolicyModifyState = Snake(snapshot.Context.LocalPolicyModifyState.ToString()),
            RulesAnalyzed = snapshot.Rules.Count,
        };
        response.ActiveProfiles.AddRange(snapshot.Context.ActiveProfiles);
        var kind = CleanFilter(request.Kind);
        var remediation = CleanFilter(request.Remediation);
        var search = CleanFilter(request.Search);
        foreach (var finding in snapshot.Findings.Where(finding =>
                     (kind.Length == 0 || finding.Kind.ToString().Equals(kind, StringComparison.OrdinalIgnoreCase)) &&
                     (remediation.Length == 0 || finding.Remediation.ToString().Equals(remediation, StringComparison.OrdinalIgnoreCase)) &&
                     (search.Length == 0 || finding.RuleName.Contains(search, StringComparison.OrdinalIgnoreCase) ||
                      finding.RelatedRuleName.Contains(search, StringComparison.OrdinalIgnoreCase) ||
                      finding.Reason.Contains(search, StringComparison.OrdinalIgnoreCase)) &&
                     (!request.CleanupEligibleOnly || IsCleanupEligible(finding))))
        {
            response.Findings.Add(ToContract(finding));
        }

        return Task.FromResult(response);
    }

    public override Task<FirewallRuleCleanupResult> ApplyRuleCleanup(FirewallRuleCleanupRequest request, ServerCallContext context)
    {
        if (_state.Firewall is not { } fw)
        {
            return Task.FromResult(CleanupError(request.Preview, "firewall_unavailable", "firewall engine is not attached"));
        }

        if (!request.Preview && _state.GateWhenLocked() is { } gate)
        {
            return Task.FromResult(CleanupError(false, "locked", gate.Message));
        }

        var selected = request.SelectedNames
            .Select(static name => name.Trim())
            .Where(static name => name.Length != 0)
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .ToArray();
        if (selected.Length == 0 || !IsSha256(request.AnalysisHash))
        {
            return Task.FromResult(CleanupError(request.Preview, "invalid_request",
                "selected rule names and a valid analysis hash are required"));
        }

        var snapshot = CaptureRuleAnalysis(fw);
        if (!CryptographicOperations.FixedTimeEquals(
                Encoding.ASCII.GetBytes(snapshot.Hash), Encoding.ASCII.GetBytes(request.AnalysisHash.ToLowerInvariant())))
        {
            return Task.FromResult(CleanupError(request.Preview, "analysis_changed",
                "firewall rules or active policy changed; analyze again before cleanup", snapshot.Hash));
        }

        var eligible = snapshot.Findings
            .Where(IsCleanupEligible)
            .Select(static finding => finding.RuleName)
            .ToHashSet(StringComparer.Ordinal);
        var liveNames = snapshot.Rules.Select(static rule => rule.Name).ToHashSet(StringComparer.Ordinal);
        var rejected = selected.Where(name =>
                !name.StartsWith(FwRuleMapper.HostsGuardPrefix, StringComparison.Ordinal) ||
                !liveNames.Contains(name) || !eligible.Contains(name))
            .ToArray();
        if (rejected.Length != 0)
        {
            var result = CleanupError(request.Preview, "unsafe_selection",
                "cleanup only accepts currently analyzed exact-duplicate HG_ rules", snapshot.Hash);
            result.RejectedNames.AddRange(rejected);
            return Task.FromResult(result);
        }

        var previewHash = CleanupPreviewHash(snapshot.Hash, selected);
        if (request.Preview)
        {
            var preview = new FirewallRuleCleanupResult
            {
                Ok = true,
                Preview = true,
                Message = $"previewed removal of {selected.Length} selected HostsGuard rule{(selected.Length == 1 ? string.Empty : "s")}",
                AnalysisHash = snapshot.Hash,
                PreviewHash = previewHash,
            };
            preview.SelectedNames.AddRange(selected);
            return Task.FromResult(preview);
        }

        if (!IsSha256(request.PreviewHash) || !CryptographicOperations.FixedTimeEquals(
                Encoding.ASCII.GetBytes(previewHash), Encoding.ASCII.GetBytes(request.PreviewHash.ToLowerInvariant())))
        {
            return Task.FromResult(CleanupError(false, "preview_mismatch",
                "preview hash does not bind this analysis and exact selected rule set", snapshot.Hash));
        }

        var deletedRules = new List<FwRule>(selected.Length);
        var byName = snapshot.Rules.ToDictionary(static rule => rule.Name, StringComparer.Ordinal);
        foreach (var name in selected)
        {
            if (!fw.DeleteRule(name))
            {
                foreach (var removed in deletedRules)
                {
                    _ = fw.CreateRule(removed);
                }

                return Task.FromResult(CleanupError(false, "delete_failed",
                    $"cleanup failed at {name}; previously removed rules were restored", snapshot.Hash));
            }

            deletedRules.Add(byName[name]);
        }

        foreach (var name in selected)
        {
            _state.Db.RemoveFwState(name);
            if (name.StartsWith("HG_VPNBind_", StringComparison.Ordinal))
            {
                _state.Db.RemoveAppVpnBindingByRuleName(name);
            }
        }

        _state.Db.LogEvent("firewall_rules", "rule_cleanup", process: "firewall",
            details: $"deleted {deletedRules.Count} preview-bound exact duplicate HG_ rule(s)", reason: "rule_analysis");
        var applied = new FirewallRuleCleanupResult
        {
            Ok = true,
            Preview = false,
            Message = $"deleted {deletedRules.Count} selected duplicate rule{(deletedRules.Count == 1 ? string.Empty : "s")}",
            AnalysisHash = snapshot.Hash,
            PreviewHash = previewHash,
            Deleted = deletedRules.Count,
        };
        applied.SelectedNames.AddRange(selected);
        return Task.FromResult(applied);
    }

    private RuleAnalysisSnapshot CaptureRuleAnalysis(IFirewallEngine fw)
    {
        var rules = fw.ListRules().OrderBy(static rule => rule.Name, StringComparer.Ordinal).ToArray();
        var profiles = fw.GetActiveInboundProfiles().Select(static profile => profile.Name)
            .Distinct(StringComparer.OrdinalIgnoreCase).Order(StringComparer.OrdinalIgnoreCase).ToArray();
        var context = new FirewallRuleAnalysisContext(profiles, fw.GetLocalPolicyModifyState());
        var report = FirewallRuleAnalyzer.Analyze(rules, context);
        return new RuleAnalysisSnapshot(rules, context, report.Findings, report.AnalysisHash);
    }

    private static Contracts.FirewallRuleAnalysisFinding ToContract(Core.FirewallRuleAnalysisFinding finding) => new()
    {
        Kind = finding.Kind,
        RuleName = finding.RuleName,
        RelatedRuleName = finding.RelatedRuleName,
        CanonicalFingerprint = finding.CanonicalFingerprint,
        Reason = finding.Reason,
        Remediation = finding.Remediation,
        CleanupEligible = IsCleanupEligible(finding),
    };

    private static bool IsCleanupEligible(Core.FirewallRuleAnalysisFinding finding) =>
        finding.CleanupEligible &&
        finding.Kind.Equals("exact_duplicate", StringComparison.Ordinal) &&
        finding.Remediation.Equals("delete_duplicate", StringComparison.Ordinal) &&
        finding.RuleName.StartsWith(FwRuleMapper.HostsGuardPrefix, StringComparison.Ordinal);

    private static FirewallRuleCleanupResult CleanupError(bool preview, string code, string message,
        string analysisHash = "", int deleted = 0) => new()
    {
        Ok = false,
        Preview = preview,
        Message = message,
        ErrorCode = $"hostsguard.error.v1/{code}",
        AnalysisHash = analysisHash,
        Deleted = deleted,
    };

    private static string CleanupPreviewHash(string analysisHash, IReadOnlyList<string> selected) =>
        Sha256(JsonSerializer.Serialize(new { analysisHash, selected }));

    private static bool IsSha256(string value) => value.Length == 64 && value.All(Uri.IsHexDigit);

    private static string Sha256(string value) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    private static string CleanFilter(string value) => (value ?? string.Empty).Trim();

    private static string Snake(string value)
    {
        var sb = new StringBuilder(value.Length + 4);
        foreach (var ch in value)
        {
            if (char.IsUpper(ch) && sb.Length != 0) sb.Append('_');
            sb.Append(char.ToLowerInvariant(ch));
        }
        return sb.ToString();
    }

    private sealed record RuleAnalysisSnapshot(
        IReadOnlyList<FwRule> Rules,
        FirewallRuleAnalysisContext Context,
        IReadOnlyList<Core.FirewallRuleAnalysisFinding> Findings,
        string Hash);

    public override Task<Ack> CloseConnection(FlowCloseRequest request, ServerCallContext context)
        => Task.FromResult(_state.FlowTeardown.CloseManual(new FlowTuple(
            request.Protocol,
            request.LocalAddr,
            request.LocalPort,
            request.RemoteAddr,
            request.RemotePort,
            request.Process)));

    public override Task<FlowTeardownStatus> GetFlowTeardown(Empty request, ServerCallContext context)
        => Task.FromResult(new FlowTeardownStatus
        {
            Available = _state.FlowTeardown.Available,
            Enabled = _state.FlowTeardown.Enabled,
            Limit = "IPv4 TCP only",
        });

    public override Task<Ack> SetFlowTeardown(FlowTeardownRequest request, ServerCallContext context)
        => Task.FromResult(_state.FlowTeardown.SetEnabled(request.Enabled));

    public override Task<LanAttackSurfaceStatus> GetLanAttackSurface(Empty request, ServerCallContext context)
    {
        var status = new LanAttackSurfaceStatus();
        foreach (var toggle in _state.LanAttackSurface.List())
        {
            status.Toggles.Add(new LanAttackSurfaceToggle
            {
                Key = toggle.Key,
                Label = toggle.Label,
                Blocked = toggle.Blocked,
                Status = toggle.Status,
                BreakNote = toggle.BreakNote,
            });
        }

        return Task.FromResult(status);
    }

    public override Task<Ack> SetLanAttackSurface(LanAttackSurfaceRequest request, ServerCallContext context)
    {
        if (_state.GateWhenLocked() is { } gate)
        {
            return Task.FromResult(gate);
        }

        return Task.FromResult(_state.LanAttackSurface.Set(request.Key, request.Blocked));
    }

    private static FirewallRule ToRule(FwRule rule, FirewallRuleSnapshotRow? snapshot, bool adopted)
    {
        var driftStatus = snapshot?.Present == true ? snapshot.ChangeKind : string.Empty;
        return new FirewallRule
        {
            Name = rule.Name,
            Direction = rule.Direction,
            Action = rule.Action,
            Enabled = rule.Enabled,
            RemoteAddr = rule.RemoteAddr,
            Protocol = rule.Protocol,
            Program = rule.Program,
            Source = rule.Source,
            Orphaned = FirewallIdentity.IsOrphaned(rule),
            Drifted = !string.IsNullOrWhiteSpace(driftStatus),
            RemotePorts = rule.RemotePorts,
            LocalPorts = rule.LocalPorts,
            ServiceName = rule.ServiceName,
            Interfaces = rule.Interfaces,
            PackageFamilyName = rule.PackageFamilyName,
            PackageSid = rule.PackageSid,
            PackageDisplayName = rule.PackageDisplayName,
            PackageFullName = rule.PackageFullName,
            PackageBinaries = rule.PackageBinaries,
            Adopted = adopted,
            DriftStatus = driftStatus,
            DriftDetail = DriftDetail(snapshot),
            FirstSeen = snapshot?.FirstSeen ?? string.Empty,
            LastSeen = snapshot?.LastSeen ?? string.Empty,
            ChangedAt = snapshot?.ChangedAt ?? string.Empty,
        };
    }

    private static FirewallRule ToRule(FirewallRuleSnapshotRow snapshot) => new()
    {
        Name = snapshot.Name,
        Direction = snapshot.Direction,
        Action = snapshot.Action,
        Enabled = snapshot.Enabled,
        RemoteAddr = snapshot.RemoteAddr,
        Protocol = snapshot.Protocol,
        Program = snapshot.Program,
        Source = snapshot.Source,
        Drifted = true,
        RemotePorts = snapshot.RemotePorts,
        LocalPorts = snapshot.LocalPorts,
        ServiceName = snapshot.ServiceName,
        Interfaces = snapshot.Interfaces,
        PackageFamilyName = snapshot.PackageFamilyName,
        PackageSid = snapshot.PackageSid,
        PackageDisplayName = snapshot.PackageDisplayName,
        PackageFullName = snapshot.PackageFullName,
        PackageBinaries = snapshot.PackageBinaries,
        DriftStatus = string.IsNullOrWhiteSpace(snapshot.ChangeKind) ? "vanished" : snapshot.ChangeKind,
        DriftDetail = DriftDetail(snapshot),
        FirstSeen = snapshot.FirstSeen,
        LastSeen = snapshot.LastSeen,
        ChangedAt = snapshot.ChangedAt,
    };

    private static string DriftDetail(FirewallRuleSnapshotRow? snapshot)
    {
        if (snapshot is null || string.IsNullOrWhiteSpace(snapshot.ChangeKind))
        {
            return string.Empty;
        }

        if (!string.IsNullOrWhiteSpace(snapshot.ChangeDetail))
        {
            return snapshot.ChangeDetail;
        }

        return snapshot.ChangeKind switch
        {
            "added" => "rule appeared after the baseline was seeded",
            "changed" => "rule fields changed after the baseline was seeded",
            "vanished" => "rule vanished after the baseline was seeded",
            _ => snapshot.ChangeKind,
        };
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
                _state.Db.UpsertFwState(name, "Out", "Block", "Any", proto, string.Empty, remotePorts: "853");
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
            _state.Db.UpsertFwState(QuicRuleName, "Out", "Block", "Any", "UDP", string.Empty, remotePorts: "443");
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

    public override Task<EnforcementPauseStatus> GetEnforcementPause(Empty request, ServerCallContext context)
        => Task.FromResult(_state.EnforcementPause.Status());

    public override Task<Ack> PauseEnforcement(EnforcementPauseRequest request, ServerCallContext context)
    {
        if (_state.GateWhenLocked() is { } gate)
        {
            return Task.FromResult(gate);
        }

        return Task.FromResult(_state.EnforcementPause.Pause(request.Minutes));
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
    {
        var guardStatus = _state.SecureRules.GetStatus();
        var status = new SecureRulesStatus
        {
            Enabled = _state.SecureRules.Enabled,
            Tracked = guardStatus.ProtectedCount,
            Quarantined = guardStatus.Conflicts.Count,
        };
        status.Conflicts.AddRange(guardStatus.Conflicts.Select(c => new HostsGuard.Contracts.SecureRuleConflict
        {
            Name = c.Name,
            DetectedAt = c.DetectedAt,
            RestoreAttempts = c.RestoreAttempts,
            LiveEvidence = c.LiveEvidence,
            TrackedEvidence = c.TrackedEvidence,
        }));
        return Task.FromResult(status);
    }

    public override Task<Ack> SetSecureRules(SecureRulesRequest request, ServerCallContext context)
    {
        _state.SecureRules.SetEnabled(request.Enabled);
        return Task.FromResult(Ok(request.Enabled
            ? $"Secure Rules armed — {_state.SecureRules.TrackedCount} HG_ rules protected against tampering"
            : "Secure Rules disarmed"));
    }

    public override Task<Ack> ResolveSecureRuleConflict(SecureRuleConflictRequest request, ServerCallContext context)
    {
        if (_state.GateWhenLocked() is { } gate)
        {
            return Task.FromResult(gate);
        }

        var name = (request.Name ?? string.Empty).Trim();
        if (!name.StartsWith(FwRuleMapper.HostsGuardPrefix, StringComparison.Ordinal))
        {
            return Task.FromResult(Error("invalid_rule", "a HostsGuard HG_ rule name is required"));
        }

        var action = (request.Action ?? string.Empty).Trim().ToLowerInvariant();
        if (action == "rearm" && !_state.SecureRules.Enabled)
        {
            return Task.FromResult(Error("secure_rules_disabled", "enable Secure Rules before re-arming a conflict"));
        }

        var resolved = action switch
        {
            "accept" => _state.SecureRules.AcceptForeignState(name),
            "rearm" => _state.SecureRules.Rearm(name),
            _ => false,
        };
        if (!resolved)
        {
            var invalidAction = action is not ("accept" or "rearm");
            return Task.FromResult(invalidAction
                ? Error("invalid_action", "action must be accept or rearm")
                : Error("not_found", $"{name} is not quarantined"));
        }

        return Task.FromResult(Ok(action == "accept"
            ? $"accepted foreign state for {name}; Secure Rules no longer tracks it"
            : $"re-armed Secure Rules recovery for {name}"));
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

        _state.FlowTeardown.CloseForProgram(path, $"scope_block:{scope}");
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

    public override async Task<Ack> CreateDomainFirewallRule(DomainFirewallRuleRequest request, ServerCallContext context)
    {
        if (_state.GateWhenLocked() is { } gate)
        {
            return gate;
        }

        return await _state.DomainFirewall.CreateOrUpdateAsync(request.Domain, request.ProgramPath, context.CancellationToken);
    }

    public override Task<Ack> DeleteDomainFirewallRule(RuleNameRequest request, ServerCallContext context)
    {
        if (_state.GateWhenLocked() is { } gate)
        {
            return Task.FromResult(gate);
        }

        return Task.FromResult(_state.DomainFirewall.Delete(request.Name));
    }

    public override Task<DomainFirewallRuleList> ListDomainFirewallRules(Empty request, ServerCallContext context)
    {
        var result = new DomainFirewallRuleList();
        foreach (var row in _state.DomainFirewall.List())
        {
            result.Rules.Add(new DomainFirewallRule
            {
                Domain = row.Domain,
                Program = row.Program,
                RuleName = row.RuleName,
                Action = row.Action,
                Enabled = row.Enabled,
                RemoteAddr = row.RemoteAddr,
                Updated = row.Updated,
            });
        }

        return Task.FromResult(result);
    }

    public override async Task<Ack> RefreshDomainFirewallRules(Empty request, ServerCallContext context)
    {
        var changed = await _state.DomainFirewall.RefreshAllAsync(context.CancellationToken);
        return Ok($"refreshed {changed} domain firewall rule{(changed == 1 ? string.Empty : "s")}");
    }

    public override Task<KillSwitchStatus> GetKillSwitch(Empty request, ServerCallContext context)
    {
        var status = new KillSwitchStatus();
        if (_state.KillSwitch is { } ks)
        {
            status.Enabled = ks.Enabled;
            status.Adapter = ks.Adapter;
            status.Engaged = ks.IsEngaged;
        }

        foreach (var a in NetworkAdapters.List())
        {
            status.Adapters.Add(new NetworkAdapterInfo
            {
                Name = a.Name,
                Description = a.Description,
                IsUp = a.IsUp,
                IsVpnLikely = a.IsVpnLikely,
            });
        }

        return Task.FromResult(status);
    }

    public override Task<Ack> SetKillSwitch(KillSwitchRequest request, ServerCallContext context)
    {
        if (_state.KillSwitch is not { } ks)
        {
            return Task.FromResult(Error("killswitch_unavailable", "kill-switch monitor is not attached to this service instance"));
        }

        if (_state.GateWhenLocked() is { } gate)
        {
            return Task.FromResult(gate);
        }

        return Task.FromResult(ks.Configure(request.Enabled, request.Adapter));
    }

    public override Task<AppVpnBindingStatus> GetAppVpnBindings(Empty request, ServerCallContext context)
    {
        var status = new AppVpnBindingStatus();
        var adapters = _state.AppVpnBindings?.ListAdapters() ?? NetworkAdapters.List();
        foreach (var a in adapters)
        {
            status.Adapters.Add(new NetworkAdapterInfo
            {
                Name = a.Name,
                Description = a.Description,
                IsUp = a.IsUp,
                IsVpnLikely = a.IsVpnLikely,
            });
        }

        if (_state.AppVpnBindings is { } bindings)
        {
            foreach (var binding in bindings.List())
            {
                var proto = new AppVpnBinding
                {
                    ProgramPath = binding.Program,
                    Adapter = binding.Adapter,
                    RuleName = binding.RuleName,
                    SelectedAdapterUp = binding.SelectedAdapterUp,
                };
                proto.BlockedInterfaces.AddRange(binding.BlockedInterfaces);
                status.Bindings.Add(proto);
            }
        }

        return Task.FromResult(status);
    }

    public override Task<Ack> SetAppVpnBinding(AppVpnBindingRequest request, ServerCallContext context)
    {
        if (_state.AppVpnBindings is not { } bindings)
        {
            return Task.FromResult(Error("app_vpn_unavailable", "app VPN binding coordinator is not attached to this service instance"));
        }

        if (_state.GateWhenLocked() is { } gate)
        {
            return Task.FromResult(gate);
        }

        return Task.FromResult(bindings.Set(request.ProgramPath, request.Adapter, request.Enabled));
    }

    private static string MapDirection(string? direction)
        => FwRuleMapper.MapDirection(direction);

    private DecisionInput BuildDecisionInput(DecisionExplainRequest request)
    {
        var target = (request.Target ?? string.Empty).Trim();
        var domain = (request.Domain ?? string.Empty).Trim().TrimEnd('.').ToLowerInvariant();
        var remote = (request.RemoteAddr ?? string.Empty).Trim();
        var programPath = (request.ProgramPath ?? string.Empty).Trim();
        var process = (request.Process ?? string.Empty).Trim();

        if (target.Length != 0)
        {
            if (domain.Length == 0 && Domains.LooksLikeDomain(target))
            {
                domain = target.TrimEnd('.').ToLowerInvariant();
            }
            else if (remote.Length == 0 && IPAddress.TryParse(target, out _))
            {
                remote = target;
            }
            else if (programPath.Length == 0 && LooksLikePath(target))
            {
                programPath = target;
                process = process.Length == 0 ? Path.GetFileName(target) : process;
            }
            else if (process.Length == 0)
            {
                process = target;
            }
        }

        var signer = (request.Signer ?? string.Empty).Trim();
        if (signer.Length == 0 && programPath.Length != 0)
        {
            signer = ResolveSigner(programPath);
        }

        return new DecisionInput(
            domain,
            remote,
            Math.Max(0, request.RemotePort),
            string.IsNullOrWhiteSpace(request.Protocol) ? "Any" : request.Protocol.Trim(),
            programPath,
            process,
            string.IsNullOrWhiteSpace(request.Direction) ? "Out" : request.Direction.Trim(),
            signer,
            (request.Service ?? string.Empty).Trim(),
            (request.PackageFamilyName ?? string.Empty).Trim(),
            (request.PackageSid ?? string.Empty).Trim());
    }

    private static FwAppPackage? ResolvePackage(IFirewallEngine fw, string packageFamilyName, string packageSid)
    {
        if (packageFamilyName.Length == 0 && packageSid.Length == 0)
        {
            return null;
        }

        var packages = fw.ListPackages();
        var found = packages.FirstOrDefault(p =>
            (packageFamilyName.Length != 0 && string.Equals(p.PackageFamilyName, packageFamilyName, StringComparison.OrdinalIgnoreCase)) ||
            (packageSid.Length != 0 && string.Equals(p.PackageSid, packageSid, StringComparison.OrdinalIgnoreCase)));
        if (found is not null)
        {
            return found;
        }

        return packageSid.StartsWith("S-1-", StringComparison.OrdinalIgnoreCase)
            ? new FwAppPackage(packageFamilyName, packageSid, string.Empty, string.Empty, string.Empty)
            : null;
    }

    private static bool LooksLikePath(string target) =>
        target.Contains('\\', StringComparison.Ordinal) ||
        target.Contains('/', StringComparison.Ordinal) ||
        target.Contains(':', StringComparison.Ordinal);

    private string ResolveSigner(string programPath)
    {
        if (_state.Consent.LookupSigner is { } hook)
        {
            return hook(programPath) ?? string.Empty;
        }

        try
        {
            return FirewallIdentity.Compute(programPath).Signer ?? string.Empty;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or CryptographicException or ArgumentException)
        {
            return string.Empty;
        }
    }

    private static DecisionExplanation ToProto(DecisionExplanationResult result)
    {
        var proto = new DecisionExplanation
        {
            Verdict = result.Verdict,
            Summary = result.Summary,
            NextSafeAction = result.NextSafeAction,
        };
        foreach (var step in result.Steps)
        {
            proto.Steps.Add(new DecisionStep
            {
                Order = step.Order,
                Layer = step.Layer,
                Outcome = step.Outcome,
                Owner = step.Owner,
                Detail = step.Detail,
                NextAction = step.NextAction,
            });
        }

        return proto;
    }

    private static Ack Ok(string message) => new() { Ok = true, Message = message };

    private static Ack Error(string code, string message) =>
        new() { Ok = false, Message = message, ErrorCode = $"hostsguard.error.v1/{code}" };

    private static Ack Unavailable() => Error("firewall_unavailable", "firewall engine is not attached to this service instance");
}
