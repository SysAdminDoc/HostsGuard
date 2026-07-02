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
            "hostsguard");
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

    public override Task<Ack> BlockEncryptedDns(DohBlockRequest request, ServerCallContext context)
        => Task.FromResult(Error("not_implemented", "DoH/DoT blocking arrives with the resolver-intelligence engine"));

    public override Task<Ack> UnblockEncryptedDns(Empty request, ServerCallContext context)
        => Task.FromResult(Error("not_implemented", "DoH/DoT blocking arrives with the resolver-intelligence engine"));

    private static string MapDirection(string? direction)
        => FwRuleMapper.MapDirection(direction);

    private static Ack Ok(string message) => new() { Ok = true, Message = message };

    private static Ack Error(string code, string message) =>
        new() { Ok = false, Message = message, ErrorCode = $"hostsguard.error.v1/{code}" };

    private static Ack Unavailable() => Error("firewall_unavailable", "firewall engine is not attached to this service instance");
}
