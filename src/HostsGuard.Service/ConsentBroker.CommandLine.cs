using System.Globalization;
using System.Security.Cryptography;
using HostsGuard.Contracts;
using HostsGuard.Core;
using HostsGuard.Windows;

namespace HostsGuard.Service;

public sealed partial class ConsentBroker
{
    // ─── Command-line rule engine (NET-156) ──────────────────────────────────

    private bool TryApplyCommandLineDecision(BlockedConnection blocked, InterpreterCommandBinding binding)
    {
        CommandLineRule? rule;
        lock (_gate)
        {
            ReapExpiredCommandLineRulesNoLock(DateTime.UtcNow);
            rule = _state.CommandLineRules.FirstOrDefault(r => CommandLineRuleMatches(r, blocked, binding));
        }

        if (rule is null)
        {
            return false;
        }

        if (rule.Action.Equals("Block", StringComparison.OrdinalIgnoreCase))
        {
            _db.LogEvent(blocked.Application, "consent_cmd_block", details: binding.ScriptPath, reason: "consent",
                provenance: blocked.Provenance);
            return true;
        }

        if (_firewall is not { } fw)
        {
            return false;
        }

        if (!fw.RuleExists(rule.RuleName))
        {
            var protocol = rule.Protocol is "TCP" or "UDP" ? rule.Protocol : "Any";
            var ports = rule.RemotePort > 0 && protocol is "TCP" or "UDP"
                ? rule.RemotePort.ToString(System.Globalization.CultureInfo.InvariantCulture)
                : "Any";
            if (CreateRuleTracked(fw, new FwRule(
                    rule.RuleName,
                    rule.Direction,
                    "Allow",
                    true,
                    rule.RemoteAddress,
                    protocol,
                    rule.Application,
                    "hostsguard",
                    RemotePorts: ports)))
            {
                _db.UpsertFwState(rule.RuleName, rule.Direction, "Allow", rule.RemoteAddress, protocol, rule.Application, remotePorts: ports);
            }
        }

        _db.LogEvent(blocked.Application, "consent_cmd_allow", details: binding.ScriptPath, reason: "consent",
            provenance: blocked.Provenance);
        return true;
    }

    private static bool CommandLineRuleMatches(CommandLineRule rule, BlockedConnection blocked, InterpreterCommandBinding binding)
    {
        if (!rule.Application.Equals(blocked.Application, StringComparison.OrdinalIgnoreCase)
            || !rule.ScriptKey.Equals(binding.ScriptKey, StringComparison.OrdinalIgnoreCase)
            || !rule.Direction.Equals(blocked.Direction, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (rule.RemoteAddress is not ("" or "Any")
            && !rule.RemoteAddress.Equals(blocked.RemoteAddress, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (rule.Protocol is not ("" or "Any")
            && !rule.Protocol.Equals(blocked.Protocol, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return rule.RemotePort <= 0 || rule.RemotePort == blocked.RemotePort;
    }

    private void ReapExpiredCommandLineRulesNoLock(DateTime nowUtc)
    {
        var expired = _state.CommandLineRules
            .Where(r => r.ExpiresUtc is { } expires && expires <= nowUtc)
            .ToList();
        if (expired.Count == 0)
        {
            return;
        }

        _state.CommandLineRules.RemoveAll(r => expired.Contains(r));
        var expiredNames = expired
            .Select(r => r.RuleName)
            .Where(n => n.Length != 0)
            .ToHashSet(StringComparer.Ordinal);
        if (expiredNames.Count != 0)
        {
            _onceRules.RemoveAll(r => expiredNames.Contains(r.RuleName));
        }

        SaveState();
        if (_firewall is not { } fw)
        {
            return;
        }

        foreach (var rule in expired.Where(r => r.RuleName.Length != 0))
        {
            DeleteRuleTracked(fw, rule.RuleName);
            _db.RemoveFwState(rule.RuleName);
        }
    }

    private Ack DecideCommandLine(
        IFirewallEngine fw,
        ConnectionDecision decision,
        string application,
        string verdict,
        WfpAuditProvenance? provenance)
    {
        var direction = decision.Direction == "In" ? "In" : "Out";
        var action = verdict == "allow" ? "Allow" : "Block";
        var stem = Path.GetFileNameWithoutExtension(application);
        var scriptKey = decision.ScriptBindingKey.Trim();
        var scriptPath = (decision.ScriptPath ?? string.Empty).Trim();
        if (scriptKey.Length == 0)
        {
            return new Ack { Ok = false, Message = "script identity is required", ErrorCode = "hostsguard.error.v1/invalid_command_line" };
        }

        var protoIsPortable = decision.Protocol is "TCP" or "UDP";
        string remote;
        string protocol;
        int remotePort;

        if (action == "Allow")
        {
            remote = (decision.RemoteAddress ?? string.Empty).Trim();
            if (!FirewallAddress.IsValid(remote))
            {
                return new Ack { Ok = false, Message = $"'{decision.RemoteAddress}' is not a valid IP/CIDR/range", ErrorCode = "hostsguard.error.v1/invalid_address" };
            }

            protocol = protoIsPortable ? decision.Protocol : "Any";
            remotePort = decision.RemotePort > 0 && protocol is "TCP" or "UDP" ? decision.RemotePort : 0;
        }
        else
        {
            remote = "Any";
            if (decision.ScopeRemote && decision.RemoteAddress.Length != 0)
            {
                if (!FirewallAddress.IsValid(decision.RemoteAddress))
                {
                    return new Ack { Ok = false, Message = $"'{decision.RemoteAddress}' is not a valid IP/CIDR/range", ErrorCode = "hostsguard.error.v1/invalid_address" };
                }

                remote = decision.RemoteAddress;
            }

            protocol = (decision.ScopeProtocol || decision.ScopePort) && protoIsPortable ? decision.Protocol : "Any";
            remotePort = decision.ScopePort && decision.RemotePort > 0 && protocol is "TCP" or "UDP" ? decision.RemotePort : 0;
        }

        var ports = remotePort > 0 && protocol is "TCP" or "UDP"
            ? remotePort.ToString(CultureInfo.InvariantCulture)
            : "Any";
        var (permanent, expiresUtc, label) = ResolveDuration(decision.Duration, decision.Permanent);
        var ruleName = action == "Allow"
            ? MakeCommandLineRuleName(action, stem, direction, scriptKey, permanent)
            : string.Empty;

        List<string> obsoleteNames;
        lock (_gate)
        {
            obsoleteNames = _state.CommandLineRules
                .Where(r => ShouldReplaceCommandLineRule(r, application, scriptKey, direction, action, remote, protocol, remotePort))
                .Select(r => r.RuleName)
                .Where(n => n.Length != 0 && !n.Equals(ruleName, StringComparison.Ordinal))
                .Distinct(StringComparer.Ordinal)
                .ToList();
            _state.CommandLineRules.RemoveAll(r => ShouldReplaceCommandLineRule(r, application, scriptKey, direction, action, remote, protocol, remotePort));
            _onceRules.RemoveAll(r => obsoleteNames.Contains(r.RuleName, StringComparer.Ordinal));

            _state.CommandLineRules.Add(new CommandLineRule
            {
                Application = application,
                ScriptKey = scriptKey,
                ScriptPath = scriptPath,
                Direction = direction,
                Action = action,
                RemoteAddress = remote,
                RemotePort = remotePort,
                Protocol = protocol,
                RuleName = ruleName,
                ExpiresUtc = permanent ? null : expiresUtc,
            });

            if (ruleName.Length != 0 && !permanent)
            {
                _onceRules.Add((ruleName, expiresUtc));
            }

            SaveState();
        }

        foreach (var oldName in obsoleteNames)
        {
            DeleteRuleTracked(fw, oldName);
            _db.RemoveFwState(oldName);
        }

        var written = true;
        if (ruleName.Length != 0)
        {
            if (fw.RuleExists(ruleName))
            {
                written = false;
            }
            else
            {
                written = CreateRuleTracked(fw, new FwRule(
                    ruleName,
                    direction,
                    action,
                    true,
                    remote,
                    protocol,
                    application,
                    "hostsguard",
                    RemotePorts: ports));
                if (written)
                {
                    _db.UpsertFwState(ruleName, direction, action, remote, protocol, application, ports);
                    _identity?.Remember(ruleName, application);
                }
                else
                {
                    return new Ack { Ok = false, Message = $"failed to create {ruleName}", ErrorCode = "hostsguard.error.v1/firewall_rule_failed" };
                }
            }
        }

        LogDecision(application, direction, remote, protocol, verdict, permanent, provenance);
        if (action == "Block")
        {
            FlowTeardown?.CloseForProgram(application, "consent_cmd_block", remote == "Any" ? null : remote, remotePort);
        }

        var scriptLabel = scriptPath.Length != 0 ? scriptPath : "script";
        return new Ack
        {
            Ok = true,
            Message = action == "Allow"
                ? $"{verdict} {stem} for {scriptLabel} ({label}) - {ruleName}"
                : $"{verdict} {stem} for {scriptLabel} ({label})",
        };

        static bool ShouldReplaceCommandLineRule(
            CommandLineRule rule,
            string app,
            string script,
            string dir,
            string newAction,
            string newRemote,
            string newProtocol,
            int newPort)
        {
            if (!rule.Application.Equals(app, StringComparison.OrdinalIgnoreCase)
                || !rule.ScriptKey.Equals(script, StringComparison.OrdinalIgnoreCase)
                || !rule.Direction.Equals(dir, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            if (newAction == "Block" && newRemote == "Any" && newProtocol == "Any" && newPort == 0)
            {
                return true;
            }

            if (rule.Action.Equals("Block", StringComparison.OrdinalIgnoreCase)
                && RuleCovers(rule, newRemote, newProtocol, newPort))
            {
                return true;
            }

            return rule.RemoteAddress.Equals(newRemote, StringComparison.OrdinalIgnoreCase)
                   && rule.Protocol.Equals(newProtocol, StringComparison.OrdinalIgnoreCase)
                   && rule.RemotePort == newPort;
        }

        static bool RuleCovers(CommandLineRule rule, string remote, string protocol, int port)
        {
            if (rule.RemoteAddress is not ("" or "Any")
                && !rule.RemoteAddress.Equals(remote, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            if (rule.Protocol is not ("" or "Any")
                && !rule.Protocol.Equals(protocol, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            return rule.RemotePort <= 0 || rule.RemotePort == port;
        }
    }

    private static string MakeCommandLineRuleName(string action, string stem, string direction, string scriptKey, bool permanent)
    {
        var prefix = permanent ? CommandLinePrefix : CommandLineOncePrefix;
        var hash = ShortHash(scriptKey);
        var suffix = permanent ? string.Empty : "_" + Guid.NewGuid().ToString("N")[..8];
        return $"{prefix}{action}_{stem}_{hash}_{direction}{suffix}";
    }

    private static string ShortHash(string value)
    {
        var bytes = SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(value));
        return Convert.ToHexString(bytes)[..12];
    }
}
