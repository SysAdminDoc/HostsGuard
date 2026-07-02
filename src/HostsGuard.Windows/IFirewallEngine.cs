using HostsGuard.Core;

namespace HostsGuard.Windows;

/// <summary>
/// Firewall mutation surface, interface-first so the service impls are testable
/// against an in-memory fake (real COM mutation requires elevation and is
/// covered by the admin-gated integration lane).
/// </summary>
public interface IFirewallEngine
{
    IReadOnlyList<FwRule> ListRules();

    bool CreateRule(FwRule rule);

    bool DeleteRule(string name);

    bool SetRuleEnabled(string name, bool enabled);

    bool RuleExists(string name);
}
