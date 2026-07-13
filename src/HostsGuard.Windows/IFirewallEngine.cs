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

    IReadOnlyList<FwAppPackage> ListPackages();

    IReadOnlyList<FwInterfaceAlias> ListInterfaceAliases() => Array.Empty<FwInterfaceAlias>();

    bool CreateRule(FwRule rule);

    /// <summary>Replace one existing rule while restoring the prior rule if replacement fails.</summary>
    bool ReplaceRule(FwRule rule) => false;

    bool DeleteRule(string name);

    bool SetRuleEnabled(string name, bool enabled);

    bool RuleExists(string name);

    /// <summary>Per-profile enabled + default-outbound posture (Domain/Private/Public).</summary>
    IReadOnlyList<FwProfilePosture> GetPosture();

    /// <summary>Inbound posture for profiles active on the current network.</summary>
    IReadOnlyList<InboundFirewallProfile> GetActiveInboundProfiles() => Array.Empty<InboundFirewallProfile>();

    /// <summary>Whether local firewall policy can be modified or is overridden by machine policy.</summary>
    FirewallLocalPolicyModifyState GetLocalPolicyModifyState() => FirewallLocalPolicyModifyState.Ok;

    /// <summary>
    /// Set DefaultOutboundAction on every profile (lockdown on/off). Idempotent:
    /// profiles already in the requested state are not touched. Never changes
    /// FirewallEnabled — HostsGuard owns the outbound default, not the firewall
    /// on/off switch (the WFC-conflict lesson).
    /// </summary>
    void SetDefaultOutboundBlock(bool block);

    /// <summary>
    /// Restore DefaultOutboundAction per profile (by name: Domain/Private/Public),
    /// so a mixed prior posture round-trips faithfully instead of collapsing.
    /// </summary>
    void SetDefaultOutboundBlock(IReadOnlyDictionary<string, bool> perProfile);

    /// <summary>Re-target an existing rule's program path (orphan rebind).</summary>
    bool SetRuleProgram(string name, string programPath);

    /// <summary>Replace an existing rule's remote-address set.</summary>
    bool SetRuleRemoteAddresses(string name, string remoteAddresses);
}
