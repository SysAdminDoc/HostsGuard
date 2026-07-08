namespace HostsGuard.Core;

/// <summary>
/// Canonical event-action taxonomy for the structured log (NET-063). Every
/// <c>LogEvent(action:...)</c> value the service emits should come from here so
/// the event stream is consistent, groupable for local-only metrics, and
/// documented in one place. <see cref="Category"/> buckets an action for the
/// diagnostics summary; unknown actions fall back to <see cref="Categories.Other"/>.
/// </summary>
public static class EventTaxonomy
{
    /// <summary>Coarse buckets for grouping actions in the diagnostics summary.</summary>
    public static class Categories
    {
        public const string Hosts = "hosts";
        public const string Firewall = "firewall";
        public const string Consent = "consent";
        public const string Dns = "dns";
        public const string Lists = "lists";
        public const string Policy = "policy";
        public const string Defender = "defender";
        public const string Support = "support";
        public const string Other = "other";
    }

    // Hosts
    public const string Blocked = "blocked";
    public const string Whitelisted = "whitelisted";
    public const string RawEdit = "raw_edit";
    public const string AclHardened = "acl_hardened";
    public const string BackupRestored = "backup_restored";

    // Firewall
    public const string FwBlocked = "fw_blocked";
    public const string FwUnblocked = "fw_unblocked";
    public const string FwRebound = "fw_rebound";
    public const string FwRuleAdded = "fw_rule_added";
    public const string FwRuleChanged = "fw_rule_changed";
    public const string FwRuleVanished = "fw_rule_vanished";
    public const string FwFlowTeardown = "fw_flow_teardown";
    public const string LockdownOn = "lockdown_on";
    public const string LockdownOff = "lockdown_off";
    public const string EnforcementPaused = "enforcement_paused";
    public const string EnforcementResumed = "enforcement_resumed";

    // Consent (WFC parity)
    public const string ConsentAllow = "consent_allow";
    public const string ConsentBlock = "consent_block";
    public const string ConsentLearn = "consent_learn";
    public const string ConsentTimeout = "consent_timeout";
    public const string ConsentOnceReaped = "consent_once_reaped";
    public const string ModeChanged = "mode_changed";
    public const string PostureRestoredOnStop = "posture_restored_on_stop";

    // Defender / support
    public const string ExclusionAdded = "exclusion_added";
    public const string BundleExport = "bundle_export";

    /// <summary>Map an action to its coarse category for grouped metrics.</summary>
    public static string Category(string? action)
    {
        var a = (action ?? string.Empty).ToLowerInvariant();
        if (a.Length == 0)
        {
            return Categories.Other;
        }

        if (a.StartsWith("consent", StringComparison.Ordinal) || a is ModeChanged or PostureRestoredOnStop)
        {
            return Categories.Consent;
        }

        if (a.StartsWith("fw_", StringComparison.Ordinal) || a is LockdownOn or LockdownOff)
        {
            return Categories.Firewall;
        }

        if (a is Blocked or Whitelisted or RawEdit or AclHardened or BackupRestored)
        {
            return Categories.Hosts;
        }

        if (a is ExclusionAdded || a.Contains("defender", StringComparison.Ordinal))
        {
            return Categories.Defender;
        }

        if (a is BundleExport || a.StartsWith("support", StringComparison.Ordinal))
        {
            return Categories.Support;
        }

        if (a.Contains("doh", StringComparison.Ordinal) || a.Contains("dns", StringComparison.Ordinal) || a.Contains("resolver", StringComparison.Ordinal))
        {
            return Categories.Dns;
        }

        if (a.Contains("blocklist", StringComparison.Ordinal) || a.Contains("allowlist", StringComparison.Ordinal) || a.Contains("list", StringComparison.Ordinal))
        {
            return Categories.Lists;
        }

        if (a.StartsWith("enforcement_", StringComparison.Ordinal)
            || a.Contains("profile", StringComparison.Ordinal) || a.Contains("schedule", StringComparison.Ordinal)
            || a.Contains("lock", StringComparison.Ordinal) || a is "imported")
        {
            return Categories.Policy;
        }

        return Categories.Other;
    }
}
