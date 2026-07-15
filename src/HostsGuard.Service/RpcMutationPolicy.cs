namespace HostsGuard.Service;

/// <summary>The settings-lock behavior assigned to every published service RPC.</summary>
public enum RpcMutationKind
{
    ReadOnly,
    ProtectiveMutation,
    LockProtectedMutation,
}

/// <summary>
/// Explicit settings-lock classification for the complete gRPC contract. A
/// protective mutation is intentionally available while locked because it is
/// read-like operational maintenance, strengthens posture, or is required to
/// authenticate/recover the lock itself. All policy-changing or potentially
/// weakening mutations are lock-protected.
/// </summary>
public static class RpcMutationPolicy
{
    private const string Package = "hostsguard.v1";

    public static IReadOnlyDictionary<string, RpcMutationKind> All { get; } = Build();

    public static string Key(string service, string method) => $"{Package}.{service}/{method}";

    public static RpcMutationKind GetRequired(string service, string method)
    {
        var key = Key(service, method);
        return All.TryGetValue(key, out var kind)
            ? kind
            : throw new InvalidOperationException($"RPC mutation policy is missing for {key}");
    }

    private static IReadOnlyDictionary<string, RpcMutationKind> Build()
    {
        var policies = new Dictionary<string, RpcMutationKind>(StringComparer.Ordinal);

        Add(policies, "Diagnostics", RpcMutationKind.ReadOnly,
            "GetStatus", "CheckCaptivePortal", "GetDefenderStatus", "GetUpdateStatus", "InspectProxyBaseline",
            "GetHyperVFirewallCoverage");
        Add(policies, "Diagnostics", RpcMutationKind.ProtectiveMutation, "ExportSupportBundle");
        Add(policies, "Diagnostics", RpcMutationKind.LockProtectedMutation, "StageUpdate", "AcceptProxyBaseline");

        Add(policies, "Recovery", RpcMutationKind.ReadOnly, "ListFullStateSnapshots", "PreviewFullStateRestore");
        Add(policies, "Recovery", RpcMutationKind.ProtectiveMutation, "CreateFullStateSnapshot");
        Add(policies, "Recovery", RpcMutationKind.LockProtectedMutation, "RestoreFullStateSnapshot");

        Add(policies, "HostsControl", RpcMutationKind.ReadOnly,
            "ListDomains", "ListRedirects", "ListTempAllows", "ListTempBlocks", "GetHostsText", "GetActivity", "GetSparkline", "ListBackups",
            "GetAiStatus", "GetHostsAdoptionStatus", "ExportAiKnowledge", "ListAiKnowledge");
        Add(policies, "HostsControl", RpcMutationKind.ProtectiveMutation,
            "Block", "BlockRoot", "BlockMany", "TempBlock", "HideRoot", "UnhideRoot", "HideDomains",
            "UnhideDomains", "BackupHosts", "HardenAcl", "ResearchPurposes", "IdentifyConnections",
            "PromoteKnowledge", "OverrideKnowledge");
        Add(policies, "HostsControl", RpcMutationKind.LockProtectedMutation,
            "Allow", "Unblock", "AllowMany", "Reconcile", "EmergencyReset", "TempAllow", "SetHostsText",
            "SetAiConfig", "CategorizeDomains", "AdoptHostsEntries", "SetHostsAdoption", "RestoreBackup",
            "AddDefenderExclusion", "PinRedirect", "RemoveRedirect");

        Add(policies, "ListControl", RpcMutationKind.ReadOnly,
            "ListBlocklistSources", "PreviewBlocklist", "PreviewBlocklistContent", "GetAllowlists",
            "GetBlocklistIntelligence", "ListIpBlocklists");
        Add(policies, "ListControl", RpcMutationKind.ProtectiveMutation,
            "ImportBlocklist", "ImportBlocklistContent", "RefreshThreatIntel", "RefreshGeoIp",
            "RefreshBlocklistIntelligence", "ImportIpBlocklist");
        Add(policies, "ListControl", RpcMutationKind.LockProtectedMutation,
            "SetBlocklistEnabled", "SetBlocklistMirrors", "RemoveBlocklistSubscription", "RestoreBlocklistCheckpoint", "RefreshBlocklists",
            "RecoverWindowsConnectivity", "SetAllowlists", "RefreshAllowlists", "SetIpBlocklistEnabled",
            "RemoveIpBlocklist", "RefreshIpBlocklists", "RollbackIpBlocklist");

        Add(policies, "FirewallControl", RpcMutationKind.ReadOnly,
            "ListRuleGroups", "AnalyzeRules", "ExplainDecision", "ListAppPackages", "ListInterfaceAliases",
            "ListRules", "GetPosture", "GetEnforcementPause", "GetSecureRules", "SuggestRebind",
            "ListDomainFirewallRules", "GetFlowTeardown", "GetLanAttackSurface", "GetKillSwitch",
            "GetAppVpnBindings");
        Add(policies, "FirewallControl", RpcMutationKind.ProtectiveMutation,
            "BlockIp", "BlockProgram", "BlockEncryptedDns", "BlockQuic", "BlockAppScope",
            "CreateDomainFirewallRule", "RefreshDomainFirewallRules", "CloseConnection");
        Add(policies, "FirewallControl", RpcMutationKind.LockProtectedMutation,
            "AdoptFirewallRules", "AssignRuleGroup", "ToggleRuleGroup", "CreateRule", "DeleteRule",
            "SetRuleEnabled", "UpdateRule", "ApplyRuleCleanup", "UnblockEncryptedDns", "UnblockQuic",
            "SetDefaultOutbound", "PauseEnforcement", "SetSecureRules", "ResolveSecureRuleConflict", "RebindRule",
            "SetGlobalMode", "UnblockAppScope", "DeleteDomainFirewallRule", "SetFlowTeardown",
            "SetLanAttackSurface", "SetKillSwitch", "SetAppVpnBinding");

        Add(policies, "DnsControl", RpcMutationKind.ReadOnly,
            "GetDohStatus", "GetIdnHomographStatus", "Inspect", "ListCache", "ResolveHosts",
            "ListResolverAdapters", "GetResolverHealth", "RunResolverHealth");
        Add(policies, "DnsControl", RpcMutationKind.ProtectiveMutation,
            "FlushCache", "FlushCacheEntry", "RefreshDohIntelligence");
        Add(policies, "DnsControl", RpcMutationKind.LockProtectedMutation,
            "SetCnameCloak", "SetIdnHomograph", "SetResolverHealthSchedule", "SetResolver", "SetSniCapture");

        Add(policies, "Monitoring", RpcMutationKind.ReadOnly,
            "WatchDns", "WatchConnections", "WatchEvents", "GetConnectionHistory", "ListEvents", "ListListeners",
            "ListAlerts", "ListAlertTypes", "GetAppBandwidth", "GetHistorySettings", "GetUsageRollups",
            "GetUsageQuotaRules", "ExportUsageQuotaHistory", "ListHistoryPrivacyExclusions", "ExportTrafficProfile");
        Add(policies, "Monitoring", RpcMutationKind.ProtectiveMutation,
            "ClearConnectionHistory", "AckAlert", "ResetUsageQuotaHistory");
        Add(policies, "Monitoring", RpcMutationKind.LockProtectedMutation,
            "SetAlertType", "SetUsageQuotaRule", "DeleteUsageQuotaRule", "SetHistoryPrivacyExclusion",
            "DeleteHistoryPrivacyExclusion", "SetHistorySettings");

        Add(policies, "Consent", RpcMutationKind.ReadOnly,
            "WatchDecisions", "GetMode", "GetDecisionHistory", "GetBaseline", "GetLearned",
            "GetTrustedPublishers", "GetTrustedFolders");
        Add(policies, "Consent", RpcMutationKind.LockProtectedMutation,
            "Decide", "SetMode", "ApplyBaseline", "ReviewLearned", "SetChildInherit", "SetInboundConsent",
            "SetTrustedPublishers", "SetTrustedFolders");

        Add(policies, "Policy", RpcMutationKind.ReadOnly,
            "ListProfiles", "GetSchedules", "ListServices", "GetLockState", "GetCurrentNetwork",
            "GetNetworkProfiles", "ExportPolicy", "PreviewPolicyImport", "ListPolicySubscriptions",
            "PreviewPolicySubscription");
        Add(policies, "Policy", RpcMutationKind.ProtectiveMutation, "SetLock", "Unlock", "SetHostsProtection");
        Add(policies, "Policy", RpcMutationKind.LockProtectedMutation,
            "SwitchProfile", "SetSchedules", "ToggleService", "SaveProfile", "DeleteProfile", "SetNetworkProfile",
            "ImportPolicy", "RestorePolicyCheckpoint", "SavePolicySubscription", "DeletePolicySubscription",
            "ApplyPolicySubscription", "RefreshPolicySubscriptions", "RollbackPolicySubscription");

        return policies;
    }

    private static void Add(
        IDictionary<string, RpcMutationKind> policies,
        string service,
        RpcMutationKind kind,
        params string[] methods)
    {
        foreach (var method in methods)
        {
            var key = Key(service, method);
            if (!policies.TryAdd(key, kind))
            {
                throw new InvalidOperationException($"RPC mutation policy is duplicated for {key}");
            }
        }
    }
}
