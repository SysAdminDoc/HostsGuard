using System.Text;
using FluentAssertions;
using Google.Protobuf.Reflection;
using Xunit;

namespace HostsGuard.Contracts.Tests;

/// <summary>
/// Schema lock: snapshots the full RPC surface (package, services, methods,
/// streaming, request/response types) from the generated file descriptor. Any
/// breaking or accidental change to hostsguard.proto flips this test red, so the
/// UI/CLI/Service contract can only change deliberately.
/// </summary>
public class SchemaLockTests
{
    private const string Expected = """
        package hostsguard.v1
        service Consent
          ApplyBaseline(Empty) returns (Ack)
          Decide(ConnectionDecision) returns (Ack)
          GetBaseline(Empty) returns (BaselineList)
          GetDecisionHistory(HistoryRequest) returns (DecisionHistory)
          GetLearned(Empty) returns (LearnedList)
          GetMode(Empty) returns (FilteringMode)
          GetTrustedFolders(Empty) returns (FolderList)
          GetTrustedPublishers(Empty) returns (PublisherList)
          ReviewLearned(LearnedReviewRequest) returns (Ack)
          SetChildInherit(ChildInheritRequest) returns (Ack)
          SetInboundConsent(InboundConsentRequest) returns (Ack)
          SetMode(FilteringMode) returns (Ack)
          SetTrustedFolders(FolderList) returns (Ack)
          SetTrustedPublishers(PublisherList) returns (Ack)
          WatchDecisions(Empty) returns (stream ConnectionDecisionRequest)
        service Diagnostics
          ExportSupportBundle(SupportBundleRequest) returns (Ack)
          GetDefenderStatus(Empty) returns (DefenderStatus)
          GetStatus(Empty) returns (ServiceStatus)
          GetUpdateStatus(Empty) returns (UpdateStatus)
          StageUpdate(StageUpdateRequest) returns (Ack)
        service DnsControl
          FlushCache(Empty) returns (Ack)
          FlushCacheEntry(DnsCacheEntryRequest) returns (Ack)
          GetDohStatus(Empty) returns (DohStatus)
          Inspect(DomainRequest) returns (DnsInspectResult)
          ListCache(DnsCacheRequest) returns (DnsCacheList)
          RefreshDohIntelligence(DohRefreshRequest) returns (Ack)
          ResolveHosts(ResolveHostsRequest) returns (ResolveHostsResult)
          SetCnameCloak(CnameCloakRequest) returns (Ack)
          SetResolver(ResolverRequest) returns (Ack)
          SetSniCapture(SniCaptureRequest) returns (Ack)
        service FirewallControl
          AdoptFirewallRules(Empty) returns (AdoptResult)
          AssignRuleGroup(RuleGroupAssignment) returns (Ack)
          BlockAppScope(AppScopeRequest) returns (Ack)
          BlockEncryptedDns(DohBlockRequest) returns (Ack)
          BlockIp(FirewallIpRequest) returns (Ack)
          BlockProgram(FirewallProgramRequest) returns (Ack)
          BlockQuic(Empty) returns (Ack)
          CloseConnection(FlowCloseRequest) returns (Ack)
          CreateDomainFirewallRule(DomainFirewallRuleRequest) returns (Ack)
          CreateRule(FirewallRule) returns (Ack)
          DeleteDomainFirewallRule(RuleNameRequest) returns (Ack)
          DeleteRule(RuleNameRequest) returns (Ack)
          ExplainDecision(DecisionExplainRequest) returns (DecisionExplanation)
          GetAppVpnBindings(Empty) returns (AppVpnBindingStatus)
          GetEnforcementPause(Empty) returns (EnforcementPauseStatus)
          GetFlowTeardown(Empty) returns (FlowTeardownStatus)
          GetKillSwitch(Empty) returns (KillSwitchStatus)
          GetLanAttackSurface(Empty) returns (LanAttackSurfaceStatus)
          GetPosture(Empty) returns (FirewallPosture)
          GetSecureRules(Empty) returns (SecureRulesStatus)
          ListAppPackages(Empty) returns (AppPackageList)
          ListDomainFirewallRules(Empty) returns (DomainFirewallRuleList)
          ListRuleGroups(Empty) returns (RuleGroupList)
          ListRules(Empty) returns (FirewallRuleList)
          PauseEnforcement(EnforcementPauseRequest) returns (Ack)
          RebindRule(RebindRequest) returns (Ack)
          RefreshDomainFirewallRules(Empty) returns (Ack)
          SetAppVpnBinding(AppVpnBindingRequest) returns (Ack)
          SetDefaultOutbound(OutboundRequest) returns (Ack)
          SetFlowTeardown(FlowTeardownRequest) returns (Ack)
          SetGlobalMode(GlobalModeRequest) returns (Ack)
          SetKillSwitch(KillSwitchRequest) returns (Ack)
          SetLanAttackSurface(LanAttackSurfaceRequest) returns (Ack)
          SetRuleEnabled(RuleEnabledRequest) returns (Ack)
          SetSecureRules(SecureRulesRequest) returns (Ack)
          SuggestRebind(RuleNameRequest) returns (RebindSuggestions)
          ToggleRuleGroup(RuleGroupToggle) returns (Ack)
          UnblockAppScope(AppScopeRequest) returns (Ack)
          UnblockEncryptedDns(Empty) returns (Ack)
          UnblockQuic(Empty) returns (Ack)
        service HostsControl
          AddDefenderExclusion(Empty) returns (Ack)
          Allow(DomainRequest) returns (Ack)
          AllowMany(BulkDomainsRequest) returns (BulkResult)
          BackupHosts(Empty) returns (Ack)
          Block(DomainRequest) returns (Ack)
          BlockMany(BulkDomainsRequest) returns (BulkResult)
          BlockRoot(DomainRequest) returns (Ack)
          CategorizeDomains(CategorizeRequest) returns (CategorizeResult)
          EmergencyReset(Empty) returns (Ack)
          ExportAiKnowledge(Empty) returns (HostsText)
          GetActivity(ActivityRequest) returns (ActivityList)
          GetAiStatus(Empty) returns (AiStatus)
          GetHostsText(Empty) returns (HostsText)
          GetSparkline(DomainRequest) returns (Sparkline)
          HardenAcl(Empty) returns (Ack)
          HideDomains(HideDomainsRequest) returns (Ack)
          HideRoot(DomainRequest) returns (Ack)
          IdentifyConnections(IdentifyRequest) returns (IdentifyResult)
          ListAiKnowledge(AiKnowledgeRequest) returns (AiKnowledgeList)
          ListBackups(Empty) returns (BackupList)
          ListDomains(ListDomainsRequest) returns (DomainList)
          ListTempAllows(Empty) returns (TempAllowList)
          OverrideKnowledge(KnowledgeOverrideRequest) returns (Ack)
          PromoteKnowledge(KnowledgeReviewRequest) returns (Ack)
          Reconcile(ReconcileRequest) returns (Ack)
          ResearchPurposes(Empty) returns (CategorizeResult)
          RestoreBackup(BackupRequest) returns (Ack)
          SetAiConfig(AiConfig) returns (Ack)
          SetHostsText(HostsText) returns (Ack)
          TempAllow(TempAllowRequest) returns (Ack)
          Unblock(DomainRequest) returns (Ack)
          UnhideDomains(HideDomainsRequest) returns (Ack)
          UnhideRoot(DomainRequest) returns (Ack)
        service ListControl
          GetAllowlists(Empty) returns (AllowlistUrls)
          GetBlocklistIntelligence(Empty) returns (BlocklistIntelStatus)
          ImportBlocklist(BlocklistRequest) returns (BlocklistResult)
          ImportIpBlocklist(BlocklistRequest) returns (IpBlocklistResult)
          ListBlocklistSources(Empty) returns (BlocklistSources)
          ListIpBlocklists(Empty) returns (IpBlocklistList)
          PreviewBlocklist(BlocklistRequest) returns (BlocklistResult)
          RefreshAllowlists(Empty) returns (Ack)
          RefreshBlocklistIntelligence(Empty) returns (Ack)
          RefreshBlocklists(Empty) returns (BlocklistResult)
          RefreshGeoIp(Empty) returns (Ack)
          RefreshIpBlocklists(Empty) returns (IpBlocklistResult)
          RefreshThreatIntel(Empty) returns (Ack)
          RemoveBlocklistSubscription(BlocklistRequest) returns (Ack)
          RemoveIpBlocklist(BlocklistRequest) returns (Ack)
          RestoreBlocklistCheckpoint(BlocklistRequest) returns (Ack)
          RollbackIpBlocklist(BlocklistRequest) returns (IpBlocklistResult)
          SetAllowlists(AllowlistUrls) returns (Ack)
          SetBlocklistEnabled(BlocklistToggleRequest) returns (Ack)
          SetIpBlocklistEnabled(BlocklistToggleRequest) returns (Ack)
        service Monitoring
          AckAlert(AlertAckRequest) returns (Ack)
          ClearConnectionHistory(Empty) returns (Ack)
          DeleteUsageQuotaRule(UsageQuotaRule) returns (Ack)
          ExportTrafficProfile(TrafficProfileRequest) returns (TrafficProfileExport)
          ExportUsageQuotaHistory(UsageQuotaHistoryRequest) returns (UsageQuotaHistoryExport)
          GetAppBandwidth(BandwidthRequest) returns (AppBandwidthList)
          GetConnectionHistory(ConnectionHistoryRequest) returns (ConnectionHistoryList)
          GetHistorySettings(Empty) returns (HistorySettings)
          GetUsageQuotaRules(Empty) returns (UsageQuotaRuleList)
          GetUsageRollups(UsageRollupRequest) returns (UsageRollupList)
          ListAlertTypes(Empty) returns (AlertTypeList)
          ListAlerts(AlertRequest) returns (AlertList)
          ListEvents(EventLogRequest) returns (EventLogList)
          ResetUsageQuotaHistory(Empty) returns (Ack)
          SetAlertType(AlertTypeRequest) returns (Ack)
          SetHistorySettings(HistorySettings) returns (Ack)
          SetUsageQuotaRule(UsageQuotaRule) returns (Ack)
          WatchConnections(Empty) returns (stream ConnectionEvent)
          WatchDns(Empty) returns (stream DnsEvent)
          WatchEvents(Empty) returns (stream ActivityEvent)
        service Policy
          ApplyPolicySubscription(PolicySubscriptionRequest) returns (ImportPolicyResult)
          DeletePolicySubscription(PolicySubscriptionRequest) returns (Ack)
          DeleteProfile(ProfileRequest) returns (Ack)
          ExportPolicy(Empty) returns (PolicyDocument)
          GetCurrentNetwork(Empty) returns (CurrentNetwork)
          GetLockState(Empty) returns (LockState)
          GetNetworkProfiles(Empty) returns (NetworkProfileMap)
          GetSchedules(Empty) returns (ScheduleList)
          ImportPolicy(ImportPolicyRequest) returns (ImportPolicyResult)
          ListPolicySubscriptions(Empty) returns (PolicySubscriptionList)
          ListProfiles(Empty) returns (ProfileList)
          ListServices(Empty) returns (ServiceStates)
          PreviewPolicyImport(ImportPolicyRequest) returns (ImportPolicyResult)
          PreviewPolicySubscription(PolicySubscriptionRequest) returns (ImportPolicyResult)
          RefreshPolicySubscriptions(Empty) returns (ImportPolicyResult)
          RestorePolicyCheckpoint(Empty) returns (ImportPolicyResult)
          RollbackPolicySubscription(PolicySubscriptionRequest) returns (ImportPolicyResult)
          SavePolicySubscription(PolicySubscriptionRequest) returns (Ack)
          SaveProfile(ProfileRequest) returns (Ack)
          SetHostsProtection(HostsProtectionRequest) returns (Ack)
          SetLock(LockRequest) returns (Ack)
          SetNetworkProfile(NetworkProfileEntry) returns (Ack)
          SetSchedules(ScheduleList) returns (Ack)
          SwitchProfile(ProfileRequest) returns (Ack)
          ToggleService(ServiceToggleRequest) returns (Ack)
          Unlock(LockRequest) returns (Ack)
        """;

    [Fact]
    public void Rpc_surface_matches_locked_snapshot()
    {
        var fd = HostsguardReflection.Descriptor;
        var sb = new StringBuilder();
        sb.Append("package ").Append(fd.Package).Append('\n');

        foreach (var svc in fd.Services.OrderBy(s => s.Name, StringComparer.Ordinal))
        {
            sb.Append("service ").Append(svc.Name).Append('\n');
            foreach (var m in svc.Methods.OrderBy(m => m.Name, StringComparer.Ordinal))
            {
                var input = m.IsClientStreaming ? $"stream {m.InputType.Name}" : m.InputType.Name;
                var output = m.IsServerStreaming ? $"stream {m.OutputType.Name}" : m.OutputType.Name;
                sb.Append("  ").Append(m.Name).Append('(').Append(input).Append(") returns (").Append(output).Append(")\n");
            }
        }

        sb.ToString().TrimEnd('\n').Should().Be(Expected.ReplaceLineEndings("\n").TrimEnd('\n'));
    }

    [Fact]
    public void Package_is_versioned() =>
        HostsguardReflection.Descriptor.Package.Should().Be("hostsguard.v1");
}
