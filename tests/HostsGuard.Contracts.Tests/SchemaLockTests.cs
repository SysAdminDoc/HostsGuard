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
        service Diagnostics
          ExportSupportBundle(Empty) returns (Ack)
          GetDefenderStatus(Empty) returns (DefenderStatus)
          GetStatus(Empty) returns (ServiceStatus)
        service DnsControl
          FlushCache(Empty) returns (Ack)
          GetDohStatus(Empty) returns (DohStatus)
          Inspect(DomainRequest) returns (DnsInspectResult)
          RefreshDohIntelligence(DohRefreshRequest) returns (Ack)
          SetResolver(ResolverRequest) returns (Ack)
        service FirewallControl
          BlockEncryptedDns(DohBlockRequest) returns (Ack)
          BlockIp(FirewallIpRequest) returns (Ack)
          BlockProgram(FirewallProgramRequest) returns (Ack)
          CreateRule(FirewallRule) returns (Ack)
          DeleteRule(RuleNameRequest) returns (Ack)
          GetPosture(Empty) returns (FirewallPosture)
          ListRules(Empty) returns (FirewallRuleList)
          RebindRule(RebindRequest) returns (Ack)
          SetDefaultOutbound(OutboundRequest) returns (Ack)
          SetRuleEnabled(RuleEnabledRequest) returns (Ack)
          SuggestRebind(RuleNameRequest) returns (RebindSuggestions)
          UnblockEncryptedDns(Empty) returns (Ack)
        service HostsControl
          AddDefenderExclusion(Empty) returns (Ack)
          Allow(DomainRequest) returns (Ack)
          BackupHosts(Empty) returns (Ack)
          Block(DomainRequest) returns (Ack)
          BlockRoot(DomainRequest) returns (Ack)
          EmergencyReset(Empty) returns (Ack)
          GetActivity(ActivityRequest) returns (ActivityList)
          GetHostsText(Empty) returns (HostsText)
          HardenAcl(Empty) returns (Ack)
          HideRoot(DomainRequest) returns (Ack)
          ListBackups(Empty) returns (BackupList)
          ListDomains(ListDomainsRequest) returns (DomainList)
          ListTempAllows(Empty) returns (TempAllowList)
          Reconcile(ReconcileRequest) returns (Ack)
          RestoreBackup(BackupRequest) returns (Ack)
          SetHostsText(HostsText) returns (Ack)
          TempAllow(TempAllowRequest) returns (Ack)
          Unblock(DomainRequest) returns (Ack)
          UnhideRoot(DomainRequest) returns (Ack)
        service ListControl
          GetAllowlists(Empty) returns (AllowlistUrls)
          ImportBlocklist(BlocklistRequest) returns (BlocklistResult)
          ListBlocklistSources(Empty) returns (BlocklistSources)
          RefreshAllowlists(Empty) returns (Ack)
          RefreshBlocklists(Empty) returns (BlocklistResult)
          RefreshGeoIp(Empty) returns (Ack)
          RefreshThreatIntel(Empty) returns (Ack)
          RemoveBlocklistSubscription(BlocklistRequest) returns (Ack)
          SetAllowlists(AllowlistUrls) returns (Ack)
        service Monitoring
          WatchConnections(Empty) returns (stream ConnectionEvent)
          WatchDns(Empty) returns (stream DnsEvent)
          WatchEvents(Empty) returns (stream ActivityEvent)
        service Policy
          DeleteProfile(ProfileRequest) returns (Ack)
          GetSchedules(Empty) returns (ScheduleList)
          ListProfiles(Empty) returns (ProfileList)
          ListServices(Empty) returns (ServiceStates)
          SaveProfile(ProfileRequest) returns (Ack)
          SetSchedules(ScheduleList) returns (Ack)
          SwitchProfile(ProfileRequest) returns (Ack)
          ToggleService(ServiceToggleRequest) returns (Ack)
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
