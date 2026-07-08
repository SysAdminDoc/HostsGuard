using FluentAssertions;
using HostsGuard.Core;
using Xunit;

namespace HostsGuard.Core.Tests;

public sealed class DecisionExplainerTests
{
    [Fact]
    public void Firewall_rule_evidence_includes_interface_scope()
    {
        var input = new DecisionInput(
            Domain: string.Empty,
            RemoteAddress: "203.0.113.10",
            RemotePort: 443,
            Protocol: "TCP",
            ProgramPath: @"C:\Apps\sync.exe",
            Process: "sync.exe",
            Direction: "Out",
            Signer: string.Empty,
            Service: string.Empty);
        var policy = new DecisionPolicyFacts(
            DomainStatus: null,
            DomainSource: null,
            RootStatus: null,
            RootSource: null,
            Rules:
            [
                new FwRule(
                    "HG_VPNBind_test",
                    "Out",
                    "Block",
                    true,
                    "Any",
                    "TCP",
                    @"C:\Apps\sync.exe",
                    "hostsguard",
                    Interfaces: "Ethernet")
            ],
            DomainFirewallRules: [],
            RuleGroups: new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal),
            Profiles: [],
            ActiveProfile: string.Empty,
            TrustedPublishers: [],
            TrustedFolders: [],
            KillSwitchEnabled: false,
            KillSwitchEngaged: false,
            KillSwitchAdapter: string.Empty);

        var result = DecisionExplainer.Explain(input, policy);

        result.Steps.Should().Contain(s =>
            s.Layer == "Firewall rule" &&
            s.Owner == "HG_VPNBind_test" &&
            s.Detail.Contains("interfaces=Ethernet", StringComparison.Ordinal));
    }
}
