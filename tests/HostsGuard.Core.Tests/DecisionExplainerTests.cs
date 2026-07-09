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

    [Fact]
    public void Package_scoped_rule_requires_matching_package_identity()
    {
        var policy = new DecisionPolicyFacts(
            DomainStatus: null,
            DomainSource: null,
            RootStatus: null,
            RootSource: null,
            Rules:
            [
                new FwRule(
                    "HG_Package_Block_Contoso_Reader_Out",
                    "Out",
                    "Block",
                    true,
                    "Any",
                    "Any",
                    string.Empty,
                    "hostsguard",
                    PackageFamilyName: "Contoso.Reader_123abc",
                    PackageSid: "S-1-15-2-123",
                    PackageDisplayName: "Contoso Reader")
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
        var nonPackage = new DecisionInput(
            Domain: string.Empty,
            RemoteAddress: "203.0.113.10",
            RemotePort: 443,
            Protocol: "TCP",
            ProgramPath: string.Empty,
            Process: string.Empty,
            Direction: "Out",
            Signer: string.Empty,
            Service: string.Empty);

        DecisionExplainer.Explain(nonPackage, policy).Verdict.Should().Be("Allowed");

        var packageTraffic = nonPackage with { PackageFamilyName = "Contoso.Reader_123abc" };
        var blocked = DecisionExplainer.Explain(packageTraffic, policy);

        blocked.Verdict.Should().Be("Blocked");
        blocked.Steps.Should().Contain(s =>
            s.Layer == "Firewall rule" &&
            s.Owner == "HG_Package_Block_Contoso_Reader_Out" &&
            s.Detail.Contains("package Contoso Reader", StringComparison.Ordinal));
    }
}
