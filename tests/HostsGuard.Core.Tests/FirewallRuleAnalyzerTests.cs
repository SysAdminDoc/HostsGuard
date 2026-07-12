using FluentAssertions;
using HostsGuard.Core;
using Xunit;

namespace HostsGuard.Core.Tests;

public sealed class FirewallRuleAnalyzerTests
{
    private static readonly FirewallRuleAnalysisContext Public = new(["Public"]);

    [Fact]
    public void Exact_duplicate_prefers_foreign_survivor_and_only_hg_rule_is_cleanup_eligible()
    {
        var report = Analyze(Rule("Windows Web", source: "system"), Rule("HG_Web"));

        var finding = report.Findings.Should().ContainSingle(row => row.Kind == "exact_duplicate").Subject;
        finding.RuleName.Should().Be("HG_Web");
        finding.RelatedRuleName.Should().Be("Windows Web");
        finding.CleanupEligible.Should().BeTrue();
        finding.Remediation.Should().Be("delete_duplicate");
    }

    [Fact]
    public void Semantic_duplicate_normalizes_selector_order_and_adjacent_port_ranges()
    {
        var first = Rule("HG_A") with { RemoteAddr = "8.8.8.8,1.1.1.1", LocalPorts = "80,81" };
        var second = Rule("HG_B") with { RemoteAddr = "1.1.1.1,8.8.8.8", LocalPorts = "80-81" };

        var finding = Analyze(first, second).Findings.Should()
            .ContainSingle(row => row.Kind == "semantic_duplicate").Subject;
        finding.CleanupEligible.Should().BeFalse();
        finding.Remediation.Should().Be("review_semantic_duplicate");
    }

    [Fact]
    public void Exact_allow_and_block_selectors_report_shadowed_allow()
    {
        var report = Analyze(Rule("Allow", action: "Allow"), Rule("Block", action: "Block"));

        var finding = report.Findings.Should().ContainSingle(row => row.Kind == "shadowed_allow").Subject;
        finding.RuleName.Should().Be("Allow");
        finding.RelatedRuleName.Should().Be("Block");
        finding.CleanupEligible.Should().BeFalse();
    }

    [Fact]
    public void Provable_partial_port_and_address_overlap_reports_contradiction()
    {
        var allow = Rule("Allow") with { LocalPorts = "80-90", RemoteAddr = "8.8.8.0/24" };
        var block = Rule("Block", action: "Block") with { LocalPorts = "85-100", RemoteAddr = "8.8.8.8" };

        Analyze(allow, block).Findings.Should().ContainSingle(row => row.Kind == "contradictory_overlap");
    }

    [Fact]
    public void Unknown_special_address_selectors_do_not_claim_overlap()
    {
        var allow = Rule("Allow") with { RemoteAddr = "LocalSubnet" };
        var block = Rule("Block", action: "Block") with { RemoteAddr = "DNS" };

        Analyze(allow, block).Findings.Should().NotContain(row => row.Kind.Contains("overlap") || row.Kind == "shadowed_allow");
    }

    [Fact]
    public void Selectors_on_different_identity_axes_do_not_claim_overlap()
    {
        var program = Rule("Program") with { Program = @"C:\Apps\web.exe" };
        var service = Rule("Service", action: "Block") with { ServiceName = "WebSvc" };

        Analyze(program, service).Findings.Should().NotContain(row => row.Kind.Contains("overlap"));
    }

    [Fact]
    public void Disabled_and_inactive_profile_rules_are_explained()
    {
        var rule = Rule("Disabled") with { Enabled = false, Profiles = "Private" };

        var findings = Analyze(rule).Findings;
        findings.Should().Contain(row => row.Kind == "disabled");
        findings.Should().Contain(row => row.Kind == "inactive_profile");
    }

    [Fact]
    public void Group_policy_override_marks_hosts_guard_rules_only()
    {
        var context = new FirewallRuleAnalysisContext(["Public"], FirewallLocalPolicyModifyState.GroupPolicyOverride);

        var report = FirewallRuleAnalyzer.Analyze([Rule("HG_Local"), Rule("Foreign", source: "system")], context);

        report.Findings.Should().ContainSingle(row => row.Kind == "policy_override" && row.RuleName == "HG_Local");
    }

    [Fact]
    public void Inbound_block_policy_marks_inbound_allow_but_not_outbound_or_block()
    {
        var context = new FirewallRuleAnalysisContext(["Public"], FirewallLocalPolicyModifyState.InboundBlocked);
        var inboundAllow = Rule("Inbound allow");
        var outboundAllow = Rule("Outbound allow") with { Direction = "Out" };
        var inboundBlock = Rule("Inbound block", action: "Block");

        var report = FirewallRuleAnalyzer.Analyze([inboundAllow, outboundAllow, inboundBlock], context);

        report.Findings.Should().ContainSingle(row => row.Kind == "inbound_policy_block" && row.RuleName == "Inbound allow");
    }

    [Fact]
    public void Analysis_hash_binds_rules_active_profiles_and_policy_state()
    {
        var rule = Rule("HG_Web");
        var baseline = Analyze(rule).AnalysisHash;

        Analyze(rule with { LocalPorts = "443" }).AnalysisHash.Should().NotBe(baseline);
        FirewallRuleAnalyzer.Analyze([rule], new FirewallRuleAnalysisContext(["Private"]))
            .AnalysisHash.Should().NotBe(baseline);
        FirewallRuleAnalyzer.Analyze([rule], new FirewallRuleAnalysisContext(["Public"], FirewallLocalPolicyModifyState.GroupPolicyOverride))
            .AnalysisHash.Should().NotBe(baseline);
    }

    [Fact]
    public void Foreign_duplicates_are_reported_but_never_cleanup_eligible()
    {
        var report = Analyze(Rule("Foreign A", source: "system"), Rule("Foreign B", source: "system"));

        report.Findings.Should().ContainSingle(row => row.Kind == "exact_duplicate")
            .Which.CleanupEligible.Should().BeFalse();
    }

    private static FirewallRuleAnalysisReport Analyze(params FwRule[] rules) =>
        FirewallRuleAnalyzer.Analyze(rules, Public);

    private static FwRule Rule(string name, string action = "Allow", string source = "hostsguard") =>
        new(name, "In", action, true, "Any", "TCP", string.Empty, source,
            LocalPorts: "80", Profiles: "Public", LocalAddresses: "Any");
}
