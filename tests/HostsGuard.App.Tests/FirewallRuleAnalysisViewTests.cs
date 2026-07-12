using System.Reflection;
using FluentAssertions;
using HostsGuard.App.Services;
using HostsGuard.App.ViewModels;
using HostsGuard.Contracts;
using HostsGuard.Ipc;
using Xunit;

namespace HostsGuard.App.Tests;

public sealed class FirewallRuleAnalysisViewTests
{
    private static FwRulesViewModel CreateVm() => new(
        new HostsServiceClient(NamedPipeChannel.Create(SessionToken.Generate(), "hg-rule-analysis-none")),
        new FakeConfirm(true));

    private static FirewallRuleFindingViewModel Finding(
        string kind = "ExactDuplicate", string name = "HG_Test_duplicate", bool eligible = true) => new()
    {
        Kind = kind,
        RuleName = name,
        RelatedRuleName = "HG_Test_original",
        Reason = "Same effective condition and action",
        Remediation = eligible ? "RemoveDuplicate" : "ReviewConflict",
        CleanupEligible = eligible,
    };

    [Theory]
    [InlineData("", true)]
    [InlineData("rule:HG_Test", true)]
    [InlineData("type:ExactDuplicate", true)]
    [InlineData("source:HostsGuard", true)]
    [InlineData("fix:RemoveDuplicate", true)]
    [InlineData("reason:condition", true)]
    [InlineData("source:Windows", false)]
    public void Analysis_filter_uses_shared_search_syntax(string query, bool expected)
    {
        var vm = CreateVm();
        vm.AnalysisFilter = query;

        vm.MatchesAnalysisFilter(Finding()).Should().Be(expected);
    }

    [Fact]
    public void Findings_group_by_reason_then_provenance()
    {
        var vm = CreateVm();
        vm.AnalysisFindings.Add(Finding());
        vm.AnalysisFindings.Add(Finding("GroupPolicyOverride", "Policy rule", false));

        vm.AnalysisView.GroupDescriptions.Should().ContainSingle()
            .Which.Should().BeOfType<System.Windows.Data.PropertyGroupDescription>()
            .Which.PropertyName.Should().Be(nameof(FirewallRuleFindingViewModel.Kind));

        vm.GroupAnalysisByProvenance = true;

        vm.AnalysisView.GroupDescriptions.Should().ContainSingle()
            .Which.Should().BeOfType<System.Windows.Data.PropertyGroupDescription>()
            .Which.PropertyName.Should().Be(nameof(FirewallRuleFindingViewModel.Provenance));
    }

    [Fact]
    public void Provenance_and_cleanup_eligibility_keep_foreign_and_policy_findings_review_only()
    {
        Finding().Provenance.Should().Be("HostsGuard");

        var foreign = Finding("SemanticDuplicate", "Third-party rule", false);
        foreign.Provenance.Should().Be("Windows / other");
        foreign.SelectionHelp.Should().Contain("review-only");

        var policy = Finding("GroupPolicyOverride", "Policy rule", false);
        policy.Provenance.Should().Be("Group Policy");
        policy.SelectionHelp.Should().Contain("review-only");
    }

    [Fact]
    public void Contract_cannot_make_a_foreign_or_policy_rule_selectable()
    {
        FirewallRuleFindingViewModel.From(new FirewallRuleAnalysisFinding
        {
            Kind = "ExactDuplicate",
            RuleName = "Third-party rule",
            CleanupEligible = true,
        }).CleanupEligible.Should().BeFalse();

        var policy = FirewallRuleFindingViewModel.From(new FirewallRuleAnalysisFinding
        {
            Kind = "GroupPolicyOverride",
            RuleName = "HG_PolicyRule",
            CleanupEligible = false,
        });
        policy.CleanupEligible.Should().BeFalse();
        policy.Provenance.Should().Be("Group Policy");
    }

    [Fact]
    public void Changed_selection_invalidates_bound_cleanup_preview()
    {
        var vm = CreateVm();
        var row = Finding();
        AttachSelectionChanged(row, vm);
        vm.AnalysisFindings.Add(row);
        SetField(vm, "_analysisHash", "analysis");
        row.Selected = true;
        SetField(vm, "_cleanupPreviewHash", "preview");
        SetField(vm, "_previewSelectionKey", row.RuleName);

        vm.ApplyRuleCleanupCommand.CanExecute(null).Should().BeTrue();

        row.Selected = false;

        vm.ApplyRuleCleanupCommand.CanExecute(null).Should().BeFalse();
    }

    private static void AttachSelectionChanged(FirewallRuleFindingViewModel row, FwRulesViewModel vm) =>
        typeof(FirewallRuleFindingViewModel)
            .GetProperty("SelectionChanged", BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public)!
            .SetValue(row, (Action)(() =>
                typeof(FwRulesViewModel).GetMethod("OnCleanupSelectionChanged", BindingFlags.Instance | BindingFlags.NonPublic)!
                    .Invoke(vm, null)));

    private static void SetField(FwRulesViewModel vm, string name, string value) =>
        typeof(FwRulesViewModel).GetField(name, BindingFlags.Instance | BindingFlags.NonPublic)!
            .SetValue(vm, value);
}
