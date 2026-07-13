using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Windows.Data;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Grpc.Core;
using HostsGuard.App.Services;
using HostsGuard.Contracts;

namespace HostsGuard.App.ViewModels;

public sealed partial class FirewallRuleFindingViewModel : ObservableObject
{
    [ObservableProperty]
    private string _kind = string.Empty;

    [ObservableProperty]
    private string _ruleName = string.Empty;

    [ObservableProperty]
    private string _relatedRuleName = string.Empty;

    [ObservableProperty]
    private string _reason = string.Empty;

    [ObservableProperty]
    private string _remediation = string.Empty;

    [ObservableProperty]
    private bool _cleanupEligible;

    [ObservableProperty]
    private bool _selected;

    public string Provenance => Kind.Equals("GroupPolicyOverride", StringComparison.OrdinalIgnoreCase)
        ? I18n.T("RuleAnalysis_ProvenancePolicy", "Group Policy")
        : RuleName.StartsWith("HG_", StringComparison.Ordinal)
            ? I18n.T("RuleAnalysis_ProvenanceHostsGuard", "HostsGuard")
            : I18n.T("RuleAnalysis_ProvenanceOther", "Windows / other");

    public string SelectionHelp => CleanupEligible
        ? I18n.T("RuleAnalysis_EligibleTip", "Eligible HG_ exact duplicate")
        : Kind.Equals("GroupPolicyOverride", StringComparison.OrdinalIgnoreCase)
            ? I18n.T("RuleAnalysis_PolicyTip", "Group Policy findings are review-only")
            : I18n.T("RuleAnalysis_ReviewOnlyTip", "Foreign and non-exact findings are review-only");

    internal Action? SelectionChanged { get; set; }

    partial void OnSelectedChanged(bool value) => SelectionChanged?.Invoke();

    public static FirewallRuleFindingViewModel From(FirewallRuleAnalysisFinding finding)
    {
        ArgumentNullException.ThrowIfNull(finding);
        return new()
        {
            Kind = finding.Kind,
            RuleName = finding.RuleName,
            RelatedRuleName = finding.RelatedRuleName,
            Reason = finding.Reason,
            Remediation = finding.Remediation,
            CleanupEligible = finding.CleanupEligible &&
                              finding.RuleName.StartsWith("HG_", StringComparison.Ordinal),
        };
    }
}

public sealed partial class FwRulesViewModel
{
    private static readonly Dictionary<string, string> AnalysisFilterAliases = new(StringComparer.Ordinal)
    {
        ["rule"] = "name",
        ["related"] = "peer",
        ["type"] = "kind",
        ["source"] = "provenance",
        ["fix"] = "remediation",
    };

    private ICollectionView? _analysisView;
    private string _analysisHash = string.Empty;
    private string _cleanupPreviewHash = string.Empty;
    private string _previewSelectionKey = string.Empty;

    public ObservableCollection<FirewallRuleFindingViewModel> AnalysisFindings { get; } = new();

    [ObservableProperty]
    private string _analysisFilter = string.Empty;

    [ObservableProperty]
    private bool _groupAnalysisByProvenance;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(AnalyzeRulesCommand))]
    [NotifyCanExecuteChangedFor(nameof(PreviewRuleCleanupCommand))]
    [NotifyCanExecuteChangedFor(nameof(ApplyRuleCleanupCommand))]
    private bool _analysisBusy;

    [ObservableProperty]
    private bool _analysisFailed;

    [ObservableProperty]
    private string _analysisStatus = I18n.T("RuleAnalysis_NotAnalyzed", "Not analyzed yet");

    [ObservableProperty]
    private string _analysisContext = string.Empty;

    public ICollectionView AnalysisView
    {
        get
        {
            if (_analysisView is null)
            {
                _analysisView = CollectionViewSource.GetDefaultView(AnalysisFindings);
                _analysisView.Filter = value =>
                    value is FirewallRuleFindingViewModel row && MatchesAnalysisFilter(row);
                ApplyAnalysisGrouping();
            }

            return _analysisView;
        }
    }

    public bool MatchesAnalysisFilter(FirewallRuleFindingViewModel row)
    {
        ArgumentNullException.ThrowIfNull(row);
        if (string.IsNullOrWhiteSpace(AnalysisFilter))
        {
            return true;
        }

        return Core.SearchQuery.Matches(new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["kind"] = row.Kind,
            ["name"] = row.RuleName,
            ["peer"] = row.RelatedRuleName,
            ["reason"] = row.Reason,
            ["remediation"] = row.Remediation,
            ["provenance"] = row.Provenance,
            ["eligible"] = row.CleanupEligible.ToString(),
        }, AnalysisFilter, AnalysisFilterAliases);
    }

    partial void OnAnalysisFilterChanged(string value) => _analysisView?.Refresh();

    partial void OnGroupAnalysisByProvenanceChanged(bool value) => ApplyAnalysisGrouping();

    private void ApplyAnalysisGrouping()
    {
        if (_analysisView is null)
        {
            return;
        }

        using (_analysisView.DeferRefresh())
        {
            _analysisView.GroupDescriptions.Clear();
            _analysisView.GroupDescriptions.Add(new PropertyGroupDescription(
                GroupAnalysisByProvenance
                    ? nameof(FirewallRuleFindingViewModel.Provenance)
                    : nameof(FirewallRuleFindingViewModel.Kind)));
        }
    }

    private bool CanAnalyzeRules() => !AnalysisBusy;

    [RelayCommand(CanExecute = nameof(CanAnalyzeRules))]
    public async Task AnalyzeRulesAsync()
    {
        AnalysisBusy = true;
        AnalysisFailed = false;
        AnalysisStatus = I18n.T("RuleAnalysis_Loading", "Analyzing effective firewall rules…");
        InvalidateCleanupPreview();
        try
        {
            var result = await _client.Firewall.AnalyzeRulesAsync(new FirewallRuleAnalysisRequest());
            _analysisHash = result.AnalysisHash;
            AnalysisContext = I18n.T("RuleAnalysis_Context", "{0} rules · profiles {1} · policy {2}",
                result.RulesAnalyzed,
                result.ActiveProfiles.Count == 0 ? I18n.T("Common_NoneLower", "none") : string.Join(", ", result.ActiveProfiles),
                result.LocalPolicyModifyState);

            AnalysisFindings.Clear();
            foreach (var finding in result.Findings)
            {
                var row = FirewallRuleFindingViewModel.From(finding);
                row.SelectionChanged = OnCleanupSelectionChanged;
                AnalysisFindings.Add(row);
            }

            AnalysisStatus = result.Findings.Count == 0
                ? I18n.T("RuleAnalysis_None", "No duplicate, contradictory, or ineffective rules found")
                : I18n.T("RuleAnalysis_Count", "{0} findings; review-only unless an HG_ exact duplicate is selected", result.Findings.Count);
        }
        catch (Exception ex) when (ex is RpcException or IOException)
        {
            AnalysisFailed = true;
            AnalysisStatus = ServiceErrors.DescribeActionFailure(I18n.T("RuleAnalysis_ActionAnalyze", "Analyze firewall rules"), ex);
        }
        finally
        {
            AnalysisBusy = false;
            NotifyCleanupCommands();
        }
    }

    private bool CanPreviewRuleCleanup() =>
        !AnalysisBusy && _analysisHash.Length != 0 && SelectedCleanupNames().Count != 0;

    [RelayCommand(CanExecute = nameof(CanPreviewRuleCleanup))]
    public async Task PreviewRuleCleanupAsync()
    {
        var selected = SelectedCleanupNames();
        if (selected.Count == 0 || _analysisHash.Length == 0)
        {
            return;
        }

        AnalysisBusy = true;
        AnalysisFailed = false;
        AnalysisStatus = I18n.T("RuleAnalysis_Previewing", "Validating selected HG_ cleanup…");
        try
        {
            var request = new FirewallRuleCleanupRequest
            {
                AnalysisHash = _analysisHash,
                Preview = true,
            };
            request.SelectedNames.AddRange(selected);
            var result = await _client.Firewall.ApplyRuleCleanupAsync(request);
            var exactPreview = result.Ok && result.RejectedNames.Count == 0 &&
                               result.AnalysisHash.Equals(_analysisHash, StringComparison.Ordinal) &&
                               SelectionKey(result.SelectedNames).Equals(SelectionKey(selected), StringComparison.Ordinal);
            _cleanupPreviewHash = exactPreview ? result.PreviewHash : string.Empty;
            _previewSelectionKey = exactPreview ? SelectionKey(selected) : string.Empty;
            AnalysisStatus = result.Message;
        }
        catch (Exception ex) when (ex is RpcException or IOException)
        {
            InvalidateCleanupPreview();
            AnalysisFailed = true;
            AnalysisStatus = ServiceErrors.DescribeActionFailure(I18n.T("RuleAnalysis_ActionPreview", "Preview firewall cleanup"), ex);
        }
        finally
        {
            AnalysisBusy = false;
            NotifyCleanupCommands();
        }
    }

    private bool CanApplyRuleCleanup()
    {
        var selected = SelectedCleanupNames();
        return !AnalysisBusy && _cleanupPreviewHash.Length != 0 &&
               SelectionKey(selected).Equals(_previewSelectionKey, StringComparison.Ordinal);
    }

    [RelayCommand(CanExecute = nameof(CanApplyRuleCleanup))]
    public async Task ApplyRuleCleanupAsync()
    {
        var selected = SelectedCleanupNames();
        if (!CanApplyRuleCleanup())
        {
            return;
        }

        AnalysisBusy = true;
        AnalysisFailed = false;
        AnalysisStatus = I18n.T("RuleAnalysis_Applying", "Applying previewed HG_ cleanup…");
        try
        {
            var request = new FirewallRuleCleanupRequest
            {
                AnalysisHash = _analysisHash,
                PreviewHash = _cleanupPreviewHash,
                Preview = false,
            };
            request.SelectedNames.AddRange(selected);
            var result = await _client.Firewall.ApplyRuleCleanupAsync(request);
            AnalysisStatus = result.Message;
            if (result.Ok)
            {
                await AnalyzeRulesAsync();
            }
        }
        catch (Exception ex) when (ex is RpcException or IOException)
        {
            AnalysisFailed = true;
            AnalysisStatus = ServiceErrors.DescribeActionFailure(I18n.T("RuleAnalysis_ActionApply", "Apply firewall cleanup"), ex);
        }
        finally
        {
            AnalysisBusy = false;
            InvalidateCleanupPreview();
            NotifyCleanupCommands();
        }
    }

    private void OnCleanupSelectionChanged()
    {
        InvalidateCleanupPreview();
        AnalysisStatus = I18n.T("RuleAnalysis_SelectionChanged", "Selection changed; preview again before cleanup.");
        NotifyCleanupCommands();
    }

    private List<string> SelectedCleanupNames() => AnalysisFindings
        .Where(row => row.CleanupEligible && row.Selected)
        .Select(row => row.RuleName)
        .OrderBy(name => name, StringComparer.Ordinal)
        .ToList();

    private static string SelectionKey(IEnumerable<string> names) => string.Join("\n", names);

    private void InvalidateCleanupPreview()
    {
        _cleanupPreviewHash = string.Empty;
        _previewSelectionKey = string.Empty;
    }

    private void NotifyCleanupCommands()
    {
        AnalyzeRulesCommand.NotifyCanExecuteChanged();
        PreviewRuleCleanupCommand.NotifyCanExecuteChanged();
        ApplyRuleCleanupCommand.NotifyCanExecuteChanged();
    }
}
