using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace HostsGuard.Core;

public enum FirewallLocalPolicyModifyState
{
    Unknown,
    Ok,
    GroupPolicyOverride,
    InboundBlocked,
}

public sealed record FirewallRuleAnalysisContext(
    IReadOnlyList<string> ActiveProfiles,
    FirewallLocalPolicyModifyState LocalPolicyModifyState = FirewallLocalPolicyModifyState.Unknown);

public sealed record FirewallRuleAnalysisFinding(
    string Kind,
    string RuleName,
    string RelatedRuleName,
    string CanonicalFingerprint,
    string Reason,
    string Remediation,
    bool CleanupEligible);

public sealed record FirewallRuleAnalysisReport(
    string AnalysisHash,
    int RulesAnalyzed,
    IReadOnlyList<FirewallRuleAnalysisFinding> Findings);

/// <summary>
/// Pure, conservative firewall-rule analysis. Unknown Windows special selectors
/// never become a claimed overlap or contradiction.
/// </summary>
public static class FirewallRuleAnalyzer
{
    public static FirewallRuleAnalysisReport Analyze(
        IEnumerable<FwRule> rules,
        FirewallRuleAnalysisContext context)
    {
        ArgumentNullException.ThrowIfNull(rules);
        ArgumentNullException.ThrowIfNull(context);
        var rows = rules.OrderBy(rule => rule.Name, StringComparer.OrdinalIgnoreCase).ToArray();
        var findings = new List<FirewallRuleAnalysisFinding>();

        AddDuplicateFindings(rows, findings, semantic: false);
        AddDuplicateFindings(rows, findings, semantic: true);
        AddContradictions(rows, findings);
        AddIneffective(rows, context, findings);

        var distinct = findings
            .DistinctBy(finding => (finding.Kind, finding.RuleName, finding.RelatedRuleName))
            .OrderBy(finding => KindOrder(finding.Kind))
            .ThenBy(finding => finding.RuleName, StringComparer.OrdinalIgnoreCase)
            .ThenBy(finding => finding.RelatedRuleName, StringComparer.OrdinalIgnoreCase)
            .ToArray();
        return new FirewallRuleAnalysisReport(AnalysisHash(rows, context), rows.Length, distinct);
    }

    private static void AddDuplicateFindings(
        IReadOnlyList<FwRule> rules,
        List<FirewallRuleAnalysisFinding> findings,
        bool semantic)
    {
        var groups = rules.GroupBy(rule => RuleKey(rule, semantic, includeAction: true), StringComparer.Ordinal)
            .Where(group => group.Count() > 1);
        foreach (var group in groups)
        {
            if (semantic && group.Select(rule => RuleKey(rule, semantic: false, includeAction: true))
                    .Distinct(StringComparer.Ordinal).Count() == 1)
            {
                continue; // already reported as exact duplicates
            }

            var ordered = group
                .OrderBy(rule => IsHostsGuard(rule) ? 1 : 0)
                .ThenBy(rule => rule.Name, StringComparer.OrdinalIgnoreCase)
                .ToArray();
            var survivor = ordered[0];
            foreach (var duplicate in ordered.Skip(1))
            {
                var kind = semantic ? "semantic_duplicate" : "exact_duplicate";
                findings.Add(new FirewallRuleAnalysisFinding(
                    kind,
                    duplicate.Name,
                    survivor.Name,
                    Hash(group.Key),
                    semantic
                        ? $"Semantically duplicates '{survivor.Name}' after normalizing selector order and port ranges."
                        : $"Duplicates the effective selectors and action of '{survivor.Name}'.",
                    !semantic && IsHostsGuard(duplicate) ? "delete_duplicate" :
                        IsHostsGuard(duplicate) ? "review_semantic_duplicate" : "review_foreign_rule",
                    !semantic && IsHostsGuard(duplicate)));
            }
        }
    }

    private static void AddContradictions(IReadOnlyList<FwRule> rules, List<FirewallRuleAnalysisFinding> findings)
    {
        for (var leftIndex = 0; leftIndex < rules.Count; leftIndex++)
        {
            var left = rules[leftIndex];
            if (!left.Enabled) continue;
            for (var rightIndex = leftIndex + 1; rightIndex < rules.Count; rightIndex++)
            {
                var right = rules[rightIndex];
                if (!right.Enabled || left.Action.Equals(right.Action, StringComparison.OrdinalIgnoreCase) ||
                    !ProvablyOverlap(left, right))
                {
                    continue;
                }

                var allow = left.Action.Equals("Allow", StringComparison.OrdinalIgnoreCase) ? left : right;
                var block = ReferenceEquals(allow, left) ? right : left;
                var sameSelectors = RuleKey(allow, semantic: true, includeAction: false)
                    .Equals(RuleKey(block, semantic: true, includeAction: false), StringComparison.Ordinal);
                var fingerprint = Hash(string.Join('\n', new[] { SemanticKey(allow), SemanticKey(block) }.Order()));
                findings.Add(new FirewallRuleAnalysisFinding(
                    sameSelectors ? "shadowed_allow" : "contradictory_overlap",
                    allow.Name,
                    block.Name,
                    fingerprint,
                    sameSelectors
                        ? $"Block rule '{block.Name}' has the same selectors and takes precedence over this allow rule."
                        : $"Allow and block selectors overlap with '{block.Name}'; Windows block precedence applies to the overlap.",
                    "review_precedence",
                    false));
            }
        }
    }

    private static void AddIneffective(
        IReadOnlyList<FwRule> rules,
        FirewallRuleAnalysisContext context,
        List<FirewallRuleAnalysisFinding> findings)
    {
        var active = context.ActiveProfiles.ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var rule in rules)
        {
            var fingerprint = Hash(SemanticKey(rule));
            var appliesToActiveProfile = active.Count == 0 || Profiles(rule.Profiles).Overlaps(active);
            if (!rule.Enabled)
            {
                findings.Add(new("disabled", rule.Name, string.Empty, fingerprint,
                    "Rule is disabled and has no current enforcement effect.", "review_disabled", false));
            }

            if (active.Count != 0 && !appliesToActiveProfile)
            {
                findings.Add(new("inactive_profile", rule.Name, string.Empty, fingerprint,
                    $"Rule does not apply to any active firewall profile ({string.Join(',', active.Order())}).",
                    "review_profile", false));
            }

            if (rule.Enabled && appliesToActiveProfile && IsHostsGuard(rule) &&
                context.LocalPolicyModifyState == FirewallLocalPolicyModifyState.GroupPolicyOverride)
            {
                findings.Add(new("policy_override", rule.Name, string.Empty, fingerprint,
                    "Local firewall policy is overridden by Group Policy, so this local rule may be ineffective.",
                    "review_group_policy", false));
            }
            else if (rule.Enabled && appliesToActiveProfile &&
                     rule.Direction.Equals("In", StringComparison.OrdinalIgnoreCase) &&
                     rule.Action.Equals("Allow", StringComparison.OrdinalIgnoreCase) &&
                     context.LocalPolicyModifyState == FirewallLocalPolicyModifyState.InboundBlocked)
            {
                findings.Add(new("inbound_policy_block", rule.Name, string.Empty, fingerprint,
                    "Current Windows policy blocks inbound traffic regardless of this allow rule.",
                    "review_policy", false));
            }
        }
    }

    private static bool ProvablyOverlap(FwRule left, FwRule right)
    {
        if (!ScalarOverlap(left.Direction, right.Direction, any: false) ||
            !ScalarOverlap(left.Protocol, right.Protocol, any: true) ||
            !Profiles(left.Profiles).Overlaps(Profiles(right.Profiles)) ||
            !IdentityOverlap(left, right) ||
            !TokenSetOverlap(left.Interfaces, right.Interfaces) ||
            !PortOverlap(left.LocalPorts, right.LocalPorts) ||
            !PortOverlap(left.RemotePorts, right.RemotePorts) ||
            !AddressOverlap(left.LocalAddresses, right.LocalAddresses) ||
            !AddressOverlap(left.RemoteAddr, right.RemoteAddr))
        {
            return false;
        }

        return true;
    }

    private static bool IdentityOverlap(FwRule left, FwRule right)
    {
        var leftUniversal = IsUniversalIdentity(left);
        var rightUniversal = IsUniversalIdentity(right);
        if (leftUniversal || rightUniversal) return true;

        // Selectors on different identity axes may or may not describe the same
        // process. Only claim overlap when every used axis matches exactly.
        return IdentityAxisEqual(left.Program, right.Program) &&
               IdentityAxisEqual(left.ServiceName, right.ServiceName) &&
               IdentityAxisEqual(left.PackageFamilyName, right.PackageFamilyName) &&
               IdentityAxisEqual(left.PackageSid, right.PackageSid);
    }

    private static bool IsUniversalIdentity(FwRule rule) =>
        string.IsNullOrWhiteSpace(rule.Program) && string.IsNullOrWhiteSpace(rule.ServiceName) &&
        string.IsNullOrWhiteSpace(rule.PackageFamilyName) && string.IsNullOrWhiteSpace(rule.PackageSid);

    private static bool IdentityAxisEqual(string left, string right) =>
        string.IsNullOrWhiteSpace(left) == string.IsNullOrWhiteSpace(right) &&
        (string.IsNullOrWhiteSpace(left) || NormalizeScalar(left) == NormalizeScalar(right));

    private static bool ScalarOverlap(string left, string right, bool any) =>
        (any && (IsAny(left) || IsAny(right))) || NormalizeScalar(left) == NormalizeScalar(right);

    private static bool TokenSetOverlap(string left, string right)
    {
        if (IsAny(left) || IsAny(right)) return true;
        var l = Tokens(left);
        var r = Tokens(right);
        return l.Overlaps(r);
    }

    private static bool PortOverlap(string left, string right)
    {
        if (IsAny(left) || IsAny(right)) return true;
        if (!TryPortRanges(left, out var l) || !TryPortRanges(right, out var r)) return false;
        return l.Any(a => r.Any(b => a.Start <= b.End && b.Start <= a.End));
    }

    private static bool TryPortRanges(string value, out IReadOnlyList<(int Start, int End)> ranges)
    {
        var parsed = new List<(int Start, int End)>();
        foreach (var token in value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (int.TryParse(token, out var exact) && exact is >= 1 and <= 65535)
            {
                parsed.Add((exact, exact));
                continue;
            }

            var bounds = token.Split('-', 2, StringSplitOptions.TrimEntries);
            if (bounds.Length != 2 || !int.TryParse(bounds[0], out var first) ||
                !int.TryParse(bounds[1], out var last) || first < 1 || last > 65535 || first > last)
            {
                ranges = Array.Empty<(int, int)>();
                return false;
            }

            parsed.Add((first, last));
        }

        if (parsed.Count == 0)
        {
            ranges = Array.Empty<(int, int)>();
            return false;
        }

        var merged = new List<(int Start, int End)>();
        foreach (var range in parsed.OrderBy(item => item.Start).ThenBy(item => item.End))
        {
            if (merged.Count == 0 || range.Start > merged[^1].End + 1)
            {
                merged.Add(range);
            }
            else
            {
                merged[^1] = (merged[^1].Start, Math.Max(merged[^1].End, range.End));
            }
        }

        ranges = merged;
        return true;
    }

    private static bool AddressOverlap(string left, string right)
    {
        if (IsAny(left) || IsAny(right)) return true;
        var leftTokens = left.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var rightTokens = right.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        foreach (var l in leftTokens)
        foreach (var r in rightTokens)
        {
            if (NormalizeScalar(l) == NormalizeScalar(r)) return true;
            if (TryNetwork(l, out var ln, out var lp) && TryNetwork(r, out var rn, out var rp) &&
                NetworksOverlap(ln, lp, rn, rp))
            {
                return true;
            }
        }

        return false;
    }

    private static bool TryNetwork(string value, out IPAddress network, out int prefix)
    {
        var split = value.Split('/', 2, StringSplitOptions.TrimEntries);
        if (!IPAddress.TryParse(split[0], out network!))
        {
            prefix = 0;
            return false;
        }

        prefix = network.GetAddressBytes().Length * 8;
        return split.Length == 1 || (int.TryParse(split[1], out prefix) && prefix >= 0 &&
            prefix <= network.GetAddressBytes().Length * 8);
    }

    private static bool NetworksOverlap(IPAddress left, int leftPrefix, IPAddress right, int rightPrefix)
    {
        var lb = left.GetAddressBytes();
        var rb = right.GetAddressBytes();
        if (lb.Length != rb.Length) return false;
        var bits = Math.Min(leftPrefix, rightPrefix);
        for (var bit = 0; bit < bits; bit++)
        {
            var mask = 1 << (7 - bit % 8);
            if ((lb[bit / 8] & mask) != (rb[bit / 8] & mask)) return false;
        }

        return true;
    }

    private static string RuleKey(FwRule rule, bool semantic, bool includeAction)
    {
        string Set(string value) => semantic ? NormalizeSet(value) : NormalizeScalar(value);
        var fields = new[]
        {
            NormalizeScalar(rule.Direction), includeAction ? NormalizeScalar(rule.Action) : string.Empty,
            rule.Enabled ? "1" : "0", Set(rule.RemoteAddr), NormalizeScalar(rule.Protocol),
            NormalizePath(rule.Program), Set(rule.RemotePorts), NormalizeScalar(rule.ServiceName),
            Set(rule.LocalPorts), Set(rule.Interfaces), NormalizeScalar(rule.PackageFamilyName),
            NormalizeScalar(rule.PackageSid), Set(rule.PackageBinaries), Set(rule.Profiles),
            Set(rule.LocalAddresses),
        };
        if (semantic)
        {
            fields[6] = NormalizePorts(rule.RemotePorts);
            fields[8] = NormalizePorts(rule.LocalPorts);
        }
        return string.Join('\u001f', fields);
    }

    private static string SemanticKey(FwRule rule) => RuleKey(rule, semantic: true, includeAction: true);

    private static string NormalizePorts(string value)
    {
        if (IsAny(value)) return "any";
        if (!TryPortRanges(value, out var ranges)) return "unknown:" + NormalizeSet(value);
        return string.Join(',', ranges.Select(range => range.Start == range.End
            ? range.Start.ToString()
            : $"{range.Start}-{range.End}"));
    }

    private static HashSet<string> Profiles(string value) => IsAny(value)
        ? new HashSet<string>(["domain", "private", "public"], StringComparer.OrdinalIgnoreCase)
        : Tokens(value);

    private static HashSet<string> Tokens(string value) => value
        .Split(new[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
        .Select(NormalizeScalar)
        .ToHashSet(StringComparer.OrdinalIgnoreCase);

    private static string NormalizeSet(string value) => IsAny(value)
        ? "any"
        : string.Join(',', Tokens(value).Order(StringComparer.Ordinal));

    private static string NormalizePath(string value)
    {
        if (string.IsNullOrWhiteSpace(value)) return string.Empty;
        try { return Path.GetFullPath(Environment.ExpandEnvironmentVariables(value)).ToLowerInvariant(); }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        { return NormalizeScalar(value); }
    }

    private static string NormalizeScalar(string value) => (value ?? string.Empty).Trim().ToLowerInvariant();
    private static bool IsAny(string value) => string.IsNullOrWhiteSpace(value) ||
        value.Trim() is "*" or "Any" or "any" or "All" or "all";
    private static bool IsHostsGuard(FwRule rule) => rule.Name.StartsWith("HG_", StringComparison.OrdinalIgnoreCase) ||
        rule.Source.Equals("hostsguard", StringComparison.OrdinalIgnoreCase);

    private static string AnalysisHash(IReadOnlyList<FwRule> rules, FirewallRuleAnalysisContext context)
    {
        var canonical = string.Join('\n', rules.Select(rule => $"{NormalizeScalar(rule.Name)}|{SemanticKey(rule)}")
            .Order(StringComparer.Ordinal));
        canonical += $"\nprofiles={string.Join(',', context.ActiveProfiles.Select(NormalizeScalar).Order())}";
        canonical += $"\nmodify={context.LocalPolicyModifyState}";
        return Hash(canonical);
    }

    private static string Hash(string value) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();

    private static int KindOrder(string kind) => kind switch
    {
        "exact_duplicate" => 0,
        "semantic_duplicate" => 1,
        "shadowed_allow" => 2,
        "contradictory_overlap" => 3,
        "policy_override" => 4,
        "inbound_policy_block" => 5,
        "inactive_profile" => 6,
        "disabled" => 7,
        _ => 8,
    };
}
