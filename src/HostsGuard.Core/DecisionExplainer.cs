using System.Net;

namespace HostsGuard.Core;

/// <summary>
/// Input for the local rule simulator. It is intentionally packet-shaped but
/// nullable: UI rows often know only an IP/process, while CLI calls can supply
/// a full executable path and signer.
/// </summary>
public sealed record DecisionInput(
    string Domain,
    string RemoteAddress,
    int RemotePort,
    string Protocol,
    string ProgramPath,
    string Process,
    string Direction,
    string Signer,
    string Service,
    string PackageFamilyName = "",
    string PackageSid = "");

public sealed record DecisionPolicyFacts(
    string? DomainStatus,
    string? DomainSource,
    string? RootStatus,
    string? RootSource,
    IReadOnlyList<FwRule> Rules,
    IReadOnlyList<DomainFirewallRuleFact> DomainFirewallRules,
    IReadOnlyDictionary<string, IReadOnlyList<string>> RuleGroups,
    IReadOnlyList<FwProfilePosture> Profiles,
    string ActiveProfile,
    IReadOnlyList<string> TrustedPublishers,
    IReadOnlyList<string> TrustedFolders,
    bool KillSwitchEnabled,
    bool KillSwitchEngaged,
    string KillSwitchAdapter);

public sealed record DomainFirewallRuleFact(
    string Domain,
    string Program,
    string RuleName,
    string Action,
    bool Enabled,
    string RemoteAddr);

public sealed record DecisionFactor(
    int Order,
    string Layer,
    string Outcome,
    string Owner,
    string Detail,
    string NextAction);

public sealed record DecisionExplanationResult(
    string Verdict,
    string Summary,
    string NextSafeAction,
    IReadOnlyList<DecisionFactor> Steps);

/// <summary>
/// Pure ordered explanation for "why would HostsGuard allow/block this?".
/// The service supplies current DB/firewall/posture facts; this class only
/// ranks evidence and simulates the driver-free decision chain.
/// </summary>
public static class DecisionExplainer
{
    public static DecisionExplanationResult Explain(DecisionInput input, DecisionPolicyFacts policy)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(policy);

        var steps = new List<DecisionFactor>();
        var order = 1;
        void Add(string layer, string outcome, string owner, string detail, string action) =>
            steps.Add(new DecisionFactor(order++, layer, outcome, owner, detail, action));

        var domain = NormalizeDomain(input.Domain);
        var root = Domains.LooksLikeDomain(domain) ? Domains.GetRoot(domain) : string.Empty;
        var direction = NormalizeDirection(input.Direction);
        var protocol = NormalizeProtocol(input.Protocol);

        Add("Input", "Observed", "query",
            DescribeInput(domain, input.RemoteAddress, input.RemotePort, protocol, input.ProgramPath, input.Process, input.Service, direction),
            "Supply missing domain/IP/program fields for a narrower simulation.");

        var hostsBlocked = false;
        var hostsAllowed = false;
        if (domain.Length != 0 && !string.IsNullOrWhiteSpace(policy.DomainStatus))
        {
            AddHostsStep(domain, policy.DomainStatus!, policy.DomainSource ?? string.Empty);
        }

        if (root.Length != 0 && !string.Equals(root, domain, StringComparison.Ordinal) &&
            !string.IsNullOrWhiteSpace(policy.RootStatus))
        {
            AddHostsStep(root, policy.RootStatus!, policy.RootSource ?? string.Empty);
        }

        void AddHostsStep(string subject, string status, string source)
        {
            var normalized = status.Trim().ToLowerInvariant();
            if (normalized == "blocked")
            {
                hostsBlocked = true;
                Add("Hosts", "Block", SourceOwner(source, subject),
                    $"{subject} is managed as blocked.",
                    $"Allow or temp-allow {subject} if this is a false positive.");
            }
            else if (normalized == "whitelisted" || normalized == "allowed")
            {
                hostsAllowed = true;
                Add("Hosts", "Allow", SourceOwner(source, subject),
                    $"{subject} is explicitly allowed in the hosts database.",
                    "Review firewall rules if traffic is still blocked.");
            }
            else
            {
                Add("Hosts", "Observed", SourceOwner(source, subject),
                    $"{subject} has managed status '{status}'.",
                    "No hosts-file action is implied by this status.");
            }
        }

        var publisher = PublisherName.Of(input.Signer);
        var publisherTrusted = publisher.Length != 0 &&
            policy.TrustedPublishers.Any(p => string.Equals(p, publisher, StringComparison.OrdinalIgnoreCase));
        if (publisherTrusted)
        {
            Add("Consent", "Allow", $"trusted publisher:{publisher}",
                "A future blocked prompt for this signed app would auto-allow.",
                "Remove the publisher from trusted publishers to force prompts again.");
        }
        else if (policy.TrustedPublishers.Count != 0 && input.ProgramPath.Length != 0 && input.Signer.Length == 0)
        {
            Add("Consent", "Unknown", "trusted publishers",
                "Trusted publishers exist, but this executable signer was not available.",
                "Run the explainer with signer data or use a signed executable path.");
        }

        var trustedFolder = policy.TrustedFolders.FirstOrDefault(f => PathScope.IsUnder(input.ProgramPath, f));
        if (!string.IsNullOrEmpty(trustedFolder))
        {
            Add("Consent", "Allow", $"trusted folder:{trustedFolder}",
                "A future blocked prompt for this app path would auto-allow.",
                "Remove the folder trust to force prompts for this path.");
        }

        var matchingRules = policy.Rules
            .Where(r => r.Enabled && RuleMatches(r, input, direction, protocol))
            .OrderBy(r => RuleRank(r.Action))
            .ThenBy(r => r.Name, StringComparer.Ordinal)
            .ToList();
        var domainRules = policy.DomainFirewallRules
            .Where(r => r.Enabled && string.Equals(NormalizeDomain(r.Domain), domain, StringComparison.Ordinal))
            .Where(r => ProgramMatches(r.Program, "hostsguard", input.ProgramPath, input.Process))
            .OrderBy(r => RuleRank(r.Action))
            .ThenBy(r => r.RuleName, StringComparer.Ordinal)
            .ToList();
        var domainBlockRules = domainRules.Where(r => string.Equals(r.Action, "Block", StringComparison.OrdinalIgnoreCase)).ToList();
        var domainAllowRules = domainRules.Where(r => string.Equals(r.Action, "Allow", StringComparison.OrdinalIgnoreCase)).ToList();

        foreach (var rule in domainRules)
        {
            Add("Domain firewall", NormalizeAction(rule.Action), rule.RuleName,
                DescribeDomainRule(rule),
                string.Equals(rule.Action, "Block", StringComparison.OrdinalIgnoreCase)
                    ? "Disable/delete this domain firewall rule if the destination should be reachable."
                    : "This domain-scoped allow covers the app when the domain resolves.");
        }

        var blockRules = matchingRules.Where(r => IsAction(r, "Block")).ToList();
        var allowRules = matchingRules.Where(r => IsAction(r, "Allow")).ToList();

        foreach (var rule in blockRules.Concat(allowRules))
        {
            var groups = policy.RuleGroups.TryGetValue(rule.Name, out var g) && g.Count != 0
                ? $" group:{string.Join(",", g)}"
                : string.Empty;
            Add("Firewall rule", NormalizeAction(rule.Action), rule.Name + groups,
                DescribeRule(rule),
                IsAction(rule, "Block")
                    ? "Disable/delete this HG_ rule or create a narrower allow only if safe."
                    : "This explicit allow covers the simulated connection.");
        }

        var activeProfiles = policy.Profiles.Where(p => p.Enabled).ToList();
        var outboundDefaultBlock = direction == "Out" && activeProfiles.Count != 0 &&
            activeProfiles.All(p => p.OutboundBlock);
        if (policy.KillSwitchEngaged)
        {
            Add("Posture", "Block", "VPN kill-switch",
                $"Kill-switch is engaged because '{policy.KillSwitchAdapter}' is down.",
                "Reconnect the VPN or disable the kill-switch before weakening rules.");
        }
        else if (policy.KillSwitchEnabled)
        {
            Add("Posture", "Observed", "VPN kill-switch",
                $"Kill-switch is armed for '{policy.KillSwitchAdapter}' but not engaged.",
                "No kill-switch action is needed.");
        }

        if (direction == "Out" && activeProfiles.Count != 0)
        {
            Add("Profile default", outboundDefaultBlock ? "Block" : "Allow",
                policy.ActiveProfile.Length == 0 ? "Windows profiles" : $"active profile:{policy.ActiveProfile}",
                string.Join(", ", activeProfiles.Select(p => $"{p.Name}={(p.OutboundBlock ? "Block" : "Allow")}")),
                outboundDefaultBlock
                    ? "Create a scoped allow rule when this traffic is expected."
                    : "Create a block rule if this traffic is unwanted.");
        }

        var (verdict, summary, action) = FinalVerdict(
            input, hostsBlocked, hostsAllowed, publisherTrusted, trustedFolder,
            domainBlockRules, domainAllowRules, blockRules, allowRules, policy.KillSwitchEngaged, outboundDefaultBlock, activeProfiles.Count);
        Add("Result", verdict, "simulator", summary, action);
        return new DecisionExplanationResult(verdict, summary, action, steps);
    }

    private static (string Verdict, string Summary, string Action) FinalVerdict(
        DecisionInput input,
        bool hostsBlocked,
        bool hostsAllowed,
        bool publisherTrusted,
        string? trustedFolder,
        IReadOnlyList<DomainFirewallRuleFact> domainBlockRules,
        IReadOnlyList<DomainFirewallRuleFact> domainAllowRules,
        IReadOnlyList<FwRule> blockRules,
        IReadOnlyList<FwRule> allowRules,
        bool killSwitchEngaged,
        bool outboundDefaultBlock,
        int profileCount)
    {
        if (hostsBlocked)
        {
            return ("Blocked", "A managed hosts entry blocks the resolved domain before firewall policy matters.",
                "Allow/temp-allow the domain or remove the owning list/source if this is wrong.");
        }

        if (domainBlockRules.Count != 0)
        {
            return ("Blocked", $"Domain firewall rule '{domainBlockRules[0].RuleName}' tracks this domain.",
                "Disable/delete that domain firewall rule or narrow it to a different app if this is wrong.");
        }

        if (blockRules.Count != 0)
        {
            return ("Blocked", $"Firewall block rule '{blockRules[0].Name}' covers this traffic.",
                "Review that rule, its group, or create a narrower allow only if the destination is trusted.");
        }

        if (domainAllowRules.Count != 0)
        {
            return ("Allowed", $"Domain firewall allow rule '{domainAllowRules[0].RuleName}' tracks this domain.",
                "Disable that domain rule if the app or destination should not connect.");
        }

        if (allowRules.Count != 0)
        {
            return ("Allowed", $"Firewall allow rule '{allowRules[0].Name}' covers this traffic.",
                "Disable that allow rule if the app or destination should not connect.");
        }

        if (killSwitchEngaged)
        {
            return ("Blocked", "The VPN kill-switch is engaged and no explicit allow rule covers this traffic.",
                "Reconnect the VPN or add a narrowly scoped allow for required tunnel recovery traffic.");
        }

        if (outboundDefaultBlock)
        {
            return ("Blocked", "Default outbound is Block and no explicit allow rule covers this traffic.",
                "Create an allow rule for the app, IP, port, or expected scope.");
        }

        if (hostsAllowed)
        {
            return ("Allowed", "The domain is explicitly allowlisted and no firewall block was found.",
                "Block the site or app if the traffic is unexpected.");
        }

        if (publisherTrusted || !string.IsNullOrEmpty(trustedFolder))
        {
            return ("Allowed", "Consent trust would auto-allow this app if a prompt were raised.",
                "Remove the trust entry or create a block rule if this should not be trusted.");
        }

        if (profileCount == 0 && input.RemoteAddress.Length == 0 && input.Domain.Length == 0)
        {
            return ("Unknown", "The simulator does not have enough endpoint data for a concrete decision.",
                "Provide a domain or remote IP, and program path when available.");
        }

        return ("Allowed", "No hosts block, matching firewall block, or blocking default posture was found.",
            "Create a block rule or hosts entry if this traffic is unwanted.");
    }

    private static bool RuleMatches(FwRule rule, DecisionInput input, string direction, string protocol)
    {
        if (!string.Equals(NormalizeDirection(rule.Direction), direction, StringComparison.Ordinal))
        {
            return false;
        }

        if (!ProtocolMatches(rule.Protocol, protocol))
        {
            return false;
        }

        if (!RemoteMatches(rule.RemoteAddr, input.RemoteAddress))
        {
            return false;
        }

        if (!PortMatches(rule.RemotePorts, input.RemotePort))
        {
            return false;
        }

        if (!ServiceMatches(rule.ServiceName, input.Service))
        {
            return false;
        }

        if (!PackageMatches(rule, input))
        {
            return false;
        }

        return ProgramMatches(rule.Program, rule.Source, input.ProgramPath, input.Process);
    }

    private static bool PackageMatches(FwRule rule, DecisionInput input)
    {
        var ruleFamily = (rule.PackageFamilyName ?? string.Empty).Trim();
        var ruleSid = (rule.PackageSid ?? string.Empty).Trim();
        if (ruleFamily.Length == 0 && ruleSid.Length == 0)
        {
            return true;
        }

        var requestFamily = (input.PackageFamilyName ?? string.Empty).Trim();
        var requestSid = (input.PackageSid ?? string.Empty).Trim();
        return (ruleFamily.Length != 0 && requestFamily.Length != 0 &&
                string.Equals(ruleFamily, requestFamily, StringComparison.OrdinalIgnoreCase)) ||
               (ruleSid.Length != 0 && requestSid.Length != 0 &&
                string.Equals(ruleSid, requestSid, StringComparison.OrdinalIgnoreCase));
    }

    private static bool ProtocolMatches(string ruleProtocol, string protocol)
    {
        var rp = NormalizeProtocol(ruleProtocol);
        return rp is "" or "Any" || protocol is "" or "Any" || string.Equals(rp, protocol, StringComparison.OrdinalIgnoreCase);
    }

    private static bool RemoteMatches(string ruleRemote, string remoteAddress)
    {
        var remote = (remoteAddress ?? string.Empty).Trim();
        var rule = (ruleRemote ?? string.Empty).Trim();
        if (rule.Length == 0 || rule is "*" or "Any" or "LocalSubnet")
        {
            return true;
        }

        if (remote.Length == 0 || !IPAddress.TryParse(remote, out var ip))
        {
            return false;
        }

        return rule.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Any(part => AddressPartMatches(part, ip));
    }

    private static bool AddressPartMatches(string part, IPAddress ip)
    {
        if (part.Contains('/', StringComparison.Ordinal))
        {
            return CidrContains(part, ip);
        }

        if (part.Contains('-', StringComparison.Ordinal))
        {
            var pieces = part.Split('-', 2, StringSplitOptions.TrimEntries);
            return pieces.Length == 2 &&
                   IPAddress.TryParse(pieces[0], out var start) &&
                   IPAddress.TryParse(pieces[1], out var end) &&
                   SameFamily(ip, start) && SameFamily(ip, end) &&
                   CompareBytes(start.GetAddressBytes(), ip.GetAddressBytes()) <= 0 &&
                   CompareBytes(ip.GetAddressBytes(), end.GetAddressBytes()) <= 0;
        }

        return IPAddress.TryParse(part, out var exact) && exact.Equals(ip);
    }

    private static bool CidrContains(string cidr, IPAddress ip)
    {
        var slash = cidr.IndexOf('/', StringComparison.Ordinal);
        if (slash <= 0 || !IPAddress.TryParse(cidr[..slash], out var network) ||
            !int.TryParse(cidr[(slash + 1)..], out var prefix) || !SameFamily(network, ip))
        {
            return false;
        }

        var addressBytes = ip.GetAddressBytes();
        var networkBytes = network.GetAddressBytes();
        var fullBytes = prefix / 8;
        var remainingBits = prefix % 8;
        if (fullBytes > addressBytes.Length || prefix < 0 || prefix > addressBytes.Length * 8)
        {
            return false;
        }

        for (var i = 0; i < fullBytes; i++)
        {
            if (addressBytes[i] != networkBytes[i])
            {
                return false;
            }
        }

        if (remainingBits == 0)
        {
            return true;
        }

        var mask = (byte)(0xFF << (8 - remainingBits));
        return (addressBytes[fullBytes] & mask) == (networkBytes[fullBytes] & mask);
    }

    private static bool SameFamily(IPAddress a, IPAddress b) => a.AddressFamily == b.AddressFamily;

    private static int CompareBytes(byte[] left, byte[] right)
    {
        for (var i = 0; i < Math.Min(left.Length, right.Length); i++)
        {
            var cmp = left[i].CompareTo(right[i]);
            if (cmp != 0)
            {
                return cmp;
            }
        }

        return left.Length.CompareTo(right.Length);
    }

    private static bool PortMatches(string rulePorts, int remotePort)
    {
        var ports = (rulePorts ?? string.Empty).Trim();
        if (ports.Length == 0 || ports is "*" or "Any")
        {
            return true;
        }

        if (remotePort <= 0)
        {
            return false;
        }

        return ports.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Any(part =>
            {
                if (part.Contains('-', StringComparison.Ordinal))
                {
                    var pieces = part.Split('-', 2, StringSplitOptions.TrimEntries);
                    return pieces.Length == 2 &&
                           int.TryParse(pieces[0], out var start) &&
                           int.TryParse(pieces[1], out var end) &&
                           remotePort >= start && remotePort <= end;
                }

                return int.TryParse(part, out var p) && remotePort == p;
            });
    }

    private static bool ProgramMatches(string ruleProgram, string ruleSource, string programPath, string process)
    {
        var rule = (ruleProgram ?? string.Empty).Trim();
        if (rule.Length == 0 || rule is "*" or "Any")
        {
            // COM reports some package-scoped Windows rules without a plain
            // Program path even though they are not machine-wide rules. Treat
            // empty-program rules as global only when HostsGuard authored them.
            return string.Equals(ruleSource, "hostsguard", StringComparison.Ordinal);
        }

        var programs = rule.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var path = (programPath ?? string.Empty).Trim();
        if (path.Length != 0 && programs.Any(p => string.Equals(NormalizePath(p), NormalizePath(path), StringComparison.OrdinalIgnoreCase)))
        {
            return true;
        }

        var processName = (process ?? string.Empty).Trim();
        if (processName.Length == 0)
        {
            return false;
        }

        return programs.Any(p =>
            string.Equals(Path.GetFileName(p), processName, StringComparison.OrdinalIgnoreCase) ||
            string.Equals(Path.GetFileNameWithoutExtension(p), Path.GetFileNameWithoutExtension(processName), StringComparison.OrdinalIgnoreCase));
    }

    private static bool ServiceMatches(string ruleService, string requestService)
    {
        var rule = (ruleService ?? string.Empty).Trim();
        if (rule.Length == 0 || rule is "*" or "Any")
        {
            return true;
        }

        var service = (requestService ?? string.Empty).Trim();
        return service.Length != 0 && string.Equals(rule, service, StringComparison.OrdinalIgnoreCase);
    }

    private static string NormalizePath(string path) => path.Trim().Replace('/', '\\');

    private static string NormalizeDomain(string? domain) => (domain ?? string.Empty).Trim().TrimEnd('.').ToLowerInvariant();

    private static string NormalizeDirection(string? direction)
        => FwRuleMapper.MapDirection(direction);

    private static string NormalizeProtocol(string? protocol)
    {
        var p = (protocol ?? string.Empty).Trim();
        return p switch
        {
            "" or "*" or "Any" or "any" => "Any",
            "6" => "TCP",
            "17" => "UDP",
            _ => p.ToUpperInvariant(),
        };
    }

    private static bool IsAction(FwRule rule, string action) =>
        string.Equals(rule.Action, action, StringComparison.OrdinalIgnoreCase);

    private static string NormalizeAction(string action) =>
        string.Equals(action, "Block", StringComparison.OrdinalIgnoreCase) ? "Block" :
        string.Equals(action, "Allow", StringComparison.OrdinalIgnoreCase) ? "Allow" :
        action;

    private static int RuleRank(string action) =>
        string.Equals(action, "Block", StringComparison.OrdinalIgnoreCase) ? 0 :
        string.Equals(action, "Allow", StringComparison.OrdinalIgnoreCase) ? 1 : 2;

    private static string SourceOwner(string source, string fallback) =>
        string.IsNullOrWhiteSpace(source) ? fallback : source.Trim();

    private static string DescribeRule(FwRule rule)
    {
        var program = !string.IsNullOrWhiteSpace(rule.PackageFamilyName)
            ? $"package {DisplayPackage(rule)}"
            : string.IsNullOrWhiteSpace(rule.Program) ? "any program" : Path.GetFileName(rule.Program);
        var remote = string.IsNullOrWhiteSpace(rule.RemoteAddr) ? "Any" : rule.RemoteAddr;
        var ports = string.IsNullOrWhiteSpace(rule.RemotePorts) ? "Any" : rule.RemotePorts;
        var interfaces = string.IsNullOrWhiteSpace(rule.Interfaces) || rule.Interfaces == "Any"
            ? string.Empty
            : $" interfaces={rule.Interfaces}";
        return $"{rule.Action} {rule.Direction} {rule.Protocol} {program} -> {remote}:{ports}{interfaces}";
    }

    private static string DisplayPackage(FwRule rule)
        => string.IsNullOrWhiteSpace(rule.PackageDisplayName)
            ? rule.PackageFamilyName
            : $"{rule.PackageDisplayName} ({rule.PackageFamilyName})";

    private static string DescribeDomainRule(DomainFirewallRuleFact rule)
    {
        var program = string.IsNullOrWhiteSpace(rule.Program) ? "any program" : Path.GetFileName(rule.Program);
        var remote = string.IsNullOrWhiteSpace(rule.RemoteAddr) ? "waiting for DNS answers" : rule.RemoteAddr;
        return $"{rule.Action} {program} when {rule.Domain} resolves to {remote}";
    }

    private static string DescribeInput(string domain, string remoteAddress, int remotePort, string protocol,
        string programPath, string process, string service, string direction)
    {
        var endpoint = domain.Length != 0 ? domain : remoteAddress.Length != 0 ? remoteAddress : "(no endpoint)";
        var port = remotePort > 0 ? $":{remotePort}" : string.Empty;
        var program = programPath.Length != 0 ? Path.GetFileName(programPath) :
            process.Length != 0 ? process : "(no process)";
        var serviceText = service.Length == 0 ? string.Empty : $" service:{service}";
        return $"{direction} {protocol} {program}{serviceText} -> {endpoint}{port}";
    }
}
