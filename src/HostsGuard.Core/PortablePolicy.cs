using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace HostsGuard.Core;

/// <summary>
/// A single versioned, portable snapshot of a HostsGuard machine's whole policy
/// (NET-089): managed domains, HG_ firewall rules, schedules, rule-set profiles,
/// settings-lock intent (never its credential), network→profile mappings, allow/blocklist subscriptions,
/// and non-secret mutable privacy posture. Serializes to one JSON document so a
/// machine's policy can be backed up and reconstructed on a clean install. Pure
/// data — no OS deps or secrets — so the service, CLI, and UI all share it.
/// </summary>
public sealed class PortablePolicy
{
    /// <summary>Document schema version; bumped only on a breaking shape change.</summary>
    public const int CurrentVersion = 1;

    public int Version { get; set; } = CurrentVersion;

    /// <summary>The HostsGuard version that produced the document (informational).</summary>
    public string App { get; set; } = string.Empty;

    /// <summary>ISO-8601 timestamp of when the document was exported (informational).</summary>
    public string Exported { get; set; } = string.Empty;

    public List<PolicyDomain> Domains { get; set; } = new();

    public List<PolicyHostsRedirect> HostsRedirects { get; set; } = new();

    public List<PolicyFirewallRule> FirewallRules { get; set; } = new();

    public List<PolicyDomainFirewallRule> DomainFirewallRules { get; set; } = new();

    public List<PolicySchedule> Schedules { get; set; } = new();

    public List<PolicyProfile> Profiles { get; set; } = new();

    public PolicyLock Lock { get; set; } = new();

    public List<PolicyNetworkProfile> NetworkProfiles { get; set; } = new();

    public List<PolicyRuleGroup> RuleGroups { get; set; } = new();

    public List<PolicyBlocklistSub> BlocklistSubs { get; set; } = new();

    public List<PolicyIpBlocklist> IpBlocklists { get; set; } = new();

    public List<string> AllowlistSubs { get; set; } = new();

    public PolicyConsent? Consent { get; set; }

    public PolicyDnsPrivacy? DnsPrivacy { get; set; }

    public PolicyKillSwitch? KillSwitch { get; set; }

    public List<PolicyAppVpnBinding> AppVpnBindings { get; set; } = new();

    public List<PolicyUsageQuota>? UsageQuotas { get; set; }

    public List<PolicyHistoryPrivacyExclusion>? HistoryPrivacyExclusions { get; set; }

    public PolicyLanAttackSurface? LanAttackSurface { get; set; }

    public PolicyAiSettings? Ai { get; set; }

    public List<PolicyAiKnowledge>? AiKnowledge { get; set; }

    public List<PolicyUserOverride>? UserOverrides { get; set; }

    public PolicyWebhooks? Webhooks { get; set; }

    /// <summary>Carried meta settings (e.g. active_profile, history_retention_days).</summary>
    public Dictionary<string, string> Settings { get; set; } = new(StringComparer.Ordinal);

    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        PropertyNameCaseInsensitive = true,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };

    public string ToJson() => JsonSerializer.Serialize(this, Options);

    /// <summary>
    /// Parse a portable-policy document. Throws <see cref="JsonException"/> on
    /// malformed input and <see cref="InvalidOperationException"/> when the
    /// document version is newer than this build understands.
    /// </summary>
    public static PortablePolicy FromJson(string json)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(json);
        using var document = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 64 });
        RejectDuplicateProperties(document.RootElement, "$", 0);
        var policy = document.RootElement.Deserialize<PortablePolicy>(Options)
            ?? throw new JsonException("policy document is empty");
        if (policy.Version <= 0 || policy.Version > CurrentVersion)
        {
            throw new InvalidOperationException(
                $"policy document version {policy.Version} is unsupported; this build accepts v1-v{CurrentVersion}");
        }

        // Defensive: deserialization can leave collections null if the JSON omits
        // a section AND the property had no initializer path taken.
        policy.Domains ??= new();
        policy.HostsRedirects ??= new();
        policy.FirewallRules ??= new();
        policy.DomainFirewallRules ??= new();
        policy.Schedules ??= new();
        policy.Profiles ??= new();
        policy.Lock ??= new();
        var legacyHash = policy.Lock.ConsumeLegacyHash();
        if (legacyHash.Length != 0 && !PasswordHash.IsValidEncoding(legacyHash))
        {
            throw new ArgumentException(
                "settings-lock hash must use the supported PBKDF2-SHA256 format and work-factor bounds",
                nameof(json));
        }

        policy.NetworkProfiles ??= new();
        for (var index = 0; index < policy.NetworkProfiles.Count; index++)
        {
            var network = policy.NetworkProfiles[index]
                ?? throw new JsonException($"NetworkProfiles[{index}] must not be null");
            network.Fingerprint ??= string.Empty;
            network.Profile ??= string.Empty;
            network.Label ??= string.Empty;
            network.GatewayMac ??= string.Empty;
            network.Ssid ??= string.Empty;
            network.InterfaceName ??= string.Empty;
            network.DnsSuffix ??= string.Empty;
        }
        policy.RuleGroups ??= new();
        policy.BlocklistSubs ??= new();
        policy.IpBlocklists ??= new();
        policy.AllowlistSubs ??= new();
        policy.AppVpnBindings ??= new();
        policy.LanAttackSurface ??= new();
        policy.LanAttackSurface.Toggles ??= new();
        policy.Settings ??= new(StringComparer.Ordinal);
        foreach (var redirect in policy.HostsRedirects)
        {
            if (redirect is null)
            {
                throw new JsonException("HostsRedirects must not contain null rows");
            }

            if (!HostRedirect.TryNormalize(redirect.Domain, redirect.Ip, out var domain, out var ip, out var error))
            {
                throw new ArgumentException($"invalid hosts redirect: {error}", nameof(json));
            }

            redirect.Domain = domain;
            redirect.Ip = ip;
        }

        if (policy.DnsPrivacy?.ResolverAdapters is { } resolverAdapters)
        {
            for (var index = 0; index < resolverAdapters.Count; index++)
            {
                var resolver = resolverAdapters[index]
                    ?? throw new JsonException($"DnsPrivacy.ResolverAdapters[{index}] must not be null");
                resolver.Adapter = (resolver.Adapter ?? string.Empty).Trim();
                resolver.Servers ??= new();
                var normalized = new List<string>();
                foreach (var server in resolver.Servers)
                {
                    if (!IPAddress.TryParse(server?.Trim(), out var address))
                    {
                        throw new JsonException($"DnsPrivacy.ResolverAdapters[{index}].Servers contains a non-IP address");
                    }

                    if (!normalized.Contains(address.ToString(), StringComparer.OrdinalIgnoreCase))
                    {
                        normalized.Add(address.ToString());
                    }
                }

                resolver.Servers = normalized;
            }
        }

        RejectDuplicateIdentities(policy);
        return policy;
    }

    private static void RejectDuplicateProperties(JsonElement element, string path, int depth)
    {
        if (depth > 64)
        {
            throw new JsonException("policy document exceeds the maximum nesting depth");
        }

        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var property in element.EnumerateObject())
            {
                if (!names.Add(property.Name))
                {
                    throw new JsonException($"duplicate JSON property '{property.Name}' at {path}");
                }

                RejectDuplicateProperties(property.Value, $"{path}.{property.Name}", depth + 1);
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            var index = 0;
            foreach (var item in element.EnumerateArray())
            {
                RejectDuplicateProperties(item, $"{path}[{index++}]", depth + 1);
            }
        }
    }

    private static void RejectDuplicateIdentities(PortablePolicy policy)
    {
        RejectDuplicates(policy.Domains, static row => NormalizeDomainIdentity(row.Domain), "Domains");
        RejectDuplicates(policy.HostsRedirects, static row => NormalizeDomainIdentity(row.Domain), "HostsRedirects");
        var managedDomains = policy.Domains
            .Select(row => NormalizeDomainIdentity(row.Domain))
            .Where(domain => domain.Length != 0)
            .ToHashSet(StringComparer.Ordinal);
        if (policy.HostsRedirects.Any(row => managedDomains.Contains(NormalizeDomainIdentity(row.Domain))))
        {
            throw new JsonException("a domain cannot be both managed and pinned in HostsRedirects");
        }
        RejectDuplicates(policy.FirewallRules, static row => row.Name, "FirewallRules");
        RejectDuplicates(policy.DomainFirewallRules, static row => row.RuleName, "DomainFirewallRules.RuleName");
        RejectDuplicates(policy.DomainFirewallRules,
            static row => $"{NormalizeDomainIdentity(row.Domain)}\u001f{CleanIdentity(row.Program)}",
            "DomainFirewallRules.Domain+Program");
        RejectDuplicates(policy.Schedules,
            static row => $"{CleanIdentity(row.Target)}\u001f{CleanIdentity(row.Days)}\u001f{CleanIdentity(row.Start)}\u001f{CleanIdentity(row.End)}",
            "Schedules");
        RejectDuplicates(policy.Profiles, static row => row.Name, "Profiles");
        foreach (var profile in policy.Profiles)
        {
            profile.Rules ??= new();
            RejectDuplicates(profile.Rules, static row => NormalizeDomainIdentity(row.Domain), $"Profiles[{profile.Name}].Rules");
        }

        RejectDuplicates(policy.NetworkProfiles, static row => NetworkIdentity(row), "NetworkProfiles");
        RejectDuplicates(policy.RuleGroups, static row => row.Name, "RuleGroups");
        foreach (var group in policy.RuleGroups)
        {
            group.Rules ??= new();
            RejectDuplicateStrings(group.Rules, $"RuleGroups[{group.Name}].Rules", StringComparer.OrdinalIgnoreCase);
        }

        RejectDuplicates(policy.BlocklistSubs, static row => row.Name, "BlocklistSubs");
        foreach (var source in policy.BlocklistSubs)
        {
            source.Mirrors ??= new();
            RejectDuplicateStrings(source.Mirrors, $"BlocklistSubs[{source.Name}].Mirrors", StringComparer.Ordinal);
            if (source.Mirrors.Count > 5 || source.Mirrors.Any(static mirror =>
                    !Uri.TryCreate(mirror, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps))
            {
                throw new JsonException($"BlocklistSubs[{source.Name}].Mirrors must contain at most 5 https URLs");
            }
        }
        RejectDuplicates(policy.IpBlocklists, static row => row.Name, "IpBlocklists");
        RejectDuplicateStrings(policy.AllowlistSubs, "AllowlistSubs", StringComparer.Ordinal);
        RejectDuplicates(policy.AppVpnBindings, static row => row.Program, "AppVpnBindings");
        if (policy.DnsPrivacy?.ResolverAdapters is { } resolverAdapters)
        {
            RejectDuplicates(resolverAdapters,
                static row => $"{CleanIdentity(row.Adapter)}\u001f{row.IsVpn}",
                "DnsPrivacy.ResolverAdapters");
        }
        if (policy.UsageQuotas is { } quotas)
        {
            RejectDuplicates(quotas, static row => $"{CleanIdentity(row.Scope)}\u001f{CleanIdentity(row.Match)}", "UsageQuotas");
        }

        if (policy.HistoryPrivacyExclusions is { } exclusions)
        {
            RejectDuplicates(exclusions, static row => $"{CleanIdentity(row.Scope)}\u001f{CleanIdentity(row.Match)}", "HistoryPrivacyExclusions");
        }

        RejectDuplicates(policy.LanAttackSurface!.Toggles, static row => row.Key, "LanAttackSurface.Toggles");
        if (policy.AiKnowledge is { } knowledge)
        {
            RejectDuplicates(knowledge, static row => $"{CleanIdentity(row.Kind)}\u001f{CleanIdentity(row.Key)}", "AiKnowledge");
        }

        if (policy.UserOverrides is { } overrides)
        {
            RejectDuplicates(overrides, static row => $"{CleanIdentity(row.Kind)}\u001f{CleanIdentity(row.Key)}", "UserOverrides");
        }

        if (policy.Webhooks?.Urls is { } webhooks)
        {
            RejectDuplicateStrings(webhooks, "Webhooks.Urls", StringComparer.Ordinal);
        }
    }

    private static string NetworkIdentity(PolicyNetworkProfile row)
    {
        try
        {
            return row.StorageFingerprint();
        }
        catch (ArgumentException)
        {
            return string.Empty;
        }
    }

    private static string CleanIdentity(string? value) => (value ?? string.Empty).Trim();

    private static string NormalizeDomainIdentity(string? value) =>
        global::HostsGuard.Core.Domains.ToAscii(value ?? string.Empty);

    private static void RejectDuplicates<T>(
        IEnumerable<T> rows,
        Func<T, string?> identity,
        string section)
        where T : class
    {
        var keys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var index = 0;
        foreach (var row in rows)
        {
            if (row is null)
            {
                throw new JsonException($"{section}[{index}] must not be null");
            }

            var key = (identity(row) ?? string.Empty).Trim();
            if (key.Length != 0 && !keys.Add(key))
            {
                throw new JsonException($"{section} contains a duplicate identity");
            }

            index++;
        }
    }

    private static void RejectDuplicateStrings(
        IEnumerable<string> values,
        string section,
        StringComparer comparer)
    {
        var keys = new HashSet<string>(comparer);
        var index = 0;
        foreach (var value in values)
        {
            if (value is null)
            {
                throw new JsonException($"{section}[{index}] must not be null");
            }

            var key = value.Trim();
            if (key.Length != 0 && !keys.Add(key))
            {
                throw new JsonException($"{section} contains a duplicate identity");
            }

            index++;
        }
    }
}

/// <summary>A managed-domain policy row (block/allow with provenance).</summary>
public sealed class PolicyDomain
{
    public string Domain { get; set; } = string.Empty;

    public string Status { get; set; } = "blocked";

    public string Source { get; set; } = string.Empty;

    public string Reason { get; set; } = string.Empty;

    public string Category { get; set; } = string.Empty;

    public string Notes { get; set; } = string.Empty;
}

/// <summary>An intentional hosts-file domain-to-IP mapping.</summary>
public sealed class PolicyHostsRedirect
{
    public string Domain { get; set; } = string.Empty;

    public string Ip { get; set; } = string.Empty;
}

/// <summary>A domain-scoped firewall rule intent whose live IPs refresh from DNS.</summary>
public sealed class PolicyDomainFirewallRule
{
    public string Domain { get; set; } = string.Empty;

    public string Program { get; set; } = string.Empty;

    public string RuleName { get; set; } = string.Empty;

    public string Action { get; set; } = "Block";

    public bool Enabled { get; set; } = true;

    public string RemoteAddr { get; set; } = string.Empty;
}

/// <summary>An HG_-authored firewall rule, everything needed to recreate it.</summary>
public sealed class PolicyFirewallRule
{
    public string Name { get; set; } = string.Empty;

    public string Direction { get; set; } = "Out";

    public string Action { get; set; } = "Block";

    public bool Enabled { get; set; } = true;

    public string RemoteAddr { get; set; } = "Any";

    public string Protocol { get; set; } = "Any";

    public string Program { get; set; } = string.Empty;

    public string PackageFamilyName { get; set; } = string.Empty;

    public string PackageSid { get; set; } = string.Empty;

    public string PackageDisplayName { get; set; } = string.Empty;

    public string PackageFullName { get; set; } = string.Empty;

    public string PackageBinaries { get; set; } = string.Empty;

    public string RemotePorts { get; set; } = "Any";

    public string LocalPorts { get; set; } = "Any";

    public string ServiceName { get; set; } = string.Empty;

    public string Interfaces { get; set; } = "Any";

    public string Description { get; set; } = string.Empty;
}

/// <summary>A scheduled block window (domain or fw:HG_ rule target).</summary>
public sealed class PolicySchedule
{
    public string Target { get; set; } = string.Empty;

    /// <summary>Comma-separated day indices, 0=Mon .. 6=Sun.</summary>
    public string Days { get; set; } = string.Empty;

    public string Start { get; set; } = string.Empty;

    public string End { get; set; } = string.Empty;
}

/// <summary>A named rule-set profile and its snapshotted domain rules.</summary>
public sealed class PolicyProfile
{
    public string Name { get; set; } = string.Empty;

    public List<PolicyProfileRule> Rules { get; set; } = new();
}

public sealed class PolicyProfileRule
{
    public string Domain { get; set; } = string.Empty;

    public string Status { get; set; } = "blocked";

    public string Source { get; set; } = string.Empty;
}

/// <summary>The settings-lock intent. Credential material is machine-local and never portable.</summary>
public sealed class PolicyLock
{
    private string? _legacyHash;

    public bool Enabled { get; set; }

    /// <summary>
    /// Deserialization-only compatibility for older v1 exports. The parser
    /// validates then clears it; new documents never serialize this value.
    /// </summary>
    [JsonPropertyName("Hash")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? LegacyHash
    {
        get => null;
        set => _legacyHash = value;
    }

    internal string ConsumeLegacyHash()
    {
        var value = _legacyHash ?? string.Empty;
        _legacyHash = null;
        return value;
    }
}

/// <summary>A network-fingerprint → profile auto-switch mapping (NET-083).</summary>
public sealed class PolicyNetworkProfile
{
    public string Fingerprint { get; set; } = string.Empty;

    public string Profile { get; set; } = string.Empty;

    public string Label { get; set; } = string.Empty;

    public string GatewayMac { get; set; } = string.Empty;

    public string Ssid { get; set; } = string.Empty;

    public string InterfaceName { get; set; } = string.Empty;

    public string DnsSuffix { get; set; } = string.Empty;

    public bool? VpnPresent { get; set; }

    public NetworkProfileMatchRule ToMatchRule() => new(
        Profile ?? string.Empty,
        Label ?? string.Empty,
        Fingerprint ?? string.Empty,
        GatewayMac ?? string.Empty,
        Ssid ?? string.Empty,
        InterfaceName ?? string.Empty,
        DnsSuffix ?? string.Empty,
        VpnPresent);

    public string StorageFingerprint() => NetworkProfileSelectorCodec.Encode(ToMatchRule());
}

/// <summary>A named rule group and its member HG_ rule names (NET-103).</summary>
public sealed class PolicyRuleGroup
{
    public string Name { get; set; } = string.Empty;

    public List<string> Rules { get; set; } = new();
}

/// <summary>A subscribed blocklist source (refresh re-imports its domains).</summary>
public sealed class PolicyBlocklistSub
{
    public string Name { get; set; } = string.Empty;

    public string Url { get; set; } = string.Empty;

    public List<string> Mirrors { get; set; } = new();
}

/// <summary>A subscribed IP-format blocklist (NET-171; refresh re-applies its HG_IPBlock_* rules).</summary>
public sealed class PolicyIpBlocklist
{
    public string Name { get; set; } = string.Empty;

    public string Url { get; set; } = string.Empty;

    public bool Enabled { get; set; } = true;
}

/// <summary>Consent-mode posture and trust sets. Null properties mean "not present in this policy".</summary>
public sealed class PolicyConsent
{
    public string? Mode { get; set; }

    public bool? ChildInherit { get; set; }

    public bool? InboundConsent { get; set; }

    public List<string>? TrustedPublishers { get; set; }

    public List<string>? TrustedFolders { get; set; }
}

/// <summary>DNS-bypass and name-attribution posture plus learned DoH resolver state.</summary>
public sealed class PolicyDnsPrivacy
{
    public bool? DohBlocking { get; set; }

    public bool? QuicBlocked { get; set; }

    public bool? CnameCloak { get; set; }

    public bool? SniCapture { get; set; }

    public PolicyDohState? DohIntelligence { get; set; }

    /// <summary>
    /// Per-adapter resolver intent. Null means a legacy document that did not
    /// carry resolver state; an empty list is an explicit snapshot with no
    /// eligible adapters. Adapter IDs are intentionally excluded as machine-local.
    /// </summary>
    public List<PolicyDnsResolver>? ResolverAdapters { get; set; }
}

public sealed class PolicyDohState
{
    public string Updated { get; set; } = string.Empty;

    public string Source { get; set; } = string.Empty;

    public string Sha256 { get; set; } = string.Empty;

    public List<string> Ips { get; set; } = new();
}

public sealed class PolicyDnsResolver
{
    public string Adapter { get; set; } = string.Empty;

    public bool IsVpn { get; set; }

    /// <summary>Empty restores DHCP; otherwise contains literal IPv4/IPv6 resolver addresses.</summary>
    public List<string> Servers { get; set; } = new();
}

/// <summary>VPN-presence kill-switch policy. Prior engaged posture is machine-local and not portable.</summary>
public sealed class PolicyKillSwitch
{
    public bool? Enabled { get; set; }

    public string? Adapter { get; set; }
}

/// <summary>Per-app adapter binding intent (live firewall interface list is machine-local).</summary>
public sealed class PolicyAppVpnBinding
{
    public string Program { get; set; } = string.Empty;

    public string Adapter { get; set; } = string.Empty;
}

/// <summary>Alert-only local usage-budget rule; no shaping or blocking posture.</summary>
public sealed class PolicyUsageQuota
{
    public string Scope { get; set; } = string.Empty;

    public string Match { get; set; } = string.Empty;

    public bool BlockOnExceed { get; set; }

    public long LimitBytes { get; set; }

    public int WindowDays { get; set; } = 30;

    public bool Enabled { get; set; } = true;
}

public sealed class PolicyHistoryPrivacyExclusion
{
    public string Scope { get; set; } = string.Empty;
    public string Match { get; set; } = string.Empty;
}

public sealed class PolicyLanAttackSurface
{
    public List<PolicyLanAttackSurfaceToggle> Toggles { get; set; } = new();
}

public sealed class PolicyLanAttackSurfaceToggle
{
    public string Key { get; set; } = string.Empty;

    public bool Blocked { get; set; }
}

/// <summary>AI settings minus the secret API key.</summary>
public sealed class PolicyAiSettings
{
    public string? Model { get; set; }

    public string? Endpoint { get; set; }

    public bool? Enabled { get; set; }

    public bool? ApiKeyConfigured { get; set; }

    public string? LastRun { get; set; }

    public string? LastResult { get; set; }

    public string? LastReviewed { get; set; }
}

public sealed class PolicyAiKnowledge
{
    public string Kind { get; set; } = string.Empty;

    public string Key { get; set; } = string.Empty;

    public string Value { get; set; } = string.Empty;

    public string Model { get; set; } = string.Empty;

    public string Created { get; set; } = string.Empty;
}

public sealed class PolicyUserOverride
{
    public string Kind { get; set; } = string.Empty;

    public string Key { get; set; } = string.Empty;

    public string Value { get; set; } = string.Empty;

    public string Created { get; set; } = string.Empty;
}

/// <summary>Webhook endpoints only; signing secrets are intentionally not portable.</summary>
public sealed class PolicyWebhooks
{
    public List<string>? Urls { get; set; }

    public bool? SecretConfigured { get; set; }
}
