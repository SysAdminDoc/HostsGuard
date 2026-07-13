using System.Text.Json;
using System.Text.Json.Serialization;

namespace HostsGuard.Core;

/// <summary>
/// A single versioned, portable snapshot of a HostsGuard machine's whole policy
/// (NET-089): managed domains, HG_ firewall rules, schedules, rule-set profiles,
/// the settings lock, network→profile mappings, allow/blocklist subscriptions,
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
        var policy = JsonSerializer.Deserialize<PortablePolicy>(json, Options)
            ?? throw new JsonException("policy document is empty");
        if (policy.Version > CurrentVersion)
        {
            throw new InvalidOperationException(
                $"policy document version {policy.Version} is newer than this build supports (v{CurrentVersion})");
        }

        // Defensive: deserialization can leave collections null if the JSON omits
        // a section AND the property had no initializer path taken.
        policy.Domains ??= new();
        policy.FirewallRules ??= new();
        policy.DomainFirewallRules ??= new();
        policy.Schedules ??= new();
        policy.Profiles ??= new();
        policy.Lock ??= new();
        policy.NetworkProfiles ??= new();
        policy.NetworkProfiles.RemoveAll(network => network is null);
        foreach (var network in policy.NetworkProfiles)
        {
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
        return policy;
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

/// <summary>The settings-lock state (armed flag + password hash, never plaintext).</summary>
public sealed class PolicyLock
{
    public bool Enabled { get; set; }

    public string Hash { get; set; } = string.Empty;
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
}

public sealed class PolicyDohState
{
    public string Updated { get; set; } = string.Empty;

    public string Source { get; set; } = string.Empty;

    public string Sha256 { get; set; } = string.Empty;

    public List<string> Ips { get; set; } = new();
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
