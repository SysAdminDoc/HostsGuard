using System.Text.Json;
using System.Text.Json.Serialization;

namespace HostsGuard.Core;

/// <summary>
/// A single versioned, portable snapshot of a HostsGuard machine's whole policy
/// (NET-089): managed domains, HG_ firewall rules, schedules, rule-set profiles,
/// the settings lock, network→profile mappings, and allow/blocklist
/// subscriptions. Serializes to one JSON document so a machine's policy can be
/// backed up and reconstructed on a clean install. Pure data — no OS deps — so
/// the service, CLI, and UI all share it.
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

    public List<PolicySchedule> Schedules { get; set; } = new();

    public List<PolicyProfile> Profiles { get; set; } = new();

    public PolicyLock Lock { get; set; } = new();

    public List<PolicyNetworkProfile> NetworkProfiles { get; set; } = new();

    public List<PolicyBlocklistSub> BlocklistSubs { get; set; } = new();

    public List<string> AllowlistSubs { get; set; } = new();

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
        policy.Schedules ??= new();
        policy.Profiles ??= new();
        policy.Lock ??= new();
        policy.NetworkProfiles ??= new();
        policy.BlocklistSubs ??= new();
        policy.AllowlistSubs ??= new();
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

    public string RemotePorts { get; set; } = "Any";

    public string ServiceName { get; set; } = string.Empty;
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
}

/// <summary>A subscribed blocklist source (refresh re-imports its domains).</summary>
public sealed class PolicyBlocklistSub
{
    public string Name { get; set; } = string.Empty;

    public string Url { get; set; } = string.Empty;
}
