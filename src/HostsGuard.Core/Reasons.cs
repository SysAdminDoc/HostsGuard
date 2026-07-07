namespace HostsGuard.Core;

/// <summary>
/// Canonical block/allow reason taxonomy. Faithful port of Python
/// <c>canonical_reason</c> / <c>reason_label</c> and the schema-v7 reason columns,
/// so legacy rows render consistently in the .NET build.
/// </summary>
public static class Reasons
{
    /// <summary>Canonical reason keys → display labels, in canonical order.</summary>
    public static readonly IReadOnlyList<KeyValuePair<string, string>> Labels = new[]
    {
        new KeyValuePair<string, string>("manual", "Manual"),
        new("blocklist", "Blocklist"),
        new("allowlist", "Allowlist"),
        new("schedule", "Schedule"),
        new("service", "Service"),
        new("telemetry", "Telemetry"),
        new("doh", "Encrypted DNS"),
        new("firewall", "Firewall"),
        new("consent", "Consent"),
        new("import", "Import"),
        new("hosts_file", "Hosts File"),
        new("cli", "CLI"),
        new("service_api", "Service API"),
        new("observed", "Observed"),
        new("unknown", "Unknown"),
    };

    private static readonly IReadOnlyDictionary<string, string> LabelMap =
        Labels.ToDictionary(kv => kv.Key, kv => kv.Value, StringComparer.Ordinal);

    private static readonly IReadOnlyDictionary<string, string> Aliases = new Dictionary<string, string>(StringComparer.Ordinal)
    {
        ["allow"] = "manual",
        ["allowed"] = "manual",
        ["whitelist"] = "allowlist",
        ["whitelisted"] = "allowlist",
        ["list"] = "blocklist",
        ["blocklists"] = "blocklist",
        ["firewall_blocked"] = "firewall",
        ["fw"] = "firewall",
        ["rpc"] = "service_api",
        ["api"] = "service_api",
        ["temp_allow"] = "manual",
        ["temp_reverted"] = "manual",
        ["paste"] = "manual",
    };

    /// <summary>Resolve a canonical reason key from any of the free-form inputs.</summary>
    public static string Canonical(string? reason = null, string? source = null, string? action = null, string? details = null)
    {
        var r = (reason ?? string.Empty).Trim().ToLowerInvariant().Replace(' ', '_').Replace('-', '_');
        r = Aliases.GetValueOrDefault(r, r);
        if (LabelMap.ContainsKey(r))
        {
            return r;
        }

        var src = (source ?? string.Empty).Trim().ToLowerInvariant();
        if (src.StartsWith("list:", StringComparison.Ordinal))
        {
            return "blocklist";
        }

        if (src.StartsWith("service:", StringComparison.Ordinal))
        {
            return "service";
        }

        src = Aliases.GetValueOrDefault(src, src);
        if (LabelMap.ContainsKey(src))
        {
            return src;
        }

        var detail = (details ?? string.Empty).Trim().ToLowerInvariant();
        var act = (action ?? string.Empty).Trim().ToLowerInvariant();
        if (act == "fw_blocked" || detail.Contains("firewall", StringComparison.Ordinal))
        {
            return "firewall";
        }

        if (detail.Contains("doh", StringComparison.Ordinal) || detail.Contains("encrypted dns", StringComparison.Ordinal))
        {
            return "doh";
        }

        if (detail.Contains("telemetry", StringComparison.Ordinal))
        {
            return "telemetry";
        }

        if (detail.Contains("schedule", StringComparison.Ordinal))
        {
            return "schedule";
        }

        if (detail.Contains("allowlist", StringComparison.Ordinal))
        {
            return "allowlist";
        }

        if (detail.Contains("blocklist", StringComparison.Ordinal) || detail.Contains("imported", StringComparison.Ordinal))
        {
            return "blocklist";
        }

        if (detail.Contains("rpc", StringComparison.Ordinal) || detail.Contains("json-rpc", StringComparison.Ordinal))
        {
            return "service_api";
        }

        if (detail.Contains("cli", StringComparison.Ordinal))
        {
            return "cli";
        }

        if (detail.Contains("import", StringComparison.Ordinal))
        {
            return "import";
        }

        if (detail.Contains("hosts file", StringComparison.Ordinal) || detail.Contains("blocked by hosts", StringComparison.Ordinal))
        {
            return "hosts_file";
        }

        if (act is "blocked" or "whitelisted")
        {
            return "manual";
        }

        return "unknown";
    }

    /// <summary>Display label for a (possibly non-canonical) reason.</summary>
    public static string Label(string? reason)
    {
        var r = Canonical(reason);
        return LabelMap.GetValueOrDefault(r, LabelMap["unknown"]);
    }
}
