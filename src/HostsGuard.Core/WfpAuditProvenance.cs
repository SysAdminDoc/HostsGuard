namespace HostsGuard.Core;

/// <summary>Structured Windows Filtering Platform audit provenance from 5157/5152 events.</summary>
public sealed record WfpAuditProvenance(
    string FilterRuntimeId = "",
    string FilterOrigin = "",
    string LayerName = "",
    string LayerRuntimeId = "",
    int InterfaceIndex = 0,
    string InterfaceName = "")
{
    private static readonly string[] DefaultFilterOrigins =
    [
        "appcontainer loopback",
        "boot time default",
        "quarantine default",
        "query user default",
        "stealth",
        "uwp default",
        "universal windows platform default",
        "wsh default",
        "windows service hardening default",
    ];

    public static readonly WfpAuditProvenance Empty = new();

    public bool HasAny =>
        FilterRuntimeId.Length != 0 ||
        FilterOrigin.Length != 0 ||
        LayerName.Length != 0 ||
        LayerRuntimeId.Length != 0 ||
        InterfaceIndex > 0 ||
        InterfaceName.Length != 0;

    public bool IsHostsGuardRule => IsHostsGuardRuleOrigin(FilterOrigin);

    public bool IsWindowsDefaultFilter => IsDefaultFilterOrigin(FilterOrigin);

    public bool IsExternalRule => IsExternalRuleOrigin(FilterOrigin);

    public string OwnerLabel => OwnerFor(FilterOrigin);

    public string CauseLabel => CauseFor(FilterOrigin);

    public string InterfaceLabel => InterfaceName.Length != 0
        ? InterfaceIndex > 0 ? $"{InterfaceName} ({InterfaceIndex})" : InterfaceName
        : InterfaceIndex > 0 ? $"ifIndex {InterfaceIndex}" : string.Empty;

    public static bool IsHostsGuardRuleOrigin(string? filterOrigin)
        => Normalize(filterOrigin).StartsWith("hg_", StringComparison.OrdinalIgnoreCase);

    public static bool IsDefaultFilterOrigin(string? filterOrigin)
    {
        var origin = Normalize(filterOrigin);
        return origin.Length != 0 && DefaultFilterOrigins.Any(defaultOrigin =>
            origin.Equals(defaultOrigin, StringComparison.OrdinalIgnoreCase) ||
            origin.Contains(defaultOrigin, StringComparison.OrdinalIgnoreCase));
    }

    public static bool IsExternalRuleOrigin(string? filterOrigin)
    {
        var origin = Normalize(filterOrigin);
        return origin.Length != 0 && !IsHostsGuardRuleOrigin(origin) && !IsDefaultFilterOrigin(origin);
    }

    public static string OwnerFor(string? filterOrigin)
    {
        var origin = Normalize(filterOrigin);
        if (origin.Length == 0)
        {
            return "Origin unavailable";
        }

        if (IsHostsGuardRuleOrigin(origin))
        {
            return "HostsGuard rule";
        }

        return IsDefaultFilterOrigin(origin)
            ? "Windows default filter"
            : "External firewall rule";
    }

    public static string CauseFor(string? filterOrigin)
    {
        var origin = Normalize(filterOrigin);
        if (origin.Length == 0)
        {
            return "Unknown origin";
        }

        if (IsHostsGuardRuleOrigin(origin))
        {
            return "HostsGuard";
        }

        return IsDefaultFilterOrigin(origin) ? "Windows default" : "Not HostsGuard";
    }

    private static string Normalize(string? value) => (value ?? string.Empty).Trim();
}
