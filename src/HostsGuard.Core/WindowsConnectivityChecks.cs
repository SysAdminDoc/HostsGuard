namespace HostsGuard.Core;

public enum WindowsConnectivityProbeKind
{
    Web,
    Dns,
}

public enum WindowsConnectivityProbeEra
{
    Current,
    Legacy,
}

public sealed record WindowsConnectivityDependency(
    string Domain,
    WindowsConnectivityProbeKind ProbeKind,
    WindowsConnectivityProbeEra Era);

/// <summary>
/// Alert-only evidence that a deliberate block can degrade Windows NCSI status.
/// It does not veto, filter, or mutate the requested import.
/// </summary>
public sealed record WindowsConnectivityWarning(
    WindowsConnectivityDependency Dependency,
    string Reason)
{
    public const string WarningCode = "windows_ncsi_dependency";
}

/// <summary>
/// Exact default Network Connectivity Status Indicator probe-host taxonomy.
/// Source: Microsoft NCSI troubleshooting guidance for current and legacy Windows.
/// Broad Microsoft suffixes and CDN implementation hosts are intentionally excluded.
/// </summary>
public static class WindowsConnectivityChecks
{
    public const string SourceUrl =
        "https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/troubleshoot-ncsi-guidance";

    private static readonly IReadOnlyDictionary<string, WindowsConnectivityDependency> ByDomain =
        new[]
        {
            new WindowsConnectivityDependency("www.msftconnecttest.com", WindowsConnectivityProbeKind.Web, WindowsConnectivityProbeEra.Current),
            new WindowsConnectivityDependency("ipv6.msftconnecttest.com", WindowsConnectivityProbeKind.Web, WindowsConnectivityProbeEra.Current),
            new WindowsConnectivityDependency("dns.msftncsi.com", WindowsConnectivityProbeKind.Dns, WindowsConnectivityProbeEra.Current),
            new WindowsConnectivityDependency("www.msftncsi.com", WindowsConnectivityProbeKind.Web, WindowsConnectivityProbeEra.Legacy),
            new WindowsConnectivityDependency("ipv6.msftncsi.com", WindowsConnectivityProbeKind.Web, WindowsConnectivityProbeEra.Legacy),
        }.ToDictionary(static dependency => dependency.Domain, StringComparer.Ordinal);

    public static IReadOnlyCollection<WindowsConnectivityDependency> Dependencies => ByDomain.Values.ToArray();

    public static bool TryGet(string? domain, out WindowsConnectivityDependency dependency)
    {
        var normalized = Normalize(domain);
        return ByDomain.TryGetValue(normalized, out dependency!);
    }

    public static IReadOnlyList<WindowsConnectivityWarning> FindBlocked(IEnumerable<string?> domains)
    {
        ArgumentNullException.ThrowIfNull(domains);
        return domains
            .Select(Normalize)
            .Where(static domain => domain.Length != 0)
            .Distinct(StringComparer.Ordinal)
            .Select(static domain => ByDomain.GetValueOrDefault(domain))
            .Where(static dependency => dependency is not null)
            .Select(static dependency => new WindowsConnectivityWarning(
                dependency!,
                dependency!.ProbeKind == WindowsConnectivityProbeKind.Dns
                    ? "Blocking this exact NCSI DNS probe can make Windows report degraded or unavailable internet connectivity."
                    : "Blocking this exact NCSI web probe can make Windows report degraded connectivity or trigger captive-portal handling."))
            .OrderBy(static warning => warning.Dependency.Era)
            .ThenBy(static warning => warning.Dependency.Domain, StringComparer.Ordinal)
            .ToArray();
    }

    private static string Normalize(string? domain)
    {
        var value = (domain ?? string.Empty).Trim().TrimEnd('.');
        if (value.Length == 0) return string.Empty;
        return Domains.ToAscii(value);
    }
}
