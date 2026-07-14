using HostsGuard.Contracts;

namespace HostsGuard.App.Services;

/// <summary>Concise, shared completeness warning for live feed surfaces.</summary>
public static class ObservationIntegrityText
{
    public static string ForFeed(ServiceStatus status, params string[] sources)
    {
        ArgumentNullException.ThrowIfNull(status);
        var wanted = sources.ToHashSet(StringComparer.Ordinal);
        var incomplete = status.ObservationSources
            .Where(row => wanted.Contains(row.Source) && row.State != "healthy")
            .OrderBy(row => row.Source, StringComparer.Ordinal)
            .ToArray();
        if (incomplete.Length == 0)
        {
            return string.Empty;
        }

        var details = string.Join("; ", incomplete.Select(row =>
        {
            var since = row.IncompleteSince.Length != 0 ? row.IncompleteSince : row.LastTransitionAt;
            return I18n.T(
                "Observation_IncompleteSource",
                "{0} {1} since {2} (lost {3}, gaps {4}, restarts {5}): {6}",
                SourceName(row.Source),
                row.State,
                TimeText.Compact(since),
                row.LossCount,
                row.GapCount,
                row.RestartCount,
                row.Detail);
        }));
        return I18n.T(
            "Observation_IncompleteFeed",
            "Evidence is incomplete — {0}",
            details);
    }

    private static string SourceName(string source) => source switch
    {
        "dns_etw" => I18n.T("Observation_DnsSource", "DNS ETW"),
        "network_etw" => I18n.T("Observation_NetworkSource", "network ETW"),
        "security_log" => I18n.T("Observation_SecuritySource", "Security log"),
        _ => source,
    };
}
