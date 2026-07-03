namespace HostsGuard.Core;

/// <summary>
/// Curated, offline hosts-file categories for well-known ad/tracking/telemetry
/// domains — promoted from reviewed AI-researched field knowledge (2026-07-03).
/// Fresh installs categorize these without any AI key; the AI only handles
/// domains this table doesn't know. Suffix-matched, longest wins; unknown
/// domains return blank. Category names follow the user-facing hosts-file
/// section style ("Google Ads", "Microsoft Telemetry").
/// </summary>
public static class DomainCategories
{
    private static readonly IReadOnlyList<(string Suffix, string Category)> Map = new[]
    {
        // Google Ads
        ("doubleclick.net", "Google Ads"),
        ("googlesyndication.com", "Google Ads"),
        ("googleadservices.com", "Google Ads"),
        ("adservice.google.com", "Google Ads"),
        ("adtrafficquality.google", "Google Ads"),
        // Google Tracking
        ("google-analytics.com", "Google Tracking"),
        ("analytics.google.com", "Google Tracking"),
        ("googletagmanager.com", "Google Tracking"),
        ("app-measurement.com", "Google Tracking"),
        // Facebook/Meta Tracking
        ("pixel.facebook.com", "Facebook/Meta Tracking"),
        ("an.facebook.com", "Facebook/Meta Tracking"),
        ("pixel.instagram.com", "Facebook/Meta Tracking"),
        ("connect.facebook.net", "Facebook/Meta Tracking"),
        // Microsoft Telemetry
        ("telemetry.microsoft.com", "Microsoft Telemetry"),
        ("vortex.data.microsoft.com", "Microsoft Telemetry"),
        ("events.data.microsoft.com", "Microsoft Telemetry"),
        ("settings-win.data.microsoft.com", "Microsoft Telemetry"),
        ("bat.bing.com", "Microsoft Telemetry"),
        // Amazon Ads
        ("amazon-adsystem.com", "Amazon Ads"),
        // Adobe Telemetry
        ("cc-api-data.adobe.io", "Adobe Telemetry"),
        ("lcs-cops.adobe.io", "Adobe Telemetry"),
        // Yandex Analytics
        ("mc.yandex.ru", "Yandex Analytics"),
        ("adfstat.yandex.ru", "Yandex Analytics"),
        ("static-mon.yandex.net", "Yandex Analytics"),
        // Major Ad Networks
        ("adnxs.com", "Major Ad Networks"),
        ("criteo.com", "Major Ad Networks"),
        ("openx.net", "Major Ad Networks"),
        ("serving-sys.com", "Major Ad Networks"),
        ("ads.yahoo.com", "Major Ad Networks"),
        ("magsrv.com", "Major Ad Networks"),
        ("tsyndicate.com", "Major Ad Networks"),
        ("twinrdengine.com", "Major Ad Networks"),
        ("rlcdn.com", "Major Ad Networks"),
        // Analytics
        ("scorecardresearch.com", "Analytics"),
        ("quantserve.com", "Analytics"),
        ("cloudflareinsights.com", "Analytics"),
        ("datadoghq.com", "Analytics"),
        ("datadoghq-browser-agent.com", "Analytics"),
        ("useinsider.com", "Analytics"),
        ("stats.wp.com", "Analytics"),
        ("pixel.wp.com", "Analytics"),
        ("sentry.io", "Analytics"),
        ("litix.io", "Analytics"),
        ("branch.io", "Analytics"),
        ("crashlytics.com", "Analytics"),
    };

    /// <summary>Best (longest-suffix) category for a domain, or "" if unknown.</summary>
    public static string Lookup(string? domain)
    {
        var d = (domain ?? string.Empty).ToLowerInvariant().Trim().TrimEnd('.');
        if (d.Length == 0)
        {
            return string.Empty;
        }

        var best = string.Empty;
        var bestLen = 0;
        foreach (var (suffix, category) in Map)
        {
            var isMatch = d.Equals(suffix, StringComparison.Ordinal) ||
                d.EndsWith("." + suffix, StringComparison.Ordinal);
            if (isMatch && suffix.Length > bestLen)
            {
                best = category;
                bestLen = suffix.Length;
            }
        }

        return best;
    }
}
