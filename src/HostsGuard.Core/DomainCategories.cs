namespace HostsGuard.Core;

/// <summary>
/// Curated, offline hosts-file categories for well-known ad/tracking/telemetry
/// domains — promoted from reviewed AI-researched field knowledge. Fresh installs
/// categorize these without any AI key; the AI only handles domains this table
/// doesn't know. Suffix-matched, longest wins; unknown domains return blank.
///
/// Categories use a small, consistent CANONICAL taxonomy (see <see cref="Canonical"/>)
/// instead of the previous fragmented per-vendor sections ("Snapchat Tracking",
/// "LinkedIn CDN", "Oracle Maxymiser", …). <see cref="Canonicalize"/> folds any
/// legacy or AI-assigned granular category into that taxonomy, so the hosts file
/// organizes into a dozen clean sections regardless of who assigned the label.
/// </summary>
public static class DomainCategories
{
    /// <summary>The canonical top-level categories, in hosts-file section order.</summary>
    public static readonly IReadOnlyList<string> Canonical = new[]
    {
        "Advertising",
        "Tracking & Analytics",
        "Telemetry",
        "Social Media",
        "CDN",
        "Streaming",
        "Gaming",
        "Email & Marketing",
        "Gambling",
        "Adult",
        "Malware",
        "Other",
    };

    /// <summary>
    /// Fold a free-form or per-vendor category (from a legacy hosts file or an AI
    /// run) into the canonical taxonomy. Keyword-matched; unknown non-empty labels
    /// fall through to "Other", blanks stay blank so callers can skip them.
    /// </summary>
    public static string Canonicalize(string? category)
    {
        var c = (category ?? string.Empty).Trim();
        if (c.Length == 0)
        {
            return string.Empty;
        }

        var l = c.ToLowerInvariant();
        if (Has(l, "malware", "phishing", "scam", "c2", "botnet")) return "Malware";
        if (Has(l, "gambl", "casino", "betting", "poker")) return "Gambling";
        if (Has(l, "adult", "porn", "nsfw", "xxx")) return "Adult";
        if (Has(l, "telemetry", "crash", "error report", "diagnostic")) return "Telemetry";
        if (Has(l, "ads", "advert", "ad network", "ad serving", "adserv", "dsp", "ssp")
            || l == "ad" || l.EndsWith(" ad", StringComparison.Ordinal)) return "Advertising";
        if (Has(l, "track", "analytic", "pixel", "beacon", "measurement", "attribution", "fingerprint")) return "Tracking & Analytics";
        if (Has(l, "cdn", "content delivery", "edge cache")) return "CDN";
        if (Has(l, "social")) return "Social Media";
        if (Has(l, "stream", "video", "music", "media")) return "Streaming";
        if (Has(l, "gaming", "game")) return "Gaming";
        if (Has(l, "mail", "marketing", "crm", "newsletter", "email")) return "Email & Marketing";

        // Already canonical? keep it; otherwise bucket as Other.
        foreach (var canon in Canonical)
        {
            if (string.Equals(c, canon, StringComparison.OrdinalIgnoreCase))
            {
                return canon;
            }
        }

        return "Other";
    }

    private static bool Has(string haystack, params string[] needles)
    {
        foreach (var n in needles)
        {
            if (haystack.Contains(n, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    private static readonly IReadOnlyList<(string Suffix, string Category)> Map = new[]
    {
        // Advertising
        ("adnxs.com", "Advertising"),
        ("ads.yahoo.com", "Advertising"),
        ("adservice.google.com", "Advertising"),
        ("adtrafficquality.google", "Advertising"),
        ("amazon-adsystem.com", "Advertising"),
        ("criteo.com", "Advertising"),
        ("doubleclick.net", "Advertising"),
        ("googleadservices.com", "Advertising"),
        ("googlesyndication.com", "Advertising"),
        ("magsrv.com", "Advertising"),
        ("openx.net", "Advertising"),
        ("rlcdn.com", "Advertising"),
        ("serving-sys.com", "Advertising"),
        ("tsyndicate.com", "Advertising"),
        ("twinrdengine.com", "Advertising"),
        ("unagi-na.amazon.com", "Advertising"),
        ("googletagservices.com", "Advertising"),
        // Tracking & Analytics
        ("adfstat.yandex.ru", "Tracking & Analytics"),
        ("an.facebook.com", "Tracking & Analytics"),
        ("analytics.google.com", "Tracking & Analytics"),
        ("app-measurement.com", "Tracking & Analytics"),
        ("branch.io", "Tracking & Analytics"),
        ("browser-intake-datadoghq.com", "Tracking & Analytics"),
        ("cloudflareinsights.com", "Tracking & Analytics"),
        ("connect.facebook.net", "Tracking & Analytics"),
        ("crashlytics.com", "Tracking & Analytics"),
        ("datadoghq-browser-agent.com", "Tracking & Analytics"),
        ("datadoghq.com", "Tracking & Analytics"),
        ("google-analytics.com", "Tracking & Analytics"),
        ("googletagmanager.com", "Tracking & Analytics"),
        ("litix.io", "Tracking & Analytics"),
        ("mc.yandex.ru", "Tracking & Analytics"),
        ("pixel.facebook.com", "Tracking & Analytics"),
        ("pixel.instagram.com", "Tracking & Analytics"),
        ("pixel.wp.com", "Tracking & Analytics"),
        ("quantserve.com", "Tracking & Analytics"),
        ("scorecardresearch.com", "Tracking & Analytics"),
        ("sentry.io", "Tracking & Analytics"),
        ("sentry.rumble.work", "Tracking & Analytics"),
        ("static-mon.yandex.net", "Tracking & Analytics"),
        ("stats.wp.com", "Tracking & Analytics"),
        ("use1-turn.fpjs.io", "Tracking & Analytics"),
        ("useinsider.com", "Tracking & Analytics"),
        // Telemetry
        ("bat.bing.com", "Telemetry"),
        ("cc-api-data.adobe.io", "Telemetry"),
        ("events.data.microsoft.com", "Telemetry"),
        ("lcs-cops.adobe.io", "Telemetry"),
        ("radstat.acmeaom.com", "Telemetry"),
        ("settings-win.data.microsoft.com", "Telemetry"),
        ("telemetry.microsoft.com", "Telemetry"),
        ("vortex.data.microsoft.com", "Telemetry"),
        // CDN
        ("cdn.dropboxexperiment.com", "CDN"),
        ("gator.volces.com", "CDN"),
        ("openfpcdn.io", "CDN"),
        // Streaming
        ("stun.hitv.com", "Streaming"),
        // Gambling
        ("betamountwo.com", "Gambling"),
        // Malware
        ("cenoobi.run", "Malware"),
        ("safebrowsdv.com", "Malware"),
        ("z.cdn.debitcrebit669.com", "Malware"),
    };

    /// <summary>Best (longest-suffix) canonical category for a domain, or "" if unknown.</summary>
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
