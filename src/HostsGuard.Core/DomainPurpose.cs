namespace HostsGuard.Core;

/// <summary>
/// A curated, offline domain-purpose map (NET-078), inspired by Little Snitch's
/// Research Assistant. It annotates the ask-to-connect prompt and the activity
/// feed with what a domain is *for* ("Microsoft telemetry", "Akamai CDN") so a
/// user can make an informed Allow/Block decision. Suffix-matched, longest wins;
/// unknown domains return blank. No cloud lookup — the data ships with the app.
/// </summary>
public static class DomainPurpose
{
    // Ordered longest-suffix-first isn't required; lookup picks the longest match.
    private static readonly IReadOnlyList<(string Suffix, string Purpose)> Map = new[]
    {
        // Microsoft
        ("telemetry.microsoft.com", "Microsoft telemetry"),
        ("vortex.data.microsoft.com", "Microsoft telemetry"),
        ("watson.telemetry.microsoft.com", "Microsoft error reporting"),
        ("windowsupdate.com", "Windows Update"),
        ("update.microsoft.com", "Windows Update"),
        ("delivery.mp.microsoft.com", "Windows Update delivery"),
        ("dl.delivery.mp.microsoft.com", "Windows Update delivery"),
        ("login.microsoftonline.com", "Microsoft account sign-in"),
        // Analytics / ads / tracking
        ("google-analytics.com", "Google Analytics"),
        ("analytics.google.com", "Google Analytics"),
        ("doubleclick.net", "Google Ads"),
        ("googlesyndication.com", "Google Ads"),
        ("googleadservices.com", "Google Ads"),
        ("scorecardresearch.com", "Comscore tracking"),
        ("branch.io", "Branch attribution/tracking"),
        ("app-measurement.com", "Firebase Analytics"),
        ("crashlytics.com", "Crashlytics reporting"),
        ("sentry.io", "Sentry error reporting"),
        // Meta
        ("facebook.com", "Meta / Facebook"),
        ("fbcdn.net", "Meta / Facebook CDN"),
        ("graph.facebook.com", "Meta Graph API"),
        // CDNs
        ("akamaiedge.net", "Akamai CDN"),
        ("akamai.net", "Akamai CDN"),
        ("cloudfront.net", "Amazon CloudFront CDN"),
        ("fastly.net", "Fastly CDN"),
        ("cdn.cloudflare.net", "Cloudflare CDN"),
        ("cloudflare.com", "Cloudflare"),
        ("gstatic.com", "Google static/CDN"),
        ("googleusercontent.com", "Google user content/CDN"),
        ("azureedge.net", "Azure CDN"),
        ("edgekey.net", "Akamai CDN"),
        // Media
        ("googlevideo.com", "YouTube video"),
        ("ytimg.com", "YouTube images"),
        ("nflxvideo.net", "Netflix video"),
        // Updaters / infra
        ("digicert.com", "Certificate validation (OCSP/CRL)"),
        ("ocsp.", "Certificate revocation check"),
        ("ntp.org", "Network time (NTP)"),
        ("time.windows.com", "Windows time sync"),
    };

    /// <summary>Best (longest-suffix) purpose label for a domain, or "" if unknown.</summary>
    public static string Lookup(string? domain)
    {
        var d = (domain ?? string.Empty).ToLowerInvariant().Trim().TrimEnd('.');
        if (d.Length == 0)
        {
            return string.Empty;
        }

        var best = string.Empty;
        var bestLen = 0;
        foreach (var (suffix, purpose) in Map)
        {
            var isMatch = d.Equals(suffix, StringComparison.Ordinal) ||
                d.EndsWith("." + suffix, StringComparison.Ordinal) ||
                (suffix.EndsWith('.') && d.Contains(suffix, StringComparison.Ordinal)); // e.g. "ocsp."
            if (isMatch && suffix.Length > bestLen)
            {
                best = purpose;
                bestLen = suffix.Length;
            }
        }

        return best;
    }
}
