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

        // ── Promoted from AI-researched field knowledge (2026-07-03 review) ──
        // Patterns
        ("in-addr.arpa", "Reverse DNS lookup (PTR)"),
        ("ip6.arpa", "Reverse DNS lookup (PTR)"),
        ("stun.", "STUN server (VoIP/WebRTC NAT traversal)"),
        // Google
        ("accounts.google.com", "Google account sign-in"),
        ("oauth2.googleapis.com", "Google OAuth sign-in"),
        ("identitytoolkit.googleapis.com", "Google sign-in toolkit"),
        ("securetoken.googleapis.com", "Firebase authentication"),
        ("firebase.googleapis.com", "Firebase backend"),
        ("firebaseinstallations.googleapis.com", "Firebase installations"),
        ("firebaseremoteconfig.googleapis.com", "Firebase Remote Config"),
        ("firebaseio.com", "Firebase Realtime Database"),
        ("fonts.googleapis.com", "Google Fonts"),
        ("ajax.googleapis.com", "Google-hosted JS libraries"),
        ("maps.googleapis.com", "Google Maps API"),
        ("storage.googleapis.com", "Google Cloud Storage"),
        ("update.googleapis.com", "Google software updates"),
        ("gvt1.com", "Google software downloads"),
        ("pki.goog", "Google certificate infrastructure"),
        ("recaptcha.net", "Google reCAPTCHA"),
        ("csp.withgoogle.com", "Google CSP reporting"),
        ("adservice.google.com", "Google Ads"),
        ("adtrafficquality.google", "Google Ads traffic quality"),
        ("googletagmanager.com", "Google Tag Manager"),
        ("ggpht.com", "YouTube/Google thumbnails"),
        ("youtube.com", "YouTube"),
        // Microsoft
        ("login.live.com", "Microsoft account sign-in"),
        ("wns.windows.com", "Windows push notifications"),
        ("msftncsi.com", "Windows connectivity check"),
        ("msftconnecttest.com", "Windows connectivity check"),
        ("events.data.microsoft.com", "Windows telemetry events"),
        ("settings-win.data.microsoft.com", "Windows settings telemetry"),
        ("displaycatalog.mp.microsoft.com", "Microsoft Store catalog"),
        ("licensing.mp.microsoft.com", "Microsoft Store licensing"),
        ("pti.store.microsoft.com", "Microsoft Store product info"),
        ("officeclient.microsoft.com", "Office client configuration"),
        ("substrate.office.com", "Microsoft 365 mailbox services"),
        ("config.edge.skype.com", "Skype/Edge configuration"),
        ("msedge.api.cdp.microsoft.com", "Edge update delivery"),
        ("bat.bing.com", "Microsoft Advertising (UET) tracking"),
        ("xboxlive.com", "Xbox Live services"),
        ("gamepass.com", "Xbox Game Pass"),
        // Gaming / media platforms
        ("steamstatic.com", "Steam static content CDN"),
        ("steamcontent.com", "Steam game downloads"),
        ("steamcommunity.com", "Steam Community"),
        ("steampowered.com", "Steam store/API"),
        ("live-video.net", "Amazon IVS / Twitch live video"),
        ("4cdn.org", "4chan CDN"),
        // Amazon / AWS
        ("amazon-adsystem.com", "Amazon Ads"),
        ("media-amazon.com", "Amazon media CDN"),
        ("ssl-images-amazon.com", "Amazon product images"),
        ("s3.amazonaws.com", "Amazon S3 storage"),
        ("awswaf.com", "AWS WAF bot protection"),
        // Dropbox
        ("dropbox.com", "Dropbox"),
        ("dropboxstatic.com", "Dropbox static content"),
        ("dropboxcaptcha.com", "Dropbox CAPTCHA"),
        // Developer / AI services
        ("anthropic.com", "Anthropic / Claude API"),
        ("claude.com", "Anthropic Claude"),
        ("openai.com", "OpenAI"),
        ("chatgpt.com", "ChatGPT"),
        ("deepseek.com", "DeepSeek AI API"),
        ("github.com", "GitHub"),
        ("githubusercontent.com", "GitHub-hosted content"),
        ("githubcopilot.com", "GitHub Copilot"),
        ("nuget.org", "NuGet packages"),
        ("pypi.org", "Python packages (PyPI)"),
        ("pythonhosted.org", "Python packages (PyPI)"),
        ("npmjs.org", "npm packages"),
        ("jsdelivr.net", "jsDelivr CDN"),
        // Social / media
        ("twimg.com", "Twitter/X media CDN"),
        ("platform.twitter.com", "Twitter embeds"),
        ("redd.it", "Reddit media"),
        ("redditmedia.com", "Reddit static content"),
        ("redditstatic.com", "Reddit static content"),
        ("imgur.com", "Imgur image hosting"),
        // Payments
        ("stripe.com", "Stripe payments"),
        ("stripe.network", "Stripe payments infrastructure"),
        // Certificates
        ("lencr.org", "Let's Encrypt certificate infrastructure"),
        ("ssl.com", "SSL.com certificate authority"),
        // Trackers / analytics / ad networks
        ("quantserve.com", "Quantcast tracking"),
        ("cloudflareinsights.com", "Cloudflare Web Analytics"),
        ("datadoghq.com", "Datadog monitoring"),
        ("datadoghq-browser-agent.com", "Datadog browser monitoring"),
        ("useinsider.com", "Insider marketing analytics"),
        ("stats.wp.com", "WordPress.com analytics"),
        ("pixel.wp.com", "WordPress.com tracking pixel"),
        ("wp.com", "WordPress.com infrastructure"),
        ("rlcdn.com", "LiveRamp identity tracking"),
        ("criteo.com", "Criteo retargeting ads"),
        ("adnxs.com", "Xandr/AppNexus ads"),
        ("openx.net", "OpenX ad exchange"),
        ("serving-sys.com", "Sizmek ad serving"),
        ("ads.yahoo.com", "Yahoo Ads"),
        ("magsrv.com", "ExoClick ad network"),
        ("tsyndicate.com", "TrafficStars ad network"),
        ("litix.io", "Mux video analytics"),
        ("sift.com", "Sift fraud detection"),
        ("fpjs.io", "FingerprintJS fingerprinting"),
        ("openfpcdn.io", "FingerprintJS open-source CDN"),
        ("ketchcdn.com", "Ketch consent management"),
        ("consentdesk.com", "ConsentDesk consent management"),
        ("vaststat.com", "VAST video-ad tracking"),
        // Yandex
        ("mc.yandex.ru", "Yandex Metrica analytics"),
        ("yastatic.net", "Yandex static CDN"),
        ("yandex.ru", "Yandex services"),
        // Adobe
        ("cc-api-data.adobe.io", "Adobe Creative Cloud telemetry"),
        ("lcs-cops.adobe.io", "Adobe licensing"),
        ("adobe.io", "Adobe cloud APIs"),
        // Comms / sync tools
        ("teamviewer.com", "TeamViewer remote access"),
        ("zoom.us", "Zoom conferencing"),
        ("pusher.com", "Pusher realtime messaging"),
        ("syncthing.net", "Syncthing sync/discovery"),
        // Maps / apps
        ("hereapi.com", "HERE Maps API"),
        ("acmeaom.com", "MyRadar weather data"),
        // ByteDance
        ("volces.com", "ByteDance Volcengine cloud"),
        ("volccdn.com", "ByteDance Volcengine CDN"),
        // Blocklist / threat-intel sources
        ("oisd.nl", "OISD blocklist source"),
        ("adaway.org", "AdAway blocklist source"),
        ("pgl.yoyo.org", "Peter Lowe blocklist source"),
        ("phishing.army", "Phishing Army blocklist source"),
        ("abuse.ch", "abuse.ch threat intelligence"),
        ("firebog.net", "Firebog blocklist source"),
        ("frogeye.fr", "Frogeye blocklist source"),
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
