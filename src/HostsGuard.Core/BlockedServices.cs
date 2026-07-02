namespace HostsGuard.Core;

/// <summary>
/// One-click "block this service" domain sets (apex + primary sub/CDN domains)
/// and the curated Microsoft telemetry endpoint preset — ported verbatim from
/// the Python BLOCK_SERVICES / MS_TELEMETRY tables. Hosts blocking matches
/// exact hostnames (no wildcards), so this is best-effort for the common
/// browser/app case; DoH can bypass it (pair with encrypted-DNS blocking).
/// </summary>
public static class BlockedServices
{
    /// <summary>Service name reserved for the Windows telemetry preset.</summary>
    public const string TelemetryService = "Windows Telemetry";

    /// <summary>
    /// Blocking telemetry endpoints trips Defender's
    /// SettingsModifier:Win32/HostsFileHijack — surface this before applying.
    /// </summary>
    public const string TelemetryDefenderNote =
        "Blocking Microsoft telemetry will trip Windows Defender's " +
        "SettingsModifier:Win32/HostsFileHijack detection — that IS the telemetry-block " +
        "scenario. Add the hosts file to Defender exclusions or expect the alert.";

    public static readonly IReadOnlyDictionary<string, IReadOnlyList<string>> Services =
        new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)
        {
            ["YouTube"] = new[] { "youtube.com", "www.youtube.com", "m.youtube.com", "youtu.be", "youtubei.googleapis.com", "youtube-nocookie.com", "yt3.ggpht.com", "googlevideo.com" },
            ["TikTok"] = new[] { "tiktok.com", "www.tiktok.com", "tiktokcdn.com", "tiktokv.com", "byteoversea.com", "ibytedtos.com", "musical.ly" },
            ["Facebook"] = new[] { "facebook.com", "www.facebook.com", "m.facebook.com", "fbcdn.net", "fb.com", "fbsbx.com", "facebook.net" },
            ["Instagram"] = new[] { "instagram.com", "www.instagram.com", "cdninstagram.com", "ig.me" },
            ["X (Twitter)"] = new[] { "twitter.com", "www.twitter.com", "x.com", "www.x.com", "twimg.com", "t.co" },
            ["Reddit"] = new[] { "reddit.com", "www.reddit.com", "old.reddit.com", "redd.it", "redditstatic.com", "redditmedia.com" },
            ["Discord"] = new[] { "discord.com", "discord.gg", "discordapp.com", "discordapp.net", "discord.media" },
            ["Snapchat"] = new[] { "snapchat.com", "www.snapchat.com", "sc-cdn.net", "snap.com" },
            ["Netflix"] = new[] { "netflix.com", "www.netflix.com", "nflxvideo.net", "nflximg.net", "nflxext.com", "nflxso.net" },
            ["Twitch"] = new[] { "twitch.tv", "www.twitch.tv", "ttvnw.net", "jtvnw.net", "twitchcdn.net" },
            ["WhatsApp"] = new[] { "whatsapp.com", "www.whatsapp.com", "whatsapp.net", "wa.me" },
            ["Telegram"] = new[] { "telegram.org", "telegram.me", "t.me", "tdesktop.com", "telegra.ph" },
            ["LinkedIn"] = new[] { "linkedin.com", "www.linkedin.com", "licdn.com", "lnkd.in" },
            ["Pinterest"] = new[] { "pinterest.com", "www.pinterest.com", "pinimg.com" },
        };

    public static readonly IReadOnlyList<string> MsTelemetry = new[]
    {
        "vortex.data.microsoft.com", "vortex-win.data.microsoft.com", "telecommand.telemetry.microsoft.com",
        "telemetry.microsoft.com", "watson.telemetry.microsoft.com", "watson.microsoft.com",
        "settings-win.data.microsoft.com", "v10.vortex-win.data.microsoft.com", "v10.events.data.microsoft.com",
        "v20.events.data.microsoft.com", "functional.events.data.microsoft.com", "self.events.data.microsoft.com",
        "browser.events.data.msn.com", "oca.telemetry.microsoft.com", "sqm.telemetry.microsoft.com",
        "df.telemetry.microsoft.com", "reports.wes.df.telemetry.microsoft.com", "services.wes.df.telemetry.microsoft.com",
        "redir.metaservices.microsoft.com", "choice.microsoft.com", "statsfe2.ws.microsoft.com", "statsfe1.ws.microsoft.com",
        "diagnostics.support.microsoft.com", "feedback.windows.com", "feedback.search.microsoft.com",
        "feedback.microsoft-hohm.com", "corp.sts.microsoft.com", "compatexchange.cloudapp.net",
    };

    /// <summary>Domain set for a service name (telemetry preset included).</summary>
    public static IReadOnlyList<string>? DomainsFor(string service)
        => service == TelemetryService ? MsTelemetry : Services.GetValueOrDefault(service);
}
