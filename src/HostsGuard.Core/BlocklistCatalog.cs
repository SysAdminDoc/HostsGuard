namespace HostsGuard.Core;

/// <summary>A curated blocklist source.</summary>
public sealed record BlocklistSourceInfo(string Category, string Name, string Url);

/// <summary>
/// The curated blocklist catalog (ported from the Python SOURCES table) and the
/// shared blocklist/allowlist text parser. Sources known to bloat the hosts
/// file past the point the Windows DNS Client service spikes CPU are flagged.
/// </summary>
public static class BlocklistCatalog
{
    public const int MaxBlocklistBytes = 25_000_000;
    public const int MaxAllowlistBytes = 5_000_000;

    /// <summary>Hosts-file entry count above which we surface a DNS-Client CPU warning.</summary>
    public const int LargeHostsWarn = 100_000;

    public static readonly IReadOnlySet<string> LargeLists = new HashSet<string>(StringComparer.Ordinal)
    {
        "HaGezi Ultimate", "OISD Full", "StevenBlack Unified", "HOSTShield Combined",
    };

    public static readonly IReadOnlyList<BlocklistSourceInfo> Sources = new BlocklistSourceInfo[]
    {
        new("Popular", "HaGezi Ultimate", "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/hosts/ultimate.txt"),
        new("Popular", "StevenBlack Unified", "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"),
        new("Popular", "OISD Full", "https://hosts.oisd.nl/"),
        new("Popular", "HOSTShield Combined", "https://github.com/SysAdminDoc/HOSTShield/releases/download/v.1/CombinedAll.txt"),
        new("Ads & Tracking", "Disconnect Tracking", "https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt"),
        new("Ads & Tracking", "Disconnect Ads", "https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt"),
        new("Ads & Tracking", "EasyList", "https://v.firebog.net/hosts/Easylist.txt"),
        new("Ads & Tracking", "EasyPrivacy", "https://v.firebog.net/hosts/Easyprivacy.txt"),
        new("Ads & Tracking", "AdGuard DNS", "https://v.firebog.net/hosts/AdguardDNS.txt"),
        new("Ads & Tracking", "AdAway", "https://adaway.org/hosts.txt"),
        new("Ads & Tracking", "Yoyo Servers", "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext"),
        new("Ads & Tracking", "NoCoin Crypto", "https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt"),
        new("Ads & Tracking", "HOSTShield Ads", "https://raw.githubusercontent.com/SysAdminDoc/HOSTShield/refs/heads/main/AdsTrackingAnalytics.txt"),
        new("Privacy", "Windows Spy Blocker", "https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt"),
        new("Privacy", "Frogeye 1st Party", "https://hostfiles.frogeye.fr/firstparty-trackers-hosts.txt"),
        new("Privacy", "Perflyst SmartTV", "https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SmartTV.txt"),
        new("Malware", "Spam404", "https://raw.githubusercontent.com/Spam404/lists/master/main-blacklist.txt"),
        new("Malware", "Phishing Army", "https://phishing.army/download/phishing_army_blocklist.txt"),
        new("Malware", "URLHaus", "https://urlhaus.abuse.ch/downloads/hostfile/"),
        new("Malware", "Stamparm Maltrail", "https://raw.githubusercontent.com/stamparm/aux/master/maltrail-malware-domains.txt"),
        new("Vendor", "Amazon", "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/hosts/native.amazon.txt"),
        new("Vendor", "Apple", "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/hosts/native.apple.txt"),
        new("Vendor", "Windows/Office", "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/hosts/native.winoffice.txt"),
        new("Vendor", "TikTok", "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/hosts/native.tiktok.extended.txt"),
        new("Vendor", "Samsung", "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/hosts/native.samsung.txt"),
    };

    /// <summary>
    /// Parse blocklist/allowlist text (hosts format or bare domain lines) into
    /// normalized domains — the Python <c>norm_line + looks_like_domain</c> pipeline.
    /// </summary>
    public static List<string> ParseDomains(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        var domains = new List<string>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var line in text.Split('\n'))
        {
            var d = HostsFile.NormLine(line, normalize: false);
            if (d is not null && Domains.LooksLikeDomain(d) && seen.Add(d))
            {
                domains.Add(d);
            }
        }

        return domains;
    }
}
