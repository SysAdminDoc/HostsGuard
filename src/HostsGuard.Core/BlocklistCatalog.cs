namespace HostsGuard.Core;

/// <summary>A curated blocklist source, with an optional fallback mirror (NET-077).</summary>
public sealed record BlocklistSourceInfo(string Category, string Name, string Url, string Mirror = "");

/// <summary>
/// A blocklist merge health report (NET-077): what parsed, what was dropped, and
/// which lines looked like a hosts-hijack (a domain pointed at a routable IP
/// rather than a sink). <see cref="Domains"/> is the clean, deduped result.
/// </summary>
public sealed record BlocklistScan(
    IReadOnlyList<string> Domains,
    int Total,
    int Duplicates,
    int Invalid,
    int HijackFlagged);

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
        new("Popular", "HaGezi Ultimate", "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/hosts/ultimate.txt",
            "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/ultimate.txt"),
        new("Popular", "StevenBlack Unified", "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
            "https://cdn.jsdelivr.net/gh/StevenBlack/hosts@master/hosts"),
        new("Popular", "OISD Full", "https://hosts.oisd.nl/", "https://big.oisd.nl/"),
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
        // Encrypted-DNS bootstrap domains: apps/browsers with hardcoded DoH
        // resolvers skip the OS resolver (and the hosts file) entirely. Blocking
        // the bootstrap domains forces them back onto plaintext DNS where hosts
        // blocking applies. Complements the DoH resolver-IP firewall intelligence.
        new("Encrypted DNS", "HaGezi DoH Servers", "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/hosts/doh.txt",
            "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/doh.txt"),
        new("Encrypted DNS", "HaGezi DoH/VPN/Proxy Bypass", "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/hosts/doh-vpn-proxy-bypass.txt",
            "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/doh-vpn-proxy-bypass.txt"),
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
        return Scan(text).Domains.ToList();
    }

    // Hosts-hijack sinks: a blocklist should map a domain to one of these.
    // A mapping to any other (routable) IP is a redirect/hijack, not a block.
    private static readonly HashSet<string> SinkIps = new(StringComparer.Ordinal)
    {
        "0.0.0.0", "127.0.0.1", "::", "::1", "0:0:0:0:0:0:0:0", "0:0:0:0:0:0:0:1",
    };

    /// <summary>
    /// Parse + health-scan blocklist text (NET-077): produces the clean deduped
    /// domain set alongside counts of duplicates, unparseable lines, and
    /// hijack-flagged entries (a domain pointed at a non-sink routable IP — the
    /// StevenBlack hosts-hijack check). Hijack lines are excluded from the result.
    /// </summary>
    public static BlocklistScan Scan(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        var domains = new List<string>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        int total = 0, duplicates = 0, invalid = 0, hijack = 0;

        foreach (var raw in text.Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line[0] is '#' or '!')
            {
                continue;
            }

            total++;

            if (LooksLikeAdblockRule(line))
            {
                invalid++;
                continue;
            }

            // Hosts-format line: "<ip> <domain> [more]". Flag a non-sink target.
            var fields = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (fields.Length >= 2 && System.Net.IPAddress.TryParse(fields[0], out _) && !SinkIps.Contains(fields[0]))
            {
                hijack++;
                continue;
            }

            var d = HostsFile.NormLine(line, normalize: false);
            if (d is null || !Domains.LooksLikeDomain(d))
            {
                invalid++;
                continue;
            }

            if (!seen.Add(d))
            {
                duplicates++;
                continue;
            }

            domains.Add(d);
        }

        return new BlocklistScan(domains, total, duplicates, invalid, hijack);
    }

    private static bool LooksLikeAdblockRule(string line)
    {
        foreach (var token in line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries))
        {
            if (token[0] == '#')
            {
                return false;
            }

            if (token.StartsWith("@@", StringComparison.Ordinal)
                || token.StartsWith("||", StringComparison.Ordinal)
                || token.StartsWith('/')
                || token.Contains('^')
                || token.Contains("##", StringComparison.Ordinal)
                || token.Contains("#@#", StringComparison.Ordinal)
                || token.Contains("#?#", StringComparison.Ordinal)
                || token.Contains("#$#", StringComparison.Ordinal)
                || token.Contains("#%#", StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }
}
