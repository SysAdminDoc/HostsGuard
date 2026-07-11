namespace HostsGuard.Core;

/// <summary>
/// A curated blocklist source with catalog metadata (NET-174): homepage,
/// license, and comma-separated tags for the "add a list" gallery, plus an
/// optional fallback mirror (NET-077).
/// </summary>
public sealed record BlocklistSourceInfo(
    string Category,
    string Name,
    string Url,
    string Mirror = "",
    string Homepage = "",
    string License = "",
    string Tags = "",
    string Description = "");

/// <summary>
/// A blocklist merge health report (NET-077): what parsed, what was dropped, and
/// which lines looked like a hosts-hijack (a domain pointed at a routable IP
/// rather than a sink). <see cref="Domains"/> is the clean, deduped result.
/// <see cref="ModifiersStripped"/> counts adblock rules whose $modifiers make a
/// whole-domain block over-broad — they are stripped, never imported (NET-174).
/// </summary>
public sealed record BlocklistScan(
    IReadOnlyList<string> Domains,
    int Total,
    int Duplicates,
    int Invalid,
    int HijackFlagged,
    int ModifiersStripped = 0);

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
            "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/ultimate.txt",
            "https://github.com/hagezi/dns-blocklists", "GPL-3.0", "ads,tracking,telemetry,malware,aggressive",
            "HaGeZi's most aggressive multi-purpose list: ads, tracking, telemetry, badware. Expect some breakage."),
        new("Popular", "StevenBlack Unified", "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
            "https://cdn.jsdelivr.net/gh/StevenBlack/hosts@master/hosts",
            "https://github.com/StevenBlack/hosts", "MIT", "ads,malware,balanced",
            "The classic consolidated hosts file: adware + malware, curated for low breakage."),
        new("Popular", "OISD Full", "https://hosts.oisd.nl/", "https://big.oisd.nl/",
            "https://oisd.nl", "", "ads,tracking,malware,balanced",
            "oisd big: blocks ads, trackers, malware, and scams while aiming to break nothing."),
        new("Popular", "HOSTShield Combined", "https://github.com/SysAdminDoc/HOSTShield/releases/download/v.1/CombinedAll.txt",
            "", "https://github.com/SysAdminDoc/HOSTShield", "MIT", "ads,tracking,telemetry,combined",
            "HOSTShield's combined release build of every category list."),
        new("Ads & Tracking", "Disconnect Tracking", "https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt",
            "", "https://disconnect.me", "GPL-3.0", "tracking",
            "Disconnect.me's simple tracker domain list."),
        new("Ads & Tracking", "Disconnect Ads", "https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt",
            "", "https://disconnect.me", "GPL-3.0", "ads",
            "Disconnect.me's simple advertising domain list."),
        new("Ads & Tracking", "EasyList", "https://v.firebog.net/hosts/Easylist.txt",
            "", "https://easylist.to", "GPL-3.0", "ads",
            "EasyList's ad domains, converted to hosts format by Firebog."),
        new("Ads & Tracking", "EasyPrivacy", "https://v.firebog.net/hosts/Easyprivacy.txt",
            "", "https://easylist.to", "GPL-3.0", "tracking,privacy",
            "EasyPrivacy's tracker domains, converted to hosts format by Firebog."),
        new("Ads & Tracking", "AdGuard DNS", "https://v.firebog.net/hosts/AdguardDNS.txt",
            "", "https://adguard-dns.io", "GPL-3.0", "ads,tracking",
            "The AdGuard DNS filter, converted to hosts format by Firebog."),
        new("Ads & Tracking", "AdAway", "https://adaway.org/hosts.txt",
            "", "https://adaway.org", "CC-BY-3.0", "ads,mobile",
            "AdAway's mobile-focused ad hosts file."),
        new("Ads & Tracking", "Yoyo Servers", "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext",
            "", "https://pgl.yoyo.org/adservers/", "MCRAE-GPL", "ads",
            "Peter Lowe's long-running ad-server domain list."),
        new("Ads & Tracking", "NoCoin Crypto", "https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt",
            "", "https://github.com/hoshsadiq/adblock-nocoin-list", "MIT", "cryptomining",
            "Browser crypto-mining and cryptojacking domains."),
        new("Ads & Tracking", "HOSTShield Ads", "https://raw.githubusercontent.com/SysAdminDoc/HOSTShield/refs/heads/main/AdsTrackingAnalytics.txt",
            "", "https://github.com/SysAdminDoc/HOSTShield", "MIT", "ads,tracking,analytics",
            "HOSTShield's ads/tracking/analytics category list."),
        new("Privacy", "Windows Spy Blocker", "https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt",
            "", "https://github.com/crazy-max/WindowsSpyBlocker", "MIT", "telemetry,windows",
            "Windows telemetry endpoints captured from real traffic analysis."),
        new("Privacy", "Frogeye 1st Party", "https://hostfiles.frogeye.fr/firstparty-trackers-hosts.txt",
            "", "https://hostfiles.frogeye.fr", "MIT", "tracking,first-party,cname",
            "First-party trackers hiding behind CNAMEs of the visited site."),
        new("Privacy", "Perflyst SmartTV", "https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SmartTV.txt",
            "", "https://github.com/Perflyst/PiHoleBlocklist", "MIT", "telemetry,smart-tv,iot",
            "Smart-TV telemetry and ad domains (Samsung, LG, Roku, and more)."),
        // Encrypted-DNS bootstrap domains: apps/browsers with hardcoded DoH
        // resolvers skip the OS resolver (and the hosts file) entirely. Blocking
        // the bootstrap domains forces them back onto plaintext DNS where hosts
        // blocking applies. Complements the DoH resolver-IP firewall intelligence.
        new("Encrypted DNS", "HaGezi DoH Servers", "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/hosts/doh.txt",
            "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/doh.txt",
            "https://github.com/hagezi/dns-blocklists", "GPL-3.0", "doh,dns-bypass",
            "Known DNS-over-HTTPS bootstrap domains, so apps cannot skip the OS resolver."),
        new("Encrypted DNS", "HaGezi DoH/VPN/Proxy Bypass", "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/hosts/doh-vpn-proxy-bypass.txt",
            "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/doh-vpn-proxy-bypass.txt",
            "https://github.com/hagezi/dns-blocklists", "GPL-3.0", "doh,vpn,proxy,dns-bypass",
            "DoH, VPN, and proxy bypass domains that dodge local DNS filtering."),
        new("Malware", "Spam404", "https://raw.githubusercontent.com/Spam404/lists/master/main-blacklist.txt",
            "", "https://spam404.com", "CC-BY-SA-4.0", "scam,phishing",
            "Spam404's scam and online-fraud domain blacklist."),
        new("Malware", "Phishing Army", "https://phishing.army/download/phishing_army_blocklist.txt",
            "", "https://phishing.army", "CC-BY-4.0", "phishing",
            "An extended phishing blocklist built from multiple curated feeds."),
        new("Malware", "URLHaus", "https://urlhaus.abuse.ch/downloads/hostfile/",
            "", "https://urlhaus.abuse.ch", "CC0", "malware",
            "abuse.ch URLhaus malware-distribution domains."),
        new("Malware", "Stamparm Maltrail", "https://raw.githubusercontent.com/stamparm/aux/master/maltrail-malware-domains.txt",
            "", "https://github.com/stamparm/maltrail", "MIT", "malware,c2",
            "Maltrail's aggregated malware and C2 trail domains."),
        new("Vendor", "Amazon", "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/hosts/native.amazon.txt",
            "", "https://github.com/hagezi/dns-blocklists", "GPL-3.0", "telemetry,vendor,amazon",
            "HaGeZi native tracker list: Amazon device/app telemetry."),
        new("Vendor", "Apple", "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/hosts/native.apple.txt",
            "", "https://github.com/hagezi/dns-blocklists", "GPL-3.0", "telemetry,vendor,apple",
            "HaGeZi native tracker list: Apple device/app telemetry."),
        new("Vendor", "Windows/Office", "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/hosts/native.winoffice.txt",
            "", "https://github.com/hagezi/dns-blocklists", "GPL-3.0", "telemetry,vendor,microsoft,windows",
            "HaGeZi native tracker list: Windows and Office telemetry."),
        new("Vendor", "TikTok", "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/hosts/native.tiktok.extended.txt",
            "", "https://github.com/hagezi/dns-blocklists", "GPL-3.0", "telemetry,vendor,tiktok",
            "HaGeZi native tracker list: TikTok telemetry (extended aggressive variant)."),
        new("Vendor", "Samsung", "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/hosts/native.samsung.txt",
            "", "https://github.com/hagezi/dns-blocklists", "GPL-3.0", "telemetry,vendor,samsung",
            "HaGeZi native tracker list: Samsung device telemetry."),
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
        int total = 0, duplicates = 0, invalid = 0, hijack = 0, stripped = 0;

        foreach (var raw in text.Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line[0] is '#' or '!')
            {
                continue;
            }

            total++;

            string? d;
            if (LooksLikeAdblockRule(line))
            {
                // NET-174 RemoveModifiers transform: a plain ||domain^ rule is a
                // whole-domain block and converts safely; a rule with $modifiers
                // is conditional (third-party, script, ...) and blocking the bare
                // domain would over-block — strip it, never import it.
                var (converted, hadModifier) = ConvertAdblockRule(line);
                if (hadModifier)
                {
                    stripped++;
                    continue;
                }

                if (converted is null)
                {
                    invalid++;
                    continue;
                }

                d = converted;
            }
            else
            {
                // Hosts-format line: "<ip> <domain> [more]". Flag a non-sink target.
                var fields = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
                if (fields.Length >= 2 && System.Net.IPAddress.TryParse(fields[0], out _) && !SinkIps.Contains(fields[0]))
                {
                    hijack++;
                    continue;
                }

                d = HostsFile.NormLine(line, normalize: false);
                if (d is null || !Domains.LooksLikeDomain(d))
                {
                    invalid++;
                    continue;
                }
            }

            if (!seen.Add(d))
            {
                duplicates++;
                continue;
            }

            domains.Add(d);
        }

        return new BlocklistScan(domains, total, duplicates, invalid, hijack, stripped);
    }

    /// <summary>
    /// Convert a single adblock network rule to a domain when that is lossless:
    /// <c>||example.com^</c> (or <c>||example.com</c>) blocks the whole domain
    /// and maps 1:1 onto a hosts entry. Returns (null, true) for a rule whose
    /// <c>$modifiers</c> make the block conditional, and (null, false) for
    /// every other adblock construct (exclusions, cosmetic, regex, wildcards).
    /// </summary>
    internal static (string? Domain, bool HadModifier) ConvertAdblockRule(string line)
    {
        if (!line.StartsWith("||", StringComparison.Ordinal) ||
            line.Contains(' ', StringComparison.Ordinal) || line.Contains('\t', StringComparison.Ordinal))
        {
            return (null, false);
        }

        var body = line[2..];
        var dollar = body.IndexOf('$', StringComparison.Ordinal);
        var hadModifier = false;
        if (dollar >= 0)
        {
            hadModifier = true;
            body = body[..dollar];
        }

        if (body.EndsWith('^'))
        {
            body = body[..^1];
        }

        if (body.Length == 0 || body.Contains('^') || body.Contains('*') || body.Contains('/') ||
            body.Contains('|') || body.Contains(':'))
        {
            return (null, false);
        }

        var domain = body.TrimEnd('.').ToLowerInvariant();
        if (!Domains.LooksLikeDomain(domain))
        {
            return (null, false);
        }

        return hadModifier ? (null, true) : (domain, false);
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
