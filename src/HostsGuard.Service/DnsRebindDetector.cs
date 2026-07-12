using System.Net;
using System.Net.Sockets;
using HostsGuard.Core;

namespace HostsGuard.Service;

/// <summary>
/// DNS-rebinding / out-of-scope-answer detector (NET-199): a public registrable
/// domain that resolves to a private-LAN address (RFC1918, CGNAT, link-local,
/// unique-local) is the classic rebinding signature — a remote name pointed at
/// the victim's internal network. This is a pure, testable classifier; the
/// service raises an alert on a hit. It is intentionally alert-only (split-horizon
/// corporate DNS is a legitimate producer of the same shape), and it never flags
/// our own hosts-file sinks (0.0.0.0 / 127.0.0.1 / :: / ::1) or local names.
/// </summary>
public static class DnsRebindDetector
{
    private static readonly string[] LocalSuffixes =
    {
        ".local", ".localhost", ".lan", ".home", ".home.arpa", ".internal",
        ".intranet", ".corp", ".in-addr.arpa", ".ip6.arpa",
    };

    /// <summary>
    /// The private-LAN answers a public domain resolved to (empty when none, or
    /// when the name isn't a public registrable domain). These are the addresses
    /// that make <paramref name="domain"/> look like a rebinding target.
    /// </summary>
    public static IReadOnlyList<string> PrivateAnswersForPublicDomain(string? domain, IEnumerable<string>? addresses)
    {
        var d = (domain ?? string.Empty).ToLowerInvariant().Trim().TrimEnd('.');
        if (d.Length == 0 || IsLocalName(d) || !Domains.LooksLikeDomain(d))
        {
            return Array.Empty<string>();
        }

        var hits = new List<string>();
        foreach (var a in addresses ?? Enumerable.Empty<string>())
        {
            if (IPAddress.TryParse((a ?? string.Empty).Trim(), out var ip) && IsPrivateLanTarget(ip)
                && !hits.Contains(ip.ToString(), StringComparer.Ordinal))
            {
                hits.Add(ip.ToString());
            }
        }

        return hits;
    }

    private static bool IsLocalName(string domain)
    {
        if (!domain.Contains('.', StringComparison.Ordinal))
        {
            return true; // single-label (e.g. a machine name) — not a public domain
        }

        foreach (var suffix in LocalSuffixes)
        {
            if (domain.EndsWith(suffix, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// A real private-LAN address (not public, not loopback, not the unspecified
    /// sink). Loopback/unspecified are excluded so a hosts-file sink answer
    /// (0.0.0.0 / 127.0.0.1) is never mistaken for a rebinding hit.
    /// </summary>
    private static bool IsPrivateLanTarget(IPAddress ip)
    {
        if (ip.IsIPv4MappedToIPv6)
        {
            ip = ip.MapToIPv4();
        }

        if (SsrfGuard.IsPublic(ip) || IPAddress.IsLoopback(ip)
            || ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any))
        {
            return false;
        }

        // Everything IsPublic rejected that isn't a sink/loopback is a genuine
        // private/link-local/CGNAT/unique-local LAN target.
        return ip.AddressFamily is AddressFamily.InterNetwork or AddressFamily.InterNetworkV6;
    }
}
