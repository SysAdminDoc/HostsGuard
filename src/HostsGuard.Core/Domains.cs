using System.Text.RegularExpressions;

namespace HostsGuard.Core;

/// <summary>
/// Domain validation and root/registrable-domain extraction. Ported faithfully
/// from the Python reference (<c>looks_like_domain</c>, <c>get_root</c>) so the
/// .NET build matches existing behavior exactly.
/// </summary>
public static partial class Domains
{
    [GeneratedRegex(@"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")]
    public static partial Regex DomainRegex();

    [GeneratedRegex(@"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")]
    public static partial Regex Ipv4Regex();

    /// <summary>Special hostnames never treated as blockable domains.</summary>
    public static readonly IReadOnlySet<string> Ignored = new HashSet<string>(StringComparer.Ordinal)
    {
        "localhost", "broadcasthost", "local", "ip6-localhost", "ip6-loopback",
        "ip6-localnet", "ip6-mcastprefix", "ip6-allnodes", "ip6-allrouters",
        "ip6-allhosts", "wpad", "isatap",
    };

    /// <summary>Multi-label public suffixes so <see cref="GetRoot"/> keeps the registrable domain.</summary>
    public static readonly IReadOnlySet<string> MultiTlds = new HashSet<string>(StringComparer.Ordinal)
    {
        "co.uk", "co.jp", "co.kr", "co.in", "co.nz", "co.za", "co.il", "co.th", "co.id",
        "com.au", "com.br", "com.cn", "com.mx", "com.ar", "com.tw", "com.hk", "com.sg",
        "com.tr", "com.my", "com.pk",
        "org.uk", "org.au", "net.au", "net.br", "ac.uk", "gov.uk", "gov.au", "gov.br",
        "edu.au", "ne.jp", "or.jp", "or.kr", "go.jp", "go.kr",
    };

    /// <summary>RFC 1035 limits: whole name ≤ 253 chars, every label ≤ 63.</summary>
    public static bool WithinDnsLimits(string d)
    {
        if (d.Length > 253)
        {
            return false;
        }

        var start = 0;
        for (var i = 0; i <= d.Length; i++)
        {
            if (i == d.Length || d[i] == '.')
            {
                if (i - start > 63)
                {
                    return false;
                }

                start = i + 1;
            }
        }

        return true;
    }

    /// <summary>
    /// Canonical form for storage and comparison: trimmed, trailing-dot-stripped,
    /// lowercased, and IDN-encoded to ASCII/punycode. A Unicode domain
    /// (<c>münchen.de</c>, <c>例え.jp</c>) becomes its <c>xn--</c> form so it can be
    /// blocked and matched; non-IDN junk is returned lowercased-and-trimmed so it
    /// still fails <see cref="LooksLikeDomain"/>. Idempotent for ASCII input.
    /// </summary>
    public static string ToAscii(string? d)
    {
        if (string.IsNullOrEmpty(d))
        {
            return string.Empty;
        }

        var trimmed = d.Trim().TrimEnd('.').ToLowerInvariant();
        if (trimmed.Length == 0 || System.Text.Ascii.IsValid(trimmed))
        {
            return trimmed;
        }

        try
        {
            return new System.Globalization.IdnMapping { AllowUnassigned = true }.GetAscii(trimmed);
        }
        catch (ArgumentException)
        {
            // Not a valid IDN — hand back the trimmed input so LooksLikeDomain rejects it.
            return trimmed;
        }
    }

    /// <summary>
    /// True if <paramref name="d"/> is a syntactically valid, non-special, non-IP
    /// domain. Unicode IDNs are accepted by validating their ASCII/punycode form.
    /// </summary>
    public static bool LooksLikeDomain(string? d)
    {
        var a = ToAscii(d);
        return a.Length != 0
            && a.Contains('.')
            && WithinDnsLimits(a)
            && DomainRegex().IsMatch(a)
            && !Ipv4Regex().IsMatch(a)
            && !Ignored.Contains(a);
    }

    /// <summary>
    /// Registrable ("root") domain, lowercased. Honors the multi-label
    /// public-suffix set (co.uk, com.au, etc.).
    /// </summary>
    public static string GetRoot(string d)
    {
        ArgumentNullException.ThrowIfNull(d);
        var parts = d.ToLowerInvariant().Split('.');
        if (parts.Length <= 2)
        {
            return d.ToLowerInvariant();
        }

        var t2 = string.Join('.', parts[^2..]);
        var t3 = parts.Length >= 3 ? string.Join('.', parts[^3..]) : null;
        if (MultiTlds.Contains(t2) && parts.Length >= 3)
        {
            return string.Join('.', parts[^3..]);
        }

        if (t3 is not null && MultiTlds.Contains(t3) && parts.Length >= 4)
        {
            return string.Join('.', parts[^4..]);
        }

        return t2;
    }
}
