using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace HostsGuard.Core;

/// <summary>
/// Support-bundle / log redaction. Faithful port of the Python
/// <c>_redact_support_*</c> helpers: scrubs secrets, URLs, domains, public IPs,
/// and filesystem paths from text and structured config so no sensitive value
/// ever leaves the machine in a diagnostics payload or a log sink.
/// </summary>
public static partial class Redaction
{
    private static readonly IReadOnlyDictionary<string, string> Markers = new Dictionary<string, string>(StringComparer.Ordinal)
    {
        ["secret"] = "<REDACTED_SECRET>",
        ["url"] = "<REDACTED_URL>",
        ["domain"] = "<REDACTED_DOMAIN>",
        ["ip"] = "<REDACTED_IP>",
        ["path"] = "<REDACTED_PATH>",
    };

    [GeneratedRegex(@"(token|secret|password|passwd|credential|api[_-]?key|webhook)", RegexOptions.IgnoreCase)]
    private static partial Regex SecretKeyRegex();

    [GeneratedRegex(@"https?://[^\s""'<>]+", RegexOptions.IgnoreCase)]
    private static partial Regex UrlRegex();

    [GeneratedRegex(@"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", RegexOptions.IgnoreCase)]
    private static partial Regex DomainTextRegex();

    [GeneratedRegex(@"\b(?:\d{1,3}\.){3}\d{1,3}\b")]
    private static partial Regex IpTextRegex();

    [GeneratedRegex(@"\b[0-9a-f]{32,}\b", RegexOptions.IgnoreCase)]
    private static partial Regex LongHexRegex();

    /// <summary>Marker with a short stable hash of the value, e.g. <c>&lt;REDACTED_URL:abcdef0123&gt;</c>.</summary>
    public static string Marker(string kind, string? value)
    {
        var bytes = Encoding.UTF8.GetBytes((value ?? string.Empty).ToLowerInvariant());
        var hash = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant()[..10];
        var baseMarker = Markers.GetValueOrDefault(kind, $"<REDACTED_{kind.ToUpperInvariant()}>");
        return baseMarker[..^1] + $":{hash}>";
    }

    /// <summary>Redact free-form text: URLs, public IPs, domains, and long hex secrets.</summary>
    public static string RedactText(string? text)
    {
        var s = text ?? string.Empty;
        s = UrlRegex().Replace(s, m => Marker("url", m.Value));
        s = IpTextRegex().Replace(s, m => LooksLikePublicIp(m.Value) ? Marker("ip", m.Value) : m.Value);
        s = DomainTextRegex().Replace(s, m => Domains.LooksLikeDomain(m.Value.ToLowerInvariant().Trim('.')) ? Marker("domain", m.Value) : m.Value);
        s = LongHexRegex().Replace(s, Markers["secret"]);
        return s;
    }

    /// <summary>Redact a single scalar given its key (key drives secret/path detection).</summary>
    public static string RedactScalar(string? key, string? value)
    {
        var text = value ?? string.Empty;
        var k = (key ?? string.Empty).ToLowerInvariant();
        if (LooksLikeUrl(text))
        {
            return Marker("url", text);
        }

        if (SecretKeyRegex().IsMatch(k))
        {
            return Markers["secret"];
        }

        if (Domains.LooksLikeDomain(text.ToLowerInvariant().Trim('.')))
        {
            return Marker("domain", text);
        }

        if (LooksLikePublicIp(text))
        {
            return Marker("ip", text);
        }

        var isPathLike = text.Contains('\\', StringComparison.Ordinal) || text.Contains('/', StringComparison.Ordinal);
        if (isPathLike && (k is "path" or "program" or "program_path"
            || k.EndsWith("_path", StringComparison.Ordinal) || k.EndsWith("_dir", StringComparison.Ordinal)
            || k.Contains("directory", StringComparison.Ordinal) || k.Contains("folder", StringComparison.Ordinal)))
        {
            if (k is "program" or "program_path")
            {
                var name = System.IO.Path.GetFileName(text);
                return name.Length != 0 ? name : Markers["path"];
            }

            return Marker("path", text);
        }

        return text;
    }

    private static bool LooksLikeUrl(string value)
    {
        var s = value.Trim().ToLowerInvariant();
        return s.StartsWith("http://", StringComparison.Ordinal) || s.StartsWith("https://", StringComparison.Ordinal);
    }

    /// <summary>True if the value parses to a routable, non-private IP address.</summary>
    public static bool LooksLikePublicIp(string? value)
    {
        if (!IPAddress.TryParse((value ?? string.Empty).Trim(), out var ip))
        {
            return false;
        }

        if (IPAddress.IsLoopback(ip) || ip.IsIPv6LinkLocal || ip.IsIPv6Multicast || ip.IsIPv6SiteLocal)
        {
            return false;
        }

        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = ip.GetAddressBytes();
            // RFC1918 + link-local + unspecified + multicast + CGN (100.64/10).
            if (b[0] == 10) return false;
            if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return false;
            if (b[0] == 192 && b[1] == 168) return false;
            if (b[0] == 169 && b[1] == 254) return false;
            if (b[0] == 0) return false;
            if (b[0] == 127) return false;
            if (b[0] >= 224 && b[0] <= 239) return false;
            if (b[0] == 100 && b[1] >= 64 && b[1] <= 127) return false;
            return true;
        }

        if (ip.AddressFamily == AddressFamily.InterNetworkV6)
        {
            var b = ip.GetAddressBytes();
            if (ip.Equals(IPAddress.IPv6Any)) return false;      // ::
            if ((b[0] & 0xFE) == 0xFC) return false;             // fc00::/7 unique-local
            if (b[0] == 0xFF) return false;                      // multicast
            return true;
        }

        return false;
    }
}
