using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace HostsGuard.Core;

/// <summary>
/// DoH resolver intelligence: the built-in resolver IP set (ported verbatim
/// from the Python DOH_IPS), payload parsing/normalization, and the SHA-256
/// gate for remote refreshes. State persistence lives in the service; this is
/// the pure logic.
/// </summary>
public static class DohResolvers
{
    public const int MaxResolverListBytes = 2_000_000;

    public static readonly IReadOnlySet<string> BuiltIn = new HashSet<string>(StringComparer.Ordinal)
    {
        "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112",
        "94.140.14.14", "94.140.15.15", "45.90.28.0", "45.90.30.0", "208.67.222.222", "208.67.220.220",
        "185.228.168.168", "185.228.169.168", "76.76.2.0", "76.76.10.0",
        "2606:4700:4700::1111", "2606:4700:4700::1001", "2001:4860:4860::8888", "2001:4860:4860::8844",
    };

    /// <summary>Canonicalize a set of IP strings, dropping anything unparseable.</summary>
    public static HashSet<string> NormalizeIpSet(IEnumerable<string>? values)
    {
        var result = new HashSet<string>(StringComparer.Ordinal);
        foreach (var value in values ?? Enumerable.Empty<string>())
        {
            var v = (value ?? string.Empty).Trim();
            if (v.Length != 0 && IPAddress.TryParse(v, out var ip))
            {
                result.Add(ip.ToString());
            }
        }

        return result;
    }

    /// <summary>
    /// Parse a resolver payload: JSON (array of strings, or an object with an
    /// "ips" array) or plain text (line/comma separated). Invalid entries drop.
    /// </summary>
    public static HashSet<string> ParsePayload(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        try
        {
            using var doc = JsonDocument.Parse(text);
            var values = doc.RootElement.ValueKind switch
            {
                JsonValueKind.Array => doc.RootElement.EnumerateArray()
                    .Where(e => e.ValueKind == JsonValueKind.String)
                    .Select(e => e.GetString() ?? string.Empty),
                JsonValueKind.Object when doc.RootElement.TryGetProperty("ips", out var ips) &&
                                          ips.ValueKind == JsonValueKind.Array
                    => ips.EnumerateArray()
                        .Where(e => e.ValueKind == JsonValueKind.String)
                        .Select(e => e.GetString() ?? string.Empty),
                _ => Enumerable.Empty<string>(),
            };
            return NormalizeIpSet(values);
        }
        catch (JsonException)
        {
            return NormalizeIpSet(text.Split('\n', ',').Select(t => t.Trim().TrimStart('#')));
        }
    }

    /// <summary>
    /// Verify a payload against the expected SHA-256 (hex, case-insensitive).
    /// Returns the actual hash; throws when it does not match — remote refresh
    /// is hash-gated so a compromised CDN cannot poison the resolver set.
    /// </summary>
    public static string VerifySha256(string payload, string expectedSha256)
    {
        ArgumentNullException.ThrowIfNull(payload);
        var actual = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(payload))).ToLowerInvariant();
        var expected = (expectedSha256 ?? string.Empty).Trim().ToLowerInvariant();
        if (expected.Length == 0)
        {
            throw new InvalidOperationException("Set the expected SHA-256 before refreshing a remote DoH resolver list");
        }

        if (actual != expected)
        {
            throw new InvalidOperationException($"DoH resolver list hash mismatch (expected {expected[..12]}…, got {actual[..12]}…)");
        }

        return actual;
    }
}
