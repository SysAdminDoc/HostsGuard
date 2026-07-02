namespace HostsGuard.Core;

/// <summary>
/// Parses the <c>QueryResults</c> field of the Microsoft-Windows-DNS-Client ETW
/// completion event (3008). The field is a <c>;</c>-delimited list of
/// <c>type: &lt;n&gt; &lt;value&gt;</c> records; type 5 is a CNAME. Extracting the
/// CNAME chain lets HostsGuard defeat CNAME-cloaking: a first-party host that
/// aliases to a blocked tracker (NET-075).
/// </summary>
public static class DnsQueryResults
{
    private const int CnameType = 5;

    /// <summary>Extract the CNAME targets from a raw QueryResults string (normalized, deduped).</summary>
    public static IReadOnlyList<string> ExtractCnames(string? queryResults)
    {
        var raw = queryResults ?? string.Empty;
        if (raw.Length == 0)
        {
            return Array.Empty<string>();
        }

        var cnames = new List<string>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var part in raw.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            // "type: 5 cdn.example.net"
            if (!part.StartsWith("type:", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var fields = part["type:".Length..].Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (fields.Length < 2 || !int.TryParse(fields[0], out var type) || type != CnameType)
            {
                continue;
            }

            if (DnsEventNormalizer.TryNormalize(fields[1], out var cname) && seen.Add(cname))
            {
                cnames.Add(cname);
            }
        }

        return cnames;
    }
}
