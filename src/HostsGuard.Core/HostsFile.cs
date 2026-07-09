namespace HostsGuard.Core;

/// <summary>Counters returned by <see cref="HostsFile.Clean"/>.</summary>
public sealed record CleanStats(int Total, int Active, int Dupes, int Whitelist, int Invalid);

/// <summary>Result of a hosts-file clean pass: normalized lines + stats.</summary>
public sealed record CleanResult(IReadOnlyList<string> Lines, CleanStats Stats);

/// <summary>
/// Hosts-file line parsing and cleaning. Faithful port of the Python
/// <c>norm_line</c> / <c>clean_hosts</c> including idempotency guarantees.
/// </summary>
public static class HostsFile
{
    public const string Product = "HostsGuard";

    /// <summary>The canonical Windows sample-hosts header we always re-emit.</summary>
    public static readonly IReadOnlyList<string> WindowsHeader = new[]
    {
        "# Copyright (c) 1993-2009 Microsoft Corp.",
        "#",
        "# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.",
        "#",
        "# localhost name resolution is handled within DNS itself.",
        "#    127.0.0.1       localhost",
        "#    ::1             localhost",
        "",
    };

    private static readonly IReadOnlySet<string> BlockPrefixes = new HashSet<string>(StringComparer.Ordinal)
    {
        "0.0.0.0", "127.0.0.1", "::", "::1", "0:0:0:0:0:0:0:0", "0:0:0:0:0:0:0:1",
    };

    private static readonly IReadOnlySet<string> NonDomainValues = new HashSet<string>(StringComparer.Ordinal)
    {
        "0.0.0.0", "127.0.0.1", "255.255.255.255", "::1", "::", "localhost", "broadcasthost", "local",
    };

    /// <summary>
    /// Normalize a single hosts line. Returns <c>null</c> for comments/blank/invalid,
    /// otherwise <c>"0.0.0.0 &lt;domain&gt;"</c> (when <paramref name="normalize"/>) or the bare domain.
    /// </summary>
    public static string? NormLine(string line, bool normalize = true)
    {
        ArgumentNullException.ThrowIfNull(line);
        line = line.Trim();
        if (line.Length == 0 || line.StartsWith('#'))
        {
            return null;
        }

        // Drop any inline comment, then split on whitespace.
        var beforeComment = line.Split('#', 2)[0];
        var parts = beforeComment.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);

        string d;
        if (parts.Length >= 2 && BlockPrefixes.Contains(parts[0]))
        {
            d = parts[1].ToLowerInvariant().Trim().TrimEnd('.');
        }
        else if (parts.Length == 1)
        {
            d = parts[0].ToLowerInvariant().Trim().TrimEnd('.');
        }
        else
        {
            return null;
        }

        if (NonDomainValues.Contains(d))
        {
            return null;
        }

        if (!Domains.WithinDnsLimits(d) || (!Domains.DomainRegex().IsMatch(d) && !d.StartsWith('*')))
        {
            return null;
        }

        return normalize ? $"0.0.0.0 {d}" : d;
    }

    /// <summary>
    /// Deduplicate + normalize hosts lines, dropping whitelisted domains and stale
    /// managed markers. Idempotent: cleaning already-clean output is a fixed point.
    /// </summary>
    public static CleanResult Clean(IEnumerable<string> lines, IReadOnlySet<string>? whitelist = null, string? version = null)
    {
        ArgumentNullException.ThrowIfNull(lines);
        whitelist ??= new HashSet<string>(StringComparer.Ordinal);
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var kept = new List<string>();
        int total = 0, active = 0, dupes = 0, wl = 0, invalid = 0;
        var header = new HashSet<string>(WindowsHeader, StringComparer.Ordinal);
        var managedMarker = $"managed by {Product}";

        foreach (var raw in lines)
        {
            total++;
            var s = raw.Trim();
            if (s.Length == 0 || s.StartsWith('#'))
            {
                // Strip EOLs so output joins cleanly; drop stale header/managed markers so repeats are idempotent.
                var c = raw.TrimEnd('\r', '\n');
                if (c.Trim().Length != 0 && !header.Contains(c) && !c.Contains(managedMarker, StringComparison.Ordinal))
                {
                    kept.Add(c);
                }

                continue;
            }

            var n = NormLine(s);
            if (n is null)
            {
                invalid++;
                continue;
            }

            var d = n.Split(' ')[^1];
            if (whitelist.Contains(d))
            {
                wl++;
                continue;
            }

            if (!seen.Add(d))
            {
                dupes++;
                continue;
            }

            kept.Add(n);
            active++;
        }

        var outLines = new List<string>(WindowsHeader)
        {
            $"# --- {seen.Count} entries managed by {Product} v{version ?? "0.1.0"} ---",
        };
        outLines.AddRange(kept);
        return new CleanResult(outLines, new CleanStats(total, active, dupes, wl, invalid));
    }
}
