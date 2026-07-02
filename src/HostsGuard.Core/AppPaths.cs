using System.Text.RegularExpressions;

namespace HostsGuard.Core;

/// <summary>
/// Program-path helpers for identity-bound firewall rules (NET-069). Auto-
/// updating apps (Chrome, Discord, Teams, Slack) live under a per-version
/// directory that changes every release, orphaning path-based rules. Normalizing
/// the version segment to a wildcard gives the rebind scanner a stable key so an
/// updated binary is still recognized as the same app.
/// </summary>
public static partial class AppPaths
{
    // A directory segment that is purely a version, optionally with an app/update
    // prefix: "1.2.3", "v1.2.3", "1_2_3", "app-4.35.126", "120.0.6099.130".
    [GeneratedRegex(@"^(?:v|app-|update-|current-)?\d+(?:[._]\d+)+$", RegexOptions.IgnoreCase)]
    private static partial Regex VersionSegment();

    /// <summary>
    /// Replace version-like directory segments with <c>*</c> so
    /// <c>…\App\1.2.3\app.exe</c> and <c>…\App\1.2.4\app.exe</c> share a key.
    /// The file name is never wildcarded. Returns the input unchanged when it has
    /// no version segment.
    /// </summary>
    public static string NormalizeVersionedPath(string? path)
    {
        var p = (path ?? string.Empty).Trim();
        if (p.Length == 0)
        {
            return string.Empty;
        }

        var segments = p.Split('\\');
        // Never touch the last segment (the file name) or the first (drive).
        for (var i = 1; i < segments.Length - 1; i++)
        {
            if (VersionSegment().IsMatch(segments[i]))
            {
                segments[i] = "*";
            }
        }

        return string.Join('\\', segments);
    }

    /// <summary>True if two paths are the same app across a version-directory change.</summary>
    public static bool SameVersionedApp(string? a, string? b)
    {
        var na = NormalizeVersionedPath(a);
        var nb = NormalizeVersionedPath(b);
        return na.Length != 0 && na.Contains('*') && na.Equals(nb, StringComparison.OrdinalIgnoreCase);
    }
}
