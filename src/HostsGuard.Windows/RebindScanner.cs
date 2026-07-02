using System.Runtime.Versioning;

namespace HostsGuard.Windows;

/// <summary>One scored replacement candidate for an orphaned program rule.</summary>
public sealed record RebindCandidateResult(string Path, int Score, string Reasons);

/// <summary>
/// Finds and ranks replacement binaries for an orphaned firewall program rule.
/// Ports the Python <c>_scan_program_rebind_candidates</c> /
/// <c>_rank_rebind_candidates</c> flow: the rule's remembered identities
/// (SHA-256 + Authenticode signer from <see cref="FirewallIdentity"/>) carry the
/// confidence; name and folder heuristics only add on top. Candidates below
/// <see cref="MinScore"/> are dropped — without identity history a same-named
/// binary is never auto-suggested, only manual rebind remains.
/// </summary>
[SupportedOSPlatform("windows")]
public static class RebindScanner
{
    public const int MinScore = 60;

    /// <summary>Top-two candidates within this delta = ambiguous (user must pick).</summary>
    public const int AmbiguousDelta = 8;

    private static readonly string[] SkippedDirs = { "$Recycle.Bin", "System Volume Information", "WinSxS" };

    private static readonly string[] GenericParents = { "", "bin", "app", "apps", "program files", "program files (x86)" };

    /// <summary>Directories worth scanning for a moved binary, existing ones only.</summary>
    public static IReadOnlyList<string> SearchRoots(string oldPath)
    {
        var roots = new List<string>();
        void Add(string? candidate)
        {
            if (string.IsNullOrWhiteSpace(candidate))
            {
                return;
            }

            try
            {
                var full = Path.GetFullPath(Environment.ExpandEnvironmentVariables(candidate));
                if (Directory.Exists(full) && !roots.Contains(full, StringComparer.OrdinalIgnoreCase))
                {
                    roots.Add(full);
                }
            }
            catch (Exception ex) when (ex is ArgumentException or IOException or System.Security.SecurityException)
            {
                // Unresolvable root — skip.
            }
        }

        var first = (oldPath ?? string.Empty).Split(',')[0].Trim();
        if (first.Length != 0)
        {
            Add(Path.GetDirectoryName(first));
            Add(Path.GetDirectoryName(Path.GetDirectoryName(first) ?? string.Empty));
        }

        Add(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles));
        Add(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86));
        Add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs"));
        return roots;
    }

    /// <summary>
    /// Depth-limited walk of the search roots collecting files with the old
    /// binary's name (or same-stem .exe). Access-denied subtrees are skipped.
    /// </summary>
    public static IReadOnlyList<string> ScanCandidates(
        string oldPath, int maxResults = 40, int maxDepth = 4, IReadOnlyList<string>? roots = null)
    {
        var old = (oldPath ?? string.Empty).Split(',')[0].Trim();
        if (old.Length == 0)
        {
            return Array.Empty<string>();
        }

        var baseName = Path.GetFileName(old);
        var stem = Path.GetFileNameWithoutExtension(old);
        if (baseName.Length == 0)
        {
            return Array.Empty<string>();
        }

        var found = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { old };
        foreach (var root in roots ?? SearchRoots(old))
        {
            var queue = new Queue<(string Dir, int Depth)>();
            queue.Enqueue((root, 0));
            while (queue.Count != 0)
            {
                var (dir, depth) = queue.Dequeue();
                try
                {
                    foreach (var file in Directory.EnumerateFiles(dir))
                    {
                        var name = Path.GetFileName(file);
                        var matches = name.Equals(baseName, StringComparison.OrdinalIgnoreCase) ||
                            (name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) &&
                             Path.GetFileNameWithoutExtension(name).Equals(stem, StringComparison.OrdinalIgnoreCase));
                        if (matches && seen.Add(file))
                        {
                            found.Add(file);
                            if (found.Count >= maxResults)
                            {
                                return found;
                            }
                        }
                    }

                    if (depth + 1 < maxDepth)
                    {
                        foreach (var sub in Directory.EnumerateDirectories(dir))
                        {
                            if (!SkippedDirs.Contains(Path.GetFileName(sub), StringComparer.OrdinalIgnoreCase))
                            {
                                queue.Enqueue((sub, depth + 1));
                            }
                        }
                    }
                }
                catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or System.Security.SecurityException)
                {
                    // Protected subtree — skip it, keep walking siblings.
                }
            }
        }

        return found;
    }

    /// <summary>
    /// Score a candidate against the rule's remembered identities. The newest
    /// history entry stands in for the (now missing) old binary; older entries
    /// count as "known previous" versions.
    /// </summary>
    public static int Score(
        string oldPath, IReadOnlyList<FileIdentity> history, FileIdentity candidate, out string reasons)
    {
        ArgumentNullException.ThrowIfNull(candidate);
        history ??= Array.Empty<FileIdentity>();
        var score = 0;
        var why = new List<string>();
        var latest = history.Count != 0 ? history[^1] : null;

        if (latest is not null && candidate.Sha256.Equals(latest.Sha256, StringComparison.OrdinalIgnoreCase))
        {
            score += 90;
            why.Add("same SHA-256");
        }
        else if (history.Any(h => h.Sha256.Equals(candidate.Sha256, StringComparison.OrdinalIgnoreCase)))
        {
            score += 70;
            why.Add("known previous SHA-256");
        }

        var oldName = Path.GetFileName((oldPath ?? string.Empty).Split(',')[0].Trim());
        var candName = Path.GetFileName(candidate.Path);
        if (oldName.Length != 0 && oldName.Equals(candName, StringComparison.OrdinalIgnoreCase))
        {
            score += 30;
            why.Add("same executable name");
        }
        else if (Path.GetFileNameWithoutExtension(oldName)
                     .Equals(Path.GetFileNameWithoutExtension(candName), StringComparison.OrdinalIgnoreCase))
        {
            score += 15;
            why.Add("same executable stem");
        }

        if (!string.IsNullOrEmpty(candidate.Signer) &&
            history.Any(h => !string.IsNullOrEmpty(h.Signer) && h.Signer == candidate.Signer))
        {
            score += 35;
            why.Add("same signer");
        }

        var oldParent = Path.GetFileName(Path.GetDirectoryName((oldPath ?? string.Empty).Split(',')[0].Trim()) ?? string.Empty);
        if (oldParent.Length != 0 && !GenericParents.Contains(oldParent.ToLowerInvariant()))
        {
            var parts = candidate.Path.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            if (parts.Any(p => p.Equals(oldParent, StringComparison.OrdinalIgnoreCase)))
            {
                score += 20;
                why.Add("same app folder family");
            }
        }

        reasons = string.Join("; ", why);
        return Math.Min(score, 100);
    }

    /// <summary>Compute identities, score, and rank; below-threshold candidates drop out.</summary>
    public static IReadOnlyList<RebindCandidateResult> Rank(
        string oldPath, IReadOnlyList<FileIdentity> history, IEnumerable<string> candidatePaths, int minScore = MinScore)
    {
        var ranked = new List<RebindCandidateResult>();
        foreach (var path in candidatePaths ?? Array.Empty<string>())
        {
            FileIdentity identity;
            try
            {
                identity = FirewallIdentity.Compute(path);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                continue; // unreadable candidate
            }

            var score = Score(oldPath, history, identity, out var reasons);
            if (score >= minScore)
            {
                ranked.Add(new RebindCandidateResult(path, score, reasons));
            }
        }

        return ranked
            .OrderByDescending(r => r.Score)
            .ThenBy(r => r.Path, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }
}
