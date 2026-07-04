namespace HostsGuard.Core;

/// <summary>
/// Folder-scope path matching (NET-117). Windows Firewall matches a single exe
/// path, not a glob, so a "trust this whole folder" rule is enforced in the
/// consent broker: a blocked app is covered when its image path sits under a
/// trusted folder. Pure — no OS deps — so the matcher is unit-testable.
/// </summary>
public static class PathScope
{
    /// <summary>True when <paramref name="appPath"/> sits under <paramref name="folder"/> (recursively).</summary>
    public static bool IsUnder(string? appPath, string? folder)
    {
        var a = Normalize(appPath);
        var f = Normalize(folder);
        if (a.Length == 0 || f.Length == 0)
        {
            return false;
        }

        f = f.TrimEnd('\\') + "\\";
        return a.StartsWith(f, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>The parent folder of an image path (for "trust this folder"), or "".</summary>
    public static string ParentFolder(string? appPath)
    {
        var a = Normalize(appPath);
        if (a.Length == 0)
        {
            return string.Empty;
        }

        var slash = a.LastIndexOf('\\');
        return slash > 0 ? a[..slash] : string.Empty;
    }

    private static string Normalize(string? path)
        => (path ?? string.Empty).Trim().Replace('/', '\\');
}
