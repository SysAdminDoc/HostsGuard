using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using HostsGuard.Core;

namespace HostsGuard.Windows;

/// <summary>Outcome of a bounded uninstall data purge.</summary>
public sealed record LocalDataPurgeResult(
    int DeletedFiles,
    int DeletedDirectories,
    int DeferredEntries,
    IReadOnlyList<string> Errors)
{
    public bool Complete => DeferredEntries == 0 && Errors.Count == 0;
}

/// <summary>
/// Removes only HostsGuard's canonical ProgramData and roaming AppData roots.
/// Reparse-point children are deleted as links and are never traversed. Files
/// still locked after the service and app stop are scheduled for deletion at
/// reboot, and the caller receives an explicit deferred result.
/// </summary>
[SupportedOSPlatform("windows")]
public static class LocalDataPurger
{
    private const int MoveFileDelayUntilReboot = 0x00000004;

    public static LocalDataPurgeResult PurgeCanonical()
    {
        var roots = AppPaths.LocalDataDirectories;
        var invalid = roots.Where(root => !AppPaths.IsCanonicalLocalDataDirectory(root)).ToArray();
        if (invalid.Length != 0)
        {
            return new LocalDataPurgeResult(
                0,
                0,
                0,
                invalid.Select(root => $"refused non-canonical data root: {root}").ToArray());
        }

        return PurgeRoots(roots, ScheduleDeleteAtReboot, protectRootReparsePoints: true);
    }

    internal static LocalDataPurgeResult PurgeRootsForTesting(
        IEnumerable<string> roots,
        Func<string, bool> scheduleDeleteAtReboot)
        => PurgeRoots(roots, scheduleDeleteAtReboot, protectRootReparsePoints: true);

    internal static bool ShouldTraverseDirectory(FileAttributes attributes)
        => attributes.HasFlag(FileAttributes.Directory) &&
           !attributes.HasFlag(FileAttributes.ReparsePoint);

    private static LocalDataPurgeResult PurgeRoots(
        IEnumerable<string> roots,
        Func<string, bool> scheduleDeleteAtReboot,
        bool protectRootReparsePoints)
    {
        ArgumentNullException.ThrowIfNull(roots);
        ArgumentNullException.ThrowIfNull(scheduleDeleteAtReboot);

        var state = new PurgeState(scheduleDeleteAtReboot);
        foreach (var root in roots.Select(Path.GetFullPath).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (!Directory.Exists(root))
            {
                continue;
            }

            try
            {
                var attributes = File.GetAttributes(root);
                if (protectRootReparsePoints && attributes.HasFlag(FileAttributes.ReparsePoint))
                {
                    state.Errors.Add($"refused reparse-point data root: {root}");
                    continue;
                }

                DeleteEntry(root, attributes, state);
            }
            catch (Exception ex) when (IsFileSystemFailure(ex))
            {
                state.Errors.Add($"could not inspect data root {root}: {ex.Message}");
            }
        }

        return new LocalDataPurgeResult(
            state.DeletedFiles,
            state.DeletedDirectories,
            state.Deferred.Count,
            state.Errors.AsReadOnly());
    }

    private static void DeleteEntry(string path, FileAttributes attributes, PurgeState state)
    {
        if (attributes.HasFlag(FileAttributes.ReparsePoint))
        {
            // Delete only the link object. Do not alter attributes because that
            // operation can target the link destination on some file systems.
            if (attributes.HasFlag(FileAttributes.Directory))
            {
                TryDeleteDirectory(path, state);
            }
            else
            {
                TryDeleteFile(path, attributes, state, clearReadOnly: false);
            }

            return;
        }

        if (ShouldTraverseDirectory(attributes))
        {
            string[] entries;
            try
            {
                entries = Directory.GetFileSystemEntries(path);
            }
            catch (Exception ex) when (IsFileSystemFailure(ex))
            {
                state.Errors.Add($"could not enumerate {path}: {ex.Message}");
                return;
            }

            foreach (var entry in entries)
            {
                try
                {
                    DeleteEntry(entry, File.GetAttributes(entry), state);
                }
                catch (FileNotFoundException)
                {
                    // Another cleanup participant already removed it.
                }
                catch (DirectoryNotFoundException)
                {
                    // Another cleanup participant already removed it.
                }
                catch (Exception ex) when (IsFileSystemFailure(ex))
                {
                    TryDefer(entry, ex, state);
                }
            }

            TryDeleteDirectory(path, state);
            return;
        }

        TryDeleteFile(path, attributes, state, clearReadOnly: true);
    }

    private static void TryDeleteFile(
        string path,
        FileAttributes attributes,
        PurgeState state,
        bool clearReadOnly)
    {
        try
        {
            if (clearReadOnly)
            {
                File.SetAttributes(path, attributes & ~FileAttributes.ReadOnly);
            }

            File.Delete(path);
            state.DeletedFiles++;
        }
        catch (FileNotFoundException)
        {
            // Already gone is a successful cleanup outcome.
        }
        catch (Exception ex) when (IsFileSystemFailure(ex))
        {
            TryDefer(path, ex, state);
        }
    }

    private static void TryDeleteDirectory(string path, PurgeState state)
    {
        try
        {
            Directory.Delete(path, recursive: false);
            state.DeletedDirectories++;
        }
        catch (DirectoryNotFoundException)
        {
            // Already gone is a successful cleanup outcome.
        }
        catch (Exception ex) when (IsFileSystemFailure(ex))
        {
            TryDefer(path, ex, state);
        }
    }

    private static void TryDefer(string path, Exception failure, PurgeState state)
    {
        if (state.ScheduleDeleteAtReboot(path))
        {
            state.Deferred.Add(path);
            return;
        }

        state.Errors.Add($"could not delete or defer {path}: {failure.Message}");
    }

    private static bool ScheduleDeleteAtReboot(string path)
        => MoveFileEx(path, null, MoveFileDelayUntilReboot);

    private static bool IsFileSystemFailure(Exception ex)
        => ex is IOException or UnauthorizedAccessException;

    [DllImport("kernel32.dll", EntryPoint = "MoveFileExW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool MoveFileEx(string existingFileName, string? newFileName, int flags);

    private sealed class PurgeState(Func<string, bool> scheduleDeleteAtReboot)
    {
        public Func<string, bool> ScheduleDeleteAtReboot { get; } = scheduleDeleteAtReboot;
        public HashSet<string> Deferred { get; } = new(StringComparer.OrdinalIgnoreCase);
        public List<string> Errors { get; } = [];
        public int DeletedFiles { get; set; }
        public int DeletedDirectories { get; set; }
    }
}
