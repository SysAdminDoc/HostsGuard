using System.Diagnostics;
using System.Text.Json;
using HostsGuard.Data;
using HostsGuard.Windows;

namespace HostsGuard.Service;

/// <summary>Durable state for one in-place update and at most one rollback.</summary>
public sealed record UpdateAttempt(
    string AttemptId,
    string ExpectedVersion,
    string PreviousVersion,
    string InstallRoot,
    string BackupRoot,
    WindowsServiceConfiguration ServiceConfiguration,
    string CreatedAt,
    string Status,
    bool RollbackAttempted,
    string Detail);

public sealed record UpdateRecoveryResult(bool Ok, string Message);

/// <summary>
/// Transaction boundary around installer replacement. Preparation stops the
/// old service before copying a versioned binary snapshot. Rollback is marked
/// before mutation and can therefore run at most once after any crash/restart.
/// </summary>
public static class UpdateRecoveryCoordinator
{
    internal const string AttemptFileName = "update_attempt.json";
    internal const string LaunchedFileName = "update_launched.json";
    internal const string RollbackHelperDirectoryName = "rollback-helper";
    private const string ServiceRelativePath = "service\\HostsGuard.Service.exe";
    private static readonly JsonSerializerOptions JsonOptions =
        new(JsonSerializerDefaults.Web) { WriteIndented = true, AllowDuplicateProperties = false };

    public static UpdateRecoveryResult Prepare(
        string dataDir,
        string installRoot,
        string expectedVersion,
        string helperExecutable,
        IWindowsServiceUpdateControl service)
    {
        ArgumentNullException.ThrowIfNull(service);
        try
        {
            var normalizedInstall = NormalizeInstallRoot(installRoot);
            var previousBinary = Path.Combine(normalizedInstall, ServiceRelativePath);
            if (!File.Exists(previousBinary))
            {
                return new UpdateRecoveryResult(false, $"installed service binary is missing: {previousBinary}");
            }

            if (!File.Exists(helperExecutable))
            {
                return new UpdateRecoveryResult(false, $"update helper is missing: {helperExecutable}");
            }

            if (ReadAttempt(dataDir) is not null)
            {
                return new UpdateRecoveryResult(false, "an unresolved update attempt already exists");
            }

            var previousVersion = FileVersionInfo.GetVersionInfo(previousBinary).ProductVersion?.Split('+')[0]
                ?? FileVersionInfo.GetVersionInfo(previousBinary).FileVersion
                ?? "unknown";
            var configuration = service.Capture();

            // This is the preflight gate: do not create a backup/attempt or let
            // Inno replace a byte until SCM confirms the old service is stopped.
            service.StopAndWait(TimeSpan.FromSeconds(30));

            var updatesDir = UpdatesDirectory(dataDir);
            Directory.CreateDirectory(updatesDir);
            var attemptId = Guid.NewGuid().ToString("N");
            var backupRoot = Path.Combine(
                updatesDir,
                $"previous-{SafeVersion(previousVersion)}-{attemptId[..12]}");
            try
            {
                CopyTree(normalizedInstall, backupRoot);
                var helperDir = Path.Combine(updatesDir, RollbackHelperDirectoryName);
                TryDeleteDirectory(helperDir);
                Directory.CreateDirectory(helperDir);
                File.Copy(helperExecutable, Path.Combine(helperDir, "HostsGuard.Service.exe"), overwrite: true);

                var attempt = new UpdateAttempt(
                    attemptId,
                    expectedVersion,
                    previousVersion,
                    normalizedInstall,
                    backupRoot,
                    configuration,
                    DateTime.UtcNow.ToString("O", System.Globalization.CultureInfo.InvariantCulture),
                    "prepared",
                    false,
                    string.Empty);
                WriteAttempt(dataDir, attempt);
                return new UpdateRecoveryResult(
                    true,
                    $"prepared update {previousVersion} -> {expectedVersion}; backup {Path.GetFileName(backupRoot)}");
            }
            catch
            {
                TryDeleteDirectory(backupRoot);
                TryDeleteFile(AttemptPath(dataDir));
                TryDeleteDirectory(Path.GetDirectoryName(RollbackHelperPath(dataDir))!);
                try
                {
                    service.StartAndWait(TimeSpan.FromSeconds(30));
                }
                catch (Exception restartError)
                {
                    throw new InvalidOperationException(
                        $"update preparation failed and the previous service could not restart: {restartError.Message}",
                        restartError);
                }

                throw;
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException or ArgumentException or
            System.ComponentModel.Win32Exception or TimeoutException or JsonException)
        {
            return new UpdateRecoveryResult(false, $"update preflight failed: {ex.Message}");
        }
    }

    public static UpdateRecoveryResult Rollback(string dataDir, IWindowsServiceUpdateControl service)
    {
        ArgumentNullException.ThrowIfNull(service);
        var attempt = ReadAttempt(dataDir);
        if (attempt is null)
        {
            return new UpdateRecoveryResult(false, "no update attempt is available for rollback");
        }

        if (attempt.RollbackAttempted)
        {
            return new UpdateRecoveryResult(false, "rollback was already attempted; refusing a second restore");
        }

        attempt = attempt with
        {
            RollbackAttempted = true,
            Status = "rolling_back",
            Detail = "rollback claimed before service or file mutation",
        };
        WriteAttempt(dataDir, attempt);

        try
        {
            ValidateAttemptPaths(dataDir, attempt);
            service.StopAndWait(TimeSpan.FromSeconds(30));
            SynchronizeTree(attempt.BackupRoot, attempt.InstallRoot);
            service.Restore(attempt.ServiceConfiguration);
            attempt = attempt with
            {
                Status = "rolled_back",
                Detail = $"restored {attempt.PreviousVersion} after {attempt.ExpectedVersion} failed health verification",
            };
            WriteAttempt(dataDir, attempt);
            // Publish the result before starting the restored service so its
            // startup reconciliation records the rollback immediately.
            service.StartAndWait(TimeSpan.FromSeconds(30));
            return new UpdateRecoveryResult(true, attempt.Detail);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException or ArgumentException or
            System.ComponentModel.Win32Exception or TimeoutException or JsonException)
        {
            attempt = attempt with { Status = "rollback_failed", Detail = ex.Message };
            WriteAttempt(dataDir, attempt);
            return new UpdateRecoveryResult(false, $"rollback failed: {ex.Message}");
        }
    }

    public static UpdateRecoveryResult CompleteHealthy(string dataDir, string expectedVersion, HostsDatabase db)
    {
        ArgumentNullException.ThrowIfNull(db);
        var attempt = ReadAttempt(dataDir);
        if (attempt is null)
        {
            return new UpdateRecoveryResult(true, "no update attempt required cleanup");
        }

        if (!VersionsEqual(attempt.ExpectedVersion, expectedVersion))
        {
            return new UpdateRecoveryResult(
                false,
                $"healthy version {expectedVersion} does not match attempted {attempt.ExpectedVersion}");
        }

        db.LogEvent(
            "self_update",
            "update_healthy",
            details: $"{attempt.PreviousVersion} -> {attempt.ExpectedVersion}; service/version/posture probe passed",
            reason: "self_update");
        Cleanup(dataDir, attempt);
        return new UpdateRecoveryResult(true, $"update {attempt.ExpectedVersion} marked healthy; rollback state cleared");
    }

    /// <summary>Record a completed rollback after the restored service opens its DB.</summary>
    public static void ReconcileOnServiceStart(string dataDir, HostsDatabase db)
    {
        var attempt = ReadAttempt(dataDir);
        if (attempt is null)
        {
            // A helper can still be running when the restored service first
            // reconciles. A later startup removes that harmless orphan.
            TryDeleteDirectory(Path.GetDirectoryName(RollbackHelperPath(dataDir))!);
            return;
        }

        if (attempt.Status != "rolled_back")
        {
            return;
        }

        db.LogEvent(
            "self_update",
            "update_rolled_back",
            details: attempt.Detail,
            reason: "self_update");
        Cleanup(dataDir, attempt);
    }

    public static UpdateAttempt? ReadAttempt(string dataDir)
    {
        try
        {
            var path = AttemptPath(dataDir);
            return File.Exists(path)
                ? JsonSerializer.Deserialize<UpdateAttempt>(File.ReadAllText(path), JsonOptions)
                : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            return null;
        }
    }

    internal static string AttemptPath(string dataDir) =>
        Path.Combine(UpdatesDirectory(dataDir), AttemptFileName);

    internal static string LaunchedPath(string dataDir) =>
        Path.Combine(UpdatesDirectory(dataDir), LaunchedFileName);

    internal static string RollbackHelperPath(string dataDir) =>
        Path.Combine(UpdatesDirectory(dataDir), RollbackHelperDirectoryName, "HostsGuard.Service.exe");

    private static void Cleanup(string dataDir, UpdateAttempt attempt)
    {
        TryDeleteDirectory(attempt.BackupRoot);
        TryDeleteFile(AttemptPath(dataDir));
        TryDeleteFile(LaunchedPath(dataDir));
        TryDeleteDirectory(Path.GetDirectoryName(RollbackHelperPath(dataDir))!);
    }

    private static void WriteAttempt(string dataDir, UpdateAttempt attempt)
    {
        var path = AttemptPath(dataDir);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var temporary = path + ".tmp";
        File.WriteAllText(temporary, JsonSerializer.Serialize(attempt, JsonOptions));
        File.Move(temporary, path, overwrite: true);
    }

    private static void ValidateAttemptPaths(string dataDir, UpdateAttempt attempt)
    {
        var updates = Path.GetFullPath(UpdatesDirectory(dataDir)) + Path.DirectorySeparatorChar;
        var backup = Path.GetFullPath(attempt.BackupRoot) + Path.DirectorySeparatorChar;
        _ = NormalizeInstallRoot(attempt.InstallRoot);
        if (!backup.StartsWith(updates, StringComparison.OrdinalIgnoreCase) ||
            !Directory.Exists(attempt.BackupRoot) ||
            !File.Exists(Path.Combine(attempt.BackupRoot, ServiceRelativePath)))
        {
            throw new InvalidOperationException("update backup path is outside the updates directory or incomplete");
        }
    }

    private static string NormalizeInstallRoot(string installRoot)
    {
        var full = Path.GetFullPath(installRoot ?? string.Empty).TrimEnd(Path.DirectorySeparatorChar);
        if (full.Length < 4 || Path.GetPathRoot(full)?.TrimEnd(Path.DirectorySeparatorChar)
                .Equals(full, StringComparison.OrdinalIgnoreCase) == true)
        {
            throw new ArgumentException("install root is not a safe application directory", nameof(installRoot));
        }

        return full;
    }

    private static string UpdatesDirectory(string dataDir) =>
        Path.Combine(Path.GetFullPath(dataDir ?? throw new ArgumentNullException(nameof(dataDir))), "updates");

    private static void CopyTree(string source, string destination)
    {
        Directory.CreateDirectory(destination);
        var options = SafeEnumeration();
        foreach (var directory in Directory.EnumerateDirectories(source, "*", options))
        {
            Directory.CreateDirectory(Path.Combine(destination, Path.GetRelativePath(source, directory)));
        }

        foreach (var file in Directory.EnumerateFiles(source, "*", options))
        {
            var relative = Path.GetRelativePath(source, file);
            if (IsInstallerState(relative))
            {
                continue;
            }

            var target = Path.Combine(destination, relative);
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            File.Copy(file, target, overwrite: false);
        }
    }

    private static void SynchronizeTree(string source, string destination)
    {
        var options = SafeEnumeration();
        var sourceFiles = Directory.EnumerateFiles(source, "*", options)
            .Select(path => Path.GetRelativePath(source, path))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var destinationFile in Directory.EnumerateFiles(destination, "*", options))
        {
            var relative = Path.GetRelativePath(destination, destinationFile);
            if (!IsInstallerState(relative) && !sourceFiles.Contains(relative))
            {
                File.Delete(destinationFile);
            }
        }

        foreach (var directory in Directory.EnumerateDirectories(destination, "*", options)
                     .OrderByDescending(path => path.Length))
        {
            if (!Directory.EnumerateFileSystemEntries(directory).Any())
            {
                Directory.Delete(directory);
            }
        }

        foreach (var file in Directory.EnumerateFiles(source, "*", options))
        {
            var relative = Path.GetRelativePath(source, file);
            if (IsInstallerState(relative))
            {
                continue;
            }

            var target = Path.Combine(destination, relative);
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            File.Copy(file, target, overwrite: true);
        }
    }

    private static EnumerationOptions SafeEnumeration() => new()
    {
        RecurseSubdirectories = true,
        IgnoreInaccessible = false,
        AttributesToSkip = FileAttributes.ReparsePoint,
    };

    private static string SafeVersion(string version) =>
        string.Concat((version ?? "unknown").Select(c => char.IsLetterOrDigit(c) || c is '.' or '-' ? c : '_'));

    private static bool IsInstallerState(string relativePath) =>
        !relativePath.Contains(Path.DirectorySeparatorChar) &&
        Path.GetFileName(relativePath).StartsWith("unins", StringComparison.OrdinalIgnoreCase);

    private static bool VersionsEqual(string left, string right) =>
        string.Equals(left.Trim().TrimStart('v', 'V'), right.Trim().TrimStart('v', 'V'), StringComparison.OrdinalIgnoreCase);

    private static void TryDeleteDirectory(string path)
    {
        try
        {
            if (Directory.Exists(path))
            {
                Directory.Delete(path, recursive: true);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
        }
    }

    private static void TryDeleteFile(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
        }
    }
}
