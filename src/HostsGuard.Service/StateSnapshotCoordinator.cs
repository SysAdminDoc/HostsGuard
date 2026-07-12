using System.Security.Cryptography;
using System.Text.Json;
using HostsGuard.Data;

namespace HostsGuard.Service;

public sealed record StateSnapshotInfo(
    string Id,
    DateTime CreatedUtc,
    string AppVersion,
    int DatabaseSchemaVersion,
    string Sha256,
    long SizeBytes,
    bool Verified,
    IReadOnlyList<string> Components);

public sealed record StateSnapshotChange(string Component, string ChangeKind);

public sealed record StateSnapshotPreview(
    StateSnapshotInfo Snapshot,
    IReadOnlyList<StateSnapshotChange> Changes,
    string Summary);

public sealed record StateSnapshotRestoreResult(
    StateSnapshotInfo Snapshot,
    string PreRestoreSnapshotId,
    bool RolledBack);

public sealed record StartupStateRestoreResult(
    bool HadPendingRestore,
    bool Restored,
    bool RolledBack,
    string SnapshotId,
    string PreRestoreSnapshotId);

public sealed record StateRestoreValidationContext(
    string HostsPath,
    string DataDirectory,
    StateSnapshotInfo Snapshot);

public sealed class StateSnapshotException(string message, Exception? innerException = null)
    : InvalidOperationException(message, innerException);

/// <summary>
/// Creates and restores complete, integrity-protected local state snapshots.
/// Secrets and downloaded/re-creatable intelligence are deliberately excluded.
/// </summary>
public sealed class StateSnapshotCoordinator
{
    public const int FormatVersion = 1;

    private const string ManifestName = "manifest.json";
    private const string PendingRestoreName = "pending_state_restore.json";
    private const string DatabaseComponent = "database";
    private const string HostsComponent = "hosts";
    private const string DatabaseRelativePath = "database/hostsguard.db";
    private const string HostsRelativePath = "hosts/hosts";

    private static readonly string[] NonSecretJsonFiles =
    {
        "consent_state.json",
        "doh_resolvers.json",
        "enforcement_pause_state.json",
        "killswitch_state.json",
        "fw_identities.json",
    };

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        AllowDuplicateProperties = false,
    };

    private readonly object _gate = new();
    private readonly HostsDatabase _database;
    private readonly string _hostsPath;
    private readonly string _dataDirectory;
    private readonly string _snapshotRoot;
    private readonly string _appVersion;
    private readonly Func<StateRestoreValidationContext, bool>? _postRestoreValidation;

    public StateSnapshotCoordinator(
        HostsDatabase database,
        string hostsPath,
        string dataDirectory,
        string appVersion,
        string? snapshotRoot = null,
        Func<StateRestoreValidationContext, bool>? postRestoreValidation = null)
    {
        _database = database ?? throw new ArgumentNullException(nameof(database));
        ArgumentException.ThrowIfNullOrWhiteSpace(hostsPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(dataDirectory);
        ArgumentException.ThrowIfNullOrWhiteSpace(appVersion);
        _hostsPath = Path.GetFullPath(hostsPath);
        _dataDirectory = Path.GetFullPath(dataDirectory);
        _snapshotRoot = Path.GetFullPath(snapshotRoot ?? Path.Combine(dataDirectory, "state-snapshots"));
        _appVersion = appVersion;
        _postRestoreValidation = postRestoreValidation;
    }

    public StateSnapshotInfo Create()
    {
        lock (_gate)
        {
            return CreateCore("snapshot");
        }
    }

    public IReadOnlyList<StateSnapshotInfo> List()
    {
        lock (_gate)
        {
            if (!Directory.Exists(_snapshotRoot))
            {
                return Array.Empty<StateSnapshotInfo>();
            }

            return Directory.EnumerateDirectories(_snapshotRoot)
                .Where(path => !Path.GetFileName(path).StartsWith(".tmp-", StringComparison.Ordinal))
                .Select(path => ReadInfo(path, verify: true))
                .OrderByDescending(info => info.CreatedUtc)
                .ToArray();
        }
    }

    public StateSnapshotPreview Preview(string id)
    {
        lock (_gate)
        {
            var path = ResolveSnapshotPath(id);
            var (manifest, info) = ReadVerified(path);
            var snapshotByComponent = manifest.Files.ToDictionary(file => file.Component, StringComparer.Ordinal);
            var changes = new List<StateSnapshotChange>();

            var currentDatabaseHash = HashCurrentDatabase();
            AddChange(changes, DatabaseComponent, currentDatabaseHash, snapshotByComponent[DatabaseComponent].Sha256);
            AddChange(changes, HostsComponent, HashFileOrEmpty(_hostsPath), snapshotByComponent[HostsComponent].Sha256);

            foreach (var name in NonSecretJsonFiles)
            {
                var component = StateComponent(name);
                var current = HashFileOrEmpty(Path.Combine(_dataDirectory, name));
                if (snapshotByComponent.TryGetValue(component, out var snapshot))
                {
                    AddChange(changes, component, current, snapshot.Sha256);
                }
                else if (current.Length != 0)
                {
                    changes.Add(new StateSnapshotChange(component, "remove"));
                }
            }

            var changed = changes.Count(change => change.ChangeKind != "unchanged");
            return new StateSnapshotPreview(
                info,
                changes,
                changed == 0 ? "Snapshot matches current state." : $"{changed} component(s) would change.");
        }
    }

    public StateSnapshotRestoreResult Restore(
        string id,
        string expectedSha256,
        bool createPreRestore = true)
    {
        lock (_gate)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(expectedSha256);
            var path = ResolveSnapshotPath(id);
            var (manifest, info) = ReadVerified(path);
            if (!CryptographicOperations.FixedTimeEquals(
                    Convert.FromHexString(info.Sha256),
                    ParseSha256(expectedSha256)))
            {
                throw new StateSnapshotException("Snapshot confirmation hash does not match the verified manifest.");
            }

            var preRestore = createPreRestore ? CreateCore("pre-restore") : null;
            try
            {
                Apply(path, manifest);
                ValidateRestoredState(info);
                return new StateSnapshotRestoreResult(info, preRestore?.Id ?? string.Empty, RolledBack: false);
            }
            catch (Exception restoreError)
                when (restoreError is IOException or UnauthorizedAccessException or InvalidOperationException or JsonException)
            {
                if (preRestore is null)
                {
                    throw new StateSnapshotException("State restore failed; no automatic rollback snapshot was requested.", restoreError);
                }

                try
                {
                    var rollbackPath = ResolveSnapshotPath(preRestore.Id);
                    var (rollbackManifest, _) = ReadVerified(rollbackPath);
                    Apply(rollbackPath, rollbackManifest);
                    ValidateRestoredState(preRestore, runPostRestoreValidation: false);
                }
                catch (Exception rollbackError)
                {
                    throw new AggregateException(
                        "State restore and automatic rollback both failed.",
                        restoreError,
                        rollbackError);
                }

                throw new StateSnapshotException(
                    $"State restore failed validation and was rolled back to {preRestore.Id}.",
                    restoreError);
            }
        }
    }

    /// <summary>
    /// Persist a hash-confirmed restore request for the next service start. The
    /// marker never contains payload data or secrets and is written atomically.
    /// </summary>
    public StateSnapshotInfo StageForStartup(string id, string expectedSha256)
    {
        lock (_gate)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(expectedSha256);
            var (_, info) = ReadVerified(ResolveSnapshotPath(id));
            if (!CryptographicOperations.FixedTimeEquals(
                    Convert.FromHexString(info.Sha256),
                    ParseSha256(expectedSha256)))
            {
                throw new StateSnapshotException("Snapshot confirmation hash does not match the verified manifest.");
            }

            WritePendingMarker(
                _dataDirectory,
                new PendingStartupRestore(info.Id, info.Sha256, string.Empty, "staged"));
            return info;
        }
    }

    /// <summary>
    /// Apply a staged restore before the long-lived service database is opened.
    /// A durable marker records the pre-restore snapshot before any replacement;
    /// an interrupted apply is rolled back on the next start. Validation failure
    /// likewise restores the exact pre-restore database, hosts, and JSON state.
    /// </summary>
    public static StartupStateRestoreResult ApplyPendingAtStartup(
        string databasePath,
        string hostsPath,
        string dataDirectory,
        string appVersion,
        string? snapshotRoot = null,
        Func<StateRestoreValidationContext, bool>? startupValidation = null)
    {
        var markerPath = Path.Combine(dataDirectory, PendingRestoreName);
        if (!File.Exists(markerPath))
        {
            return new StartupStateRestoreResult(false, false, false, string.Empty, string.Empty);
        }

        var marker = ReadPendingMarker(markerPath);
        var interruptedApply = marker.Phase == "preparing" && marker.PreRestoreSnapshotId.Length != 0;
        var root = snapshotRoot ?? Path.Combine(dataDirectory, "state-snapshots");
        StateSnapshotManifest targetManifest;
        StateSnapshotInfo targetInfo;
        StateSnapshotManifest preManifest;
        StateSnapshotInfo preInfo;

        using (var database = new HostsDatabase(databasePath))
        {
            var coordinator = new StateSnapshotCoordinator(
                database, hostsPath, dataDirectory, appVersion, root, startupValidation);
            (targetManifest, targetInfo) = coordinator.ReadVerified(coordinator.ResolveSnapshotPath(marker.SnapshotId));
            if (!HashEquals(targetInfo.Sha256, marker.ExpectedSha256))
            {
                throw new StateSnapshotException("Pending snapshot hash no longer matches its staged confirmation.");
            }

            if (marker.PreRestoreSnapshotId.Length == 0)
            {
                preInfo = coordinator.CreateCore("pre-startup-restore");
                marker = marker with { PreRestoreSnapshotId = preInfo.Id, Phase = "preparing" };
                WritePendingMarker(dataDirectory, marker);
            }
            else
            {
                preInfo = coordinator.ReadVerified(
                    coordinator.ResolveSnapshotPath(marker.PreRestoreSnapshotId)).Info;
            }

            preManifest = coordinator.ReadVerified(
                coordinator.ResolveSnapshotPath(preInfo.Id)).Manifest;
        }

        // A previous process stopped between recording its fallback and marking
        // the target fully copied. Prefer the known-good fallback over guessing
        // which subset of files reached disk.
        if (interruptedApply)
        {
            ApplyOffline(root, preInfo.Id, preManifest, databasePath, hostsPath, dataDirectory);
            ValidateOffline(databasePath, hostsPath, dataDirectory, preInfo, startupValidation: null);
            File.Delete(markerPath);
            return new StartupStateRestoreResult(true, false, true, targetInfo.Id, preInfo.Id);
        }

        try
        {
            ApplyOffline(root, targetInfo.Id, targetManifest, databasePath, hostsPath, dataDirectory);
            marker = marker with { Phase = "applied" };
            WritePendingMarker(dataDirectory, marker);
            ValidateOffline(databasePath, hostsPath, dataDirectory, targetInfo, startupValidation);
            File.Delete(markerPath);
            return new StartupStateRestoreResult(true, true, false, targetInfo.Id, preInfo.Id);
        }
        catch (Exception restoreError)
            when (restoreError is IOException or UnauthorizedAccessException or InvalidOperationException or JsonException)
        {
            try
            {
                ApplyOffline(root, preInfo.Id, preManifest, databasePath, hostsPath, dataDirectory);
                ValidateOffline(databasePath, hostsPath, dataDirectory, preInfo, startupValidation: null);
                File.Delete(markerPath);
            }
            catch (Exception rollbackError)
            {
                throw new AggregateException(
                    "Startup state restore and automatic rollback both failed; the recovery marker was retained.",
                    restoreError,
                    rollbackError);
            }

            throw new StateSnapshotException(
                $"Startup state restore failed validation and was rolled back to {preInfo.Id}.",
                restoreError);
        }
    }

    private StateSnapshotInfo CreateCore(string prefix)
    {
        Directory.CreateDirectory(_snapshotRoot);
        var created = DateTime.UtcNow;
        var id = $"{prefix}-{created:yyyyMMddTHHmmssfffffffZ}-{Guid.NewGuid():N}";
        var finalPath = Path.Combine(_snapshotRoot, id);
        var stagingPath = Path.Combine(_snapshotRoot, ".tmp-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(stagingPath);

        try
        {
            var files = new List<StateSnapshotFile>();
            var databasePath = Path.Combine(stagingPath, DatabaseRelativePath.Replace('/', Path.DirectorySeparatorChar));
            _database.BackupTo(databasePath);
            files.Add(Describe(DatabaseComponent, DatabaseRelativePath, databasePath));

            var hostsDestination = Path.Combine(stagingPath, HostsRelativePath.Replace('/', Path.DirectorySeparatorChar));
            CopyFile(_hostsPath, hostsDestination);
            files.Add(Describe(HostsComponent, HostsRelativePath, hostsDestination));

            foreach (var name in NonSecretJsonFiles)
            {
                var source = Path.Combine(_dataDirectory, name);
                if (!File.Exists(source))
                {
                    continue;
                }

                ValidateJson(source);
                var relative = "state/" + name;
                var destination = Path.Combine(stagingPath, relative.Replace('/', Path.DirectorySeparatorChar));
                CopyFile(source, destination);
                files.Add(Describe(StateComponent(name), relative, destination));
            }

            var manifest = new StateSnapshotManifest(
                FormatVersion,
                id,
                created,
                _appVersion,
                HostsDatabase.SchemaVersion,
                files.OrderBy(file => file.RelativePath, StringComparer.Ordinal).ToArray());
            var manifestPath = Path.Combine(stagingPath, ManifestName);
            WriteDurableText(manifestPath, JsonSerializer.Serialize(manifest, JsonOptions));
            Directory.Move(stagingPath, finalPath);
            return ReadInfo(finalPath, verify: true);
        }
        catch
        {
            if (Directory.Exists(stagingPath))
            {
                Directory.Delete(stagingPath, recursive: true);
            }

            throw;
        }
    }

    private void Apply(string snapshotPath, StateSnapshotManifest manifest)
    {
        var byComponent = manifest.Files.ToDictionary(file => file.Component, StringComparer.Ordinal);
        _database.RestoreFrom(PayloadPath(snapshotPath, byComponent[DatabaseComponent].RelativePath));
        AtomicCopy(PayloadPath(snapshotPath, byComponent[HostsComponent].RelativePath), _hostsPath);

        foreach (var name in NonSecretJsonFiles)
        {
            var component = StateComponent(name);
            var destination = Path.Combine(_dataDirectory, name);
            if (byComponent.TryGetValue(component, out var file))
            {
                AtomicCopy(PayloadPath(snapshotPath, file.RelativePath), destination);
            }
            else if (File.Exists(destination))
            {
                File.Delete(destination);
            }
        }
    }

    private void ValidateRestoredState(StateSnapshotInfo info, bool runPostRestoreValidation = true)
    {
        var verification = CreateValidationDatabaseCopy();
        try
        {
            HostsDatabase.ValidateBackup(verification, HostsDatabase.SchemaVersion);
        }
        finally
        {
            File.Delete(verification);
        }

        _ = File.ReadAllText(_hostsPath);
        foreach (var name in NonSecretJsonFiles)
        {
            var path = Path.Combine(_dataDirectory, name);
            if (File.Exists(path))
            {
                ValidateJson(path);
            }
        }

        if (runPostRestoreValidation &&
            _postRestoreValidation is not null &&
            !_postRestoreValidation(new StateRestoreValidationContext(_hostsPath, _dataDirectory, info)))
        {
            throw new StateSnapshotException("Post-restore startup validation rejected the restored state.");
        }
    }

    private (StateSnapshotManifest Manifest, StateSnapshotInfo Info) ReadVerified(string snapshotPath)
    {
        var manifestPath = Path.Combine(snapshotPath, ManifestName);
        var manifestBytes = File.ReadAllBytes(manifestPath);
        var manifest = JsonSerializer.Deserialize<StateSnapshotManifest>(manifestBytes, JsonOptions)
            ?? throw new StateSnapshotException("Snapshot manifest is empty.");
        if (manifest.FormatVersion != FormatVersion ||
            manifest.DatabaseSchemaVersion != HostsDatabase.SchemaVersion ||
            !string.Equals(manifest.Id, Path.GetFileName(snapshotPath), StringComparison.Ordinal))
        {
            throw new StateSnapshotException("Snapshot format, schema, or identifier is incompatible.");
        }

        if (manifest.Files.Count < 2 ||
            manifest.Files.Select(file => file.Component).Distinct(StringComparer.Ordinal).Count() != manifest.Files.Count ||
            manifest.Files.Select(file => file.RelativePath).Distinct(StringComparer.Ordinal).Count() != manifest.Files.Count ||
            !manifest.Files.Any(file => file.Component == DatabaseComponent) ||
            !manifest.Files.Any(file => file.Component == HostsComponent))
        {
            throw new StateSnapshotException("Snapshot component inventory is incomplete or duplicated.");
        }

        var allowedComponents = new HashSet<string>(
            new[] { DatabaseComponent, HostsComponent }.Concat(NonSecretJsonFiles.Select(StateComponent)),
            StringComparer.Ordinal);
        foreach (var file in manifest.Files)
        {
            if (!allowedComponents.Contains(file.Component) || file.SizeBytes < 0)
            {
                throw new StateSnapshotException($"Snapshot contains an unsupported component: {file.Component}.");
            }

            var payloadPath = PayloadPath(snapshotPath, file.RelativePath);
            var actualSize = new FileInfo(payloadPath).Length;
            var actualHash = HashFile(payloadPath);
            if (actualSize != file.SizeBytes || !HashEquals(actualHash, file.Sha256))
            {
                throw new StateSnapshotException($"Snapshot integrity verification failed for {file.Component}.");
            }

            if (file.Component.StartsWith("state:", StringComparison.Ordinal))
            {
                ValidateJson(payloadPath);
            }
        }

        var payloadFiles = Directory.EnumerateFiles(snapshotPath, "*", SearchOption.AllDirectories)
            .Where(file => !string.Equals(Path.GetFileName(file), ManifestName, StringComparison.Ordinal))
            .Select(file => Path.GetRelativePath(snapshotPath, file).Replace('\\', '/'))
            .Order(StringComparer.Ordinal)
            .ToArray();
        if (!payloadFiles.SequenceEqual(manifest.Files.Select(file => file.RelativePath).Order(StringComparer.Ordinal), StringComparer.Ordinal))
        {
            throw new StateSnapshotException("Snapshot contains unmanifested payload files.");
        }

        HostsDatabase.ValidateBackup(
            PayloadPath(snapshotPath, manifest.Files.Single(file => file.Component == DatabaseComponent).RelativePath),
            manifest.DatabaseSchemaVersion);

        var info = ToInfo(manifest, Convert.ToHexString(SHA256.HashData(manifestBytes)).ToLowerInvariant(), verified: true);
        return (manifest, info);
    }

    private StateSnapshotInfo ReadInfo(string snapshotPath, bool verify)
    {
        try
        {
            if (verify)
            {
                return ReadVerified(snapshotPath).Info;
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or InvalidOperationException)
        {
            var id = Path.GetFileName(snapshotPath);
            return new StateSnapshotInfo(id, DateTime.MinValue, string.Empty, 0, string.Empty, 0, false, Array.Empty<string>());
        }

        throw new InvalidOperationException("Snapshot metadata could not be read.");
    }

    private static StateSnapshotInfo ToInfo(StateSnapshotManifest manifest, string hash, bool verified) =>
        new(
            manifest.Id,
            manifest.CreatedUtc,
            manifest.AppVersion,
            manifest.DatabaseSchemaVersion,
            hash,
            manifest.Files.Sum(file => file.SizeBytes),
            verified,
            manifest.Files.Select(file => file.Component).Order(StringComparer.Ordinal).ToArray());

    private string ResolveSnapshotPath(string id)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(id);
        if (id.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 ||
            id.Contains('/') || id.Contains('\\') || id is "." or "..")
        {
            throw new StateSnapshotException("Snapshot identifier is invalid.");
        }

        var path = Path.GetFullPath(Path.Combine(_snapshotRoot, id));
        if (!string.Equals(Path.GetDirectoryName(path), _snapshotRoot, StringComparison.OrdinalIgnoreCase) ||
            !Directory.Exists(path))
        {
            throw new StateSnapshotException("Snapshot was not found.");
        }

        return path;
    }

    private string HashCurrentDatabase()
    {
        var path = CreateValidationDatabaseCopy();
        try
        {
            return HashFile(path);
        }
        finally
        {
            File.Delete(path);
        }
    }

    private string CreateValidationDatabaseCopy()
    {
        Directory.CreateDirectory(_snapshotRoot);
        var path = Path.Combine(_snapshotRoot, ".tmp-db-" + Guid.NewGuid().ToString("N") + ".db");
        _database.BackupTo(path);
        return path;
    }

    private static void AddChange(List<StateSnapshotChange> changes, string component, string currentHash, string snapshotHash)
    {
        changes.Add(new StateSnapshotChange(
            component,
            currentHash.Length == 0 ? "add" : HashEquals(currentHash, snapshotHash) ? "unchanged" : "replace"));
    }

    private static byte[] ParseSha256(string hash)
    {
        try
        {
            var bytes = Convert.FromHexString(hash);
            if (bytes.Length == SHA256.HashSizeInBytes)
            {
                return bytes;
            }
        }
        catch (FormatException)
        {
        }

        throw new StateSnapshotException("Snapshot confirmation hash must be a 64-character SHA-256 value.");
    }

    private static string PayloadPath(string snapshotPath, string relativePath)
    {
        if (string.IsNullOrWhiteSpace(relativePath) || Path.IsPathRooted(relativePath))
        {
            throw new StateSnapshotException("Snapshot payload path is invalid.");
        }

        var normalizedRoot = Path.GetFullPath(snapshotPath) + Path.DirectorySeparatorChar;
        var fullPath = Path.GetFullPath(Path.Combine(snapshotPath, relativePath.Replace('/', Path.DirectorySeparatorChar)));
        if (!fullPath.StartsWith(normalizedRoot, StringComparison.OrdinalIgnoreCase) || !File.Exists(fullPath))
        {
            throw new StateSnapshotException("Snapshot payload path escapes the snapshot directory or is missing.");
        }

        return fullPath;
    }

    private static StateSnapshotFile Describe(string component, string relativePath, string path) =>
        new(component, relativePath, new FileInfo(path).Length, HashFile(path));

    private static string StateComponent(string name) => "state:" + name;

    private static string HashFile(string path)
    {
        using var stream = File.OpenRead(path);
        return Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
    }

    private static string HashFileOrEmpty(string path) => File.Exists(path) ? HashFile(path) : string.Empty;

    private static bool HashEquals(string left, string right)
    {
        try
        {
            return CryptographicOperations.FixedTimeEquals(ParseSha256(left), ParseSha256(right));
        }
        catch (StateSnapshotException)
        {
            return false;
        }
    }

    private static void ValidateJson(string path)
    {
        using var stream = File.OpenRead(path);
        using var _ = JsonDocument.Parse(stream, new JsonDocumentOptions
        {
            AllowTrailingCommas = false,
            CommentHandling = JsonCommentHandling.Disallow,
            MaxDepth = 64,
        });
    }

    private static void CopyFile(string source, string destination)
    {
        if (!File.Exists(source))
        {
            throw new FileNotFoundException("Snapshot source file was not found.", source);
        }

        Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
        using var input = new FileStream(source, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        using var output = new FileStream(destination, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        input.CopyTo(output);
        output.Flush(flushToDisk: true);
    }

    private static void AtomicCopy(string source, string destination)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
        var temporary = destination + ".restore-" + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            CopyFile(source, temporary);
            File.Move(temporary, destination, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporary))
            {
                File.Delete(temporary);
            }
        }
    }

    private static void ApplyOffline(
        string snapshotRoot,
        string snapshotId,
        StateSnapshotManifest manifest,
        string databasePath,
        string hostsPath,
        string dataDirectory)
    {
        var snapshotPath = Path.Combine(snapshotRoot, snapshotId);
        var byComponent = manifest.Files.ToDictionary(file => file.Component, StringComparer.Ordinal);
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        foreach (var sidecar in new[] { databasePath + "-wal", databasePath + "-shm" })
        {
            if (File.Exists(sidecar))
            {
                File.Delete(sidecar);
            }
        }

        AtomicCopy(PayloadPath(snapshotPath, byComponent[DatabaseComponent].RelativePath), databasePath);
        AtomicCopy(PayloadPath(snapshotPath, byComponent[HostsComponent].RelativePath), hostsPath);
        foreach (var name in NonSecretJsonFiles)
        {
            var destination = Path.Combine(dataDirectory, name);
            if (byComponent.TryGetValue(StateComponent(name), out var file))
            {
                AtomicCopy(PayloadPath(snapshotPath, file.RelativePath), destination);
            }
            else if (File.Exists(destination))
            {
                File.Delete(destination);
            }
        }
    }

    private static void ValidateOffline(
        string databasePath,
        string hostsPath,
        string dataDirectory,
        StateSnapshotInfo info,
        Func<StateRestoreValidationContext, bool>? startupValidation)
    {
        using (var database = new HostsDatabase(databasePath))
        {
            if (database.SchemaVersionOnDisk() != HostsDatabase.SchemaVersion)
            {
                throw new StateSnapshotException("Restored database did not start with the expected schema.");
            }
        }

        _ = File.ReadAllText(hostsPath);
        foreach (var name in NonSecretJsonFiles)
        {
            var path = Path.Combine(dataDirectory, name);
            if (File.Exists(path))
            {
                ValidateJson(path);
            }
        }

        if (startupValidation is not null &&
            !startupValidation(new StateRestoreValidationContext(hostsPath, dataDirectory, info)))
        {
            throw new StateSnapshotException("Startup validation rejected the restored state.");
        }
    }

    private static PendingStartupRestore ReadPendingMarker(string markerPath)
    {
        var marker = JsonSerializer.Deserialize<PendingStartupRestore>(File.ReadAllText(markerPath), JsonOptions)
            ?? throw new StateSnapshotException("Pending state-restore marker is empty.");
        if (marker.SnapshotId.Length == 0 ||
            marker.ExpectedSha256.Length == 0 ||
            marker.Phase is not ("staged" or "preparing" or "applied"))
        {
            throw new StateSnapshotException("Pending state-restore marker is invalid.");
        }

        return marker;
    }

    private static void WritePendingMarker(string dataDirectory, PendingStartupRestore marker)
    {
        Directory.CreateDirectory(dataDirectory);
        var destination = Path.Combine(dataDirectory, PendingRestoreName);
        var temporary = destination + ".tmp";
        WriteDurableText(temporary, JsonSerializer.Serialize(marker, JsonOptions));
        File.Move(temporary, destination, overwrite: true);
    }

    private static void WriteDurableText(string path, string content)
    {
        var bytes = System.Text.Encoding.UTF8.GetBytes(content);
        using var stream = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None);
        stream.Write(bytes);
        stream.Flush(flushToDisk: true);
    }

    private sealed record StateSnapshotManifest(
        int FormatVersion,
        string Id,
        DateTime CreatedUtc,
        string AppVersion,
        int DatabaseSchemaVersion,
        IReadOnlyList<StateSnapshotFile> Files);

    private sealed record StateSnapshotFile(
        string Component,
        string RelativePath,
        long SizeBytes,
        string Sha256);

    private sealed record PendingStartupRestore(
        string SnapshotId,
        string ExpectedSha256,
        string PreRestoreSnapshotId,
        string Phase);
}
