using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using HostsGuard.Data;

namespace HostsGuard.Service;

/// <summary>A staged, hash-verified installer waiting for the next service restart.</summary>
public sealed record PendingUpdate(string Version, string Sha256, string InstallerPath, string StagedAt);

/// <summary>One self-update check/stage outcome.</summary>
public sealed record UpdateOutcome(bool Ok, string Message, string LatestVersion = "", bool UpdateAvailable = false);

/// <summary>
/// SHA-256-verified service self-update (NET-187) — deliberately unsigned per
/// project policy. "Check" reads the GitHub latest-release feed; "stage"
/// downloads the matching installer asset, verifies it against the SHA-256 the
/// release feed pins for that asset (reject on mismatch, fail closed when the
/// feed carries no digest), and parks it under <c>%ProgramData%\HostsGuard\updates</c>.
/// The staged installer is applied on the next service start: the manifest is
/// moved to a durable launched record before process creation (a crashing
/// installer can never loop), then the installer performs a health-checked,
/// rollback-capable stop/replace/restart transaction.
/// </summary>
public sealed class SelfUpdater
{
    public const string DefaultFeedUrl = "https://api.github.com/repos/SysAdminDoc/HostsGuard/releases/latest";

    /// <summary>Installer download ceiling; the win-x64 setup is ~80 MB today.</summary>
    internal const int MaxInstallerBytes = 300_000_000;

    // AllowDuplicateProperties=false hardens parsing of the (remote, untrusted)
    // release feed and the on-disk manifest against duplicate-key smuggling.
    // Unmapped members stay allowed — the GitHub release feed carries many fields
    // we don't map, so rejecting them would break the updater entirely.
    private static readonly JsonSerializerOptions JsonOptions =
        new(JsonSerializerDefaults.Web) { WriteIndented = true, AllowDuplicateProperties = false };

    private readonly HostsDatabase _db;
    private readonly string _updatesDir;
    private readonly IListFetcher _fetcher;
    private readonly string _installedVersion;
    private readonly string _feedUrl;
    private readonly string _assetArch;
    private readonly object _gate = new();

    private string _lastCheck = string.Empty;
    private string _lastError = string.Empty;
    private string _latestVersion = string.Empty;

    public SelfUpdater(
        HostsDatabase db,
        string dataDir,
        IListFetcher fetcher,
        string installedVersion,
        string feedUrl = DefaultFeedUrl,
        string? assetArch = null)
    {
        _db = db ?? throw new ArgumentNullException(nameof(db));
        _updatesDir = Path.Combine(dataDir ?? throw new ArgumentNullException(nameof(dataDir)), "updates");
        _fetcher = fetcher ?? throw new ArgumentNullException(nameof(fetcher));
        _installedVersion = (installedVersion ?? string.Empty).Trim();
        _feedUrl = feedUrl;
        _assetArch = assetArch ?? (System.Runtime.InteropServices.RuntimeInformation.OSArchitecture
            == System.Runtime.InteropServices.Architecture.Arm64 ? "arm64" : "x64");
    }

    public string InstalledVersion => _installedVersion;

    public string LastCheck { get { lock (_gate) { return _lastCheck; } } }

    public string LastError { get { lock (_gate) { return _lastError; } } }

    public string LatestVersion { get { lock (_gate) { return _latestVersion; } } }

    public PendingUpdate? Staged => ReadManifest(ManifestPath(_updatesDir));

    /// <summary>Read-only feed check: what is the latest release, and is it newer?</summary>
    public async Task<UpdateOutcome> CheckAsync(CancellationToken ct)
    {
        try
        {
            var (version, _) = await FetchFeedAsync(ct);
            var available = CompareVersions(_installedVersion, version) < 0;
            lock (_gate)
            {
                _lastCheck = DateTime.Now.ToString("o", System.Globalization.CultureInfo.InvariantCulture);
                _lastError = string.Empty;
                _latestVersion = version;
            }

            return new UpdateOutcome(true,
                available
                    ? $"update available: {version} (installed {_installedVersion})"
                    : $"up to date: installed {_installedVersion}, latest {version}",
                version, available);
        }
        catch (Exception ex) when (ex is System.Net.Http.HttpRequestException or InvalidOperationException or TaskCanceledException or IOException or JsonException)
        {
            lock (_gate)
            {
                _lastCheck = DateTime.Now.ToString("o", System.Globalization.CultureInfo.InvariantCulture);
                _lastError = ex.Message;
            }

            return new UpdateOutcome(false, $"update check failed: {ex.Message}");
        }
    }

    /// <summary>
    /// Download the latest installer, verify the feed-pinned SHA-256, and stage
    /// it for the next restart. Rejects on hash mismatch or a digest-less feed.
    /// </summary>
    public async Task<UpdateOutcome> StageAsync(CancellationToken ct)
    {
        try
        {
            var (version, assets) = await FetchFeedAsync(ct);
            if (CompareVersions(_installedVersion, version) >= 0)
            {
                return new UpdateOutcome(true, $"already up to date ({_installedVersion}); nothing staged", version);
            }

            var asset = SelectInstallerAsset(version, assets);
            if (asset.Url.Length == 0)
            {
                throw new InvalidOperationException($"asset {asset.Name} has no download URL");
            }

            var pinned = NormalizeSha256(asset.Digest)
                ?? throw new InvalidOperationException(
                    $"the release feed pins no sha256 digest for {asset.Name} — refusing to stage an unverifiable installer");

            var bytes = await _fetcher.FetchBytesAsync(asset.Url, MaxInstallerBytes, ct);
            var actual = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
            if (!string.Equals(actual, pinned, StringComparison.OrdinalIgnoreCase))
            {
                _db.LogEvent("self_update", "update_hash_mismatch",
                    details: $"{asset.Name}: feed pinned {pinned}, downloaded {actual}", reason: "self_update");
                return new UpdateOutcome(false,
                    $"REJECTED: downloaded {asset.Name} hashes {actual} but the release feed pins {pinned}");
            }

            Directory.CreateDirectory(_updatesDir);
            var installerPath = Path.Combine(_updatesDir, Path.GetFileName(asset.Name));
            File.WriteAllBytes(installerPath, bytes);
            WriteManifest(new PendingUpdate(version, actual, installerPath,
                DateTime.Now.ToString("o", System.Globalization.CultureInfo.InvariantCulture)));
            _db.LogEvent("self_update", "update_staged",
                details: $"{asset.Name} ({bytes.Length:N0} bytes, sha256 {actual}) — applies on next service restart",
                reason: "self_update");
            return new UpdateOutcome(true,
                $"staged {version} ({bytes.Length:N0} bytes, sha256 verified) — applies on the next service restart",
                version, true);
        }
        catch (Exception ex) when (ex is System.Net.Http.HttpRequestException or InvalidOperationException or TaskCanceledException or IOException or JsonException)
        {
            return new UpdateOutcome(false, $"stage failed: {ex.Message}");
        }
    }

    /// <summary>
    /// Stage a caller-supplied local copy of the release installer. The GitHub
    /// release feed remains the authority: name, architecture, newer version,
    /// and SHA-256 must all match its selected asset. <paramref name="expectedSha256"/>
    /// is only an optional additional assertion; it never authorizes content.
    /// </summary>
    public async Task<UpdateOutcome> StageLocalAsync(
        string localPath,
        string? expectedSha256 = null,
        CancellationToken ct = default)
    {
        string? temporaryPath = null;
        try
        {
            var (version, assets) = await FetchFeedAsync(ct);
            if (CompareVersions(_installedVersion, version) >= 0)
            {
                return new UpdateOutcome(false,
                    $"refusing local installer for {version}: installed {_installedVersion} is not older");
            }

            var asset = SelectInstallerAsset(version, assets);
            var pinned = NormalizeSha256(asset.Digest)
                ?? throw new InvalidOperationException(
                    $"the release feed pins no sha256 digest for {asset.Name} — refusing to stage an unverifiable installer");

            var supplied = (expectedSha256 ?? string.Empty).Trim();
            if (supplied.Length != 0)
            {
                var normalizedSupplied = NormalizeSha256(supplied);
                if (normalizedSupplied is null)
                {
                    return new UpdateOutcome(false, "REJECTED: --sha256 must be a 64-digit SHA-256 value");
                }

                if (!string.Equals(normalizedSupplied, pinned, StringComparison.OrdinalIgnoreCase))
                {
                    return new UpdateOutcome(false,
                        $"REJECTED: caller hash {normalizedSupplied} does not match release metadata {pinned}");
                }
            }

            if (!string.Equals(Path.GetFileName(localPath), asset.Name, StringComparison.OrdinalIgnoreCase))
            {
                return new UpdateOutcome(false,
                    $"REJECTED: local file must be named {asset.Name} for release {version}");
            }

            if (!File.Exists(localPath))
            {
                return new UpdateOutcome(false, $"installer not found: {localPath}");
            }

            var length = new FileInfo(localPath).Length;
            if (length > MaxInstallerBytes)
            {
                return new UpdateOutcome(false,
                    $"REJECTED: local installer is {length:N0} bytes; limit is {MaxInstallerBytes:N0}");
            }

            Directory.CreateDirectory(_updatesDir);
            temporaryPath = Path.Combine(_updatesDir, $".{Guid.NewGuid():N}.tmp");
            var actual = await CopyAndHashBoundedAsync(localPath, temporaryPath, ct);
            if (!string.Equals(actual, pinned, StringComparison.OrdinalIgnoreCase))
            {
                _db.LogEvent("self_update", "update_hash_mismatch",
                    details: $"local {asset.Name}: release pinned {pinned}, selected file {actual}", reason: "self_update");
                return new UpdateOutcome(false,
                    $"REJECTED: {asset.Name} hashes {actual} but release metadata pins {pinned}");
            }

            var installerPath = Path.Combine(_updatesDir, asset.Name);
            File.Move(temporaryPath, installerPath, overwrite: true);
            temporaryPath = null;
            WriteManifest(new PendingUpdate(version, actual, installerPath,
                DateTime.Now.ToString("o", System.Globalization.CultureInfo.InvariantCulture)));
            _db.LogEvent("self_update", "update_staged",
                details: $"local copy of {asset.Name} ({length:N0} bytes, feed-verified sha256 {actual}) — applies on next service restart",
                reason: "self_update");
            return new UpdateOutcome(true,
                $"staged local copy of {version} (feed-verified sha256 {actual}) — applies on the next service restart",
                version, true);
        }
        catch (Exception ex) when (ex is System.Net.Http.HttpRequestException or InvalidOperationException or
            OperationCanceledException or IOException or JsonException or UnauthorizedAccessException)
        {
            return new UpdateOutcome(false, $"stage failed: {ex.Message}");
        }
        finally
        {
            if (temporaryPath is not null)
            {
                TryDelete(temporaryPath);
            }
        }
    }

    /// <summary>
    /// Startup hook: if a staged installer is pending and still newer than the
    /// running build, consume the manifest before launch (crash-safe: never loops) and
    /// launch the installer detached; it performs stop/replace/restart. Returns
    /// what happened for logging/tests. The launcher is injectable for tests.
    /// </summary>
    public static string ApplyPendingOnStart(
        string dataDir,
        string installedVersion,
        HostsDatabase db,
        Func<string, bool>? launcher = null)
    {
        var updatesDir = Path.Combine(dataDir, "updates");
        var manifestPath = ManifestPath(updatesDir);
        var pending = ReadManifest(manifestPath);
        if (pending is null)
        {
            return "no pending update";
        }

        if (pending.Version != "(local)" && CompareVersions(installedVersion, pending.Version) >= 0)
        {
            TryDelete(manifestPath);
            TryDelete(pending.InstallerPath);
            db.LogEvent("self_update", "update_already_applied",
                details: $"staged {pending.Version} <= installed {installedVersion}; cleaned up", reason: "self_update");
            return $"staged {pending.Version} already applied";
        }

        if (!File.Exists(pending.InstallerPath))
        {
            TryDelete(manifestPath);
            return "staged installer is missing; nothing to apply";
        }

        // Re-verify the staged bytes against the manifest hash — a tampered or
        // torn file in ProgramData must never be executed by the service.
        var actual = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(pending.InstallerPath))).ToLowerInvariant();
        if (!string.Equals(actual, pending.Sha256, StringComparison.OrdinalIgnoreCase))
        {
            TryDelete(manifestPath);
            TryDelete(pending.InstallerPath);
            db.LogEvent("self_update", "update_hash_mismatch",
                details: $"staged installer no longer matches its manifest hash ({actual} != {pending.Sha256}); deleted",
                reason: "self_update");
            return "staged installer failed re-verification and was deleted";
        }

        // Preserve exactly what was launched for post-install diagnostics, but
        // remove it from the pending path before process creation so a failed
        // installer can never be re-executed by a service restart.
        try
        {
            File.Move(manifestPath, UpdateRecoveryCoordinator.LaunchedPath(dataDir), overwrite: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return $"pending update manifest could not be consumed: {ex.Message}";
        }

        var launched = (launcher ?? LaunchInstaller)(pending.InstallerPath);
        db.LogEvent("self_update", launched ? "update_applying" : "update_launch_failed",
            details: $"{Path.GetFileName(pending.InstallerPath)} ({pending.Version})", reason: "self_update");
        return launched ? $"applying staged update {pending.Version}" : "staged installer failed to launch";
    }

    private static bool LaunchInstaller(string path)
    {
        try
        {
            using var process = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(path)
            {
                Arguments = "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART",
                UseShellExecute = false,
            });
            return process is not null;
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            return false;
        }
    }

    private async Task<(string Version, IReadOnlyList<FeedAsset> Assets)> FetchFeedAsync(CancellationToken ct)
    {
        var json = await _fetcher.FetchAsync(_feedUrl, 2_000_000, ct);
        var release = JsonSerializer.Deserialize<ReleaseDto>(json, JsonOptions)
            ?? throw new InvalidOperationException("release feed returned no document");
        var version = (release.TagName ?? string.Empty).Trim();
        if (version.Length == 0)
        {
            throw new InvalidOperationException("release feed did not include a tag");
        }

        var assets = (release.Assets ?? new())
            .Where(a => !string.IsNullOrWhiteSpace(a.Name))
            .Select(a => new FeedAsset(a.Name!.Trim(), (a.Digest ?? string.Empty).Trim(), (a.BrowserDownloadUrl ?? string.Empty).Trim()))
            .ToList();
        return (version, assets);
    }

    private FeedAsset SelectInstallerAsset(string version, IReadOnlyList<FeedAsset> assets)
    {
        var wanted = $"win-{_assetArch}-dotnet-Setup.exe";
        var asset = assets.FirstOrDefault(a => a.Name.EndsWith(wanted, StringComparison.OrdinalIgnoreCase))
            ?? throw new InvalidOperationException($"release {version} has no *{wanted} asset");

        // The selected feed name becomes a LocalSystem-executed path. The digest
        // constrains content, not location, so accept a plain file name only.
        if (!IsSafeAssetName(asset.Name))
        {
            throw new InvalidOperationException($"refusing asset with an unsafe name: {asset.Name}");
        }

        return asset;
    }

    private static async Task<string> CopyAndHashBoundedAsync(
        string sourcePath,
        string destinationPath,
        CancellationToken ct)
    {
        const int BufferBytes = 128 * 1024;
        var buffer = new byte[BufferBytes];
        long total = 0;
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        await using (var source = new FileStream(
            sourcePath, FileMode.Open, FileAccess.Read, FileShare.Read, BufferBytes,
            FileOptions.Asynchronous | FileOptions.SequentialScan))
        await using (var destination = new FileStream(
            destinationPath, FileMode.CreateNew, FileAccess.Write, FileShare.None, BufferBytes,
            FileOptions.Asynchronous | FileOptions.SequentialScan))
        {
            while (true)
            {
                var read = await source.ReadAsync(buffer.AsMemory(0, buffer.Length), ct);
                if (read == 0)
                {
                    break;
                }

                total += read;
                if (total > MaxInstallerBytes)
                {
                    throw new InvalidOperationException(
                        $"local installer exceeds the {MaxInstallerBytes:N0}-byte limit");
                }

                hash.AppendData(buffer, 0, read);
                await destination.WriteAsync(buffer.AsMemory(0, read), ct);
            }

            await destination.FlushAsync(ct);
        }

        return Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
    }

    /// <summary>Accepts "sha256:HEX" (GitHub digest form) or bare hex; null when absent/invalid.</summary>
    public static string? NormalizeSha256(string? digest)
    {
        var value = (digest ?? string.Empty).Trim();
        if (value.StartsWith("sha256:", StringComparison.OrdinalIgnoreCase))
        {
            value = value["sha256:".Length..];
        }

        return value.Length == 64 && value.All(Uri.IsHexDigit) ? value.ToLowerInvariant() : null;
    }

    internal static int CompareVersions(string installed, string latest)
    {
        static Version? Parse(string value)
        {
            var core = value.Trim().TrimStart('v', 'V');
            var meta = core.IndexOfAny(['-', '+']);
            if (meta >= 0)
            {
                core = core[..meta];
            }

            return Version.TryParse(core.Count(c => c == '.') == 0 ? core + ".0" : core, out var parsed)
                ? parsed
                : null;
        }

        // Fail closed: if either the installed or the candidate version is
        // unparseable, never treat the candidate as newer (return "not older").
        // A garbled build stamp or a malformed feed tag must not auto-stage.
        var pi = Parse(installed);
        var pl = Parse(latest);
        return pi is null || pl is null ? 1 : pi.CompareTo(pl);
    }

    /// <summary>
    /// True when a feed asset name is a plain file name — no path separators,
    /// drive/stream markers, or ".." traversal — so it can't escape the updates
    /// directory when combined into a path the service later executes.
    /// </summary>
    public static bool IsSafeAssetName(string name) =>
        !string.IsNullOrEmpty(name)
        && string.Equals(name, Path.GetFileName(name), StringComparison.Ordinal)
        && !name.Contains("..", StringComparison.Ordinal);

    private static string ManifestPath(string updatesDir) => Path.Combine(updatesDir, "update_pending.json");

    private void WriteManifest(PendingUpdate pending) =>
        File.WriteAllText(ManifestPath(_updatesDir), JsonSerializer.Serialize(pending, JsonOptions));

    private static PendingUpdate? ReadManifest(string path)
    {
        try
        {
            return File.Exists(path)
                ? JsonSerializer.Deserialize<PendingUpdate>(File.ReadAllText(path), JsonOptions)
                : null;
        }
        catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    private static void TryDelete(string path)
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

    private sealed record FeedAsset(string Name, string Digest, string Url);

    private sealed class ReleaseDto
    {
        [JsonPropertyName("tag_name")]
        public string? TagName { get; init; }

        [JsonPropertyName("assets")]
        public List<AssetDto>? Assets { get; init; }
    }

    private sealed class AssetDto
    {
        [JsonPropertyName("name")]
        public string? Name { get; init; }

        [JsonPropertyName("digest")]
        public string? Digest { get; init; }

        [JsonPropertyName("browser_download_url")]
        public string? BrowserDownloadUrl { get; init; }
    }
}
