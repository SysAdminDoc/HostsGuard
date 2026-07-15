using System.Globalization;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace HostsGuard.App.Services;

public interface IReleaseUpdateChecker
{
    Task<ReleaseUpdateResult> CheckAsync(string installedVersion, CancellationToken cancellationToken = default);
}

public enum ReleaseUpdateState
{
    UpdateAvailable,
    UpToDate,
    InstalledNewer,
    Unavailable,
}

public sealed record ReleaseAssetInfo(string Name, long Size, string? Digest, string? DownloadUrl);

public sealed record ReleaseUpdateResult(
    ReleaseUpdateState State,
    string InstalledVersion,
    string? LatestVersion,
    DateTimeOffset? PublishedAt,
    IReadOnlyList<ReleaseAssetInfo> Assets,
    string Message);

public sealed class ReleaseUpdateChecker : IReleaseUpdateChecker
{
    private static readonly Uri DefaultEndpoint =
        new("https://api.github.com/repos/SysAdminDoc/HostsGuard/releases/latest");

    private static readonly HttpClient DefaultClient = new();

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private readonly HttpClient _http;
    private readonly TimeSpan _timeout;
    private readonly Uri _endpoint;

    public ReleaseUpdateChecker(HttpClient http, TimeSpan? timeout = null, Uri? endpoint = null)
    {
        _http = http ?? throw new ArgumentNullException(nameof(http));
        _timeout = timeout ?? TimeSpan.FromSeconds(5);
        _endpoint = endpoint ?? DefaultEndpoint;
    }

    public static IReleaseUpdateChecker CreateDefault() => new ReleaseUpdateChecker(DefaultClient);

    public async Task<ReleaseUpdateResult> CheckAsync(
        string installedVersion, CancellationToken cancellationToken = default)
    {
        var installed = string.IsNullOrWhiteSpace(installedVersion)
            ? I18n.T("Release_UnknownVersion", "unknown")
            : installedVersion.Trim();
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(_timeout);
            using var request = new HttpRequestMessage(HttpMethod.Get, _endpoint);
            request.Headers.UserAgent.Add(new ProductInfoHeaderValue("HostsGuard", UserAgentVersion(installed)));
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));

            using var response = await _http.SendAsync(
                request, HttpCompletionOption.ResponseHeadersRead, timeout.Token).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                return Unavailable(installed, I18n.T(
                    "Release_HttpStatus",
                    "GitHub returned {0}",
                    DescribeStatus(response.StatusCode, response.ReasonPhrase)));
            }

            await using var body = await response.Content.ReadAsStreamAsync(timeout.Token).ConfigureAwait(false);
            var release = await JsonSerializer.DeserializeAsync<GitHubReleaseDto>(
                body, JsonOptions, timeout.Token).ConfigureAwait(false);
            if (release is null || string.IsNullOrWhiteSpace(release.TagName))
            {
                return Unavailable(installed, I18n.T(
                    "Release_MissingTag",
                    "GitHub latest release response did not include a tag"));
            }

            var latest = release.TagName.Trim();
            var assets = (release.Assets ?? [])
                .Where(a => !string.IsNullOrWhiteSpace(a.Name))
                .Select(a => new ReleaseAssetInfo(
                    a.Name!.Trim(),
                    Math.Max(0, a.Size),
                    string.IsNullOrWhiteSpace(a.Digest) ? null : a.Digest.Trim(),
                    string.IsNullOrWhiteSpace(a.BrowserDownloadUrl) ? null : a.BrowserDownloadUrl.Trim()))
                .ToArray();

            var state = CompareVersions(installed, latest) switch
            {
                < 0 => ReleaseUpdateState.UpdateAvailable,
                0 => ReleaseUpdateState.UpToDate,
                _ => ReleaseUpdateState.InstalledNewer,
            };
            return new ReleaseUpdateResult(
                state,
                installed,
                latest,
                release.PublishedAt,
                assets,
                BuildMessage(state, installed, latest, release.PublishedAt, assets));
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return Unavailable(installed, I18n.T(
                "Release_Timeout",
                "GitHub request timed out after {0:0} seconds",
                _timeout.TotalSeconds));
        }
        catch (HttpRequestException ex)
        {
            return Unavailable(installed, I18n.T("Release_RequestFailed", "GitHub request failed: {0}", ex.Message));
        }
        catch (JsonException ex)
        {
            return Unavailable(installed, I18n.T("Release_ParseFailed", "GitHub response could not be parsed: {0}", ex.Message));
        }
    }

    private static ReleaseUpdateResult Unavailable(string installedVersion, string message) =>
        new(ReleaseUpdateState.Unavailable, installedVersion, null, null, [],
            I18n.T("Release_CheckFailed", "Update check failed: {0}", message));

    private static string BuildMessage(
        ReleaseUpdateState state,
        string installed,
        string latest,
        DateTimeOffset? publishedAt,
        IReadOnlyList<ReleaseAssetInfo> assets)
    {
        var date = publishedAt?.ToString("d", CultureInfo.CurrentCulture)
            ?? I18n.T("Release_DateUnavailable", "date unavailable");
        var asset = DescribeAsset(assets);
        return state switch
        {
            ReleaseUpdateState.UpdateAvailable =>
                I18n.T("Release_UpdateAvailable",
                    "Update available: {0} (published {1}). {2}. No auto-install performed.",
                    latest, date, asset),
            ReleaseUpdateState.UpToDate =>
                I18n.T("Release_UpToDate",
                    "HostsGuard is up to date: {0} (latest {1}, published {2}). {3}.",
                    installed, latest, date, asset),
            ReleaseUpdateState.InstalledNewer =>
                I18n.T("Release_InstalledNewer",
                    "Installed {0} is newer than latest GitHub release {1} (published {2}). {3}.",
                    installed, latest, date, asset),
            _ => I18n.T("Release_LatestUnavailable",
                "Update check failed: latest release unavailable. {0}.", asset),
        };
    }

    private static string DescribeAsset(IReadOnlyList<ReleaseAssetInfo> assets)
    {
        if (assets.Count == 0)
        {
            return I18n.T("Release_NoAssets", "No release assets listed");
        }

        var asset = assets.FirstOrDefault(a => a.Name.Contains("Setup", StringComparison.OrdinalIgnoreCase))
            ?? assets[0];
        var digest = asset.Digest ?? I18n.T("Release_HashUnavailable", "hash unavailable");
        var total = assets.Count == 1
            ? I18n.T("Release_AssetCountOne", "1 asset")
            : I18n.T("Release_AssetCountMany", "{0} assets", assets.Count);
        return I18n.T("Release_AssetSummary", "{0} ({1}, {2}; {3} listed)",
            asset.Name, FormatSize(asset.Size), digest, total);
    }

    private static string FormatSize(long bytes)
    {
        if (bytes < 1024)
        {
            return I18n.T("Release_SizeBytes", "{0} B", bytes);
        }

        var kb = bytes / 1024.0;
        if (kb < 1024)
        {
            return I18n.T("Release_SizeKilobytes", "{0:0.#} KB", kb);
        }

        var mb = kb / 1024.0;
        return I18n.T("Release_SizeMegabytes", "{0:0.#} MB", mb);
    }

    private static int CompareVersions(string installed, string latest)
    {
        var installedOk = TryParseSemVer(installed, out var installedVersion);
        var latestOk = TryParseSemVer(latest, out var latestVersion);
        if (installedOk && latestOk)
        {
            return installedVersion.CompareTo(latestVersion);
        }

        return string.Compare(installed, latest, StringComparison.OrdinalIgnoreCase);
    }

    private static bool TryParseSemVer(string value, out Version version)
    {
        var core = value.Trim();
        if (core.StartsWith('v') || core.StartsWith('V'))
        {
            core = core[1..];
        }

        var metadata = core.IndexOfAny(['-', '+']);
        if (metadata >= 0)
        {
            core = core[..metadata];
        }

        var parts = core.Split('.', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (parts.Length is < 2 or > 4)
        {
            version = new Version(0, 0, 0, 0);
            return false;
        }

        var values = new int[4];
        for (var i = 0; i < values.Length; i++)
        {
            if (i >= parts.Length)
            {
                values[i] = 0;
                continue;
            }

            if (!int.TryParse(parts[i], NumberStyles.None, CultureInfo.InvariantCulture, out var parsed))
            {
                version = new Version(0, 0, 0, 0);
                return false;
            }

            values[i] = parsed;
        }

        version = new Version(values[0], values[1], values[2], values[3]);
        return true;
    }

    private static string UserAgentVersion(string installed) =>
        TryParseSemVer(installed, out var version)
            ? version.ToString(3)
            : "0";

    private static string DescribeStatus(HttpStatusCode status, string? reason)
    {
        var label = string.IsNullOrWhiteSpace(reason) ? status.ToString() : reason.Trim();
        return string.Concat(((int)status).ToString(CultureInfo.InvariantCulture), " ", label);
    }

    private sealed class GitHubReleaseDto
    {
        [JsonPropertyName("tag_name")]
        public string? TagName { get; init; }

        [JsonPropertyName("published_at")]
        public DateTimeOffset? PublishedAt { get; init; }

        [JsonPropertyName("assets")]
        public List<GitHubAssetDto>? Assets { get; init; }
    }

    private sealed class GitHubAssetDto
    {
        [JsonPropertyName("name")]
        public string? Name { get; init; }

        [JsonPropertyName("size")]
        public long Size { get; init; }

        [JsonPropertyName("digest")]
        public string? Digest { get; init; }

        [JsonPropertyName("browser_download_url")]
        public string? BrowserDownloadUrl { get; init; }
    }
}
