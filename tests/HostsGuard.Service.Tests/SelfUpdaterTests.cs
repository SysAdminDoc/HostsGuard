using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using FluentAssertions;
using HostsGuard.Data;
using Microsoft.Data.Sqlite;
using Xunit;

namespace HostsGuard.Service.Tests;

/// <summary>
/// NET-187: SHA-256-verified service self-update. Staging verifies the
/// downloaded installer against the digest the release feed pins (reject on
/// mismatch, fail closed on a digest-less feed); apply-on-start moves the
/// manifest to a launched-attempt record before process creation so a crashing
/// installer can never loop.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class SelfUpdaterTests : IDisposable
{
    private const string FeedUrl = "https://api.github.com/repos/SysAdminDoc/HostsGuard/releases/latest";
    private const string AssetName = "HostsGuard-v9.9.9-win-x64-dotnet-Setup.exe";
    private const string AssetUrl = "https://github.com/SysAdminDoc/HostsGuard/releases/download/v9.9.9/HostsGuard-v9.9.9-win-x64-dotnet-Setup.exe";

    private static readonly byte[] Installer = Encoding.UTF8.GetBytes("fake installer payload");
    private static readonly string InstallerHash = Convert.ToHexString(SHA256.HashData(Installer)).ToLowerInvariant();

    private readonly string _dir;
    private readonly HostsDatabase _db;
    private readonly FakeListFetcher _fetcher = new();
    private readonly SelfUpdater _updater;

    public SelfUpdaterTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "hg_update_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        _db = new HostsDatabase(Path.Combine(_dir, "hostsguard.db"));
        _updater = new SelfUpdater(_db, _dir, _fetcher, "1.0.0", FeedUrl, assetArch: "x64");
    }

    private void ServeFeed(string version, string? digest)
    {
        _fetcher.Responses[FeedUrl] = $$"""
            {
              "tag_name": "{{version}}",
              "assets": [
                {
                  "name": "HostsGuard-{{version}}-win-x64-dotnet-Setup.exe",
                  "digest": {{(digest is null ? "null" : $"\"sha256:{digest}\"")}},
                  "browser_download_url": "{{AssetUrl}}"
                }
              ]
            }
            """;
        _fetcher.BinaryResponses[AssetUrl] = Installer;
    }

    private string WriteLocalInstaller(byte[]? bytes = null, string fileName = AssetName)
    {
        var local = Path.Combine(_dir, fileName);
        File.WriteAllBytes(local, bytes ?? Installer);
        return local;
    }

    [Fact]
    public async Task Check_reports_a_newer_release()
    {
        ServeFeed("v9.9.9", InstallerHash);

        var outcome = await _updater.CheckAsync(CancellationToken.None);

        outcome.Ok.Should().BeTrue();
        outcome.UpdateAvailable.Should().BeTrue();
        outcome.LatestVersion.Should().Be("v9.9.9");
    }

    [Fact]
    public async Task Stage_verifies_the_pinned_hash_and_parks_the_installer()
    {
        ServeFeed("v9.9.9", InstallerHash);

        var outcome = await _updater.StageAsync(CancellationToken.None);

        outcome.Ok.Should().BeTrue();
        var staged = _updater.Staged;
        staged.Should().NotBeNull();
        staged!.Version.Should().Be("v9.9.9");
        staged.Sha256.Should().Be(InstallerHash);
        File.ReadAllBytes(staged.InstallerPath).Should().Equal(Installer);
    }

    [Fact]
    public async Task Stage_rejects_a_hash_mismatch()
    {
        ServeFeed("v9.9.9", new string('a', 64)); // feed pins a hash the download won't match

        var outcome = await _updater.StageAsync(CancellationToken.None);

        outcome.Ok.Should().BeFalse();
        outcome.Message.Should().Contain("REJECTED");
        _updater.Staged.Should().BeNull("a mismatching installer must never be staged");
        Directory.Exists(Path.Combine(_dir, "updates")).Should().BeFalse();
    }

    [Fact]
    public async Task Stage_fails_closed_when_the_feed_pins_no_digest()
    {
        ServeFeed("v9.9.9", digest: null);

        var outcome = await _updater.StageAsync(CancellationToken.None);

        outcome.Ok.Should().BeFalse();
        outcome.Message.Should().Contain("no sha256 digest");
        _updater.Staged.Should().BeNull();
    }

    [Fact]
    public async Task Stage_declines_when_already_up_to_date()
    {
        ServeFeed("v0.9.0", InstallerHash);

        var outcome = await _updater.StageAsync(CancellationToken.None);

        outcome.Ok.Should().BeTrue();
        outcome.Message.Should().Contain("already up to date");
        _updater.Staged.Should().BeNull();
    }

    [Fact]
    public async Task Stage_refuses_a_path_traversal_asset_name()
    {
        // A feed asset name with directory traversal still satisfies the
        // "*-Setup.exe" suffix gate; it must be refused before any write so it
        // can't escape the updates dir into a LocalSystem-executed location.
        _fetcher.Responses[FeedUrl] = """
            {
              "tag_name": "v9.9.9",
              "assets": [
                {
                  "name": "..\\..\\..\\evil-win-x64-dotnet-Setup.exe",
                  "digest": "sha256:HASH",
                  "browser_download_url": "URL"
                }
              ]
            }
            """.Replace("HASH", InstallerHash, StringComparison.Ordinal)
               .Replace("URL", AssetUrl, StringComparison.Ordinal);
        _fetcher.BinaryResponses[AssetUrl] = Installer;

        var outcome = await _updater.StageAsync(CancellationToken.None);

        outcome.Ok.Should().BeFalse();
        outcome.Message.Should().Contain("unsafe name");
        _updater.Staged.Should().BeNull();
        Directory.Exists(Path.Combine(_dir, "updates")).Should().BeFalse();
    }

    [Fact]
    public async Task Stage_rejects_a_release_feed_with_duplicate_keys()
    {
        // Duplicate-key smuggling is rejected (AllowDuplicateProperties=false); the
        // JsonException is caught and staging fails gracefully.
        _fetcher.Responses[FeedUrl] = """{ "tag_name": "v9.9.9", "tag_name": "v0.0.1", "assets": [] }""";

        var outcome = await _updater.StageAsync(CancellationToken.None);

        outcome.Ok.Should().BeFalse();
        _updater.Staged.Should().BeNull();
    }

    [Fact]
    public async Task Stage_fails_closed_when_the_installed_version_is_unparseable()
    {
        // A garbled build stamp must never make every remote look "newer".
        var updater = new SelfUpdater(_db, _dir, _fetcher, "(garbled build)", FeedUrl, assetArch: "x64");
        ServeFeed("v9.9.9", InstallerHash);

        var outcome = await updater.StageAsync(CancellationToken.None);

        outcome.Ok.Should().BeTrue();
        outcome.Message.Should().Contain("already up to date");
        updater.Staged.Should().BeNull("an unparseable installed version must fail closed, never auto-stage");
    }

    [Theory]
    [InlineData("HostsGuard-v9.9.9-win-x64-dotnet-Setup.exe", true)]
    [InlineData("..\\evil-Setup.exe", false)]
    [InlineData("sub/evil-Setup.exe", false)]
    [InlineData("C:\\Windows\\Temp\\evil-Setup.exe", false)]
    [InlineData("", false)]
    public void IsSafeAssetName_only_accepts_plain_file_names(string name, bool expected)
        => SelfUpdater.IsSafeAssetName(name).Should().Be(expected);

    [Fact]
    public async Task Local_staging_rejects_a_caller_hash_that_differs_from_the_feed()
    {
        ServeFeed("v9.9.9", InstallerHash);
        var local = WriteLocalInstaller();

        var outcome = await _updater.StageLocalAsync(local, new string('b', 64));

        outcome.Ok.Should().BeFalse();
        outcome.Message.Should().Contain("REJECTED");
        outcome.Message.Should().Contain("release metadata");
        _updater.Staged.Should().BeNull();
    }

    [Fact]
    public async Task Local_staging_records_the_feed_version_and_verified_hash()
    {
        ServeFeed("v9.9.9", InstallerHash);
        var local = WriteLocalInstaller();

        var outcome = await _updater.StageLocalAsync(local, InstallerHash);

        outcome.Ok.Should().BeTrue();
        _updater.Staged!.Sha256.Should().Be(InstallerHash);
        _updater.Staged.Version.Should().Be("v9.9.9");
        _updater.Staged.InstallerPath.Should().EndWith(AssetName);
        File.ReadAllBytes(_updater.Staged.InstallerPath).Should().Equal(Installer);
    }

    [Fact]
    public async Task Local_staging_fails_closed_without_release_metadata()
    {
        var local = WriteLocalInstaller();

        var outcome = await _updater.StageLocalAsync(local);

        outcome.Ok.Should().BeFalse();
        outcome.Message.Should().Contain("no fake response");
        _updater.Staged.Should().BeNull();
    }

    [Fact]
    public async Task Local_staging_rejects_a_different_file_name()
    {
        ServeFeed("v9.9.9", InstallerHash);
        var local = WriteLocalInstaller(fileName: "renamed-setup.exe");

        var outcome = await _updater.StageLocalAsync(local);

        outcome.Ok.Should().BeFalse();
        outcome.Message.Should().Contain($"must be named {AssetName}");
        _updater.Staged.Should().BeNull();
    }

    [Fact]
    public async Task Local_staging_rejects_bytes_that_do_not_match_the_feed()
    {
        ServeFeed("v9.9.9", InstallerHash);
        var local = WriteLocalInstaller(Encoding.UTF8.GetBytes("different installer"));

        var outcome = await _updater.StageLocalAsync(local);

        outcome.Ok.Should().BeFalse();
        outcome.Message.Should().Contain("release metadata pins");
        _updater.Staged.Should().BeNull();
        Directory.GetFiles(Path.Combine(_dir, "updates"), "*.tmp").Should().BeEmpty();
    }

    [Fact]
    public async Task Local_staging_rejects_an_oversized_file_before_copying()
    {
        ServeFeed("v9.9.9", InstallerHash);
        var local = Path.Combine(_dir, AssetName);
        using (var stream = new FileStream(local, FileMode.CreateNew, FileAccess.Write, FileShare.None))
        {
            stream.SetLength((long)SelfUpdater.MaxInstallerBytes + 1);
        }

        var outcome = await _updater.StageLocalAsync(local);

        outcome.Ok.Should().BeFalse();
        outcome.Message.Should().Contain("limit is");
        _updater.Staged.Should().BeNull();
    }

    [Fact]
    public async Task Local_staging_rejects_a_stale_release()
    {
        ServeFeed("v0.9.0", InstallerHash);
        var local = WriteLocalInstaller(fileName: "HostsGuard-v0.9.0-win-x64-dotnet-Setup.exe");

        var outcome = await _updater.StageLocalAsync(local);

        outcome.Ok.Should().BeFalse();
        outcome.Message.Should().Contain("is not older");
        _updater.Staged.Should().BeNull();
    }

    [Fact]
    public async Task Apply_on_start_launches_a_feed_verified_local_copy_once()
    {
        ServeFeed("v9.9.9", InstallerHash);
        var local = WriteLocalInstaller();
        (await _updater.StageLocalAsync(local)).Ok.Should().BeTrue();

        var launched = new List<string>();
        var first = SelfUpdater.ApplyPendingOnStart(_dir, "1.0.0", _db, p => { launched.Add(p); return true; });
        var second = SelfUpdater.ApplyPendingOnStart(_dir, "1.0.0", _db, p => { launched.Add(p); return true; });

        first.Should().StartWith("applying");
        launched.Should().ContainSingle("the manifest is consumed before launch, so a second start never re-runs it");
        second.Should().Be("no pending update");
        File.Exists(UpdateRecoveryCoordinator.LaunchedPath(_dir)).Should().BeTrue();
    }

    [Fact]
    public async Task Apply_on_start_does_not_requeue_a_launcher_failure()
    {
        ServeFeed("v9.9.9", InstallerHash);
        (await _updater.StageAsync(CancellationToken.None)).Ok.Should().BeTrue();

        var first = SelfUpdater.ApplyPendingOnStart(_dir, "1.0.0", _db, _ => false);
        var second = SelfUpdater.ApplyPendingOnStart(_dir, "1.0.0", _db, _ => true);

        first.Should().Contain("failed to launch");
        second.Should().Be("no pending update");
        File.Exists(UpdateRecoveryCoordinator.LaunchedPath(_dir)).Should().BeTrue();
    }

    [Fact]
    public async Task Apply_on_start_cleans_up_an_already_applied_version()
    {
        ServeFeed("v9.9.9", InstallerHash);
        (await _updater.StageAsync(CancellationToken.None)).Ok.Should().BeTrue();
        var installerPath = _updater.Staged!.InstallerPath;

        var launched = 0;
        var result = SelfUpdater.ApplyPendingOnStart(_dir, "9.9.9", _db, _ => { launched++; return true; });

        result.Should().Contain("already applied");
        launched.Should().Be(0);
        File.Exists(installerPath).Should().BeFalse();
    }

    [Fact]
    public async Task Apply_on_start_deletes_a_tampered_staged_installer()
    {
        ServeFeed("v9.9.9", InstallerHash);
        (await _updater.StageAsync(CancellationToken.None)).Ok.Should().BeTrue();
        var installerPath = _updater.Staged!.InstallerPath;
        File.WriteAllText(installerPath, "tampered after staging");

        var launched = 0;
        var result = SelfUpdater.ApplyPendingOnStart(_dir, "1.0.0", _db, _ => { launched++; return true; });

        result.Should().Contain("re-verification");
        launched.Should().Be(0);
        File.Exists(installerPath).Should().BeFalse();
    }

    [Theory]
    [InlineData("sha256:ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef0123456789", "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")]
    [InlineData("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789", "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")]
    [InlineData("", null)]
    [InlineData("sha1:abcdef", null)]
    public void Digest_normalization_accepts_github_and_bare_forms(string digest, string? expected)
        => SelfUpdater.NormalizeSha256(digest).Should().Be(expected);

    public void Dispose()
    {
        _db.Dispose();
        try
        {
            Directory.Delete(_dir, recursive: true);
        }
        catch (IOException)
        {
        }
    }
}
