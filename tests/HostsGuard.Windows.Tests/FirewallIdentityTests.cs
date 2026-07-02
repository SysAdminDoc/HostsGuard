using System.Runtime.Versioning;
using FluentAssertions;
using HostsGuard.Core;
using HostsGuard.Windows;
using Xunit;

namespace HostsGuard.Windows.Tests;

[SupportedOSPlatform("windows")]
public sealed class FirewallIdentityTests : IDisposable
{
    private readonly string _dir;

    public FirewallIdentityTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "hg_fwid_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, true); } catch (IOException) { /* best effort */ }
    }

    private string Make(string name, string content)
    {
        var p = Path.Combine(_dir, name);
        Directory.CreateDirectory(Path.GetDirectoryName(p)!);
        File.WriteAllText(p, content);
        return p;
    }

    [Fact]
    public void Compute_hashes_and_signer_is_null_for_unsigned()
    {
        var path = Make("app.exe", "not a real pe, just bytes");
        var id = FirewallIdentity.Compute(path);
        id.Sha256.Should().MatchRegex("^[0-9a-f]{64}$");
        id.Signer.Should().BeNull(); // plain file has no Authenticode signer
    }

    [Fact]
    public void IsOrphaned_flags_moved_program_only_for_hg_rules()
    {
        var missing = new FwRule("HG_Block_x", "Out", "Block", true, "Any", "Any", @"C:\gone\missing.exe", "hostsguard");
        FirewallIdentity.IsOrphaned(missing).Should().BeTrue();

        var present = new FwRule("HG_Block_ps", "Out", "Block", true, "Any", "Any",
            Environment.ProcessPath ?? "C:\\Windows\\System32\\cmd.exe", "hostsguard");
        FirewallIdentity.IsOrphaned(present).Should().BeFalse();

        var systemRule = new FwRule("Sys", "Out", "Block", true, "Any", "Any", @"C:\gone\x.exe", "system");
        FirewallIdentity.IsOrphaned(systemRule).Should().BeFalse();

        var noProgram = new FwRule("HG_IP", "Out", "Block", true, "1.2.3.4", "Any", "", "hostsguard");
        FirewallIdentity.IsOrphaned(noProgram).Should().BeFalse();
    }

    [Fact]
    public void Remember_then_match_by_hash_after_move()
    {
        var cache = new FirewallIdentity(Path.Combine(_dir, "identities.json"));
        var v1 = Make("chrome_v1.exe", "chrome-binary-bytes-v1");
        cache.Remember("HG_Block_chrome", v1);

        // Same app moved to a new versioned path (same bytes) → matches by hash.
        var moved = Make("chrome_v2\\chrome.exe".Replace('\\', Path.DirectorySeparatorChar), "chrome-binary-bytes-v1");
        cache.MatchesRemembered("HG_Block_chrome", moved).Should().BeTrue();

        // A different binary does not match.
        var other = Make("other.exe", "totally-different");
        cache.MatchesRemembered("HG_Block_chrome", other).Should().BeFalse();
    }

    [Fact]
    public void Cache_persists_across_instances()
    {
        var cachePath = Path.Combine(_dir, "persist.json");
        var v1 = Make("app.exe", "bytes");
        new FirewallIdentity(cachePath).Remember("HG_Block_app", v1);

        var reopened = new FirewallIdentity(cachePath);
        reopened.Get("HG_Block_app").Should().ContainSingle();
        reopened.MatchesRemembered("HG_Block_app", v1).Should().BeTrue();
    }
}
