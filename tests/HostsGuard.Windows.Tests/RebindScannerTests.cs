using System.Runtime.Versioning;
using FluentAssertions;
using HostsGuard.Windows;
using Xunit;

namespace HostsGuard.Windows.Tests;

/// <summary>
/// NET-022b rebind scoring/scanning: identity history carries the confidence,
/// name-only matches never clear the suggestion threshold, and the candidate
/// walk is depth-limited with the old binary excluded.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class RebindScannerTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("hg_rebind_").FullName;

    public void Dispose()
    {
        try { Directory.Delete(_dir, true); } catch (IOException) { /* best effort */ }
    }

    private string WriteExe(string relative, string content)
    {
        var path = Path.Combine(_dir, relative);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, content);
        return path;
    }

    [Fact]
    public void Scan_finds_same_named_binary_in_sibling_tree_and_skips_the_original()
    {
        var old = WriteExe(@"vendor\v1\app.exe", "one");
        var moved = WriteExe(@"vendor\v2\app.exe", "one");
        WriteExe(@"vendor\v2\other.exe", "x");

        var found = RebindScanner.ScanCandidates(old, roots: new[] { _dir });

        found.Should().Contain(moved);
        found.Should().NotContain(old);
        found.Should().NotContain(f => f.EndsWith("other.exe"));
    }

    [Fact]
    public void Scan_respects_the_depth_limit()
    {
        var old = WriteExe(@"a\app.exe", "one");
        var tooDeep = WriteExe(@"a\b\c\d\e\app.exe", "one");

        var found = RebindScanner.ScanCandidates(old, maxDepth: 3, roots: new[] { _dir });

        found.Should().NotContain(tooDeep);
    }

    [Fact]
    public void Hash_match_from_identity_history_ranks_first_and_clears_the_threshold()
    {
        var old = Path.Combine(_dir, "gone", "tool.exe"); // never exists — orphaned
        var sameHash = WriteExe(@"apps\tool.exe", "payload-v1");
        var otherHash = WriteExe(@"misc\tool.exe", "payload-v2");
        var history = new[] { FirewallIdentity.Compute(sameHash) };

        var ranked = RebindScanner.Rank(old, history, new[] { otherHash, sameHash });

        ranked.Should().NotBeEmpty();
        ranked[0].Path.Should().Be(sameHash);
        ranked[0].Score.Should().BeGreaterThanOrEqualTo(90);
        ranked[0].Reasons.Should().Contain("same SHA-256");
        ranked.Select(r => r.Path).Should().NotContain(otherHash); // name-only = below threshold
    }

    [Fact]
    public void Versioned_path_move_clears_the_threshold_even_when_unsigned()
    {
        // Same app, new version directory, different content (an update). Neither
        // hash nor signer matches, but same-name (30) + same-versioned-path (30)
        // clears the 60-point threshold so the update is recognized.
        var old = WriteExe(@"app\1.2.3\tool.exe", "v1");
        var updated = WriteExe(@"app\1.3.0\tool.exe", "v2-different");
        // History is the old binary; the candidate is the moved+updated one.
        var history = new[] { FirewallIdentity.Compute(old) };

        var ranked = RebindScanner.Rank(old, history, new[] { updated });

        ranked.Should().ContainSingle();
        ranked[0].Path.Should().Be(updated);
        ranked[0].Reasons.Should().Contain("same versioned app path");
    }

    [Fact]
    public void Name_only_match_without_history_is_never_suggested()
    {
        var old = Path.Combine(_dir, "gone", "tool.exe");
        var impostor = WriteExe(@"elsewhere\tool.exe", "unrelated");

        var ranked = RebindScanner.Rank(old, Array.Empty<FileIdentity>(), new[] { impostor });

        ranked.Should().BeEmpty();
    }

    [Fact]
    public void Older_history_hash_scores_as_known_previous_version()
    {
        var old = Path.Combine(_dir, "gone", "tool.exe");
        var v1 = WriteExe(@"h\v1\tool.exe", "v1");
        var v2 = WriteExe(@"h\v2\tool.exe", "v2");
        // History: v1 (older), then v2 (latest). A binary matching v1 is a
        // "known previous SHA-256" (70), not the latest identity (90).
        var history = new[] { FirewallIdentity.Compute(v1), FirewallIdentity.Compute(v2) };
        var candidate = WriteExe(@"candidates\tool.exe", "v1");

        var ranked = RebindScanner.Rank(old, history, new[] { candidate });

        ranked.Should().ContainSingle();
        ranked[0].Reasons.Should().Contain("known previous SHA-256");
    }
}
