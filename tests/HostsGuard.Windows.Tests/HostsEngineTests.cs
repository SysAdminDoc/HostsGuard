using FluentAssertions;
using HostsGuard.Windows;
using Xunit;

namespace HostsGuard.Windows.Tests;

public sealed class HostsEngineTests : IDisposable
{
    private readonly string _dir;
    private readonly string _hosts;

    public HostsEngineTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "hg_hosts_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        _hosts = Path.Combine(_dir, "hosts");
        File.WriteAllText(_hosts, "# custom header\n127.0.0.1 myserver\n\n");
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, true); } catch (IOException) { /* best effort */ }
    }

    private HostsEngine New() => new(_hosts);

    [Fact]
    public void Block_adds_domain_and_persists()
    {
        var e = New();
        e.Block("ads.example.com").Should().BeTrue();
        e.GetBlocked().Should().Contain("ads.example.com");
        // Re-read from disk via a fresh engine.
        New().GetBlocked().Should().Contain("ads.example.com");
    }

    [Fact]
    public void Blocks_a_unicode_idn_as_punycode_and_unblocks_it()
    {
        // NET-170: a Unicode IDN is stored and matched as its xn-- form.
        var e = New();
        e.Block("münchen.de").Should().BeTrue();
        e.GetBlocked().Should().Contain("xn--mnchen-3ya.de");
        File.ReadAllText(_hosts).Should().Contain("0.0.0.0 xn--mnchen-3ya.de");

        // Unblock accepts the Unicode form and removes the punycode line.
        e.Unblock("münchen.de").Should().BeTrue();
        New().GetBlocked().Should().NotContain("xn--mnchen-3ya.de");
    }

    [Fact]
    public void Managed_redirect_replaces_a_sink_block_and_preserves_foreign_mappings()
    {
        File.WriteAllText(_hosts,
            "192.168.1.5 intranet.example.com\n0.0.0.0 pinned.example.com\n");
        var engine = New();

        engine.PinRedirect("pinned.example.com", "192.168.1.20").Should().BeTrue();
        engine.PinRedirect("pinned.example.com", "192.168.1.20").Should().BeFalse("the exact pin is idempotent");

        var lines = File.ReadAllLines(_hosts);
        lines.Should().Contain("192.168.1.5 intranet.example.com");
        lines.Should().Contain($"192.168.1.20 pinned.example.com {HostsEngine.ManagedRedirectMarker}");
        lines.Should().NotContain("0.0.0.0 pinned.example.com");
        engine.GetBlocked().Should().NotContain("pinned.example.com");

        engine.Block("pinned.example.com").Should().BeTrue();
        File.ReadAllText(_hosts).Should().NotContain(HostsEngine.ManagedRedirectMarker)
            .And.Contain("0.0.0.0 pinned.example.com");

        engine.PinRedirect("pinned.example.com", "192.168.1.20").Should().BeTrue();
        engine.RemoveRedirect("pinned.example.com").Should().BeTrue();
        File.ReadAllText(_hosts).Should().NotContain("pinned.example.com");
    }

    [Fact]
    public void Redirect_reconcile_replaces_only_managed_pin_lines()
    {
        File.WriteAllText(_hosts,
            $"10.0.0.2 old.example.com {HostsEngine.ManagedRedirectMarker}\n10.0.0.9 foreign.example.com\n");
        var engine = New();

        engine.ReconcileRedirects(new[] { ("new.example.com", "10.0.0.3") }).Should().BeGreaterThan(0);

        var text = File.ReadAllText(_hosts);
        text.Should().NotContain("old.example.com");
        text.Should().Contain($"10.0.0.3 new.example.com {HostsEngine.ManagedRedirectMarker}");
        text.Should().Contain("10.0.0.9 foreign.example.com");
    }

    [Fact]
    public void Unblock_removes_a_trailing_dot_fqdn_line()
    {
        // NET-177: a manually-added "0.0.0.0 example.com." line must be removable
        // via Unblock("example.com"); normalization strips the trailing dot.
        File.WriteAllText(_hosts, "# header\n0.0.0.0 example.com.\n");
        var e = New();
        e.Unblock("example.com").Should().BeTrue();
        New().GetBlocked().Should().NotContain("example.com");
        File.ReadAllText(_hosts).Should().NotContain("example.com.");
    }

    [Theory]
    [InlineData(0, false)]
    [InlineData(99_999, false)]
    [InlineData(100_000, true)]
    [InlineData(250_000, true)]
    public void Scale_threshold_predicate_flags_large_lists(int count, bool over) =>
        HostsEngine.IsOverScaleThreshold(count).Should().Be(over);

    [Fact]
    public void Bulk_block_scales_and_crosses_the_warning_threshold()
    {
        // NET-183: exercise the AtomicWrite + reconcile path at scale and confirm
        // the ceiling predicate flips. Kept at threshold size to bound test time;
        // the linear write cost extrapolates to the 200k documented ceiling.
        var e = New();
        var domains = Enumerable.Range(0, HostsEngine.ScaleWarnThreshold)
            .Select(i => $"scale-{i}.example.com");

        e.BlockBulk(domains).Should().Be(HostsEngine.ScaleWarnThreshold);
        HostsEngine.IsOverScaleThreshold(e.GetBlocked().Count).Should().BeTrue();

        // The persisted file re-reads to the same count (no truncation at scale).
        New().GetBlocked().Count.Should().BeGreaterThanOrEqualTo(HostsEngine.ScaleWarnThreshold);
    }

    [Fact]
    public void Block_is_idempotent_and_validates()
    {
        var e = New();
        e.Block("ads.example.com").Should().BeTrue();
        e.Block("ads.example.com").Should().BeFalse(); // already blocked
        e.Block("not a domain").Should().BeFalse();     // invalid
        e.Block("192.168.1.1").Should().BeFalse();       // IP is not a blockable domain
    }

    [Fact]
    public async Task Block_survives_a_transient_hold_on_the_hosts_file()
    {
        // Simulates a scanner holding the hosts file open right after a write:
        // File.Move needs delete access on the target, which a plain read
        // handle (no FileShare.Delete) denies. The engine must retry past it.
        var e = New();
        var hold = new FileStream(_hosts, FileMode.Open, FileAccess.Read, FileShare.Read);
        var release = Task.Run(async () =>
        {
            await Task.Delay(300);
            hold.Dispose();
        });

        e.Block("retry.example.com").Should().BeTrue();

        await release;
        New().GetBlocked().Should().Contain("retry.example.com");
    }

    [Fact]
    public void Block_surfaces_a_persistent_hold_as_a_write_failure()
    {
        var engine = New();
        using var hold = new FileStream(_hosts, FileMode.Open, FileAccess.Read, FileShare.Read);

        // Windows reports the denied replace as either exception depending on
        // the path taken; both mean "hosts file held" to callers.
        var ex = Record.Exception(() => engine.Block("stuck.example.com"));

        ex.Should().Match(e => e is IOException || e is UnauthorizedAccessException);
    }

    [Fact]
    public void Unblock_removes_only_that_domain_and_preserves_custom()
    {
        var e = New();
        e.BlockBulk(new[] { "a.com", "b.com" }).Should().Be(2);
        e.Unblock("a.com").Should().BeTrue();
        e.GetBlocked().Should().NotContain("a.com").And.Contain("b.com");
        // Custom non-managed mapping preserved.
        e.GetLines().Should().Contain(l => l.Contains("myserver"));
    }

    [Fact]
    public void Unblock_preserves_non_sink_address_mappings()
    {
        File.WriteAllText(_hosts, "192.168.1.5 intranet.local\n0.0.0.0 intranet.local\n");
        var e = New();
        e.Unblock("intranet.local");
        var lines = e.GetLines();
        lines.Should().Contain(l => l.Contains("192.168.1.5 intranet.local"));
        lines.Should().NotContain(l => l.Contains("0.0.0.0 intranet.local"));
    }

    [Fact]
    public void OrganizeByCategory_appends_to_an_existing_section_and_creates_missing_ones()
    {
        File.WriteAllText(_hosts, "# Google Ads\n0.0.0.0 ad.doubleclick.net\n\n# HostsGuard\n0.0.0.0 pagead2.googlesyndication.com\n0.0.0.0 telemetry.microsoft.com\n");
        var e = New();

        var moved = e.OrganizeByCategory(new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["pagead2.googlesyndication.com"] = "Google Ads",
            ["telemetry.microsoft.com"] = "Microsoft Telemetry",
        });

        moved.Should().Be(2);
        var lines = File.ReadAllLines(_hosts).ToList();
        // Appended inside the existing Google Ads section (after its last entry).
        lines.IndexOf("0.0.0.0 pagead2.googlesyndication.com")
            .Should().Be(lines.IndexOf("# Google Ads") + 2);
        // New section created for the category with no header.
        var header = lines.IndexOf("# Microsoft Telemetry");
        header.Should().BeGreaterThan(0);
        lines[header + 1].Should().Be("0.0.0.0 telemetry.microsoft.com");
        // Both domains still blocked exactly once.
        e.GetBlocked().Should().Contain(new[] { "pagead2.googlesyndication.com", "telemetry.microsoft.com" });
        lines.Count(l => l.Contains("pagead2")).Should().Be(1);
    }

    [Fact]
    public void NormalizeCategorySections_folds_fragmented_sections_into_the_canonical_taxonomy()
    {
        File.WriteAllText(_hosts,
            "# Snapchat Tracking\n0.0.0.0 sc.example.com\n\n" +
            "# LinkedIn CDN\n0.0.0.0 cdn.linkedin.example\n\n" +
            "# Google Ads\n0.0.0.0 ad.doubleclick.net\n0.0.0.0 pagead.example.com\n");
        var e = New();

        static string Canon(string c)
        {
            var l = c.ToLowerInvariant();
            if (l.Contains("track")) return "Tracking & Analytics";
            if (l.Contains("cdn")) return "CDN";
            if (l.Contains("ad")) return "Advertising";
            return "Other";
        }

        var count = e.NormalizeCategorySections(Canon, curated: null,
            categoryOrder: new[] { "Advertising", "Tracking & Analytics", "CDN" });

        count.Should().Be(4);
        var lines = File.ReadAllLines(_hosts).Where(l => l.Length > 0).ToList();
        // Fragmented per-vendor headers are gone; three canonical sections remain,
        // in the given order, each domain filed under it.
        lines.Where(l => l.StartsWith('#')).Should()
            .Equal("# Advertising", "# Tracking & Analytics", "# CDN");
        lines.IndexOf("0.0.0.0 sc.example.com").Should().BeGreaterThan(lines.IndexOf("# Tracking & Analytics"));
        lines.IndexOf("0.0.0.0 cdn.linkedin.example").Should().BeGreaterThan(lines.IndexOf("# CDN"));
        e.GetBlocked().Should().HaveCount(4);

        // Idempotent: a second pass rewrites nothing.
        e.NormalizeCategorySections(Canon, curated: null,
            categoryOrder: new[] { "Advertising", "Tracking & Analytics", "CDN" }).Should().Be(0);
    }

    [Fact]
    public void OrganizeByCategory_leaves_unmapped_and_custom_lines_alone()
    {
        File.WriteAllText(_hosts, "# custom header\n127.0.0.1 myserver\n0.0.0.0 keep-where-it-is.com\n");
        var e = New();

        e.OrganizeByCategory(new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["not-in-file.com"] = "Ads",
        }).Should().Be(0);

        File.ReadAllLines(_hosts).Should().ContainInOrder(
            "# custom header", "127.0.0.1 myserver", "0.0.0.0 keep-where-it-is.com");
        File.ReadAllText(_hosts).Should().NotContain("not-in-file.com");
    }

    [Fact]
    public void Reconcile_enforces_exact_set_preserving_custom_lines()
    {
        var e = New();
        e.BlockBulk(new[] { "old1.com", "old2.com" });
        var (added, target) = e.Reconcile(new[] { "old1.com", "new1.com" });
        added.Should().Be(1);   // new1
        target.Should().Be(2);
        var blocked = e.GetBlocked();
        blocked.Should().Contain(new[] { "old1.com", "new1.com" });
        blocked.Should().NotContain("old2.com");
        // Non-managed entries survive.
        e.GetLines().Should().Contain(l => l.Contains("myserver"));
        e.GetLines().Should().Contain(l => l.Contains("# custom header"));
    }

    [Fact]
    public void EmergencyReset_leaves_only_header_and_no_blocks()
    {
        var e = New();
        e.BlockBulk(new[] { "a.com", "b.com" });
        e.EmergencyReset();
        e.GetBlocked().Should().BeEmpty();
        e.GetLines().Should().Contain(l => l.Contains("Microsoft"));
    }

    [Fact]
    public void SelfChange_recognizes_our_write_once()
    {
        var e = New();
        e.Block("x.example.com");
        var hash = e.CurrentFileHash();
        e.IsSelfChange(hash).Should().BeTrue();  // our write
        e.IsSelfChange(hash).Should().BeFalse(); // consumed — a second detection is treated as external
        e.IsSelfChange(null).Should().BeFalse();
    }

    [Fact]
    public void External_edit_is_not_a_self_change()
    {
        var e = New();
        e.Block("x.example.com");
        // Simulate an external tamper by writing directly, bypassing the engine.
        File.AppendAllText(_hosts, "0.0.0.0 evil.example.com\n");
        var hash = e.CurrentFileHash();
        e.IsSelfChange(hash).Should().BeFalse();
    }

    // Property/fuzz: Reconcile never loses non-managed lines and always yields exactly the target set.
    [Theory]
    [InlineData(1)]
    [InlineData(7)]
    [InlineData(42)]
    [InlineData(1234)]
    public void Reconcile_property_preserves_custom_and_matches_target(int seed)
    {
        var rng = new Random(seed);
        var custom = new List<string> { "# preserve me", "127.0.0.1 keepserver", "0.0.0.0 not_a_domain_line_kept?" };
        File.WriteAllText(_hosts, string.Join('\n', custom) + "\n");

        var e = New();
        // Random churn.
        for (var i = 0; i < 20; i++)
        {
            e.Block($"d{rng.Next(30)}.example.com");
        }

        var target = Enumerable.Range(0, rng.Next(1, 25)).Select(i => $"t{i}.example.com").ToList();
        e.Reconcile(target);

        var blocked = e.GetBlocked();
        blocked.Should().BeEquivalentTo(target); // exactly the target set
        var lines = e.GetLines();
        lines.Should().Contain(l => l.Contains("# preserve me"));
        lines.Should().Contain(l => l.Contains("keepserver"));
    }
}
